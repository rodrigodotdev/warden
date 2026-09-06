//! The two audit phases, and the different consequence each failure has.
//!
//! ```text
//! attempt -> written BEFORE execution.  Sink failure => the query does not run.
//! outcome -> written AFTER  execution.  Sink failure => an alarm, and the result
//!                                       is returned anyway.
//! ```
//!
//! The asymmetry is the whole point of ADR-0022, and it lives here rather than in the
//! sink: a sink only reports that a write did not happen. [`record_attempt`] returns a
//! `Result` its caller must handle; [`record_outcome`] returns unit, so no caller can
//! accidentally fail a request because the second write failed after execution had
//! already succeeded.

use std::fmt;
use std::sync::Arc;

use tokio::time::timeout;
use tracing::Instrument as _;
use tracing::instrument::WithSubscriber as _;
use warden_core::analysis::StatementKind;
use warden_core::connection::ConnectionMetadata;
use warden_core::context::RequestContext;
use warden_core::error::PublicErrorCode;
use warden_core::fingerprint::QueryFingerprint;
use warden_policy::DenyReason;
use warden_ports::{
    AuditAttempt, AuditError, AuditEventId, AuditOperation, AuditOutcome, AuditOutcomeEvent,
    AuditSink,
};

use crate::limits::AUDIT_WRITE_TIMEOUT;

/// What an attempt says about a statement, when there is one.
///
/// Grouped rather than passed as two parameters so a catalog read can write
/// `StatementFacts::default()` and mean it: no kind, no fingerprint, and no way to
/// pass one without the other by accident.
#[derive(Debug, Clone, Default)]
pub(crate) struct StatementFacts {
    /// The analyzed root statement kind.
    pub(crate) kind: Option<StatementKind>,
    /// The versioned fingerprint, when the adapter computed one.
    pub(crate) fingerprint: Option<QueryFingerprint>,
}

/// Builds the attempt for one request.
///
/// There is no `sql` parameter and no `parameters` parameter, because `AuditAttempt`
/// has no such fields: raw SQL and parameter values are off by default and a field
/// that does not exist cannot be switched on by a configuration mistake
/// (`docs/security.md` section 11.3).
pub(crate) fn attempt(
    context: &RequestContext,
    connection: &ConnectionMetadata,
    operation: AuditOperation,
    facts: StatementFacts,
    deny_reasons: Vec<DenyReason>,
) -> AuditAttempt {
    AuditAttempt {
        id: AuditEventId::generate(),
        timestamp: time::OffsetDateTime::now_utc(),
        request_id: context.request_id().clone(),
        principal: context.principal().clone(),
        client: context.client().clone(),
        connection: connection.name.clone(),
        dialect: connection.dialect,
        environment: connection.environment.clone(),
        operation,
        fingerprint: facts.fingerprint,
        statement_kind: facts.kind,
        deny_reasons,
    }
}

/// Records the attempt. The caller must not proceed if this fails.
pub(crate) async fn record_attempt(
    sink: &dyn AuditSink,
    event: &AuditAttempt,
) -> Result<(), AuditError> {
    let span = tracing::debug_span!("audit.attempt");
    match timeout(AUDIT_WRITE_TIMEOUT, sink.record_attempt(event))
        .instrument(span)
        .await
    {
        Ok(result) => result,
        Err(_elapsed) => Err(AuditError::Timeout),
    }
}

/// Records the outcome, raising an alarm if it cannot be written.
///
/// Returns unit on purpose. Execution has already happened; there is nothing left to
/// prevent, and a caller that could see the failure would eventually be tempted to
/// turn a successful query into an error (ADR-0022).
///
/// The alarm carries the attempt id, the outcome, and the sink error's `Display`,
/// which prints no `detail` field — so the operator log gains no hostname, database
/// user, or statement fragment (`docs/security.md` section 10).
pub(crate) async fn record_outcome(sink: &dyn AuditSink, event: AuditOutcomeEvent) {
    let span = tracing::debug_span!("audit.outcome");
    let written = match timeout(AUDIT_WRITE_TIMEOUT, sink.record_outcome(&event))
        .instrument(span)
        .await
    {
        Ok(result) => result,
        Err(_elapsed) => Err(AuditError::Timeout),
    };
    if let Err(error) = written {
        tracing::error!(
            target: "warden.audit",
            attempt_id = %event.attempt_id,
            outcome = %event.outcome,
            %error,
            "the audit outcome could not be recorded"
        );
    }
}

/// Tracks a recorded attempt through queueing, database access, and redaction.
///
/// An abandoned pending request raises an alarm and detaches a best-effort outcome.
/// Cancellation during completion raises only an alarm: the sink may already have
/// persisted that terminal record, so writing another would risk a contradiction.
pub(crate) struct OutcomeGuard {
    sink: Arc<dyn AuditSink>,
    state: OutcomeState,
    /// The service root that owns this attempt, retained for a detached outcome.
    parent: tracing::Span,
    /// The dispatcher that created `parent`, because spawned tasks do not inherit it.
    dispatch: tracing::Dispatch,
}

#[derive(Debug)]
enum OutcomeState {
    Pending(AuditEventId),
    Completing {
        attempt_id: AuditEventId,
        outcome: AuditOutcome,
    },
    Finished,
}

/// Prints only the attempt's terminal-state tracking, omitting the sink and dispatcher.
///
/// `AuditSink` is not `Debug` — the same reason `QueryService`, `ExplainService`, and
/// `SchemaService` all hand-write this impl and omit the port (`query.rs`).
impl fmt::Debug for OutcomeGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutcomeGuard")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl OutcomeGuard {
    /// Arms the guard for an attempt that is already on record under `parent`.
    pub(crate) fn arm(
        sink: Arc<dyn AuditSink>,
        attempt_id: AuditEventId,
        parent: tracing::Span,
    ) -> Self {
        Self {
            sink,
            state: OutcomeState::Pending(attempt_id),
            parent,
            dispatch: tracing::dispatcher::get_default(Clone::clone),
        }
    }

    /// Records the outcome the request actually had and disarms.
    pub(crate) async fn complete(mut self, event: AuditOutcomeEvent) {
        self.state = OutcomeState::Completing {
            attempt_id: event.attempt_id,
            outcome: event.outcome,
        };
        record_outcome(self.sink.as_ref(), event).await;
        self.state = OutcomeState::Finished;
    }
}

impl Drop for OutcomeGuard {
    fn drop(&mut self) {
        // Drop can run outside the dispatch that originally polled the request.
        let _dispatch = tracing::dispatcher::set_default(&self.dispatch);
        let attempt_id = match std::mem::replace(&mut self.state, OutcomeState::Finished) {
            OutcomeState::Finished => return,
            OutcomeState::Pending(attempt_id) => attempt_id,
            OutcomeState::Completing {
                attempt_id,
                outcome,
            } => {
                tracing::error!(
                    target: "warden.audit",
                    attempt_id = %attempt_id,
                    outcome = %outcome,
                    "audit outcome completion was interrupted; persistence is unknown"
                );
                return;
            }
        };
        // Always on stderr, whether or not the durable write below survives: a
        // runtime that is shutting down accepts a spawn and never polls it, and an
        // abandoned attempt must not depend on that task for its only trace.
        tracing::error!(
            target: "warden.audit",
            attempt_id = %attempt_id,
            outcome = AuditOutcome::Abandoned.as_str(),
            "a request ended without recording its own outcome"
        );
        let event = AuditOutcomeEvent {
            attempt_id,
            outcome: AuditOutcome::Abandoned,
            duration: None,
            queue_wait: None,
            rows_returned: None,
            result_bytes: None,
            error_code: Some(PublicErrorCode::InternalError),
        };
        // `Drop` cannot await, so the durable write is detached. The future carries
        // both the owning service span and its dispatcher because Tokio tasks inherit
        // neither. It is bounded by `AUDIT_WRITE_TIMEOUT` like every other write, and
        // there is no runtime to spawn on when a request is dropped during shutdown —
        // the alarm above is what covers that case.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                let sink = Arc::clone(&self.sink);
                let parent = self.parent.clone();
                let dispatch = self.dispatch.clone();
                handle.spawn(
                    async move { record_outcome(sink.as_ref(), event).await }
                        .instrument(parent)
                        .with_subscriber(dispatch),
                );
            }
            Err(_no_runtime) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::collections::BTreeMap;
    use std::fmt;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, OnceLock};
    use std::time::Duration;

    use tracing::field::{Field, Visit};
    use tracing::span;
    use tracing::{Event, Metadata, Subscriber};
    use warden_core::dialect::Dialect;
    use warden_ports::{AuditError, AuditOutcome};

    use super::*;
    use crate::testing;

    #[derive(Debug)]
    struct CapturedEvent {
        target: String,
        fields: BTreeMap<String, String>,
    }

    #[derive(Debug)]
    struct AuditAlarmSubscriber {
        events: Arc<Mutex<Vec<CapturedEvent>>>,
    }

    impl Subscriber for AuditAlarmSubscriber {
        fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
            true
        }

        fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
            Some(tracing::level_filters::LevelFilter::TRACE)
        }

        fn new_span(&self, _attributes: &span::Attributes<'_>) -> span::Id {
            span::Id::from_u64(1)
        }

        fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}

        fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}

        fn event(&self, event: &Event<'_>) {
            let mut visitor = FieldVisitor::default();
            event.record(&mut visitor);
            self.events.lock().unwrap().push(CapturedEvent {
                target: event.metadata().target().to_owned(),
                fields: visitor.fields,
            });
        }

        fn enter(&self, _span: &span::Id) {}

        fn exit(&self, _span: &span::Id) {}
    }

    #[derive(Default)]
    struct FieldVisitor {
        fields: BTreeMap<String, String>,
    }

    impl Visit for FieldVisitor {
        fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
            self.fields
                .insert(field.name().to_owned(), format!("{value:?}"));
        }
    }

    static ALARM_TEST_LOCK: AtomicBool = AtomicBool::new(false);

    struct AlarmTestLock;

    impl Drop for AlarmTestLock {
        fn drop(&mut self) {
            ALARM_TEST_LOCK.store(false, Ordering::Release);
        }
    }

    fn alarm_test_lock() -> AlarmTestLock {
        while ALARM_TEST_LOCK.swap(true, Ordering::Acquire) {
            std::thread::yield_now();
        }
        AlarmTestLock
    }

    fn alarm_events() -> Arc<Mutex<Vec<CapturedEvent>>> {
        static EVENTS: OnceLock<Arc<Mutex<Vec<CapturedEvent>>>> = OnceLock::new();
        Arc::clone(EVENTS.get_or_init(|| {
            let events = Arc::new(Mutex::new(Vec::new()));
            tracing::subscriber::set_global_default(AuditAlarmSubscriber {
                events: Arc::clone(&events),
            })
            .unwrap();
            events
        }))
    }

    fn outcome() -> AuditOutcomeEvent {
        AuditOutcomeEvent {
            attempt_id: AuditEventId::generate(),
            outcome: AuditOutcome::Succeeded,
            duration: Some(Duration::from_millis(1)),
            queue_wait: None,
            rows_returned: Some(1),
            result_bytes: Some(3),
            error_code: None,
        }
    }

    /// A sink that may have persisted before its completion future is cancelled.
    struct PendingOutcomeSink(Mutex<Vec<AuditOutcomeEvent>>);

    impl AuditSink for PendingOutcomeSink {
        fn record_attempt<'a>(
            &'a self,
            _event: &'a AuditAttempt,
        ) -> warden_ports::BoxFuture<'a, Result<(), AuditError>> {
            Box::pin(async { Ok(()) })
        }

        fn record_outcome<'a>(
            &'a self,
            event: &'a AuditOutcomeEvent,
        ) -> warden_ports::BoxFuture<'a, Result<(), AuditError>> {
            self.0.lock().unwrap().push(*event);
            Box::pin(std::future::pending())
        }
    }

    #[tokio::test]
    async fn cancelling_completion_alarms_without_writing_a_duplicate_outcome() {
        use std::future::Future as _;
        use std::task::{Context, Waker};

        let _lock = alarm_test_lock();
        let events = alarm_events();
        events.lock().unwrap().clear();
        let sink = Arc::new(PendingOutcomeSink(Mutex::new(Vec::new())));
        let recorded = outcome();
        let guard = OutcomeGuard::arm(sink.clone(), recorded.attempt_id, tracing::Span::none());
        let mut completion = Box::pin(guard.complete(recorded));
        assert!(
            completion
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(*sink.0.lock().unwrap(), vec![recorded]);
        drop(completion);

        let events = events.lock().unwrap();
        let alarms: Vec<_> = events
            .iter()
            .filter(|event| {
                event.fields.get("attempt_id") == Some(&recorded.attempt_id.to_string())
            })
            .collect();
        assert_eq!(
            alarms.len(),
            1,
            "cancellation must leave a synchronous alarm"
        );
        let alarm = alarms[0];
        assert_eq!(alarm.target, "warden.audit");
        assert_eq!(alarm.fields.get("outcome"), Some(&"succeeded".to_owned()));
        assert_eq!(
            alarm.fields.keys().map(String::as_str).collect::<Vec<_>>(),
            vec!["attempt_id", "message", "outcome"]
        );
        // A blindly detached retry would own another Arc even before being polled.
        assert_eq!(Arc::strong_count(&sink), 1);
        assert_eq!(*sink.0.lock().unwrap(), vec![recorded]);
    }

    #[test]
    fn an_attempt_carries_every_denial_and_no_statement() {
        let reasons = vec![DenyReason::new(warden_policy::DenyCode::WriteStatement)];
        let recorded = attempt(
            &testing::request_context(),
            &testing::connection(Dialect::MySql),
            AuditOperation::Query,
            StatementFacts {
                kind: Some(StatementKind::Insert),
                fingerprint: None,
            },
            reasons.clone(),
        );
        assert_eq!(recorded.deny_reasons, reasons);
        assert_eq!(recorded.statement_kind, Some(StatementKind::Insert));
        assert_eq!(
            recorded.connection,
            testing::connection(Dialect::MySql).name
        );
    }

    #[tokio::test]
    async fn a_recorded_attempt_reaches_the_sink() {
        let sink = testing::FakeAuditSink::new();
        let recorded = testing::attempt();
        record_attempt(&sink, &recorded).await.unwrap();
        assert_eq!(sink.attempts().len(), 1);
    }

    #[tokio::test]
    async fn a_broken_attempt_write_is_reported_so_the_caller_fails_closed() {
        let sink = testing::FakeAuditSink::broken_attempts();
        let error = record_attempt(&sink, &testing::attempt())
            .await
            .unwrap_err();
        assert!(matches!(error, AuditError::Unavailable { .. }));
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_attempt_write_is_bounded_rather_than_awaited_forever() {
        let sink = testing::FakeAuditSink::taking(AUDIT_WRITE_TIMEOUT * 10);
        let error = record_attempt(&sink, &testing::attempt())
            .await
            .unwrap_err();
        assert_eq!(error, AuditError::Timeout);
    }

    #[tokio::test]
    async fn a_recorded_outcome_reaches_the_sink() {
        let sink = testing::FakeAuditSink::new();
        let recorded = outcome();
        record_outcome(&sink, recorded).await;
        assert_eq!(sink.outcomes(), vec![recorded]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_outcome_write_is_cancelled_at_the_audit_timeout() {
        let _guard = alarm_test_lock();
        let _events = alarm_events();
        let sink = testing::FakeAuditSink::taking(AUDIT_WRITE_TIMEOUT * 10);
        record_outcome(&sink, outcome()).await;
        assert!(sink.outcomes().is_empty());
    }

    #[tokio::test]
    async fn a_broken_outcome_write_raises_a_sanitized_alarm_without_failing_the_request() {
        let _guard = alarm_test_lock();
        let events = alarm_events();
        events.lock().unwrap().clear();
        let sink = testing::FakeAuditSink::broken_outcomes();
        let recorded = outcome();

        record_outcome(&sink, recorded).await;

        let events = events.lock().unwrap();
        let alarms: Vec<_> = events
            .iter()
            .filter(|event| {
                event.fields.get("attempt_id") == Some(&recorded.attempt_id.to_string())
            })
            .collect();
        assert_eq!(alarms.len(), 1);
        let alarm = alarms[0];
        assert_eq!(alarm.target, "warden.audit");
        assert_eq!(
            alarm.fields.get("attempt_id"),
            Some(&recorded.attempt_id.to_string())
        );
        assert_eq!(alarm.fields.get("outcome"), Some(&"succeeded".to_owned()));
        assert_eq!(
            alarm.fields.get("error"),
            Some(&"the audit sink is unavailable".to_owned())
        );
        assert!(
            !alarm
                .fields
                .values()
                .any(|value| value.contains("the fake sink is broken"))
        );
    }

    #[test]
    fn an_unstarted_statement_has_an_outcome_that_does_not_claim_it_ran() {
        assert_eq!(AuditOutcome::NotStarted.as_str(), "not_started");
        assert!(AuditOutcome::ALL.contains(&AuditOutcome::NotStarted));
    }
}
