//! The one place in this crate that may reach a database.
//!
//! ADR-0032 made the concurrency permit a parameter of `execute_read_only` and
//! `explain`, so execution cannot begin without a slot. It deliberately did not
//! resolve two remaining gaps, both recorded in `docs/open-questions.md` item 14:
//!
//! * a `&QueryPermit` carries no connection identity, so a permit taken on one
//!   connection type-checks against another's executor;
//! * nothing ordered the permit against `AuditSink::record_attempt`, which ADR-0022
//!   requires to happen first.
//!
//! [`ExecutionGate`] closes both by construction. Its only constructor records the
//! attempt, and *then* acquires the permit from the same [`ConnectionRuntime`] it
//! stores and later dispatches to. There is no other constructor, no accessor that
//! hands the permit out, and no way to build one from a runtime it will not use
//! (ADR-0038).
//!
//! The guarantee is scoped honestly: it holds because this gate is the only caller of
//! `acquire_query_permit`, `executor()`, and `explainer()` in `warden-service`, which
//! `tests/service_rules.rs` asserts mechanically. It does not constrain a future crate
//! that calls the ports directly, and it does not replace database privileges
//! (ADR-0016).

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;
use warden_core::analysis::StatementKind;
use warden_core::context::RequestContext;
use warden_core::error::{PublicError as _, PublicErrorCode};
use warden_core::explain::QueryPlan;
use warden_core::query::QueryRequest;
use warden_core::result::ResultSet;
use warden_policy::{AuthorizedQuery, PolicyEngine, PolicyRejection};
use warden_ports::{
    AnalyzeError, AuditAttempt, AuditError, AuditOperation, AuditOutcome, AuditOutcomeEvent,
    AuditSink, ConnectionError, ConnectionRegistry, ConnectionRuntime, ExecuteError, ExplainError,
    QueryPermit,
};

use crate::audit::{self, StatementFacts};
use crate::limits::RequestBudget;
use crate::redaction::Redactor;

/// The collaborators every service in this crate holds, and the sequence two of them
/// share.
///
/// All three services — query, explain, schema — held the identical five fields and an
/// identical `new`. Two of them also ran the identical preflight: resolve the
/// connection, analyse the statement, authorise it, build the attempt, each with its
/// own span and its own audited refusal arm. That was ~150 duplicated lines in which
/// the *order* is the security property (ADR-0022), which is the worst possible thing
/// to keep two copies of.
///
/// This deduplicates a body, not a concept. The three services stay separate public
/// types with separate error enums, because `docs/security.md` section 10 wants that
/// error map readable.
#[derive(Clone)]
pub(crate) struct ServiceCore {
    registry: Arc<dyn ConnectionRegistry>,
    engine: Arc<PolicyEngine>,
    audit: Arc<dyn AuditSink>,
    redactor: Arc<Redactor>,
    shutdown: CancellationToken,
}

/// Prints only non-secret configuration state.
///
/// Port implementations are deliberately omitted: an adapter may hold a driver pool
/// whose debug output includes connection options. The cancellation token is omitted
/// too — token state is runtime coordination rather than useful configuration.
impl fmt::Debug for ServiceCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceCore")
            .field("redactor_is_empty", &self.redactor.is_empty())
            .finish_non_exhaustive()
    }
}

/// Everything decided before a permit is taken: the connection, the authorised
/// statement, and the attempt that must be recorded before either is used.
///
/// The caller owns this, and [`ServiceCore::gate`] borrows from it. That split is not
/// stylistic: `ExecutionGate<'a>` borrows the `ConnectionRuntime`, and
/// `ConnectionRegistry::get` returns an owned `Arc`, so a single call that both
/// resolved the connection and opened the gate would be returning a borrow of its own
/// local. It also matches the two halves ADR-0022 already distinguishes — everything
/// before the audited attempt, and the attempt-then-permit sequence the gate exists to
/// make unskippable.
pub(crate) struct Preflight {
    runtime: Arc<ConnectionRuntime>,
    attempt: AuditAttempt,
    authorized: AuthorizedQuery,
}

impl Preflight {
    /// The connection, the attempt, and the authorised statement.
    ///
    /// Consuming rather than borrowing, because `AuthorizedQuery` is deliberately not
    /// `Clone`: it is the capability token that proves policy ran, and a type that can
    /// be duplicated is a capability that can be reused (ADR-0021). The caller holds
    /// the returned `Arc` for as long as the gate borrowed from it lives.
    pub(crate) fn into_parts(self) -> (Arc<ConnectionRuntime>, AuditAttempt, AuthorizedQuery) {
        (self.runtime, self.attempt, self.authorized)
    }
}

/// Why a request was refused before it reached the gate.
///
/// Every variant here has already been audited: [`ServiceCore::preflight`] records the
/// attempt and completes it before returning any of them, so a caller cannot forget to.
/// The service error types convert from this, which is what keeps their own error maps
/// exhaustive and readable.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub(crate) enum PreflightError {
    /// The name resolved to no connection.
    #[error(transparent)]
    Connection(#[from] ConnectionError),
    /// The statement did not parse.
    #[error(transparent)]
    Analyze(#[from] AnalyzeError),
    /// Policy denied the statement.
    #[error(transparent)]
    Rejected(#[from] PolicyRejection),
}

impl ServiceCore {
    /// Wires the collaborators one request needs.
    pub(crate) fn new(
        registry: Arc<dyn ConnectionRegistry>,
        engine: Arc<PolicyEngine>,
        audit: Arc<dyn AuditSink>,
        redactor: Arc<Redactor>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            registry,
            engine,
            audit,
            redactor,
            shutdown,
        }
    }

    /// The response redactor, for the one step each service does differently.
    pub(crate) fn redactor(&self) -> &Redactor {
        &self.redactor
    }

    /// The connection registry, for `list_connections` and for schema resolution.
    pub(crate) fn registry(&self) -> &dyn ConnectionRegistry {
        self.registry.as_ref()
    }

    /// The audit sink, for the schema service's own attempt writes.
    pub(crate) fn audit(&self) -> &Arc<dyn AuditSink> {
        &self.audit
    }

    /// The policy engine, for the schema service's object filter.
    pub(crate) fn engine(&self) -> &PolicyEngine {
        self.engine.as_ref()
    }

    /// A token that cancels when the process shuts down.
    ///
    /// A child token, never the parent: cancelling one request must not cancel the
    /// others, while a shutdown still reaches every one of them.
    pub(crate) fn child_token(&self) -> CancellationToken {
        self.shutdown.child_token()
    }

    /// Resolve, analyse, authorise, and build the attempt — in ADR-0022's order.
    ///
    /// Every failing arm records the attempt and completes it before returning, so a
    /// refusal is audited whether or not the caller remembers to. SPEC section 6,
    /// invariant 24: an attempt that never reached policy is still an attempt.
    ///
    /// # Errors
    ///
    /// [`PreflightError`], already audited.
    pub(crate) async fn preflight(
        &self,
        context: &RequestContext,
        request: QueryRequest,
        operation: AuditOperation,
    ) -> Result<Preflight, PreflightError> {
        let runtime = {
            let _entered = tracing::debug_span!("connection.resolve").entered();
            self.registry.get(request.connection())
        }?;

        let analysis_result = {
            let _entered = tracing::debug_span!("sql.analyze").entered();
            runtime.analyzer().analyze(request)
        };
        let analyzed = match analysis_result {
            Ok(analyzed) => analyzed,
            Err(error) => {
                // `AnalyzeError::deny_reason` is the only producer of
                // `DenyCode::ParserRecursionLimit`, and it copies no parser text into
                // the record.
                let attempt = audit::attempt(
                    context,
                    runtime.metadata(),
                    operation,
                    StatementFacts {
                        kind: Some(StatementKind::Unknown),
                        fingerprint: None,
                    },
                    vec![error.deny_reason()],
                );
                self.refuse(&attempt, AuditOutcome::Denied, error.public_code())
                    .await;
                return Err(error.into());
            }
        };

        let statement_kind = analyzed.analysis().root_kind();
        let fingerprint = analyzed.analysis().fingerprint().cloned();
        // `runtime.limits()` and nothing else: `AuthorizedQuery::limits()` is whatever
        // the caller passed here, and the adapter treats it as authoritative for the
        // row and byte bounds (`crates/warden-ports/src/runtime.rs`).
        let authorization = {
            let _entered = tracing::debug_span!("policy.evaluate").entered();
            self.engine
                .authorize(context, runtime.metadata(), analyzed, runtime.limits())
        };
        let authorized = match authorization {
            Ok(authorized) => authorized,
            Err(rejection) => {
                let attempt = audit::attempt(
                    context,
                    runtime.metadata(),
                    operation,
                    StatementFacts {
                        kind: Some(statement_kind),
                        fingerprint,
                    },
                    rejection.reasons().to_vec(),
                );
                self.refuse(&attempt, AuditOutcome::Denied, rejection.public_code())
                    .await;
                return Err(rejection.into());
            }
        };

        let attempt = audit::attempt(
            context,
            runtime.metadata(),
            operation,
            StatementFacts {
                kind: Some(statement_kind),
                fingerprint,
            },
            Vec::new(),
        );
        Ok(Preflight {
            runtime,
            attempt,
            authorized,
        })
    }

    /// Records the attempt, arms its outcome guard, then takes the permit.
    ///
    /// # Errors
    ///
    /// [`GateError`], whose two variants differ in whether an outcome is still owed.
    pub(crate) async fn gate<'a>(
        &self,
        runtime: &'a ConnectionRuntime,
        attempt: &AuditAttempt,
        authorized: AuthorizedQuery,
        outcome_parent: tracing::Span,
    ) -> Result<(ExecutionGate<'a>, audit::OutcomeGuard), GateError> {
        ExecutionGate::enter(
            runtime,
            Arc::clone(&self.audit),
            attempt,
            authorized,
            self.shutdown.child_token(),
            outcome_parent,
        )
        .await
    }

    /// Records a refused attempt and its terminal outcome together.
    ///
    /// Analysis and policy refusals happen before [`ExecutionGate`] records an
    /// attempt. The attempt write's failure is logged rather than returned: the
    /// statement was already refused, so there is no execution window for a
    /// fail-closed rule to protect (ADR-0022).
    pub(crate) async fn refuse(
        &self,
        attempt: &AuditAttempt,
        outcome: AuditOutcome,
        error_code: PublicErrorCode,
    ) {
        if let Err(error) = audit::record_attempt(self.audit.as_ref(), attempt).await {
            tracing::error!(
                target: "warden.audit",
                attempt_id = %attempt.id,
                %error,
                "the audit attempt could not be recorded for a refused request"
            );
        }
        // No gate was ever entered for a refused statement, so there is no permit
        // acquisition to time.
        self.complete(attempt, outcome, None, None, error_code)
            .await;
    }

    /// Records the terminal state of an attempt without writing the attempt again.
    pub(crate) async fn complete(
        &self,
        attempt: &AuditAttempt,
        outcome: AuditOutcome,
        duration: Option<Duration>,
        queue_wait: Option<Duration>,
        error_code: PublicErrorCode,
    ) {
        audit::record_outcome(
            self.audit.as_ref(),
            AuditOutcomeEvent {
                attempt_id: attempt.id,
                outcome,
                duration,
                queue_wait,
                rows_returned: None,
                result_bytes: None,
                error_code: Some(error_code),
            },
        )
        .await;
    }
}

/// Why a request never reached the database.
///
/// The two variants have different consequences for the caller, which is why they are
/// distinct: an audit failure means no attempt was recorded, so there is no outcome to
/// complete, while a connection failure means the gate has completed the recorded
/// attempt as `AuditOutcome::NotStarted` before returning the error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum GateError {
    /// The attempt could not be recorded, so nothing may run.
    #[error(transparent)]
    Audit(AuditError),
    /// The connection could not give this request a slot.
    #[error("{error}")]
    Connection {
        /// Why the connection refused.
        #[source]
        error: ConnectionError,
        /// How long the request waited before it was refused.
        ///
        /// The same measurement the gate records in its `not_started` outcome.
        queue_wait: Duration,
    },
}

/// An authorized statement, its connection, a recorded attempt, and that connection's
/// permit — in that order, held together.
#[derive(Debug)]
pub(crate) struct ExecutionGate<'a> {
    runtime: &'a ConnectionRuntime,
    query: AuthorizedQuery,
    /// Both the witness `execute_read_only` and `explain` require (ADR-0032) and the
    /// slot itself: dropping the gate releases it.
    permit: QueryPermit,
    /// How long this request waited for its permit.
    queue_wait: Duration,
    deadline: Instant,
    cancel: CancellationToken,
}

impl<'a> ExecutionGate<'a> {
    /// Records the attempt, arms its outcome guard, then takes a permit from the same runtime.
    ///
    /// The order is the contract. A caller cannot reverse it, skip the attempt, or
    /// pair the permit with a different connection, because this is the only
    /// constructor and it does all three itself. The returned guard must survive
    /// execution and redaction, then complete with the terminal result.
    pub(crate) async fn enter(
        runtime: &'a ConnectionRuntime,
        sink: Arc<dyn AuditSink>,
        attempt: &AuditAttempt,
        query: AuthorizedQuery,
        cancel: CancellationToken,
        outcome_parent: tracing::Span,
    ) -> Result<(Self, audit::OutcomeGuard), GateError> {
        audit::record_attempt(sink.as_ref(), attempt)
            .await
            .map_err(GateError::Audit)?;
        let guard = audit::OutcomeGuard::arm(sink, attempt.id, outcome_parent);
        let queued_at = Instant::now();
        let span = tracing::debug_span!("concurrency.acquire");
        let permit = match runtime.acquire_query_permit().instrument(span).await {
            Ok(permit) => permit,
            Err(error) => {
                let queue_wait = queued_at.elapsed();
                guard
                    .complete(AuditOutcomeEvent {
                        attempt_id: attempt.id,
                        outcome: AuditOutcome::NotStarted,
                        duration: None,
                        queue_wait: Some(queue_wait),
                        rows_returned: None,
                        result_bytes: None,
                        error_code: Some(error.public_code()),
                    })
                    .await;
                return Err(GateError::Connection { error, queue_wait });
            }
        };
        let acquired_at = Instant::now();
        Ok((
            Self {
                runtime,
                query,
                permit,
                queue_wait: acquired_at.saturating_duration_since(queued_at),
                deadline: RequestBudget::new(runtime.limits()).deadline(acquired_at),
                cancel,
            },
            guard,
        ))
    }

    /// How long this request waited for its permit.
    pub(crate) fn queue_wait(&self) -> Duration {
        self.queue_wait
    }

    /// Runs the statement, releasing the slot when the call returns.
    ///
    /// Takes `self` by value so the permit is dropped at the end of the call rather
    /// than whenever the caller happens to drop the gate.
    pub(crate) async fn execute(self) -> Result<ResultSet, ExecuteError> {
        self.runtime
            .executor()
            .execute_read_only(
                &self.query,
                &self.permit,
                self.deadline,
                self.cancel.clone(),
            )
            .await
    }

    /// Plans the statement without running it, releasing the slot when the call
    /// returns.
    pub(crate) async fn explain(self) -> Result<QueryPlan, ExplainError> {
        self.runtime
            .explainer()
            .explain(
                &self.query,
                &self.permit,
                self.deadline,
                self.cancel.clone(),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    /// A gate entered on `runtime` with the default fakes.
    ///
    /// Almost every test in this module is about what the gate does once it is open,
    /// and the nine lines that open one were repeated before each of them. The two
    /// tests that vary a token or a sink still call `ExecutionGate::enter` directly:
    /// there, the argument being varied is the subject, and spelling it out is the
    /// point.
    /// A gate entered on `runtime` under a caller-supplied cancellation token.
    ///
    /// The token is the subject of every test that uses this, so it stays at the call
    /// site; the rest is the same default wiring [`entered`] supplies.
    async fn entered_with_token(
        runtime: &ConnectionRuntime,
        cancel: CancellationToken,
    ) -> (ExecutionGate<'_>, audit::OutcomeGuard) {
        ExecutionGate::enter(
            runtime,
            Arc::new(testing::FakeAuditSink::new()),
            &testing::attempt(),
            testing::authorized(runtime),
            cancel,
            tracing::Span::none(),
        )
        .await
        .unwrap()
    }

    async fn entered(runtime: &ConnectionRuntime) -> (ExecutionGate<'_>, audit::OutcomeGuard) {
        ExecutionGate::enter(
            runtime,
            Arc::new(testing::FakeAuditSink::new()),
            &testing::attempt(),
            testing::authorized(runtime),
            CancellationToken::new(),
            tracing::Span::none(),
        )
        .await
        .unwrap()
    }

    use std::sync::Arc;
    use std::time::Duration;

    use tokio_util::sync::CancellationToken;
    use warden_core::dialect::Dialect;
    use warden_core::limits::ExecutionLimits;
    use warden_ports::{ConnectionError, ExecuteError, ExplainError};

    use super::*;
    use crate::testing;

    #[tokio::test]
    async fn entering_records_the_attempt_before_taking_a_permit() {
        let sink = Arc::new(testing::FakeAuditSink::new());
        let runtime = testing::runtime(Dialect::MySql);
        let attempt = testing::attempt();
        let (gate, _guard) = ExecutionGate::enter(
            &runtime,
            sink.clone(),
            &attempt,
            testing::authorized(&runtime),
            CancellationToken::new(),
            tracing::Span::none(),
        )
        .await
        .unwrap();
        assert_eq!(sink.attempts().len(), 1);
        assert_eq!(
            runtime.available_permits(),
            ExecutionLimits::default().max_concurrent_queries - 1
        );
        drop(gate);
        assert_eq!(
            runtime.available_permits(),
            ExecutionLimits::default().max_concurrent_queries
        );
    }

    #[tokio::test]
    async fn a_broken_attempt_write_takes_no_permit_and_reaches_no_executor() {
        let sink = Arc::new(testing::FakeAuditSink::broken_attempts());
        let executor = Arc::new(testing::FakeExecutor::new());
        let runtime = testing::runtime_with_executor(Dialect::MySql, Arc::clone(&executor));
        let error = ExecutionGate::enter(
            &runtime,
            sink.clone(),
            &testing::attempt(),
            testing::authorized(&runtime),
            CancellationToken::new(),
            tracing::Span::none(),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, GateError::Audit(_)));
        assert!(
            sink.attempts().is_empty(),
            "a failed write must not look recorded"
        );
        assert_eq!(executor.calls(), 0, "the database must not be reached");
        assert_eq!(
            runtime.available_permits(),
            ExecutionLimits::default().max_concurrent_queries
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_saturated_connection_reports_busy_after_max_queue_wait() {
        let limits = ExecutionLimits {
            max_concurrent_queries: 1,
            ..ExecutionLimits::default()
        };
        let runtime = testing::runtime_with_limits(Dialect::MySql, limits);
        let sink = Arc::new(testing::FakeAuditSink::new());
        let (held, _held_guard) = ExecutionGate::enter(
            &runtime,
            sink.clone(),
            &testing::attempt(),
            testing::authorized(&runtime),
            CancellationToken::new(),
            tracing::Span::none(),
        )
        .await
        .unwrap();
        let error = ExecutionGate::enter(
            &runtime,
            sink.clone(),
            &testing::attempt(),
            testing::authorized(&runtime),
            CancellationToken::new(),
            tracing::Span::none(),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            GateError::Connection {
                error: ConnectionError::Busy { .. },
                ..
            }
        ));
        // The second attempt was still recorded: the ordering is attempt first.
        assert_eq!(sink.attempts().len(), 2);
        drop(held);
    }

    #[test]
    fn a_connection_gate_error_exposes_its_typed_source() {
        let source = ConnectionError::Busy {
            name: "production-db".parse().unwrap(),
        };
        let error = GateError::Connection {
            error: source.clone(),
            queue_wait: Duration::from_millis(3),
        };

        let exposed = std::error::Error::source(&error)
            .and_then(|source| source.downcast_ref::<ConnectionError>());

        assert_eq!(exposed, Some(&source));
    }

    #[tokio::test]
    async fn the_gate_passes_the_client_deadline_and_the_token_through() {
        let runtime = testing::runtime(Dialect::MySql);
        let cancel = CancellationToken::new();
        cancel.cancel();
        let (gate, _guard) = entered_with_token(&runtime, cancel).await;
        assert_eq!(gate.execute().await.unwrap_err(), ExecuteError::Cancelled);
        assert_eq!(
            runtime.available_permits(),
            ExecutionLimits::default().max_concurrent_queries
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_adapter_meets_the_deadline_rather_than_running_forever() {
        let runtime = testing::runtime_with_executor(
            Dialect::MySql,
            Arc::new(testing::FakeExecutor::taking(Duration::from_secs(600))),
        );
        let (gate, _guard) = entered(&runtime).await;
        assert_eq!(gate.execute().await.unwrap_err(), ExecuteError::Timeout);
        assert_eq!(
            runtime.available_permits(),
            ExecutionLimits::default().max_concurrent_queries
        );
    }

    #[tokio::test]
    async fn a_successful_execution_releases_its_permit() {
        let runtime = testing::runtime(Dialect::MySql);
        let (gate, _guard) = entered(&runtime).await;

        gate.execute().await.unwrap();

        assert_eq!(
            runtime.available_permits(),
            ExecutionLimits::default().max_concurrent_queries
        );
    }

    #[tokio::test]
    async fn an_adapter_execution_error_releases_its_permit() {
        let runtime = testing::runtime_with_executor(
            Dialect::MySql,
            Arc::new(testing::FakeExecutor::failing(ExecuteError::Database {
                detail: "fixture failure".to_owned(),
            })),
        );
        let (gate, _guard) = entered(&runtime).await;

        assert!(matches!(
            gate.execute().await,
            Err(ExecuteError::Database { .. })
        ));
        assert_eq!(
            runtime.available_permits(),
            ExecutionLimits::default().max_concurrent_queries
        );
    }

    #[tokio::test]
    async fn a_successful_explain_releases_its_permit() {
        let runtime = testing::runtime(Dialect::MySql);
        let (gate, _guard) = entered(&runtime).await;

        gate.explain().await.unwrap();

        assert_eq!(
            runtime.available_permits(),
            ExecutionLimits::default().max_concurrent_queries
        );
    }

    #[tokio::test]
    async fn an_adapter_explain_error_releases_its_permit() {
        let runtime = testing::runtime_with_explainer(
            Dialect::MySql,
            Arc::new(testing::FakeExplainer::failing(ExplainError::Database {
                detail: "fixture failure".to_owned(),
            })),
        );
        let (gate, _guard) = entered(&runtime).await;

        assert!(matches!(
            gate.explain().await,
            Err(ExplainError::Database { .. })
        ));
        assert_eq!(
            runtime.available_permits(),
            ExecutionLimits::default().max_concurrent_queries
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cancelling_an_explain_releases_its_permit() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let runtime = testing::runtime_with_explainer(
            Dialect::MySql,
            Arc::new(testing::FakeExplainer::taking(Duration::from_secs(600))),
        );
        let (gate, _guard) = entered_with_token(&runtime, cancel).await;

        assert_eq!(gate.explain().await.unwrap_err(), ExplainError::Cancelled);
        assert_eq!(
            runtime.available_permits(),
            ExecutionLimits::default().max_concurrent_queries
        );
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_an_in_flight_execution_releases_its_permit() {
        let limits = ExecutionLimits {
            max_concurrent_queries: 1,
            ..ExecutionLimits::default()
        };
        let executor = Arc::new(testing::FakeExecutor::taking(Duration::from_secs(600)));
        let mut parts = testing::FakeParts::new(Dialect::MySql);
        parts.limits = limits;
        parts.executor = executor;
        let runtime = testing::runtime_from(parts);
        let (gate, _guard) = entered(&runtime).await;
        let mut execution = Box::pin(gate.execute());
        tokio::select! {
            result = &mut execution => panic!("execution unexpectedly finished: {result:?}"),
            () = tokio::time::sleep(Duration::from_millis(1)) => {}
        }
        assert_eq!(runtime.available_permits(), 0);

        drop(execution);

        assert_eq!(runtime.available_permits(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_an_in_flight_explain_releases_its_permit() {
        let limits = ExecutionLimits {
            max_concurrent_queries: 1,
            ..ExecutionLimits::default()
        };
        let explainer = Arc::new(testing::FakeExplainer::taking(Duration::from_secs(600)));
        let mut parts = testing::FakeParts::new(Dialect::MySql);
        parts.limits = limits;
        parts.explainer = explainer;
        let runtime = testing::runtime_from(parts);
        let (gate, _guard) = entered(&runtime).await;
        let mut explanation = Box::pin(gate.explain());
        tokio::select! {
            result = &mut explanation => panic!("explain unexpectedly finished: {result:?}"),
            () = tokio::time::sleep(Duration::from_millis(1)) => {}
        }
        assert_eq!(runtime.available_permits(), 0);

        drop(explanation);

        assert_eq!(runtime.available_permits(), 1);
    }

    #[tokio::test]
    async fn execute_receives_the_same_cancellation_domain_not_a_child() {
        let executor = Arc::new(testing::FakeExecutor::new());
        let runtime = testing::runtime_with_executor(Dialect::MySql, Arc::clone(&executor));
        let cancel = CancellationToken::new();
        let (gate, _guard) = entered_with_token(&runtime, cancel.clone()).await;

        gate.execute().await.unwrap();

        let (_, observed_cancel) = executor.latest_observation();
        observed_cancel.cancel();
        assert!(cancel.is_cancelled());
    }

    #[tokio::test]
    async fn explain_receives_the_same_cancellation_domain_not_a_child() {
        let explainer = Arc::new(testing::FakeExplainer::new());
        let runtime = testing::runtime_with_explainer(Dialect::MySql, Arc::clone(&explainer));
        let cancel = CancellationToken::new();
        let (gate, _guard) = entered_with_token(&runtime, cancel.clone()).await;

        gate.explain().await.unwrap();

        let (_, observed_cancel) = explainer.latest_observation();
        observed_cancel.cancel();
        assert!(cancel.is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn execute_receives_the_original_token_and_a_post_queue_deadline() {
        let queue_wait = Duration::from_millis(500);
        let limits = ExecutionLimits {
            max_concurrent_queries: 1,
            ..ExecutionLimits::default()
        };
        let executor = Arc::new(testing::FakeExecutor::new());
        let mut parts = testing::FakeParts::new(Dialect::MySql);
        parts.limits = limits;
        parts.executor = Arc::clone(&executor) as Arc<dyn warden_ports::QueryExecutor>;
        let runtime = testing::runtime_from(parts);
        let (held, _held_guard) = entered(&runtime).await;
        let cancel = CancellationToken::new();
        let waiting_sink = Arc::new(testing::FakeAuditSink::new());
        let waiting_attempt = testing::attempt();
        let mut waiting = Box::pin(ExecutionGate::enter(
            &runtime,
            waiting_sink.clone(),
            &waiting_attempt,
            testing::authorized(&runtime),
            cancel.clone(),
            tracing::Span::none(),
        ));
        tokio::select! {
            result = &mut waiting => panic!("permit acquired while held: {result:?}"),
            () = tokio::time::sleep(queue_wait) => {}
        }
        drop(held);
        let (gate, _guard) = waiting.await.unwrap();
        let permit_acquired_at = Instant::now();

        gate.execute().await.unwrap();

        let (deadline, observed_cancel) = executor.latest_observation();
        assert_eq!(deadline, permit_acquired_at + limits.client_timeout());
        assert!(!observed_cancel.is_cancelled());
        cancel.cancel();
        assert!(observed_cancel.is_cancelled());
        assert_eq!(runtime.available_permits(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn explain_receives_the_original_token_and_a_post_queue_deadline() {
        let queue_wait = Duration::from_millis(500);
        let limits = ExecutionLimits {
            max_concurrent_queries: 1,
            ..ExecutionLimits::default()
        };
        let explainer = Arc::new(testing::FakeExplainer::new());
        let mut parts = testing::FakeParts::new(Dialect::MySql);
        parts.limits = limits;
        parts.explainer = Arc::clone(&explainer) as Arc<dyn warden_ports::Explainer>;
        let runtime = testing::runtime_from(parts);
        let (held, _held_guard) = entered(&runtime).await;
        let cancel = CancellationToken::new();
        let waiting_sink = Arc::new(testing::FakeAuditSink::new());
        let waiting_attempt = testing::attempt();
        let mut waiting = Box::pin(ExecutionGate::enter(
            &runtime,
            waiting_sink.clone(),
            &waiting_attempt,
            testing::authorized(&runtime),
            cancel.clone(),
            tracing::Span::none(),
        ));
        tokio::select! {
            result = &mut waiting => panic!("permit acquired while held: {result:?}"),
            () = tokio::time::sleep(queue_wait) => {}
        }
        drop(held);
        let (gate, _guard) = waiting.await.unwrap();
        let permit_acquired_at = Instant::now();

        gate.explain().await.unwrap();

        let (deadline, observed_cancel) = explainer.latest_observation();
        assert_eq!(deadline, permit_acquired_at + limits.client_timeout());
        assert!(!observed_cancel.is_cancelled());
        cancel.cancel();
        assert!(observed_cancel.is_cancelled());
        assert_eq!(runtime.available_permits(), 1);
    }
}
