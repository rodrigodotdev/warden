//! The Milestone 12 audit sink.
//!
//! `warden_service::Services` requires an `AuditSink`, and Milestone 13 owns the
//! persistent one. This writes structured `tracing` events to stderr under the field list
//! `docs/operations.md` section 10.2 allows, which is enough to make every attempt and
//! outcome observable in a local session and honest about what it is not: a `tracing` macro
//! returns unit, so this sink cannot fail, and ADR-0022's fail-closed attempt therefore has
//! nothing to fail on yet. That is why the definition-of-done box for two-phase auditing
//! stays unchecked at the end of this milestone.
//!
//! It records deny **codes**, not `DenyReason::internal_detail`. The detail exists so an
//! auditor can see why a rule fired without the agent seeing it
//! (`docs/security.md` section 6); which of it belongs in a durable record is a decision
//! Milestone 13's sink makes with its own format, not one a stderr line should make first.

use warden_ports::{AuditAttempt, AuditError, AuditOutcomeEvent, AuditSink, BoxFuture};

/// The target both events carry, matching `warden-service`'s own audit alarm.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "read back only by this module's own test until Task 9 wires the sink"
    )
)]
const AUDIT_TARGET: &str = "warden.audit";

/// Every field [`TracingAuditSink::record_attempt`] emits, in the order it emits them.
///
/// `docs/operations.md` section 10.2 forbids `raw_sql`, `raw_parameters`, `password`, and
/// `dsn`; [`AuditAttempt`] carries no field that could hold any of them, so this list is
/// what the module's own test pins instead. It extends section 10.2's allowed set with
/// `attempt_id`, which correlates the two phases, `client`, `fingerprint`, and
/// `deny_codes` — all four already public or already non-reversible, and the first is the
/// only thing that makes a pair of stderr lines readable as one record.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the declaration of what this module emits; only its test reads it back"
    )
)]
const ATTEMPT_FIELDS: &[&str] = &[
    "attempt_id",
    "request_id",
    "principal_id",
    "client",
    "connection",
    "dialect",
    "environment",
    "statement_kind",
    "fingerprint",
    "deny_codes",
];

/// Every field [`TracingAuditSink::record_outcome`] emits, in the order it emits them.
///
/// `rows`, `result_bytes`, and `duration_ms` are section 10.2's measurements under
/// section 10.2's names. They stay absent rather than becoming zero when the statement
/// never ran, because [`AuditOutcomeEvent`] leaves them absent for exactly that reason.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the declaration of what this module emits; only its test reads it back"
    )
)]
const OUTCOME_FIELDS: &[&str] = &[
    "attempt_id",
    "outcome",
    "duration_ms",
    "rows",
    "result_bytes",
    "error_code",
];

/// Writes every audit record to stderr as a structured `tracing` event.
///
/// A unit struct: it holds no handle, no buffer, and no configuration, which is the
/// whole reason it cannot fail. `warden_config::AuditMode` therefore has no effect here
/// yet — Milestone 13's sink is what gives the mode its meaning.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "`crate::startup::build` is the only caller, and Task 9 gives it one"
    )
)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct TracingAuditSink;

impl AuditSink for TracingAuditSink {
    fn record_attempt<'a>(
        &'a self,
        event: &'a AuditAttempt,
    ) -> BoxFuture<'a, Result<(), AuditError>> {
        Box::pin(async move {
            // Codes, not reasons: `DenyReason`'s `internal_detail` names the object or
            // function that tripped a rule, and Milestone 13 decides where that belongs.
            let deny_codes = event
                .deny_reasons
                .iter()
                .map(|reason| reason.code().as_str())
                .collect::<Vec<_>>()
                .join(",");
            tracing::info!(
                target: AUDIT_TARGET,
                attempt_id = %event.id,
                request_id = %event.request_id,
                principal_id = %event.principal,
                client = %event.client,
                connection = %event.connection,
                dialect = %event.dialect,
                environment = %event.environment,
                statement_kind = event.statement_kind.as_str(),
                fingerprint = event.fingerprint.as_ref().map(|value| value.as_str()),
                deny_codes = %deny_codes,
                "audit attempt"
            );
            Ok(())
        })
    }

    fn record_outcome<'a>(
        &'a self,
        event: &'a AuditOutcomeEvent,
    ) -> BoxFuture<'a, Result<(), AuditError>> {
        Box::pin(async move {
            tracing::info!(
                target: AUDIT_TARGET,
                attempt_id = %event.attempt_id,
                outcome = event.outcome.as_str(),
                // Saturating rather than truncating: a duration beyond `u64` milliseconds
                // is not reachable under any configured deadline, and reporting the
                // ceiling is still true where wrapping would not be.
                duration_ms = event
                    .duration
                    .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)),
                rows = event.rows_returned,
                result_bytes = event.result_bytes,
                error_code = event.error_code.map(|code| code.as_str()),
                "audit outcome"
            );
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::collections::BTreeMap;
    use std::fmt;
    use std::sync::{Mutex, OnceLock};
    use std::time::Duration;

    use tracing::field::{Field, Visit};
    use tracing::span;
    use tracing::{Event, Metadata, Subscriber};
    use warden_ports::AuditEventId;

    use super::*;

    #[tokio::test]
    async fn both_phases_succeed_and_neither_can_fail_the_request() {
        // The tracing sink cannot fail: a `tracing` macro returns unit. That is honest for
        // Milestone 12 and is exactly why the two-phase definition-of-done box stays
        // unchecked until Milestone 13 ships a sink that can (ADR-0022).
        install_capture();
        let id = AuditEventId::generate();
        let sink = TracingAuditSink;
        assert!(sink.record_attempt(&attempt(id)).await.is_ok());
        sink.record_outcome(&outcome(id)).await.unwrap();
    }

    #[test]
    fn the_recorded_field_set_is_the_documented_one() {
        // docs/operations.md section 10.2 allows request_id, principal_id, connection,
        // dialect, environment, statement_kind, rows, result_bytes and duration_ms, and
        // forbids raw_sql, raw_parameters, password and dsn. AuditAttempt has no field
        // that could carry the forbidden four, so this test pins the *emitted* set
        // instead, read from the module's own constant list.
        assert_eq!(
            ATTEMPT_FIELDS,
            [
                "attempt_id",
                "request_id",
                "principal_id",
                "client",
                "connection",
                "dialect",
                "environment",
                "statement_kind",
                "fingerprint",
                "deny_codes",
            ]
        );
        for forbidden in ["raw_sql", "raw_parameters", "password", "dsn", "sql"] {
            assert!(!ATTEMPT_FIELDS.contains(&forbidden), "{forbidden}");
            assert!(!OUTCOME_FIELDS.contains(&forbidden), "{forbidden}");
        }
    }

    #[tokio::test]
    async fn the_sink_emits_the_declared_fields_and_never_an_internal_detail() {
        // Without the field assertion the two constants above would be a comment the
        // compiler cannot check: a field renamed in a `tracing::info!` call would leave
        // the documented list still passing and still wrong. Without the value assertion,
        // nothing would hold this sink to `docs/security.md` section 6, which keeps
        // `DenyReason::internal_detail` off every surface but the durable audit record
        // Milestone 13 has yet to design.
        install_capture();
        let id = AuditEventId::generate();
        let sink = TracingAuditSink;
        sink.record_attempt(&attempt(id)).await.unwrap();
        sink.record_outcome(&outcome(id)).await.unwrap();
        let recorded = events_for(id);

        assert_eq!(recorded.len(), 2);
        for event in &recorded {
            assert_eq!(event.target, AUDIT_TARGET);
        }
        assert_eq!(recorded[0].fields, ATTEMPT_FIELDS);
        assert_eq!(recorded[1].fields, OUTCOME_FIELDS);

        assert_eq!(
            recorded[0].values.get("deny_codes").map(String::as_str),
            Some("object_not_allowed")
        );
        for event in &recorded {
            for (name, value) in &event.values {
                assert!(!value.contains("app.secrets"), "{name} = {value}");
            }
        }
    }

    /// The two events carrying `id`, in the order they were emitted.
    ///
    /// Selecting by attempt id rather than draining the buffer is what lets one
    /// subscriber serve a binary whose tests run in parallel: another test's events are
    /// in there too, and clearing the buffer would race them.
    fn events_for(id: AuditEventId) -> Vec<CapturedEvent> {
        let wanted = id.to_string();
        CAPTURED
            .lock()
            // A test that panicked elsewhere must not make this one fail for a reason
            // that has nothing to do with the sink.
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|event| event.values.get("attempt_id") == Some(&wanted))
            .cloned()
            .collect()
    }

    /// Every event this test binary emits, in emission order.
    static CAPTURED: Mutex<Vec<CapturedEvent>> = Mutex::new(Vec::new());

    /// Installs the binary's one subscriber, once, before anything emits.
    ///
    /// Global rather than scoped, which is the opposite of what isolation would suggest
    /// and the only arrangement that is not racy: `tracing` recomputes a process-wide
    /// callsite interest and maximum level whenever a subscriber is registered or
    /// dropped, and a callsite that first fires with no subscriber registered caches
    /// "never" — so a scoped subscriber loses events to whatever test happens to run
    /// beside it. Every test here that emits calls this first, so no callsite ever fires
    /// without one and nothing is ever unregistered.
    fn install_capture() {
        static INSTALLED: OnceLock<()> = OnceLock::new();
        INSTALLED.get_or_init(|| {
            let installed = tracing::subscriber::set_global_default(CapturingSubscriber);
            assert!(installed.is_ok(), "a subscriber was already installed");
        });
    }

    /// One event's target, its declared field names in order, and its recorded values.
    #[derive(Debug, Clone)]
    struct CapturedEvent {
        target: String,
        fields: Vec<String>,
        values: BTreeMap<String, String>,
    }

    /// Appends every event's target, declared field names, and recorded values to
    /// [`CAPTURED`].
    struct CapturingSubscriber;

    impl Subscriber for CapturingSubscriber {
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
            let metadata = event.metadata();
            // `message` is the literal this module writes, not a recorded field.
            let fields = metadata
                .fields()
                .iter()
                .map(|field| field.name().to_owned())
                .filter(|name| name != "message")
                .collect();
            let mut visitor = FieldVisitor::default();
            event.record(&mut visitor);
            CAPTURED
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(CapturedEvent {
                    target: metadata.target().to_owned(),
                    fields,
                    values: visitor.values,
                });
        }

        fn enter(&self, _span: &span::Id) {}

        fn exit(&self, _span: &span::Id) {}
    }

    #[derive(Default)]
    struct FieldVisitor {
        values: BTreeMap<String, String>,
    }

    impl Visit for FieldVisitor {
        fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
            self.values
                .insert(field.name().to_owned(), format!("{value:?}"));
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            self.values
                .insert(field.name().to_owned(), value.to_owned());
        }
    }

    fn attempt(id: AuditEventId) -> AuditAttempt {
        AuditAttempt {
            id,
            timestamp: time::OffsetDateTime::UNIX_EPOCH,
            request_id: "request-1".parse().unwrap(),
            principal: "local-stdio".parse().unwrap(),
            client: "example-client".parse().unwrap(),
            connection: "production-db".parse().unwrap(),
            dialect: warden_core::dialect::Dialect::MySql,
            environment: warden_core::connection::Environment::Production,
            fingerprint: None,
            statement_kind: warden_core::analysis::StatementKind::Select,
            deny_reasons: vec![warden_policy::DenyReason::with_detail(
                warden_policy::DenyCode::ObjectNotAllowed,
                "app.secrets",
            )],
        }
    }

    fn outcome(id: AuditEventId) -> AuditOutcomeEvent {
        AuditOutcomeEvent {
            attempt_id: id,
            outcome: warden_ports::AuditOutcome::Succeeded,
            duration: Some(Duration::from_millis(3)),
            rows_returned: Some(2),
            result_bytes: Some(64),
            error_code: None,
        }
    }
}
