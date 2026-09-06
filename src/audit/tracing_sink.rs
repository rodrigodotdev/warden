//! The stderr audit sink: Milestone 12's, rebuilt on Milestone 13's record.
//!
//! `warden_service::Services` requires an `AuditSink`, and this is the sink that has
//! served every deployment since Milestone 12. It no longer declares its own field
//! list: `ATTEMPT_FIELDS` and `OUTCOME_FIELDS` below are `record::ATTEMPT_FIELDS`
//! and `record::OUTCOME_FIELDS` with the two keys `record::TRACING_OMITS` names
//! removed, because the subscriber stamps its own time and the `warden.audit`
//! target already identifies the stream a `schema` key would repeat.
//!
//! A `tracing` macro returns unit, so this sink still cannot fail, and ADR-0022's
//! fail-closed attempt therefore still has nothing to fail on. That is why the
//! definition-of-done box for two-phase auditing stays unchecked until Milestone 13
//! ships a sink that can.
//!
//! It records deny **codes**, not `DenyReason::internal_detail`, for the same reason
//! `record::AttemptRecord` does (`docs/security.md` section 6): the detail names the
//! object or function that tripped a rule, and it stays on the auditor's side of
//! that line. `audit.mode` now has an effect here too, and the same one it has on
//! the record: `none` drops `statement_kind` and `fingerprint` and keeps everything
//! else (ADR-0026 — the record itself is invariant 24, so the mode can narrow what
//! it describes but never switch it off).

use warden_config::AuditMode;
use warden_ports::{AuditAttempt, AuditError, AuditOutcomeEvent, AuditSink, BoxFuture};

/// Every field [`TracingAuditSink::record_attempt`] emits, in the order it emits
/// them: `record::ATTEMPT_FIELDS` minus `record::TRACING_OMITS`, which the module's
/// own test proves.
#[cfg(test)]
const ATTEMPT_FIELDS: &[&str] = &[
    "event",
    "attempt_id",
    "request_id",
    "principal_id",
    "client",
    "connection",
    "dialect",
    "environment",
    "operation",
    "statement_kind",
    "fingerprint",
    "deny_codes",
];

/// Every field [`TracingAuditSink::record_outcome`] emits, in the order it emits
/// them: `record::OUTCOME_FIELDS` minus `record::TRACING_OMITS`.
#[cfg(test)]
const OUTCOME_FIELDS: &[&str] = &[
    "event",
    "attempt_id",
    "outcome",
    "duration_ms",
    "queue_wait_ms",
    "rows",
    "result_bytes",
    "error_code",
];

/// The target both events carry, matching `warden-service`'s own audit alarm.
const AUDIT_TARGET: &str = "warden.audit";

/// Writes every audit record to stderr as a structured `tracing` event.
///
/// Holds only the mode: no handle, no buffer, nothing that could fail to open,
/// which is still the whole reason [`AuditSink::record_attempt`] and
/// [`AuditSink::record_outcome`] cannot fail here.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TracingAuditSink {
    mode: AuditMode,
}

impl TracingAuditSink {
    /// Builds a sink that gates `statement_kind` and `fingerprint` on `mode`, the
    /// same way `record::AttemptRecord::new` gates them.
    pub(crate) fn new(mode: AuditMode) -> Self {
        Self { mode }
    }
}

impl AuditSink for TracingAuditSink {
    fn record_attempt<'a>(
        &'a self,
        event: &'a AuditAttempt,
    ) -> BoxFuture<'a, Result<(), AuditError>> {
        Box::pin(async move {
            // Codes, not reasons: `DenyReason`'s `internal_detail` names the object or
            // function that tripped a rule, and `docs/security.md` section 6 keeps it
            // off every surface but the auditor's own investigation.
            let deny_codes = event
                .deny_reasons
                .iter()
                .map(|reason| reason.code().as_str())
                .collect::<Vec<_>>()
                .join(",");
            // The same gate `record::AttemptRecord::new` applies: `none` records that
            // a request happened and nothing about the statement it carried.
            let (statement_kind, fingerprint) = super::record::statement_fields(event, self.mode);
            tracing::info!(
                target: AUDIT_TARGET,
                event = "attempt",
                attempt_id = %event.id,
                request_id = %event.request_id,
                principal_id = %event.principal,
                client = %event.client,
                connection = %event.connection,
                dialect = %event.dialect,
                environment = %event.environment,
                operation = event.operation.as_str(),
                statement_kind,
                fingerprint,
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
                event = "outcome",
                attempt_id = %event.attempt_id,
                outcome = event.outcome.as_str(),
                // Saturating rather than truncating: a duration beyond `u64` milliseconds
                // is not reachable under any configured deadline, and reporting the
                // ceiling is still true where wrapping would not be.
                duration_ms = event
                    .duration
                    .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)),
                // Saturating for the same reason as `duration_ms`: a queue wait beyond
                // `u64` milliseconds is not reachable under any configured
                // `max_queue_wait`.
                queue_wait_ms = event
                    .queue_wait
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

    use super::super::record;
    use super::*;

    #[tokio::test]
    async fn both_phases_succeed_and_neither_can_fail_the_request() {
        // The tracing sink cannot fail: a `tracing` macro returns unit. That is honest for
        // Milestone 12 and is exactly why the two-phase definition-of-done box stays
        // unchecked until Milestone 13 ships a sink that can (ADR-0022).
        install_capture();
        let id = AuditEventId::generate();
        let sink = TracingAuditSink::new(AuditMode::Fingerprint);
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
                "event",
                "attempt_id",
                "request_id",
                "principal_id",
                "client",
                "connection",
                "dialect",
                "environment",
                "operation",
                "statement_kind",
                "fingerprint",
                "deny_codes",
            ]
        );
        for forbidden in record::FORBIDDEN_FIELDS {
            assert!(!ATTEMPT_FIELDS.contains(forbidden), "{forbidden}");
            assert!(!OUTCOME_FIELDS.contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn the_stderr_sink_emits_the_record_format_minus_the_two_keys_it_does_not_repeat() {
        let expected: Vec<&str> = record::ATTEMPT_FIELDS
            .iter()
            .filter(|field| !record::TRACING_OMITS.contains(field))
            .copied()
            .collect();
        assert_eq!(ATTEMPT_FIELDS, expected.as_slice());
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
        let sink = TracingAuditSink::new(AuditMode::Fingerprint);
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

    #[tokio::test]
    async fn the_none_mode_drops_statement_kind_and_fingerprint_from_the_wire() {
        // `audit.mode` is invariant 24's own knob (ADR-0026): it narrows what the
        // record describes, and this sink honors it exactly as `record::AttemptRecord`
        // does — the same two keys, nothing more.
        install_capture();
        let id = AuditEventId::generate();
        let sink = TracingAuditSink::new(AuditMode::None_);
        sink.record_attempt(&attempt(id)).await.unwrap();
        let recorded = events_for(id);

        assert_eq!(recorded[0].values.get("statement_kind"), None);
        assert_eq!(recorded[0].values.get("fingerprint"), None);

        let fingerprint_id = AuditEventId::generate();
        TracingAuditSink::new(AuditMode::Fingerprint)
            .record_attempt(&attempt(fingerprint_id))
            .await
            .unwrap();
        let fingerprint_records = events_for(fingerprint_id);
        assert_eq!(
            fingerprint_records[0]
                .values
                .get("statement_kind")
                .map(String::as_str),
            Some("select")
        );
        assert_eq!(
            fingerprint_records[0].values.get("fingerprint"),
            Some(&format!("v1:{}", "a".repeat(64)))
        );
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
            operation: warden_ports::AuditOperation::Query,
            fingerprint: Some(
                warden_core::fingerprint::QueryFingerprint::v1(&"a".repeat(64)).unwrap(),
            ),
            statement_kind: Some(warden_core::analysis::StatementKind::Select),
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
            queue_wait: Some(Duration::from_millis(1)),
            rows_returned: Some(2),
            result_bytes: Some(64),
            error_code: None,
        }
    }
}
