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

use tokio::time::timeout;
use warden_core::analysis::StatementKind;
use warden_core::connection::ConnectionMetadata;
use warden_core::context::RequestContext;
use warden_core::fingerprint::QueryFingerprint;
use warden_policy::DenyReason;
use warden_ports::{AuditAttempt, AuditError, AuditEventId, AuditOutcomeEvent, AuditSink};

use crate::limits::AUDIT_WRITE_TIMEOUT;

/// Builds the attempt for one request.
///
/// There is no `sql` parameter and no `parameters` parameter, because `AuditAttempt`
/// has no such fields: raw SQL and parameter values are off by default and a field
/// that does not exist cannot be switched on by a configuration mistake
/// (`docs/security.md` section 11.3).
pub(crate) fn attempt(
    context: &RequestContext,
    connection: &ConnectionMetadata,
    statement_kind: StatementKind,
    fingerprint: Option<QueryFingerprint>,
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
        fingerprint,
        statement_kind,
        deny_reasons,
    }
}

/// Records the attempt. The caller must not proceed if this fails.
pub(crate) async fn record_attempt(
    sink: &dyn AuditSink,
    event: &AuditAttempt,
) -> Result<(), AuditError> {
    match timeout(AUDIT_WRITE_TIMEOUT, sink.record_attempt(event)).await {
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
    let written = match timeout(AUDIT_WRITE_TIMEOUT, sink.record_outcome(&event)).await {
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::time::Duration;

    use warden_core::dialect::Dialect;
    use warden_ports::{AuditError, AuditOutcome};

    use super::*;
    use crate::testing;

    #[test]
    fn an_attempt_carries_every_denial_and_no_statement() {
        let reasons = vec![DenyReason::new(warden_policy::DenyCode::WriteStatement)];
        let recorded = attempt(
            &testing::request_context(),
            &testing::connection(Dialect::MySql),
            StatementKind::Insert,
            None,
            reasons.clone(),
        );
        assert_eq!(recorded.deny_reasons, reasons);
        assert_eq!(recorded.statement_kind, StatementKind::Insert);
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
    async fn a_broken_outcome_write_does_not_fail_the_request() {
        let sink = testing::FakeAuditSink::broken_outcomes();
        record_outcome(
            &sink,
            AuditOutcomeEvent {
                attempt_id: AuditEventId::generate(),
                outcome: AuditOutcome::Succeeded,
                duration: Some(Duration::from_millis(1)),
                rows_returned: Some(1),
                result_bytes: Some(3),
                error_code: None,
            },
        )
        .await;
    }

    #[test]
    fn an_unstarted_statement_has_an_outcome_that_does_not_claim_it_ran() {
        assert_eq!(AuditOutcome::NotStarted.as_str(), "not_started");
        assert!(AuditOutcome::ALL.contains(&AuditOutcome::NotStarted));
    }
}
