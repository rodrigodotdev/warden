//! The two-phase audit port.
//!
//! ```text
//! attempt -> written BEFORE execution.  Sink failure => deny the query.
//! outcome -> written AFTER  execution.  Sink failure => alarm, no rollback.
//! ```
//!
//! One event would lose the attempt in exactly the case where an audit matters most:
//! the process dying mid-execution. Two events also answer the question v0.2 never
//! did — does a query run when the sink is down? — with "no" (ADR-0022).
//!
//! Neither record derives `Serialize`. `DenyReason` deliberately does not, so
//! `AuditAttempt` could not anyway, and that is the property worth keeping: a record
//! carrying `internal_detail` cannot be attached to a tool response by accident
//! (`docs/security.md` section 6). Milestone 13 decides the wire format its sink
//! writes, and writes only the fields it is allowed to.
//!
//! # What is deliberately absent
//!
//! There is no `sql` field and no `parameters` field. Raw SQL and parameters are off
//! by default (`docs/security.md` section 11.3), and a field that does not exist
//! cannot be switched on by a configuration mistake. The fingerprint is what makes
//! two attempts comparable.
//!
//! These types live here rather than in `warden-core` because `AuditAttempt` carries
//! `DenyReason`, which lives in `warden-policy`, downstream of the core.

use std::fmt;
use std::time::Duration;

use time::OffsetDateTime;
use uuid::Uuid;
use warden_core::analysis::StatementKind;
use warden_core::connection::{ConnectionName, Environment};
use warden_core::context::{ClientName, PrincipalId, RequestId};
use warden_core::dialect::Dialect;
use warden_core::error::PublicErrorCode;
use warden_core::fingerprint::QueryFingerprint;
use warden_policy::DenyReason;

use crate::BoxFuture;
use crate::error::AuditError;

/// Correlates one attempt with its outcome.
///
/// A newtype rather than a bare `Uuid` so that an attempt id and any future
/// identifier cannot be swapped at a call site and still compile — the same reason
/// `warden-core` wraps request, principal, and client identifiers
/// (`docs/security.md` section 11.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AuditEventId(Uuid);

impl AuditEventId {
    /// Generates a fresh random identifier.
    ///
    /// Named `generate` rather than `new` because it is not a pure constructor: two
    /// calls produce two different values.
    #[must_use]
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }

    /// Borrows the underlying UUID.
    #[must_use]
    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl fmt::Display for AuditEventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// What Warden is about to attempt, recorded before anything runs.
///
/// Written before the concurrency permit is acquired, so a process that dies during
/// execution still leaves the attempt behind (ADR-0022).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditAttempt {
    /// This attempt's identifier, repeated by its outcome.
    pub id: AuditEventId,
    /// When the attempt was recorded.
    pub timestamp: OffsetDateTime,
    /// The request this attempt belongs to.
    pub request_id: RequestId,
    /// Who asked.
    pub principal: PrincipalId,
    /// Which client they asked through.
    pub client: ClientName,
    /// Which connection the statement targets.
    pub connection: ConnectionName,
    /// The dialect the statement was analyzed with.
    pub dialect: Dialect,
    /// The connection's environment.
    pub environment: Environment,
    /// The statement's fingerprint, when the adapter computed one.
    ///
    /// The only stable way to recognize the same statement across attempts without
    /// storing the statement (`docs/security.md` section 11.4).
    pub fingerprint: Option<QueryFingerprint>,
    /// What kind of statement it was.
    pub statement_kind: StatementKind,
    /// **Every** denial, not only the one the agent was told about.
    ///
    /// Empty when the statement was authorized. An auditor investigating a denial
    /// needs the complete picture; the agent gets one code so the error cannot be
    /// used as an oracle that reveals the rules one at a time (ADR-0012).
    pub deny_reasons: Vec<DenyReason>,
}

/// How an attempt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditOutcome {
    /// Policy denied the statement, so it never ran.
    Denied,
    /// The statement ran and returned a result.
    Succeeded,
    /// The statement ran and the database failed it.
    Failed,
    /// The statement exceeded its deadline.
    TimedOut,
    /// The statement was cancelled.
    Cancelled,
    /// The statement was authorized but never reached the database.
    ///
    /// The attempt is recorded before the concurrency permit is acquired
    /// (ADR-0022), so an authorized statement can end here — the queue was still
    /// full when `max_queue_wait` elapsed, or the connection became unavailable.
    /// [`AuditOutcome::Failed`] would say the database failed the statement, which
    /// is a different fact, and an audit record must not state one for the other.
    NotStarted,
}

impl AuditOutcome {
    /// Every outcome. Milestone 13's sink iterates this to prove each has a mapping.
    pub const ALL: [Self; 6] = [
        Self::Denied,
        Self::Succeeded,
        Self::Failed,
        Self::TimedOut,
        Self::Cancelled,
        Self::NotStarted,
    ];

    /// The stable name used in audit records, trace fields, and metric labels.
    ///
    /// The match is exhaustive on purpose: a new outcome must not compile until it
    /// has a documented spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
            Self::NotStarted => "not_started",
        }
    }
}

impl fmt::Display for AuditOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What actually happened, recorded after execution.
///
/// Every measurement is optional because a denied attempt never ran and has none of
/// them. Inventing a zero would make an audit record say something untrue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditOutcomeEvent {
    /// The attempt this outcome completes.
    pub attempt_id: AuditEventId,
    /// How it ended.
    pub outcome: AuditOutcome,
    /// Wall-clock execution time, when the statement ran.
    pub duration: Option<Duration>,
    /// Rows returned after truncation, when the statement ran.
    pub rows_returned: Option<usize>,
    /// Normalized result size in bytes, when the statement ran.
    pub result_bytes: Option<usize>,
    /// The code the agent received, when the attempt failed.
    ///
    /// The enum rather than a `&'static str`, so an outcome cannot record a code
    /// outside the closed set `docs/security.md` section 10 documents.
    pub error_code: Option<PublicErrorCode>,
}

/// Where audit records go.
///
/// The two methods differ in consequence, not in shape, and the caller enforces the
/// difference (`warden-service`): a failed [`AuditSink::record_attempt`] denies the
/// query, and a failed [`AuditSink::record_outcome`] raises an alarm and returns the
/// result anyway, because execution has already happened and there is nothing left
/// to prevent (ADR-0022).
///
/// Neither method takes a deadline. There is no server-side work to cancel, so the
/// caller bounds the write with `tokio::time::timeout`; ADR-0022 still requires the
/// attempt phase to be cheap, because it sits in the latency-critical path.
pub trait AuditSink: Send + Sync {
    /// Records an attempt. The query must not proceed if this fails.
    fn record_attempt<'a>(
        &'a self,
        event: &'a AuditAttempt,
    ) -> BoxFuture<'a, Result<(), AuditError>>;

    /// Records an outcome. A failure here is an alarm, not a rollback.
    fn record_outcome<'a>(
        &'a self,
        event: &'a AuditOutcomeEvent,
    ) -> BoxFuture<'a, Result<(), AuditError>>;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::collections::BTreeSet;
    use std::sync::Arc;

    use warden_policy::DenyCode;

    use super::*;
    use crate::testing;

    #[test]
    fn every_outcome_has_a_distinct_stable_spelling() {
        let names: BTreeSet<&str> = AuditOutcome::ALL.iter().map(|o| o.as_str()).collect();
        assert_eq!(names.len(), AuditOutcome::ALL.len());
        assert_eq!(AuditOutcome::Denied.to_string(), "denied");
    }

    #[test]
    fn two_generated_identifiers_differ() {
        assert_ne!(AuditEventId::generate(), AuditEventId::generate());
    }

    #[test]
    fn an_attempt_records_every_denial_not_only_the_reported_one() {
        let attempt = testing::attempt(vec![
            DenyReason::new(DenyCode::WriteStatement),
            DenyReason::with_detail(DenyCode::ObjectNotAllowed, "app.secrets"),
        ]);
        assert_eq!(attempt.deny_reasons.len(), 2);
        assert_eq!(
            attempt.deny_reasons[1].internal_detail(),
            Some("app.secrets")
        );
        assert_eq!(attempt.statement_kind, StatementKind::Select);
    }

    #[tokio::test]
    async fn a_sink_works_behind_a_trait_object_in_both_phases() {
        let sink: Arc<dyn AuditSink> = Arc::new(testing::FakeAuditSink::default());
        let attempt = testing::attempt(Vec::new());
        sink.record_attempt(&attempt).await.unwrap();

        let outcome = AuditOutcomeEvent {
            attempt_id: attempt.id,
            outcome: AuditOutcome::Succeeded,
            duration: Some(Duration::from_millis(3)),
            rows_returned: Some(1),
            result_bytes: Some(64),
            error_code: None,
        };
        sink.record_outcome(&outcome).await.unwrap();
    }

    #[tokio::test]
    async fn a_broken_sink_reports_the_failure_the_caller_must_fail_closed_on() {
        let sink = testing::FakeAuditSink::broken();
        let attempt = testing::attempt(Vec::new());
        let error = sink.record_attempt(&attempt).await.unwrap_err();
        assert!(matches!(error, AuditError::Unavailable { .. }), "{error:?}");
    }
}
