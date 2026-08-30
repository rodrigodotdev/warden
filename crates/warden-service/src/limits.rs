//! What one request may cost in wall-clock time, end to end.
//!
//! `ExecutionLimits::timeout` bounds the *query*, not the call. Both adapters run
//! cancellation, `ROLLBACK`, and — on PostgreSQL — `DEALLOCATE ALL` under their own
//! budgets *after* the query has resolved, so a truncated or failed request can
//! outlast its deadline (`docs/operations.md` section 5.3, which asks Milestone 11
//! for exactly this figure). A caller that wants an aggregate request timeout —
//! Milestone 12's stdio handler, Milestone 14's HTTP transport — needs
//! [`RequestBudget::total`], never `limits.timeout` alone.

use std::time::Duration;

use tokio::time::Instant;
use warden_core::limits::ExecutionLimits;

/// How long a service waits for one audit-sink write.
///
/// The sink takes no deadline of its own — it has no server-side work to cancel — so
/// the caller bounds the write (`crates/warden-ports/src/audit.rs`). Two seconds
/// rather than the query deadline, because ADR-0022 requires the attempt phase to be
/// cheap: it sits in the latency-critical path in front of every query.
pub const AUDIT_WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// The longest an adapter's post-query cleanup can add after the deadline.
///
/// PostgreSQL's worst case is the sum of three sequential two-second budgets —
/// cancellation, `ROLLBACK`, then `DEALLOCATE ALL` — and MySQL's is two of them,
/// `KILL QUERY` and `ROLLBACK` (`docs/operations.md` section 5.3). The larger figure
/// is used for both: this is a bound, not a measurement, and a bound that held for
/// only one engine would be wrong on the other.
pub const MAX_ADAPTER_CLEANUP: Duration = Duration::from_secs(6);

/// The wall-clock envelope of one request on one connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestBudget {
    limits: ExecutionLimits,
}

impl RequestBudget {
    /// The budget implied by a connection's validated limits.
    #[must_use]
    pub fn new(limits: ExecutionLimits) -> Self {
        Self { limits }
    }

    /// The deadline passed to every port that runs SQL.
    ///
    /// The *client* timeout, deliberately: the server-side deadline is configured to
    /// fire first, so the ordinary path returns a clean database error with an intact
    /// pooled connection and this value stays the safety net
    /// (`docs/operations.md` section 5.3). `tokio::time::Instant` is the clock
    /// `timeout_at` and `pause` both understand, which is what makes a deadline test
    /// deterministic instead of slow.
    #[must_use]
    pub fn deadline(&self, now: Instant) -> Instant {
        now + self.limits.client_timeout()
    }

    /// The longest one request can take, including everything the deadline excludes.
    #[must_use]
    pub fn total(&self) -> Duration {
        self.limits
            .max_queue_wait
            .saturating_add(self.limits.client_timeout())
            .saturating_add(MAX_ADAPTER_CLEANUP)
            .saturating_add(AUDIT_WRITE_TIMEOUT.saturating_mul(2))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn the_deadline_is_the_client_timeout_not_the_server_one() {
        let limits = ExecutionLimits::default();
        let now = Instant::now();
        let budget = RequestBudget::new(limits);
        assert_eq!(budget.deadline(now), now + limits.client_timeout());
        assert!(limits.client_timeout() > limits.server_timeout());
    }

    #[test]
    fn the_total_budget_covers_queueing_cleanup_and_both_audit_writes() {
        let limits = ExecutionLimits::default();
        let total = RequestBudget::new(limits).total();
        assert_eq!(
            total,
            limits.max_queue_wait
                + limits.client_timeout()
                + MAX_ADAPTER_CLEANUP
                + AUDIT_WRITE_TIMEOUT * 2
        );
        assert!(total > limits.client_timeout(), "{total:?}");
    }
}
