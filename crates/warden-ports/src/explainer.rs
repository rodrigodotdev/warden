//! The non-executing plan port.
//!
//! `explain` takes an [`AuthorizedQuery`], not an `ExplainRequest`. PostgreSQL's
//! planner constant-folds `IMMUTABLE` functions, so a malicious immutable function
//! runs during planning: every policy that applies to `query` applies here
//! (`docs/mcp.md` section 3.1), and SPEC section 6, invariant 12 requires an
//! authorization before anything reaches the database. `ExplainRequest` stays the
//! MCP-facing input type that Milestone 12 converts into a `QueryRequest` for
//! analysis and authorization.
//!
//! This is also the only design point where the string sent to the database differs
//! from the analyzed one. The adapter prefixes the statement, reparses the result,
//! and verifies that it is an `EXPLAIN` of the same statement
//! (`docs/mcp.md` section 3.2). `EXPLAIN ANALYZE` is never produced: it executes the
//! query (SPEC section 6, invariant 11).

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use warden_core::explain::QueryPlan;
use warden_policy::AuthorizedQuery;

use crate::BoxFuture;
use crate::error::ExplainError;
use crate::runtime::QueryPermit;

/// Plans an authorized statement without running it.
pub trait Explainer: Send + Sync {
    /// Produces a structured plan for the statement.
    ///
    /// `permit` is the connection's concurrency slot, and it is a parameter rather
    /// than a caller's discipline. `ConnectionRuntime::explainer()` hands this trait
    /// object to anyone who asks, so without the parameter nothing stops a call that
    /// never waited for a slot, and SPEC section 6, invariant 17 would hold only for
    /// as long as every future call site remembered it (ADR-0032). Planning also runs
    /// real work on the server and shares `agent_pool` with `execute_read_only`
    /// (`docs/mcp.md` section 3.1), so its concurrency must be bounded by the same
    /// permit.
    ///
    /// It proves a permit exists; it does not prove the permit came from this
    /// connection. ADR-0032 states that limit rather than implying more.
    fn explain<'a>(
        &'a self,
        query: &'a AuthorizedQuery,
        permit: &'a QueryPermit,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<QueryPlan, ExplainError>>;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::Arc;
    use std::time::Duration;

    use warden_core::dialect::Dialect;
    use warden_core::limits::ExecutionLimits;

    use super::*;
    use crate::testing;

    #[tokio::test(start_paused = true)]
    async fn an_explainer_works_behind_a_trait_object() {
        let explainer: Arc<dyn Explainer> = Arc::new(testing::FakeExplainer::default());
        let query = testing::authorized(Dialect::PostgreSql);
        let (_runtime, permit) = testing::with_permit(ExecutionLimits::default()).await;
        let plan = explainer
            .explain(
                &query,
                &permit,
                Instant::now() + Duration::from_secs(5),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(plan.dialect, Dialect::PostgreSql);
        // No invented cost metric: MySQL and PostgreSQL units are not comparable
        // (`docs/architecture.md` section 11).
        assert_eq!(plan.summary.estimated_rows, Some(1200));
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_prefix_verification_is_a_failure_not_a_warning() {
        let explainer = testing::FakeExplainer::failing(ExplainError::PrefixVerificationFailed);
        let query = testing::authorized(Dialect::PostgreSql);
        let (_runtime, permit) = testing::with_permit(ExecutionLimits::default()).await;
        let error = explainer
            .explain(
                &query,
                &permit,
                Instant::now() + Duration::from_secs(5),
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error, ExplainError::PrefixVerificationFailed);
    }

    #[tokio::test(start_paused = true)]
    async fn a_cancelled_token_stops_planning_before_its_deadline() {
        let explainer = testing::FakeExplainer::taking(Duration::from_secs(30));
        let query = testing::authorized(Dialect::PostgreSql);
        let (_runtime, permit) = testing::with_permit(ExecutionLimits::default()).await;
        let cancel = CancellationToken::new();
        cancel.cancel();
        let error = explainer
            .explain(
                &query,
                &permit,
                Instant::now() + Duration::from_secs(5),
                cancel,
            )
            .await
            .unwrap_err();
        assert_eq!(error, ExplainError::Cancelled);
    }

    #[tokio::test(start_paused = true)]
    async fn the_deadline_reaches_the_adapter_instead_of_being_a_dropped_future() {
        let explainer = testing::FakeExplainer::taking(Duration::from_secs(30));
        let query = testing::authorized(Dialect::PostgreSql);
        let (_runtime, permit) = testing::with_permit(ExecutionLimits::default()).await;
        let error = explainer
            .explain(
                &query,
                &permit,
                Instant::now() + Duration::from_secs(5),
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error, ExplainError::Timeout);
    }
}
