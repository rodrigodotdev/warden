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

/// Plans an authorized statement without running it.
pub trait Explainer: Send + Sync {
    /// Produces a structured plan for the statement.
    fn explain<'a>(
        &'a self,
        query: &'a AuthorizedQuery,
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

    use super::*;
    use crate::testing;

    #[tokio::test(start_paused = true)]
    async fn an_explainer_works_behind_a_trait_object() {
        let explainer: Arc<dyn Explainer> = Arc::new(testing::FakeExplainer::default());
        let query = testing::authorized(Dialect::PostgreSql);
        let plan = explainer
            .explain(
                &query,
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
        let error = explainer
            .explain(
                &query,
                Instant::now() + Duration::from_secs(5),
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error, ExplainError::PrefixVerificationFailed);
    }
}
