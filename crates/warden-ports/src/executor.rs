//! The execution port.
//!
//! This is the narrowest surface in Warden and the reason the type pipeline exists.
//! There is no `execute(sql: &str)`, no `execute_unchecked`, and no way to reach the
//! database with anything other than an [`AuthorizedQuery`], which only
//! `warden-policy` can build (SPEC section 6, invariant 12; ADR-0010).

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use warden_core::result::ResultSet;
use warden_policy::AuthorizedQuery;

use crate::BoxFuture;
use crate::error::ExecuteError;

/// Runs one authorized statement inside a read-only transaction.
pub trait QueryExecutor: Send + Sync {
    /// Executes the statement and returns a bounded, normalized result.
    ///
    /// `deadline` and `cancel` are separate parameters on purpose. Dropping this
    /// future does **not** stop the server-side query, so an adapter that only knew
    /// it had been dropped could never issue a PostgreSQL cancel request or a MySQL
    /// `KILL QUERY`, and repeated timeouts would accumulate orphaned queries
    /// (ADR-0024; `docs/operations.md` section 5.4).
    ///
    /// The deadline is a `tokio::time::Instant` because it is the clock
    /// `tokio::time::timeout_at` and `tokio::time::pause` both understand, which is
    /// what makes a deadline test deterministic instead of slow.
    ///
    /// The server-side timeout is configured to fire first, so the ordinary path
    /// returns a clean database error with an intact pooled connection and this
    /// deadline stays a safety net (`docs/operations.md` section 5.3).
    ///
    /// `query.limits()` is the authority for this call's row and byte bounds; the
    /// adapter is responsible for enforcing them (SPEC section 6, invariants 14 and
    /// 15), not `ConnectionRuntime::limits()`, which describes the connection rather
    /// than this one authorized statement.
    fn execute_read_only<'a>(
        &'a self,
        query: &'a AuthorizedQuery,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<ResultSet, ExecuteError>>;
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
    async fn an_executor_works_behind_a_trait_object() {
        let executor: Arc<dyn QueryExecutor> = Arc::new(testing::FakeExecutor::default());
        let query = testing::authorized(Dialect::MySql);
        let result = executor
            .execute_read_only(
                &query,
                Instant::now() + Duration::from_secs(5),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(result.stats.rows_returned, result.rows.len());
        result.validate().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn the_deadline_reaches_the_adapter_instead_of_being_a_dropped_future() {
        let executor = testing::FakeExecutor::taking(Duration::from_secs(30));
        let query = testing::authorized(Dialect::MySql);
        let error = executor
            .execute_read_only(
                &query,
                Instant::now() + Duration::from_secs(5),
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error, ExecuteError::Timeout);
    }

    #[tokio::test(start_paused = true)]
    async fn a_cancelled_token_stops_the_query_before_its_deadline() {
        let executor = testing::FakeExecutor::taking(Duration::from_secs(30));
        let query = testing::authorized(Dialect::MySql);
        let cancel = CancellationToken::new();
        cancel.cancel();
        let error = executor
            .execute_read_only(&query, Instant::now() + Duration::from_secs(5), cancel)
            .await
            .unwrap_err();
        assert_eq!(error, ExecuteError::Cancelled);
    }
}
