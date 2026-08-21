//! The schema-discovery port.
//!
//! Schema metadata comes from adapter-owned static SQL — `information_schema` on
//! MySQL, `pg_catalog` plus `information_schema` on PostgreSQL — and never from
//! agent SQL (`docs/data-model.md` section 9). The port therefore accepts the two
//! bounded request types from `warden-core` and nothing else.

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use warden_core::schema::{
    SchemaDescribeRequest, SchemaDescription, SchemaSearchRequest, SchemaSearchResult,
};

use crate::BoxFuture;
use crate::error::SchemaError;

/// Reads bounded schema metadata for one connection.
///
/// Both methods take a deadline and a cancellation token for the same reason the
/// executor does: a catalog query runs on a real server and can hang, and a dropped
/// future does not stop it (`docs/operations.md` section 5.4).
///
/// Object policy applies inside the adapter rather than after it, so a denied table
/// is not merely unqueryable but also undescribable and unsearchable
/// (`docs/security.md` section 5.2). Milestone 9 implements that filtering; this
/// port is where `SchemaError::Rejected` becomes possible.
pub trait SchemaInspector: Send + Sync {
    /// Ranks relations against the request's terms, bounded by its limit.
    fn search_schema<'a>(
        &'a self,
        request: &'a SchemaSearchRequest,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<SchemaSearchResult, SchemaError>>;

    /// Describes the requested relations, at most `MAX_DESCRIBE_TABLES` of them.
    fn describe_schema<'a>(
        &'a self,
        request: &'a SchemaDescribeRequest,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<SchemaDescription, SchemaError>>;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::testing;

    #[tokio::test(start_paused = true)]
    async fn an_inspector_works_behind_a_trait_object() {
        let inspector: Arc<dyn SchemaInspector> = Arc::new(testing::FakeInspector::default());
        let deadline = Instant::now() + Duration::from_secs(5);

        let search = testing::search_request();
        let found = inspector
            .search_schema(&search, deadline, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(found.matches.len(), 1);
        assert!(!found.truncated);

        let describe = testing::describe_request();
        let described = inspector
            .describe_schema(&describe, deadline, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(described.schemas.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_denied_object_fails_as_a_rejection_at_the_source() {
        let inspector = testing::FakeInspector::rejecting();
        let describe = testing::describe_request();
        let error = inspector
            .describe_schema(
                &describe,
                Instant::now() + Duration::from_secs(5),
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, SchemaError::Rejected(_)), "{error:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_cancelled_token_stops_a_catalog_query() {
        let inspector = testing::FakeInspector::default();
        let cancel = CancellationToken::new();
        cancel.cancel();
        let search = testing::search_request();
        let error = inspector
            .search_schema(&search, Instant::now() + Duration::from_secs(5), cancel)
            .await
            .unwrap_err();
        assert_eq!(error, SchemaError::Cancelled);
    }
}
