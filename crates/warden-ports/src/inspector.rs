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
use warden_policy::ObjectFilter;

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
/// (`docs/security.md` section 5.2). The filter is a parameter under ADR-0036, so
/// the adapter applies it before its response can reveal or count a denied object.
pub trait SchemaInspector: Send + Sync {
    /// Ranks relations against the request's terms, bounded by its limit.
    ///
    /// A relation the `filter` refuses is dropped before the limit is applied, so a
    /// denied table neither appears in the response nor displaces an allowed one.
    fn search_schema<'a>(
        &'a self,
        request: &'a SchemaSearchRequest,
        filter: ObjectFilter<'a>,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<SchemaSearchResult, SchemaError>>;

    /// Describes the requested relations, at most `MAX_DESCRIBE_TABLES` of them.
    ///
    /// A table the `filter` refuses fails the whole call with
    /// [`SchemaError::Rejected`]: the agent named it, so a silent omission would be
    /// a worse answer than a refusal.
    fn describe_schema<'a>(
        &'a self,
        request: &'a SchemaDescribeRequest,
        filter: ObjectFilter<'a>,
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
    use warden_core::dialect::Dialect;
    use warden_policy::DenyCode;

    #[tokio::test(start_paused = true)]
    async fn an_inspector_works_behind_a_trait_object() {
        let inspector: Arc<dyn SchemaInspector> = Arc::new(testing::FakeInspector::default());
        let deadline = Instant::now() + Duration::from_secs(5);
        let engine = testing::engine();
        let connection = testing::connection(Dialect::PostgreSql);
        let context = testing::request_context();
        let filter = testing::object_filter(&engine, &connection, &context);

        let search = testing::search_request();
        let found = inspector
            .search_schema(&search, filter, deadline, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(found.matches.len(), 1);
        assert!(!found.truncated);

        let describe = testing::describe_request();
        let described = inspector
            .describe_schema(&describe, filter, deadline, CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(described.schemas.len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_denied_object_fails_as_a_rejection_at_the_source() {
        let inspector = testing::FakeInspector::rejecting();
        let describe = testing::describe_request();
        let engine = testing::engine();
        let connection = testing::connection(Dialect::PostgreSql);
        let context = testing::request_context();
        let filter = testing::object_filter(&engine, &connection, &context);
        let error = inspector
            .describe_schema(
                &describe,
                filter,
                Instant::now() + Duration::from_secs(5),
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, SchemaError::Rejected(_)), "{error:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn a_cancelled_token_stops_a_catalog_query() {
        let inspector = testing::FakeInspector::taking(Duration::from_secs(30));
        let cancel = CancellationToken::new();
        cancel.cancel();
        let search = testing::search_request();
        let engine = testing::engine();
        let connection = testing::connection(Dialect::PostgreSql);
        let context = testing::request_context();
        let filter = testing::object_filter(&engine, &connection, &context);
        let error = inspector
            .search_schema(
                &search,
                filter,
                Instant::now() + Duration::from_secs(5),
                cancel,
            )
            .await
            .unwrap_err();
        assert_eq!(error, SchemaError::Cancelled);
    }

    #[tokio::test(start_paused = true)]
    async fn a_cancelled_token_stops_a_describe_lookup() {
        let inspector = testing::FakeInspector::taking(Duration::from_secs(30));
        let cancel = CancellationToken::new();
        cancel.cancel();
        let describe = testing::describe_request();
        let engine = testing::engine();
        let connection = testing::connection(Dialect::PostgreSql);
        let context = testing::request_context();
        let filter = testing::object_filter(&engine, &connection, &context);
        let error = inspector
            .describe_schema(
                &describe,
                filter,
                Instant::now() + Duration::from_secs(5),
                cancel,
            )
            .await
            .unwrap_err();
        assert_eq!(error, SchemaError::Cancelled);
    }

    #[tokio::test(start_paused = true)]
    async fn the_deadline_reaches_the_adapter_instead_of_being_a_dropped_future() {
        let inspector = testing::FakeInspector::taking(Duration::from_secs(30));
        let search = testing::search_request();
        let engine = testing::engine();
        let connection = testing::connection(Dialect::PostgreSql);
        let context = testing::request_context();
        let filter = testing::object_filter(&engine, &connection, &context);
        let error = inspector
            .search_schema(
                &search,
                filter,
                Instant::now() + Duration::from_secs(5),
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        assert_eq!(error, SchemaError::Timeout);
    }

    #[tokio::test(start_paused = true)]
    async fn an_inspector_can_refuse_an_object_with_the_filter_it_was_given() {
        let engine = testing::denying_engine();
        let connection = testing::connection(Dialect::PostgreSql);
        let context = testing::request_context();
        let filter = testing::object_filter(&engine, &connection, &context);

        // What an adapter does per relation before it ever builds a response.
        let denied = testing::table(Some("app"), "secrets");
        assert!(!filter.permits(&denied));
        let rejection = filter.check(&denied).unwrap_err();
        assert_eq!(rejection.primary_code(), DenyCode::ObjectNotAllowed);
    }
}
