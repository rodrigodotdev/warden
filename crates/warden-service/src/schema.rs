//! Bounded schema discovery.
//!
//! Two things this path deliberately does **not** do:
//!
//! * **It takes no `QueryPermit`.** A catalog read runs on `control_pool` with static
//!   adapter-owned SQL, not on the agent path, so it is not what SPEC section 6,
//!   invariant 17 bounds — and reserving agent slots for it is exactly the coupling
//!   ADR-0025's second pool exists to avoid.
//! * **It records no audit attempt.** `AuditAttempt` is statement-shaped: it carries a
//!   `StatementKind`, a fingerprint, and denial reasons, and a catalog read has none of
//!   the three. SPEC section 6, invariant 24 binds query attempts; filling those fields
//!   with invented values would break `docs/architecture.md` section 11. Auditing
//!   schema reads needs its own event shape and belongs to Milestone 13
//!   (`docs/open-questions.md`).
//!
//! What it does do is hand the adapter the request's object rules as a parameter, so a
//! denied relation is filtered at the source rather than after the response was built
//! (ADR-0036), and redact the description before it returns, because column defaults
//! and comments can carry secrets (`docs/security.md` section 8).

use std::fmt;
use std::sync::Arc;

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use warden_core::context::RequestContext;
use warden_core::schema::{
    SchemaDescribeRequest, SchemaDescription, SchemaSearchRequest, SchemaSearchResult,
};
use warden_policy::{ObjectFilter, PolicyContext, PolicyEngine};
use warden_ports::ConnectionRegistry;

use crate::error::SchemaServiceError;
use crate::limits::RequestBudget;
use crate::redaction::Redactor;

/// Resolves one connection and dispatches bounded catalog reads to its inspector.
pub struct SchemaService {
    registry: Arc<dyn ConnectionRegistry>,
    engine: Arc<PolicyEngine>,
    redactor: Arc<Redactor>,
    shutdown: CancellationToken,
}

/// Prints only non-secret configuration state.
///
/// Port implementations and the cancellation token are deliberately omitted: an
/// adapter may hold a driver pool whose debug output contains connection options,
/// while token state is runtime coordination rather than useful configuration.
impl fmt::Debug for SchemaService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SchemaService")
            .field("redactor_is_empty", &self.redactor.is_empty())
            .finish_non_exhaustive()
    }
}

impl SchemaService {
    /// Wires the collaborators one schema request needs.
    #[must_use]
    pub fn new(
        registry: Arc<dyn ConnectionRegistry>,
        engine: Arc<PolicyEngine>,
        redactor: Arc<Redactor>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            registry,
            engine,
            redactor,
            shutdown,
        }
    }

    /// Searches relation names through the selected connection's inspector.
    pub async fn search(
        &self,
        context: &RequestContext,
        request: SchemaSearchRequest,
    ) -> Result<SchemaSearchResult, SchemaServiceError> {
        let runtime = self.registry.get(request.connection())?;
        if !runtime.capabilities().schema_search {
            return Err(SchemaServiceError::SearchUnsupported);
        }
        let filter = ObjectFilter::new(
            self.engine.as_ref(),
            PolicyContext::new(context, runtime.metadata()),
        );
        let deadline = RequestBudget::new(runtime.limits()).deadline(Instant::now());
        let found = runtime
            .inspector()
            .search_schema(&request, filter, deadline, self.shutdown.child_token())
            .await?;
        Ok(found)
    }

    /// Describes relations and redacts sensitive catalog text before returning it.
    pub async fn describe(
        &self,
        context: &RequestContext,
        request: SchemaDescribeRequest,
    ) -> Result<SchemaDescription, SchemaServiceError> {
        let runtime = self.registry.get(request.connection())?;
        let filter = ObjectFilter::new(
            self.engine.as_ref(),
            PolicyContext::new(context, runtime.metadata()),
        );
        let deadline = RequestBudget::new(runtime.limits()).deadline(Instant::now());
        let mut described = runtime
            .inspector()
            .describe_schema(&request, filter, deadline, self.shutdown.child_token())
            .await?;
        self.redactor.redact_description(&mut described);
        Ok(described)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::Arc;
    use std::time::Duration;

    use tokio::time::Instant;
    use tokio_util::sync::CancellationToken;
    use warden_core::dialect::Dialect;
    use warden_core::error::{PublicError, PublicErrorCode};
    use warden_core::limits::ExecutionLimits;
    use warden_core::schema::{MatchReason, SchemaMatch, TableKind};
    use warden_policy::{ObjectRules, PolicyEngine, PolicySettings};
    use warden_ports::{ConnectionRegistry, QueryPermit, SchemaError, SchemaInspector};

    use super::*;
    use crate::StaticConnectionRegistry;
    use crate::error::SchemaServiceError;
    use crate::redaction::REDACTED;
    use crate::testing;

    fn denying_engine() -> Arc<PolicyEngine> {
        Arc::new(
            PolicyEngine::with_defaults(&PolicySettings {
                objects: ObjectRules {
                    deny_tables: vec!["app.secrets".to_owned()],
                    ..ObjectRules::default()
                },
                ..PolicySettings::default()
            })
            .unwrap(),
        )
    }

    fn service_with_runtime(
        parts: testing::FakeParts,
        engine: Arc<PolicyEngine>,
        redactor: Arc<crate::Redactor>,
        shutdown: CancellationToken,
    ) -> SchemaService {
        let runtime = Arc::new(testing::runtime_from(parts));
        let registry: Arc<dyn ConnectionRegistry> =
            Arc::new(StaticConnectionRegistry::new(vec![runtime]).unwrap());
        SchemaService::new(registry, engine, redactor, shutdown)
    }

    fn service_with_shutdown(
        shutdown: &CancellationToken,
    ) -> (SchemaService, Arc<testing::FakeInspector>) {
        let inspector = Arc::new(testing::FakeInspector::new());
        let service = testing::schema_service(testing::ServiceFakes {
            inspector: Arc::clone(&inspector) as Arc<dyn SchemaInspector>,
            shutdown: shutdown.clone(),
            ..testing::ServiceFakes::default()
        });
        (service, inspector)
    }

    async fn schema_service_with_held_permit()
    -> (SchemaService, Arc<testing::FakeInspector>, QueryPermit) {
        let inspector = Arc::new(testing::FakeInspector::new());
        let limits = ExecutionLimits {
            max_concurrent_queries: 1,
            ..ExecutionLimits::default()
        };
        let mut parts = testing::FakeParts::new(Dialect::MySql);
        parts.limits = limits;
        parts.inspector = Arc::clone(&inspector) as Arc<dyn SchemaInspector>;
        let runtime = Arc::new(testing::runtime_from(parts));
        let held = runtime.acquire_query_permit().await.unwrap();
        let registry: Arc<dyn ConnectionRegistry> =
            Arc::new(StaticConnectionRegistry::new(vec![runtime]).unwrap());
        let service = SchemaService::new(
            registry,
            testing::engine(),
            testing::redactor(&[]),
            CancellationToken::new(),
        );
        (service, inspector, held)
    }

    fn schema_service_failing_with(source: SchemaError) -> SchemaService {
        testing::schema_service(testing::ServiceFakes {
            inspector: Arc::new(testing::FakeInspector::failing(source)),
            ..testing::ServiceFakes::default()
        })
    }

    #[tokio::test]
    async fn search_returns_the_bounded_adapter_result_without_redacting_relation_names() {
        let inspector = Arc::new(testing::FakeInspector::new());
        let service = testing::schema_service(testing::ServiceFakes {
            inspector: Arc::clone(&inspector) as Arc<dyn SchemaInspector>,
            redactor: testing::redactor(&["orders.secret"]),
            ..testing::ServiceFakes::default()
        });

        let found = service
            .search(&testing::request_context(), testing::search_request())
            .await
            .unwrap();

        assert_eq!(
            found.matches,
            vec![SchemaMatch {
                schema: "app".to_owned(),
                table: "orders".to_owned(),
                kind: TableKind::Table,
                reason: MatchReason::ExactTable,
            }]
        );
        assert!(!found.truncated);
        assert_eq!(inspector.search_calls(), 1);
    }

    #[tokio::test]
    async fn describe_redacts_only_sensitive_catalog_text_before_returning() {
        let service = testing::schema_service(testing::ServiceFakes {
            redactor: testing::redactor(&["orders.secret"]),
            ..testing::ServiceFakes::default()
        });

        let described = service
            .describe(&testing::request_context(), testing::describe_request())
            .await
            .unwrap();

        let columns = &described.schemas[0].tables[0].columns;
        assert_eq!(
            (
                columns[0].default.as_deref(),
                columns[0].comment.as_deref(),
                columns[1].default.as_deref(),
                columns[1].comment.as_deref(),
            ),
            (
                Some("nextval('orders_id_seq')"),
                Some("public identifier"),
                Some(REDACTED),
                Some(REDACTED),
            )
        );
    }

    #[tokio::test]
    async fn unknown_search_connection_never_reaches_the_inspector() {
        let inspector = Arc::new(testing::FakeInspector::new());
        let service = testing::schema_service(testing::ServiceFakes {
            inspector: Arc::clone(&inspector) as Arc<dyn SchemaInspector>,
            ..testing::ServiceFakes::default()
        });

        let error = service
            .search(
                &testing::request_context(),
                testing::search_request_for("staging-db"),
            )
            .await
            .unwrap_err();

        assert_eq!(error.public_code(), PublicErrorCode::ConnectionNotFound);
        assert_eq!(
            (inspector.search_calls(), inspector.describe_calls()),
            (0, 0)
        );
    }

    #[tokio::test]
    async fn unknown_describe_connection_never_reaches_the_inspector() {
        let inspector = Arc::new(testing::FakeInspector::new());
        let service = testing::schema_service(testing::ServiceFakes {
            inspector: Arc::clone(&inspector) as Arc<dyn SchemaInspector>,
            ..testing::ServiceFakes::default()
        });

        let error = service
            .describe(
                &testing::request_context(),
                testing::describe_request_for("staging-db"),
            )
            .await
            .unwrap_err();

        assert_eq!(error.public_code(), PublicErrorCode::ConnectionNotFound);
        assert_eq!(
            (inspector.search_calls(), inspector.describe_calls()),
            (0, 0)
        );
    }

    #[tokio::test]
    async fn unsupported_search_stops_before_the_inspector() {
        let inspector = Arc::new(testing::FakeInspector::new());
        let service = testing::schema_service(testing::ServiceFakes {
            capabilities: testing::capabilities_without_search(),
            inspector: Arc::clone(&inspector) as Arc<dyn SchemaInspector>,
            ..testing::ServiceFakes::default()
        });

        let error = service
            .search(&testing::request_context(), testing::search_request())
            .await
            .unwrap_err();

        assert_eq!(error, SchemaServiceError::SearchUnsupported);
        assert_eq!(error.public_code(), PublicErrorCode::SchemaLookupError);
        assert_eq!(
            (inspector.search_calls(), inspector.describe_calls()),
            (0, 0)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn search_passes_the_runtime_filter_and_client_deadline() {
        let inspector = Arc::new(testing::FakeInspector::new());
        let limits = ExecutionLimits {
            timeout: Duration::from_secs(41),
            ..ExecutionLimits::default()
        };
        let mut parts = testing::FakeParts::new(Dialect::MySql);
        parts.limits = limits;
        parts.inspector = Arc::clone(&inspector) as Arc<dyn SchemaInspector>;
        let service = service_with_runtime(
            parts,
            denying_engine(),
            testing::redactor(&[]),
            CancellationToken::new(),
        );
        let started = Instant::now();

        service
            .search(&testing::request_context(), testing::search_request())
            .await
            .unwrap();

        let observed = inspector.latest_search();
        assert_eq!(observed.request, testing::search_request());
        assert_eq!(
            observed.filter_connection,
            testing::connection(Dialect::MySql)
        );
        assert!(!observed.filter_permits_secret);
        assert_eq!(observed.deadline, started + Duration::from_secs(42));
    }

    #[tokio::test(start_paused = true)]
    async fn describe_passes_the_runtime_filter_and_client_deadline() {
        let inspector = Arc::new(testing::FakeInspector::new());
        let limits = ExecutionLimits {
            timeout: Duration::from_secs(73),
            ..ExecutionLimits::default()
        };
        let mut parts = testing::FakeParts::new(Dialect::PostgreSql);
        parts.limits = limits;
        parts.inspector = Arc::clone(&inspector) as Arc<dyn SchemaInspector>;
        let service = service_with_runtime(
            parts,
            denying_engine(),
            testing::redactor(&[]),
            CancellationToken::new(),
        );
        let started = Instant::now();

        service
            .describe(&testing::request_context(), testing::describe_request())
            .await
            .unwrap();

        let observed = inspector.latest_describe();
        assert_eq!(observed.request, testing::describe_request());
        assert_eq!(
            observed.filter_connection,
            testing::connection(Dialect::PostgreSql)
        );
        assert!(!observed.filter_permits_secret);
        assert_eq!(observed.deadline, started + Duration::from_secs(74));
    }

    #[tokio::test]
    async fn search_uses_the_runtime_selected_by_the_request() {
        let production_inspector = Arc::new(testing::FakeInspector::new());
        let analytics_inspector = Arc::new(testing::FakeInspector::new());
        let mut production = testing::FakeParts::new(Dialect::MySql);
        production.inspector = Arc::clone(&production_inspector) as Arc<dyn SchemaInspector>;
        let mut analytics = testing::FakeParts::new(Dialect::PostgreSql);
        analytics.metadata.name = "analytics-db".parse().unwrap();
        analytics.inspector = Arc::clone(&analytics_inspector) as Arc<dyn SchemaInspector>;
        let runtimes = vec![
            Arc::new(testing::runtime_from(production)),
            Arc::new(testing::runtime_from(analytics)),
        ];
        let registry: Arc<dyn ConnectionRegistry> =
            Arc::new(StaticConnectionRegistry::new(runtimes).unwrap());
        let service = SchemaService::new(
            registry,
            testing::engine(),
            testing::redactor(&[]),
            CancellationToken::new(),
        );

        service
            .search(
                &testing::request_context(),
                testing::search_request_for("analytics-db"),
            )
            .await
            .unwrap();

        assert_eq!(production_inspector.search_calls(), 0);
        assert_eq!(analytics_inspector.search_calls(), 1);
        assert_eq!(
            analytics_inspector
                .latest_search()
                .filter_connection
                .name
                .as_str(),
            "analytics-db"
        );
    }

    #[tokio::test]
    async fn root_cancellation_reaches_the_search_child_token() {
        let shutdown = CancellationToken::new();
        let (service, inspector) = service_with_shutdown(&shutdown);

        service
            .search(&testing::request_context(), testing::search_request())
            .await
            .unwrap();
        let observed = inspector.latest_search();
        assert!(!observed.cancel.is_cancelled());
        shutdown.cancel();
        assert!(observed.cancel.is_cancelled());
    }

    #[tokio::test]
    async fn cancelling_the_search_child_does_not_cancel_the_root() {
        let shutdown = CancellationToken::new();
        let (service, inspector) = service_with_shutdown(&shutdown);

        service
            .search(&testing::request_context(), testing::search_request())
            .await
            .unwrap();
        inspector.latest_search().cancel.cancel();

        assert!(!shutdown.is_cancelled());
    }

    #[tokio::test]
    async fn root_cancellation_reaches_the_describe_child_token() {
        let shutdown = CancellationToken::new();
        let (service, inspector) = service_with_shutdown(&shutdown);

        service
            .describe(&testing::request_context(), testing::describe_request())
            .await
            .unwrap();
        let observed = inspector.latest_describe();
        assert!(!observed.cancel.is_cancelled());
        shutdown.cancel();
        assert!(observed.cancel.is_cancelled());
    }

    #[tokio::test]
    async fn cancelling_the_describe_child_does_not_cancel_the_root() {
        let shutdown = CancellationToken::new();
        let (service, inspector) = service_with_shutdown(&shutdown);

        service
            .describe(&testing::request_context(), testing::describe_request())
            .await
            .unwrap();
        inspector.latest_describe().cancel.cancel();

        assert!(!shutdown.is_cancelled());
    }

    #[tokio::test]
    async fn search_propagates_every_schema_error_with_its_public_code() {
        let cases = [
            (
                SchemaError::Rejected(testing::rejection_with_internal_detail()),
                PublicErrorCode::QueryRejected,
            ),
            (SchemaError::Timeout, PublicErrorCode::QueryTimeout),
            (SchemaError::Cancelled, PublicErrorCode::QueryCancelled),
            (
                SchemaError::Database {
                    detail: "driver-secret".to_owned(),
                },
                PublicErrorCode::SchemaLookupError,
            ),
        ];

        for (source, expected_code) in cases {
            let service = schema_service_failing_with(source.clone());
            let error = service
                .search(&testing::request_context(), testing::search_request())
                .await
                .unwrap_err();
            assert_eq!(error, SchemaServiceError::Schema(source));
            assert_eq!(error.public_code(), expected_code);
            for hidden in ["staging-db", "production-db", "driver-secret"] {
                assert!(!error.to_string().contains(hidden), "{error}");
            }
        }
    }

    #[tokio::test]
    async fn describe_propagates_every_schema_error_with_its_public_code() {
        let cases = [
            (
                SchemaError::Rejected(testing::rejection_with_internal_detail()),
                PublicErrorCode::QueryRejected,
            ),
            (SchemaError::Timeout, PublicErrorCode::QueryTimeout),
            (SchemaError::Cancelled, PublicErrorCode::QueryCancelled),
            (
                SchemaError::Database {
                    detail: "driver-secret".to_owned(),
                },
                PublicErrorCode::SchemaLookupError,
            ),
        ];

        for (source, expected_code) in cases {
            let service = schema_service_failing_with(source.clone());
            let error = service
                .describe(&testing::request_context(), testing::describe_request())
                .await
                .unwrap_err();
            assert_eq!(error, SchemaServiceError::Schema(source));
            assert_eq!(error.public_code(), expected_code);
            for hidden in ["staging-db", "production-db", "driver-secret"] {
                assert!(!error.to_string().contains(hidden), "{error}");
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn search_does_not_wait_for_an_execution_permit() {
        let (service, inspector, held) = schema_service_with_held_permit().await;
        let started = Instant::now();

        service
            .search(&testing::request_context(), testing::search_request())
            .await
            .unwrap();

        assert_eq!(started.elapsed(), Duration::ZERO);
        assert_eq!(
            (inspector.search_calls(), inspector.describe_calls()),
            (1, 0)
        );
        drop(held);
    }

    #[tokio::test(start_paused = true)]
    async fn describe_does_not_wait_for_an_execution_permit() {
        let (service, inspector, held) = schema_service_with_held_permit().await;
        let started = Instant::now();

        service
            .describe(&testing::request_context(), testing::describe_request())
            .await
            .unwrap();

        assert_eq!(started.elapsed(), Duration::ZERO);
        assert_eq!(
            (inspector.search_calls(), inspector.describe_calls()),
            (0, 1)
        );
        drop(held);
    }

    #[test]
    fn debug_omits_ports_and_cancellation_token_state() {
        let service = testing::schema_service(testing::ServiceFakes::default());

        let rendered = format!("{service:?}");

        assert!(rendered.contains("SchemaService"), "{rendered}");
        assert!(rendered.contains("redactor_is_empty"), "{rendered}");
        for hidden in [
            "registry",
            "engine",
            "FakeInspector",
            "CancellationToken",
            "shutdown",
        ] {
            assert!(!rendered.contains(hidden), "{rendered}");
        }
    }
}
