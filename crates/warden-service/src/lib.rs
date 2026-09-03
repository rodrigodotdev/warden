//! Warden's application services: the orchestration between an MCP tool call and a
//! database adapter.
//!
//! This crate depends on `warden-core`, `warden-policy`, and `warden-ports`, and must
//! not depend on `sqlx`, `sqlparser`, or `rmcp` (SPEC section 6, invariants 26–28;
//! `docs/architecture.md` section 3), a rule `tests/architecture.rs` enforces
//! mechanically.
//!
//! # The order this crate owns
//!
//! ```text
//! QueryRequest        size-validated by its own constructor, before it arrives here
//!    │ registry       resolve the connection            -> ConnectionError
//!    │ analyzer       parse in the target dialect       -> AnalyzedQuery
//!    │ engine         evaluate every policy             -> AuthorizedQuery
//!    │ audit sink     record the attempt, FAIL CLOSED   (ADR-0022)
//!    │ runtime        acquire a permit within max_queue_wait
//!    │ executor       run under a deadline and a token  (ADR-0024)
//!    │ redactor       apply the configured column rules
//!    │ audit sink     record the outcome, fail open with an alarm
//! ResultSet
//! ```
//!
//! # Why the middle four steps are a type
//!
//! ADR-0032 made the concurrency permit a parameter, so execution cannot begin
//! without one — but a `&QueryPermit` carries no connection identity, and nothing
//! ordered it against the audit attempt (`docs/open-questions.md` item 14).
//! `crate::pipeline`'s gate closes both gaps: its single constructor records the
//! attempt and then acquires the permit from the same [`ConnectionRuntime`] it will
//! dispatch to, and it is the only place in this crate's production code allowed to
//! name `executor()`, `explainer()`, or `acquire_query_permit()` (ADR-0038).
//! `tests/service_rules.rs` enforces that mechanically.
//!
//! # What this crate does not do
//!
//! It does not normalize rows: bounding and normalization happen inside the adapter,
//! under the limits carried by the `AuthorizedQuery` this crate authorized
//! (`docs/architecture.md` section 8, step 8). It does not sanitize errors for the
//! wire either; it returns typed errors whose [`warden_core::error::PublicError`]
//! code `crates/warden-mcp/src/error.rs` turns into a `CallToolResult` at the MCP
//! boundary. That module is the only one in `warden-mcp` that builds a failed result,
//! and it takes a code rather than a message, so nothing this crate returns can carry a
//! driver string across (`docs/security.md` section 10).

use std::fmt;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use warden_policy::PolicyEngine;

pub mod error;
pub mod explain;
pub mod limits;
pub mod query;
pub mod redaction;
pub mod registry;
pub mod schema;

mod pipeline;

mod audit;

pub use error::{ExplainServiceError, QueryServiceError, SchemaServiceError, ServiceBuildError};
pub use explain::ExplainService;
pub use limits::{AUDIT_WRITE_TIMEOUT, MAX_ADAPTER_CLEANUP, RequestBudget};
pub use query::QueryService;
pub use redaction::{REDACTED, RedactionRuleError, RedactionSettings, RedactionStrategy, Redactor};
pub use registry::{RegistryError, StaticConnectionRegistry};
pub use schema::SchemaService;
pub use warden_ports::{
    AuditSink, ConnectionRegistry, ConnectionRuntime, ConnectionRuntimeParts, RuntimeError,
};

/// Everything the three services need, assembled by the composition root.
///
/// A parts struct makes every collaborator explicit at the call site, preventing
/// similarly shaped trait objects from being transposed accidentally. Its fields are
/// public because filling them is the composition root's responsibility.
pub struct ServiceParts {
    /// Every configured connection.
    pub registry: Arc<dyn ConnectionRegistry>,
    /// The one policy engine every request evaluates against.
    pub engine: Arc<PolicyEngine>,
    /// Where audit records go.
    pub audit: Arc<dyn AuditSink>,
    /// The configured redaction rules, still unparsed.
    pub redaction: RedactionSettings,
    /// The root cancellation token shared by all services.
    pub shutdown: CancellationToken,
}

/// Prints only safe composition metadata, never collaborators or rule contents.
impl fmt::Debug for ServiceParts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceParts")
            .field("connection_count", &self.registry.list().len())
            .field("policy_count", &self.engine.policy_names().len())
            .field(
                "object_policy_count",
                &self.engine.object_policy_names().len(),
            )
            .field("redaction_rule_count", &self.redaction.columns.len())
            .finish_non_exhaustive()
    }
}

/// The application services, sharing one registry, engine, sink, and redactor.
pub struct Services {
    registry: Arc<dyn ConnectionRegistry>,
    query: QueryService,
    explain: ExplainService,
    schema: SchemaService,
    redactor_is_empty: bool,
}

impl Services {
    /// Parses redaction rules once and wires the three services.
    ///
    /// # Errors
    ///
    /// Returns [`ServiceBuildError`] when any configured redaction rule is invalid.
    pub fn new(parts: ServiceParts) -> Result<Self, ServiceBuildError> {
        let redactor = Arc::new(Redactor::new(&parts.redaction)?);
        let redactor_is_empty = redactor.is_empty();
        let query = QueryService::new(
            Arc::clone(&parts.registry),
            Arc::clone(&parts.engine),
            Arc::clone(&parts.audit),
            Arc::clone(&redactor),
            parts.shutdown.clone(),
        );
        let explain = ExplainService::new(
            Arc::clone(&parts.registry),
            Arc::clone(&parts.engine),
            Arc::clone(&parts.audit),
            Arc::clone(&redactor),
            parts.shutdown.clone(),
        );
        let schema = SchemaService::new(
            Arc::clone(&parts.registry),
            Arc::clone(&parts.engine),
            redactor,
            parts.shutdown,
        );
        Ok(Self {
            registry: parts.registry,
            query,
            explain,
            schema,
            redactor_is_empty,
        })
    }

    /// The query service.
    #[must_use]
    pub fn query(&self) -> &QueryService {
        &self.query
    }

    /// The explain service.
    #[must_use]
    pub fn explain(&self) -> &ExplainService {
        &self.explain
    }

    /// The schema service.
    #[must_use]
    pub fn schema(&self) -> &SchemaService {
        &self.schema
    }

    /// Every configured connection, for `list_connections`.
    ///
    /// This is the same registry supplied at startup, so `warden-mcp` observes the
    /// service layer's connection authority rather than reconstructing one.
    #[must_use]
    pub fn registry(&self) -> &dyn ConnectionRegistry {
        self.registry.as_ref()
    }
}

/// Prints only safe composition metadata, never services or collaborators.
impl fmt::Debug for Services {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Services")
            .field("connection_count", &self.registry.list().len())
            .field("redactor_is_empty", &self.redactor_is_empty)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod testing;

#[cfg(test)]
mod composition_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::Arc;

    use tokio_util::sync::CancellationToken;
    use warden_core::dialect::Dialect;
    use warden_core::explain::ExplainRequest;
    use warden_core::result::ResultValue;
    use warden_policy::PolicyEngine;
    use warden_ports::{AuditSink, ConnectionRegistry};

    use super::*;
    use crate::testing;

    #[tokio::test]
    async fn one_parsed_redactor_applies_to_query_explain_and_schema_services() {
        let mut runtime_parts = testing::FakeParts::new(Dialect::MySql);
        let executor = Arc::new(testing::FakeExecutor::returning(testing::secret_result()));
        let explainer = Arc::new(testing::FakeExplainer::new());
        let inspector = Arc::new(testing::FakeInspector::new());
        runtime_parts.executor = Arc::clone(&executor) as Arc<dyn warden_ports::QueryExecutor>;
        runtime_parts.explainer = Arc::clone(&explainer) as Arc<dyn warden_ports::Explainer>;
        runtime_parts.inspector = Arc::clone(&inspector) as Arc<dyn warden_ports::SchemaInspector>;
        let registry: Arc<dyn ConnectionRegistry> = Arc::new(
            StaticConnectionRegistry::new(vec![Arc::new(testing::runtime_from(runtime_parts))])
                .unwrap(),
        );
        let shutdown = CancellationToken::new();
        let services = Services::new(ServiceParts {
            registry,
            engine: Arc::new(PolicyEngine::with_defaults(&Default::default()).unwrap()),
            audit: Arc::new(testing::FakeAuditSink::new()) as Arc<dyn AuditSink>,
            redaction: RedactionSettings {
                columns: vec!["*.password".to_owned(), "orders.secret".to_owned()],
                ..RedactionSettings::default()
            },
            shutdown: shutdown.clone(),
        })
        .unwrap();

        assert!(Arc::ptr_eq(
            query::redactor_arc(services.query()),
            explain::redactor_arc(services.explain())
        ));
        assert!(Arc::ptr_eq(
            query::redactor_arc(services.query()),
            schema::redactor_arc(services.schema())
        ));

        let result = services
            .query()
            .execute(&testing::request_context(), testing::request())
            .await
            .unwrap();
        let plan = services
            .explain()
            .explain(
                &testing::request_context(),
                ExplainRequest::new(testing::request()),
            )
            .await
            .unwrap();
        let description = services
            .schema()
            .describe(&testing::request_context(), testing::describe_request())
            .await
            .unwrap();

        assert_eq!(result.rows[0][1], ResultValue::String(REDACTED.to_owned()));
        assert_eq!(plan.plan["password"], serde_json::json!(REDACTED));
        assert_eq!(
            description.schemas[0].tables[0].columns[1]
                .default
                .as_deref(),
            Some(REDACTED)
        );

        let query_child = executor.latest_observation().1;
        let explain_child = explainer.latest_observation().1;
        let schema_child = inspector.latest_describe().cancel;
        assert_ne!(query_child, shutdown);
        assert_ne!(explain_child, shutdown);
        assert_ne!(schema_child, shutdown);
        shutdown.cancel();
        assert!(query_child.is_cancelled());
        assert!(explain_child.is_cancelled());
        assert!(schema_child.is_cancelled());
    }
}
