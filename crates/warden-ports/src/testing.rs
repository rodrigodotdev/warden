//! Fakes and fixtures for this crate's tests.
//!
//! `warden-ports` has no parser, no driver, and no database — that is the point of
//! the milestone — so every test here runs against a fake.
//!
//! They live in a `#[cfg(test)]` module rather than behind a `testing` feature
//! because Cargo unifies features across a workspace build
//! (`docs/architecture.md` section 4.3): a feature that exposed these to this
//! crate's tests would expose them to `warden-mcp` too. `warden-service` writes its
//! own fakes in Milestone 11 for the same reason.

#![allow(clippy::unwrap_used, clippy::expect_used)]
// Helpers are shared by tests in several modules. One that the module you are
// editing happens not to use is not dead code.
#![allow(dead_code)]

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use time::OffsetDateTime;
use tokio::time::{Instant, sleep, sleep_until};
use tokio_util::sync::CancellationToken;
use warden_core::analysis::{
    ObjectKind, ObjectRef, QueryAnalysis, QueryAnalysisParts, SqlIdentifier, StatementKind,
};
use warden_core::connection::{Capabilities, ConnectionMetadata, Environment};
use warden_core::context::RequestContext;
use warden_core::dialect::Dialect;
use warden_core::explain::{PlanSummary, QueryPlan};
use warden_core::limits::ExecutionLimits;
use warden_core::query::{InputLimits, QueryRequest};
use warden_core::result::{QueryStats, ResultColumn, ResultSet, ResultValue};
use warden_core::schema::{
    ColumnDescription, MatchReason, Schema, SchemaDescribeRequest, SchemaDescription, SchemaMatch,
    SchemaSearchRequest, SchemaSearchResult, Table, TableKind,
};
use warden_policy::{
    AnalyzedQuery, AuthorizedQuery, DenyReason, ObjectFilter, ObjectRules, PolicyContext,
    PolicyEngine, PolicyRejection, PolicySettings,
};

use crate::BoxFuture;
use crate::analyzer::QueryAnalyzer;
use crate::audit::{AuditAttempt, AuditEventId, AuditOutcomeEvent, AuditSink};
use crate::error::{
    AnalyzeError, AuditError, ConnectionError, ExecuteError, ExplainError, RuntimeError,
    SchemaError,
};
use crate::executor::QueryExecutor;
use crate::explainer::Explainer;
use crate::inspector::SchemaInspector;
use crate::registry::ConnectionRegistry;
use crate::runtime::{ConnectionRuntime, ConnectionRuntimeParts, QueryPermit};

/// The statement every fixture uses.
pub(crate) const SQL: &str = "SELECT id FROM orders";

/// A valid request against the fixture connection.
pub(crate) fn request() -> QueryRequest {
    QueryRequest::new(
        "production-db".parse().unwrap(),
        SQL.to_owned(),
        Vec::new(),
        &InputLimits::default(),
    )
    .unwrap()
}

/// A fixed request identity.
pub(crate) fn request_context() -> RequestContext {
    RequestContext::new(
        "req-1".parse().unwrap(),
        "alice@example.com".parse().unwrap(),
        "Claude Code".parse().unwrap(),
    )
}

/// A production connection on the given dialect.
pub(crate) fn connection(dialect: Dialect) -> ConnectionMetadata {
    ConnectionMetadata {
        name: "production-db".parse().unwrap(),
        dialect,
        environment: Environment::Production,
        database: "app".to_owned(),
    }
}

/// An adapter that can do everything.
pub(crate) fn capabilities() -> Capabilities {
    Capabilities {
        read_only_transactions: true,
        structured_explain: true,
        server_statement_timeout: true,
        schema_search: true,
    }
}

/// The baseline evidence: one safe `SELECT`, no risks, no objects.
pub(crate) fn parts(dialect: Dialect) -> QueryAnalysisParts {
    QueryAnalysisParts {
        dialect,
        statement_count: NonZeroUsize::MIN,
        root_kind: StatementKind::Select,
        nested_kinds: Vec::new(),
        objects: Vec::new(),
        functions: Vec::new(),
        risks: Vec::new(),
        has_locking_clause: false,
        has_side_effects: false,
        fingerprint: None,
    }
}

/// The baseline, frozen.
pub(crate) fn analysis(dialect: Dialect) -> QueryAnalysis {
    QueryAnalysis::new(parts(dialect))
}

/// The baseline paired with the fixture request.
pub(crate) fn analyzed(dialect: Dialect) -> AnalyzedQuery {
    AnalyzedQuery::new(request(), analysis(dialect))
}

/// The real engine with the hardened default settings.
pub(crate) fn engine() -> PolicyEngine {
    PolicyEngine::with_defaults(&PolicySettings::default()).unwrap()
}

/// An engine whose object rules refuse one table.
pub(crate) fn denying_engine() -> PolicyEngine {
    let settings = PolicySettings {
        objects: ObjectRules {
            deny_tables: vec!["app.secrets".to_owned()],
            ..ObjectRules::default()
        },
        ..PolicySettings::default()
    };
    PolicyEngine::with_defaults(&settings).expect("the default rule set builds")
}

/// A schema-qualified table reference, as an adapter would build one.
pub(crate) fn table(schema: Option<&str>, name: &str) -> ObjectRef {
    ObjectRef {
        catalog: None,
        schema: schema.map(SqlIdentifier::unquoted),
        name: SqlIdentifier::unquoted(name),
        kind: ObjectKind::Table,
    }
}

/// A filter over the default engine and the fixture connection.
///
/// Held by the caller rather than returned by value: `ObjectFilter` borrows both.
pub(crate) fn object_filter<'a>(
    engine: &'a PolicyEngine,
    connection: &'a ConnectionMetadata,
    context: &'a RequestContext,
) -> ObjectFilter<'a> {
    ObjectFilter::new(engine, PolicyContext::new(context, connection))
}

/// A real authorization, produced by the real engine.
///
/// There is no shortcut and there must never be one: `AllowDecision` is unforgeable
/// outside `warden-policy` (ADR-0010), so even a test in a downstream crate has to
/// go through `PolicyEngine::authorize`. That this fixture is the only way to build
/// the executor's argument is the capability token working as designed.
pub(crate) fn authorized(dialect: Dialect) -> AuthorizedQuery {
    engine()
        .authorize(
            &request_context(),
            &connection(dialect),
            analyzed(dialect),
            ExecutionLimits::default(),
        )
        .unwrap()
}

/// A real rejection, produced by asking the engine to authorize a write.
pub(crate) fn rejection() -> PolicyRejection {
    let analysis = QueryAnalysis::new(QueryAnalysisParts {
        root_kind: StatementKind::Insert,
        ..parts(Dialect::MySql)
    });
    engine()
        .authorize(
            &request_context(),
            &connection(Dialect::MySql),
            AnalyzedQuery::new(request(), analysis),
            ExecutionLimits::default(),
        )
        .unwrap_err()
}

/// An analyzer with a fixed outcome.
#[derive(Debug)]
pub(crate) struct FakeAnalyzer {
    dialect: Dialect,
    outcome: Result<(), AnalyzeError>,
}

impl FakeAnalyzer {
    /// An analyzer that always produces the baseline evidence.
    pub(crate) fn new(dialect: Dialect) -> Self {
        Self {
            dialect,
            outcome: Ok(()),
        }
    }

    /// An analyzer that always fails the same way.
    pub(crate) fn failing(error: AnalyzeError) -> Self {
        Self {
            dialect: Dialect::MySql,
            outcome: Err(error),
        }
    }
}

impl QueryAnalyzer for FakeAnalyzer {
    fn dialect(&self) -> Dialect {
        self.dialect
    }

    fn analyze(&self, request: QueryRequest) -> Result<AnalyzedQuery, AnalyzeError> {
        match &self.outcome {
            Ok(()) => Ok(AnalyzedQuery::new(request, analysis(self.dialect))),
            Err(error) => Err(error.clone()),
        }
    }
}

/// A bounded search request against the fixture connection.
pub(crate) fn search_request() -> SchemaSearchRequest {
    SchemaSearchRequest::new("production-db".parse().unwrap(), "orders", 10).unwrap()
}

/// A bounded describe request against the fixture connection.
pub(crate) fn describe_request() -> SchemaDescribeRequest {
    SchemaDescribeRequest::new(
        "production-db".parse().unwrap(),
        vec!["app.orders".parse().unwrap()],
    )
    .unwrap()
}

/// One normalized row, so a fake result is a valid result.
pub(crate) fn result_set() -> ResultSet {
    ResultSet {
        columns: vec![ResultColumn {
            name: "id".to_owned(),
            database_type: "BIGINT".to_owned(),
            nullable: Some(false),
        }],
        rows: vec![vec![ResultValue::I64(1)]],
        truncated: false,
        stats: QueryStats {
            rows_returned: 1,
            bytes: 1,
            duration: Duration::from_millis(1),
        },
    }
}

/// An executor that pretends the database takes `duration`.
#[derive(Debug, Default)]
pub(crate) struct FakeExecutor {
    duration: Duration,
}

impl FakeExecutor {
    /// An executor whose query takes the given time to finish.
    pub(crate) fn taking(duration: Duration) -> Self {
        Self { duration }
    }
}

impl QueryExecutor for FakeExecutor {
    fn execute_read_only<'a>(
        &'a self,
        query: &'a AuthorizedQuery,
        _permit: &'a QueryPermit,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<ResultSet, ExecuteError>> {
        Box::pin(async move {
            // The real adapters race the same three futures. A real one also issues
            // a cancel request or a KILL QUERY on the last two arms, which is the
            // whole reason the token is a parameter (ADR-0024).
            tokio::select! {
                () = sleep(self.duration) => {}
                () = cancel.cancelled() => return Err(ExecuteError::Cancelled),
                () = sleep_until(deadline) => return Err(ExecuteError::Timeout),
            }
            assert_eq!(query.sql(), SQL, "the executed SQL is the analyzed SQL");
            Ok(result_set())
        })
    }
}

/// An inspector with a fixed outcome.
#[derive(Debug, Default)]
pub(crate) struct FakeInspector {
    rejects: bool,
    duration: Duration,
}

impl FakeInspector {
    /// An inspector whose object rules deny everything.
    pub(crate) fn rejecting() -> Self {
        Self {
            rejects: true,
            duration: Duration::ZERO,
        }
    }

    /// An inspector whose lookup takes the given time to finish.
    pub(crate) fn taking(duration: Duration) -> Self {
        Self {
            rejects: false,
            duration,
        }
    }

    /// Races the same three futures the executor does, so `SchemaInspector`'s
    /// deadline and cancellation reach a real caller exactly like
    /// `QueryExecutor`'s do (ADR-0024), for both methods below without
    /// duplicating the race in each.
    async fn guard(
        &self,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<(), SchemaError> {
        tokio::select! {
            () = sleep(self.duration) => {}
            () = cancel.cancelled() => return Err(SchemaError::Cancelled),
            () = sleep_until(deadline) => return Err(SchemaError::Timeout),
        }
        if self.rejects {
            return Err(SchemaError::Rejected(rejection()));
        }
        Ok(())
    }
}

impl SchemaInspector for FakeInspector {
    fn search_schema<'a>(
        &'a self,
        _request: &'a SchemaSearchRequest,
        _filter: ObjectFilter<'a>,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<SchemaSearchResult, SchemaError>> {
        Box::pin(async move {
            self.guard(deadline, &cancel).await?;
            Ok(SchemaSearchResult {
                matches: vec![SchemaMatch {
                    schema: "app".to_owned(),
                    table: "orders".to_owned(),
                    kind: TableKind::Table,
                    reason: MatchReason::ExactTable,
                }],
                truncated: false,
            })
        })
    }

    fn describe_schema<'a>(
        &'a self,
        _request: &'a SchemaDescribeRequest,
        _filter: ObjectFilter<'a>,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<SchemaDescription, SchemaError>> {
        Box::pin(async move {
            self.guard(deadline, &cancel).await?;
            Ok(SchemaDescription {
                schemas: vec![Schema {
                    name: "app".to_owned(),
                    tables: vec![Table {
                        schema: "app".to_owned(),
                        name: "orders".to_owned(),
                        kind: TableKind::Table,
                        columns: vec![ColumnDescription {
                            name: "id".to_owned(),
                            database_type: "BIGINT".to_owned(),
                            nullable: false,
                            default: None,
                            comment: None,
                        }],
                        primary_key: vec!["id".to_owned()],
                        foreign_keys: Vec::new(),
                        indexes: Vec::new(),
                    }],
                }],
            })
        })
    }
}

/// An explainer with a fixed outcome.
#[derive(Debug, Default)]
pub(crate) struct FakeExplainer {
    duration: Duration,
    failure: Option<ExplainError>,
}

impl FakeExplainer {
    /// An explainer that always fails the same way.
    pub(crate) fn failing(error: ExplainError) -> Self {
        Self {
            duration: Duration::ZERO,
            failure: Some(error),
        }
    }

    /// An explainer whose planning takes the given time to finish.
    pub(crate) fn taking(duration: Duration) -> Self {
        Self {
            duration,
            failure: None,
        }
    }
}

impl Explainer for FakeExplainer {
    fn explain<'a>(
        &'a self,
        query: &'a AuthorizedQuery,
        _permit: &'a QueryPermit,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<QueryPlan, ExplainError>> {
        Box::pin(async move {
            // Races the same three futures the executor does, so a dropped future
            // is never the only thing standing between planning and a hung
            // connection (ADR-0024).
            tokio::select! {
                () = sleep(self.duration) => {}
                () = cancel.cancelled() => return Err(ExplainError::Cancelled),
                () = sleep_until(deadline) => return Err(ExplainError::Timeout),
            }
            if let Some(error) = &self.failure {
                return Err(error.clone());
            }
            Ok(QueryPlan {
                dialect: query.dialect(),
                summary: PlanSummary {
                    estimated_rows: Some(1200),
                },
                plan: serde_json::json!({ "Node Type": "Seq Scan" }),
            })
        })
    }
}

/// An attempt against the fixture connection, carrying the given denials.
pub(crate) fn attempt(deny_reasons: Vec<DenyReason>) -> AuditAttempt {
    AuditAttempt {
        id: AuditEventId::generate(),
        timestamp: OffsetDateTime::UNIX_EPOCH,
        request_id: "req-1".parse().unwrap(),
        principal: "alice@example.com".parse().unwrap(),
        client: "Claude Code".parse().unwrap(),
        connection: "production-db".parse().unwrap(),
        dialect: Dialect::MySql,
        environment: Environment::Production,
        fingerprint: None,
        statement_kind: StatementKind::Select,
        deny_reasons,
    }
}

/// A sink that either accepts everything or fails everything.
#[derive(Debug, Default)]
pub(crate) struct FakeAuditSink {
    broken: bool,
}

impl FakeAuditSink {
    /// A sink that cannot accept a record, so the caller must fail closed.
    pub(crate) fn broken() -> Self {
        Self { broken: true }
    }

    fn result(&self) -> Result<(), AuditError> {
        if self.broken {
            return Err(AuditError::Unavailable {
                detail: "the fake sink is broken".to_owned(),
            });
        }
        Ok(())
    }
}

impl AuditSink for FakeAuditSink {
    fn record_attempt<'a>(
        &'a self,
        _event: &'a AuditAttempt,
    ) -> BoxFuture<'a, Result<(), AuditError>> {
        Box::pin(async move { self.result() })
    }

    fn record_outcome<'a>(
        &'a self,
        _event: &'a AuditOutcomeEvent,
    ) -> BoxFuture<'a, Result<(), AuditError>> {
        Box::pin(async move { self.result() })
    }
}

/// A runtime whose analyzer matches the connection's dialect.
pub(crate) fn runtime(dialect: Dialect, limits: ExecutionLimits) -> ConnectionRuntime {
    try_runtime(dialect, limits, dialect).unwrap()
}

/// A runtime built from parts that may deliberately disagree.
pub(crate) fn try_runtime(
    dialect: Dialect,
    limits: ExecutionLimits,
    analyzer_dialect: Dialect,
) -> Result<ConnectionRuntime, RuntimeError> {
    ConnectionRuntime::new(ConnectionRuntimeParts {
        metadata: connection(dialect),
        capabilities: capabilities(),
        limits,
        analyzer: Arc::new(FakeAnalyzer::new(analyzer_dialect)),
        executor: Arc::new(FakeExecutor::default()),
        inspector: Arc::new(FakeInspector::default()),
        explainer: Arc::new(FakeExplainer::default()),
    })
}

/// A runtime and one permit taken from it.
///
/// Both are returned because a test almost always needs both: the permit to pass to
/// a port, and the runtime to assert `available_permits` against.
pub(crate) async fn with_permit(limits: ExecutionLimits) -> (ConnectionRuntime, QueryPermit) {
    let runtime = runtime(Dialect::MySql, limits);
    let permit = runtime.acquire_query_permit().await.unwrap();
    (runtime, permit)
}

/// A registry holding exactly the fixture connection.
#[derive(Debug)]
pub(crate) struct FakeRegistry {
    runtime: Arc<ConnectionRuntime>,
}

impl FakeRegistry {
    /// A registry serving one connection on the given dialect.
    pub(crate) fn new(dialect: Dialect) -> Self {
        Self {
            runtime: Arc::new(runtime(dialect, ExecutionLimits::default())),
        }
    }
}

impl ConnectionRegistry for FakeRegistry {
    fn get(
        &self,
        name: &warden_core::connection::ConnectionName,
    ) -> Result<Arc<ConnectionRuntime>, ConnectionError> {
        if name == &self.runtime.metadata().name {
            return Ok(Arc::clone(&self.runtime));
        }
        Err(ConnectionError::NotFound { name: name.clone() })
    }

    fn list(&self) -> Vec<warden_core::connection::ConnectionMetadata> {
        vec![self.runtime.metadata().clone()]
    }
}
