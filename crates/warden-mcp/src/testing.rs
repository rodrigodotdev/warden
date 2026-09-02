//! Fakes and fixtures for this crate's tests.
//!
//! They live in a `#[cfg(test)]` module rather than behind a `testing` feature because
//! Cargo unifies features across a workspace build, and a feature that exposed a fake
//! executor to this crate's tests would expose it to the binary too
//! (`docs/architecture.md` section 4.3).
//!
//! `warden-ports` and `warden-policy` are dev-dependencies for the same reason: a fake
//! has to implement the port traits and the fixture registry needs a real
//! [`PolicyEngine`], but `docs/architecture.md` section 3 keeps this crate's production
//! edge at core + service + rmcp. `tests/architecture.rs` excludes dev-dependency edges
//! from the graph it enforces.

#![allow(clippy::unwrap_used, clippy::expect_used)]
// Helpers are shared by tests in several modules. One that the module you are editing
// happens not to use is not dead code.
#![allow(dead_code)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use warden_core::analysis::{QueryAnalysis, QueryAnalysisParts, StatementKind};
use warden_core::connection::{Capabilities, ConnectionMetadata, Environment};
use warden_core::dialect::Dialect;
use warden_core::explain::{PlanSummary, QueryPlan};
use warden_core::limits::ExecutionLimits;
use warden_core::query::QueryRequest;
use warden_core::result::{QueryStats, ResultColumn, ResultSet, ResultValue};
use warden_core::schema::{
    ColumnDescription, MatchReason, Schema, SchemaDescribeRequest, SchemaDescription, SchemaMatch,
    SchemaSearchRequest, SchemaSearchResult, Table, TableKind,
};
use warden_policy::{AnalyzedQuery, AuthorizedQuery, ObjectFilter, PolicyEngine, PolicySettings};
use warden_ports::{
    AnalyzeError, AuditAttempt, AuditError, AuditOutcomeEvent, AuditSink, ConnectionRegistry,
    ConnectionRuntime, ConnectionRuntimeParts, ExecuteError, ExplainError, Explainer,
    QueryAnalyzer, QueryExecutor, QueryPermit, SchemaError, SchemaInspector,
};
use warden_service::{RedactionSettings, ServiceParts, Services, StaticConnectionRegistry};

/// The connection every fixture registry holds.
pub(crate) const CONNECTION: &str = "production-db";

/// A second, always-healthy connection, for tests that need a surviving sibling.
pub(crate) const HEALTHY_CONNECTION: &str = "healthy-db";

/// The fixture connection's public metadata.
pub(crate) fn connection(dialect: Dialect) -> ConnectionMetadata {
    connection_named(CONNECTION, dialect)
}

/// The same metadata under another name, so one registry can hold two connections.
pub(crate) fn connection_named(name: &str, dialect: Dialect) -> ConnectionMetadata {
    ConnectionMetadata {
        name: name.parse().unwrap(),
        dialect,
        environment: Environment::Production,
        database: "app".to_owned(),
    }
}

/// An adapter that can do everything, schema search included.
pub(crate) fn capabilities() -> Capabilities {
    Capabilities {
        read_only_transactions: true,
        structured_explain: true,
        server_statement_timeout: true,
        schema_search: true,
    }
}

/// The baseline evidence: one safe `SELECT`, no risks, no objects.
fn analysis_parts(dialect: Dialect) -> QueryAnalysisParts {
    QueryAnalysisParts {
        dialect,
        statement_count: std::num::NonZeroUsize::MIN,
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

/// Evidence that policy denies, because it writes and nests a second write.
fn writing_analysis(dialect: Dialect) -> QueryAnalysis {
    QueryAnalysis::new(QueryAnalysisParts {
        root_kind: StatementKind::Insert,
        nested_kinds: vec![StatementKind::Delete],
        ..analysis_parts(dialect)
    })
}

/// A one-row normalized result.
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

/// A structured plan with an engine document.
pub(crate) fn plan() -> QueryPlan {
    QueryPlan {
        dialect: Dialect::MySql,
        summary: PlanSummary {
            estimated_rows: Some(1200),
        },
        plan: serde_json::json!({ "Node Type": "Seq Scan" }),
    }
}

/// A bounded search result naming one relation.
pub(crate) fn schema_search_result() -> SchemaSearchResult {
    SchemaSearchResult {
        matches: vec![SchemaMatch {
            schema: "app".to_owned(),
            table: "orders".to_owned(),
            kind: TableKind::Table,
            reason: MatchReason::ExactTable,
        }],
        truncated: false,
    }
}

/// A description of the one fixture relation.
pub(crate) fn schema_description() -> SchemaDescription {
    SchemaDescription {
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
                    comment: Some("public identifier".to_owned()),
                }],
                primary_key: vec!["id".to_owned()],
                foreign_keys: Vec::new(),
                indexes: Vec::new(),
                truncated: false,
            }],
        }],
    }
}

/// An analyzer with a fixed outcome.
#[derive(Debug)]
pub(crate) struct FakeAnalyzer {
    dialect: Dialect,
    writing: bool,
}

impl FakeAnalyzer {
    /// Creates an analyzer that returns safe read evidence.
    pub(crate) fn new(dialect: Dialect) -> Self {
        Self {
            dialect,
            writing: false,
        }
    }

    /// Creates an analyzer that returns write evidence, which policy denies.
    pub(crate) fn writing(dialect: Dialect) -> Self {
        Self {
            dialect,
            writing: true,
        }
    }
}

impl QueryAnalyzer for FakeAnalyzer {
    fn dialect(&self) -> Dialect {
        self.dialect
    }

    fn analyze(&self, request: QueryRequest) -> Result<AnalyzedQuery, AnalyzeError> {
        let analysis = if self.writing {
            writing_analysis(self.dialect)
        } else {
            QueryAnalysis::new(analysis_parts(self.dialect))
        };
        Ok(AnalyzedQuery::new(request, analysis))
    }
}

/// An executor with a fixed outcome and an observable call count.
#[derive(Debug)]
pub(crate) struct FakeExecutor {
    failure: Option<ExecuteError>,
    calls: AtomicUsize,
}

impl Default for FakeExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeExecutor {
    /// Creates an executor that returns the fixture result.
    pub(crate) fn new() -> Self {
        Self {
            failure: None,
            calls: AtomicUsize::new(0),
        }
    }

    /// Creates an executor that always fails with the given driver error.
    pub(crate) fn failing(error: ExecuteError) -> Self {
        Self {
            failure: Some(error),
            calls: AtomicUsize::new(0),
        }
    }

    /// The number of calls this executor received.
    pub(crate) fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
}

impl QueryExecutor for FakeExecutor {
    fn execute_read_only<'a>(
        &'a self,
        _query: &'a AuthorizedQuery,
        _permit: &'a QueryPermit,
        _deadline: Instant,
        _cancel: CancellationToken,
    ) -> warden_ports::BoxFuture<'a, Result<ResultSet, ExecuteError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::Relaxed);
            match &self.failure {
                Some(error) => Err(error.clone()),
                None => Ok(result_set()),
            }
        })
    }
}

/// An executor that panics where a driver bug would.
///
/// Decision 8: the panic has to cross a task boundary for the tool to answer at all,
/// so this is what proves the request really runs in its own task.
#[derive(Debug, Default)]
pub(crate) struct PanickingExecutor;

impl QueryExecutor for PanickingExecutor {
    fn execute_read_only<'a>(
        &'a self,
        _query: &'a AuthorizedQuery,
        _permit: &'a QueryPermit,
        _deadline: Instant,
        _cancel: CancellationToken,
    ) -> warden_ports::BoxFuture<'a, Result<ResultSet, ExecuteError>> {
        Box::pin(async move { panic!("a fake adapter panicked with hunter2 in its payload") })
    }
}

/// An explainer that returns the fixture plan.
#[derive(Debug, Default)]
pub(crate) struct FakeExplainer;

impl Explainer for FakeExplainer {
    fn explain<'a>(
        &'a self,
        _query: &'a AuthorizedQuery,
        _permit: &'a QueryPermit,
        _deadline: Instant,
        _cancel: CancellationToken,
    ) -> warden_ports::BoxFuture<'a, Result<QueryPlan, ExplainError>> {
        Box::pin(async move { Ok(plan()) })
    }
}

/// An inspector that returns the fixture catalog answers.
#[derive(Debug, Default)]
pub(crate) struct FakeInspector;

impl SchemaInspector for FakeInspector {
    fn search_schema<'a>(
        &'a self,
        _request: &'a SchemaSearchRequest,
        _filter: ObjectFilter<'a>,
        _deadline: Instant,
        _cancel: CancellationToken,
    ) -> warden_ports::BoxFuture<'a, Result<SchemaSearchResult, SchemaError>> {
        Box::pin(async move { Ok(schema_search_result()) })
    }

    fn describe_schema<'a>(
        &'a self,
        _request: &'a SchemaDescribeRequest,
        _filter: ObjectFilter<'a>,
        _deadline: Instant,
        _cancel: CancellationToken,
    ) -> warden_ports::BoxFuture<'a, Result<SchemaDescription, SchemaError>> {
        Box::pin(async move { Ok(schema_description()) })
    }
}

/// An audit sink that records both phases in memory.
#[derive(Debug, Default)]
pub(crate) struct FakeAuditSink {
    attempts: Mutex<Vec<AuditAttempt>>,
    outcomes: Mutex<Vec<AuditOutcomeEvent>>,
}

impl FakeAuditSink {
    /// Creates a sink that records both phases.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The attempts this sink recorded.
    pub(crate) fn attempts(&self) -> Vec<AuditAttempt> {
        self.attempts.lock().unwrap().clone()
    }

    /// The outcomes this sink recorded.
    pub(crate) fn outcomes(&self) -> Vec<AuditOutcomeEvent> {
        self.outcomes.lock().unwrap().clone()
    }
}

impl AuditSink for FakeAuditSink {
    fn record_attempt<'a>(
        &'a self,
        event: &'a AuditAttempt,
    ) -> warden_ports::BoxFuture<'a, Result<(), AuditError>> {
        Box::pin(async move {
            self.attempts.lock().unwrap().push(event.clone());
            Ok(())
        })
    }

    fn record_outcome<'a>(
        &'a self,
        event: &'a AuditOutcomeEvent,
    ) -> warden_ports::BoxFuture<'a, Result<(), AuditError>> {
        Box::pin(async move {
            self.outcomes.lock().unwrap().push(*event);
            Ok(())
        })
    }
}

/// Swappable fixtures for the one fixture connection's four ports.
///
/// One constructor per test scenario, so a test names the single collaborator it cares
/// about rather than assembling a runtime itself.
pub(crate) struct FakeParts {
    /// Metadata exposed by the runtime.
    pub(crate) metadata: ConnectionMetadata,
    /// Adapter capabilities.
    pub(crate) capabilities: Capabilities,
    /// Per-connection execution limits.
    pub(crate) limits: ExecutionLimits,
    /// The analyzer port.
    pub(crate) analyzer: Arc<dyn QueryAnalyzer>,
    /// The executor port.
    pub(crate) executor: Arc<dyn QueryExecutor>,
    /// The inspector port.
    pub(crate) inspector: Arc<dyn SchemaInspector>,
    /// The explainer port.
    pub(crate) explainer: Arc<dyn Explainer>,
}

impl Default for FakeParts {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeParts {
    /// Consistent defaults: one MySQL connection whose ports all succeed.
    pub(crate) fn new() -> Self {
        Self {
            metadata: connection(Dialect::MySql),
            capabilities: capabilities(),
            limits: ExecutionLimits::default(),
            analyzer: Arc::new(FakeAnalyzer::new(Dialect::MySql)),
            executor: Arc::new(FakeExecutor::new()),
            inspector: Arc::new(FakeInspector),
            explainer: Arc::new(FakeExplainer),
        }
    }

    /// Defaults, but the analyzer reports write evidence that policy denies.
    pub(crate) fn writing() -> Self {
        Self {
            analyzer: Arc::new(FakeAnalyzer::writing(Dialect::MySql)),
            ..Self::new()
        }
    }

    /// Defaults, but the executor fails with the given driver error.
    pub(crate) fn failing(error: ExecuteError) -> Self {
        Self {
            executor: Arc::new(FakeExecutor::failing(error)),
            ..Self::new()
        }
    }

    /// Defaults, but the executor panics.
    pub(crate) fn panicking() -> Self {
        Self {
            executor: Arc::new(PanickingExecutor),
            ..Self::new()
        }
    }
}

/// The services a tool test runs against: one MySQL connection, every port fake.
pub(crate) fn services() -> Arc<Services> {
    services_from(FakeParts::new())
}

/// The same services with exactly one port replaced.
pub(crate) fn services_from(parts: FakeParts) -> Arc<Services> {
    services_over(vec![parts])
}

/// Services whose [`CONNECTION`] panics and whose [`HEALTHY_CONNECTION`] does not.
///
/// Per-request containment is a property of *one* server: what it buys is that a call
/// whose adapter panicked leaves the server that made it able to answer the next call,
/// on this connection and on its siblings. A second, freshly built server would prove
/// only that the process survived, which returning from the first call already proves.
pub(crate) fn services_with_a_panicking_connection() -> Arc<Services> {
    let healthy = FakeParts {
        metadata: connection_named(HEALTHY_CONNECTION, Dialect::MySql),
        ..FakeParts::new()
    };
    services_over(vec![FakeParts::panicking(), healthy])
}

/// Builds the services over one registry holding every supplied connection.
fn services_over(connections: Vec<FakeParts>) -> Arc<Services> {
    let runtimes = connections
        .into_iter()
        .map(|parts| Arc::new(runtime_from(parts)))
        .collect();
    let registry: Arc<dyn ConnectionRegistry> =
        Arc::new(StaticConnectionRegistry::new(runtimes).unwrap());
    Arc::new(
        Services::new(ServiceParts {
            registry,
            engine: Arc::new(PolicyEngine::with_defaults(&PolicySettings::default()).unwrap()),
            audit: Arc::new(FakeAuditSink::new()),
            redaction: RedactionSettings::default(),
            shutdown: CancellationToken::new(),
        })
        .unwrap(),
    )
}

/// A runtime over one connection's four fake ports.
fn runtime_from(parts: FakeParts) -> ConnectionRuntime {
    ConnectionRuntime::new(ConnectionRuntimeParts {
        metadata: parts.metadata,
        capabilities: parts.capabilities,
        limits: parts.limits,
        analyzer: parts.analyzer,
        executor: parts.executor,
        inspector: parts.inspector,
        explainer: parts.explainer,
    })
    .unwrap()
}
