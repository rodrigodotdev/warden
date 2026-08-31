//! Fakes and fixtures for this crate's tests.
//!
//! `warden-service` has no parser, no driver, and no database — M11's tests run
//! against fakes on purpose (`docs/milestones.md`, M11). They live in a
//! `#[cfg(test)]` module rather than behind a `testing` feature because Cargo
//! unifies features across a workspace build: a feature that exposed these to this
//! crate's tests would expose them to `warden-mcp` too
//! (`docs/architecture.md` section 4.3).

#![allow(clippy::unwrap_used, clippy::expect_used)]
// Helpers are shared by tests in several modules. One that the module you are
// editing happens not to use is not dead code.
#![allow(dead_code)]

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::time::{Instant, sleep, sleep_until};
use tokio_util::sync::CancellationToken;
use warden_core::analysis::{QueryAnalysis, QueryAnalysisParts, StatementKind};
use warden_core::connection::{Capabilities, ConnectionMetadata, Environment};
use warden_core::context::RequestContext;
use warden_core::dialect::Dialect;
use warden_core::explain::{PlanSummary, QueryPlan};
use warden_core::limits::ExecutionLimits;
use warden_core::query::{InputLimits, QueryRequest};
use warden_core::result::{QueryStats, ResultColumn, ResultSet, ResultValue};
use warden_core::schema::{
    SchemaDescribeRequest, SchemaDescription, SchemaSearchRequest, SchemaSearchResult,
};
use warden_policy::{
    AnalyzedQuery, AuthorizedQuery, DenyReason, ObjectFilter, PolicyEngine, PolicyRejection,
    PolicySettings,
};
use warden_ports::{
    AnalyzeError, AuditAttempt, AuditError, AuditEventId, AuditOutcomeEvent, AuditSink,
    ConnectionRegistry, ConnectionRuntime, ConnectionRuntimeParts, ExecuteError, ExplainError,
    Explainer, QueryAnalyzer, QueryExecutor, QueryPermit, SchemaError, SchemaInspector,
};

use crate::explain::ExplainService;
use crate::query::QueryService;
use crate::{RedactionSettings, Redactor, StaticConnectionRegistry};

/// The statement every fixture uses.
pub(crate) const SQL: &str = "SELECT id FROM orders";

/// A valid request against the fixture connection.
pub(crate) fn request() -> QueryRequest {
    request_for("production-db")
}

/// A valid request against the named fixture connection.
pub(crate) fn request_for(connection: &str) -> QueryRequest {
    QueryRequest::new(
        connection.parse().unwrap(),
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

/// A valid audit attempt with no policy denials.
pub(crate) fn attempt() -> AuditAttempt {
    AuditAttempt {
        id: AuditEventId::generate(),
        timestamp: time::OffsetDateTime::now_utc(),
        request_id: request_context().request_id().clone(),
        principal: request_context().principal().clone(),
        client: request_context().client().clone(),
        connection: connection(Dialect::MySql).name,
        dialect: Dialect::MySql,
        environment: Environment::Production,
        fingerprint: None,
        statement_kind: StatementKind::Select,
        deny_reasons: Vec::<DenyReason>::new(),
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

/// An adapter without schema search.
pub(crate) fn capabilities_without_search() -> Capabilities {
    Capabilities {
        schema_search: false,
        ..capabilities()
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

/// The baseline analysis.
pub(crate) fn analysis(dialect: Dialect) -> QueryAnalysis {
    QueryAnalysis::new(parts(dialect))
}

/// The baseline analysis tied to the fixture request.
pub(crate) fn analyzed(dialect: Dialect) -> AnalyzedQuery {
    AnalyzedQuery::new(request(), analysis(dialect))
}

/// Analysis that policy denies because it writes.
pub(crate) fn writing_analysis(dialect: Dialect) -> QueryAnalysis {
    QueryAnalysis::new(QueryAnalysisParts {
        root_kind: StatementKind::Insert,
        nested_kinds: vec![StatementKind::Delete],
        ..parts(dialect)
    })
}

/// The real default policy engine, behind the normal shared boundary.
pub(crate) fn engine() -> Arc<PolicyEngine> {
    Arc::new(PolicyEngine::with_defaults(&PolicySettings::default()).unwrap())
}

/// A default engine; write evidence makes it deny.
pub(crate) fn denying_engine() -> Arc<PolicyEngine> {
    engine()
}

/// A real policy rejection caused by the fixture's write evidence.
pub(crate) fn rejection() -> PolicyRejection {
    denying_engine()
        .authorize(
            &request_context(),
            &connection(Dialect::MySql),
            AnalyzedQuery::new(request(), writing_analysis(Dialect::MySql)),
            ExecutionLimits::default(),
        )
        .unwrap_err()
}

/// A real rejection whose audit-only detail names mismatched connections.
pub(crate) fn rejection_with_internal_detail() -> PolicyRejection {
    engine()
        .authorize(
            &request_context(),
            &connection(Dialect::MySql),
            AnalyzedQuery::new(request_for("staging-db"), analysis(Dialect::MySql)),
            ExecutionLimits::default(),
        )
        .unwrap_err()
}

/// A valid normalized result.
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

/// A normalized result containing one column that the query-service tests redact.
pub(crate) fn secret_result() -> ResultSet {
    let rows = vec![vec![
        ResultValue::I64(1),
        ResultValue::String("hunter2".to_owned()),
    ]];
    let bytes = rows
        .iter()
        .map(|row| warden_core::result::row_json_bytes(row))
        .sum();
    ResultSet {
        columns: vec![
            ResultColumn {
                name: "id".to_owned(),
                database_type: "BIGINT".to_owned(),
                nullable: Some(false),
            },
            ResultColumn {
                name: "password".to_owned(),
                database_type: "TEXT".to_owned(),
                nullable: Some(false),
            },
        ],
        rows,
        truncated: false,
        stats: QueryStats {
            rows_returned: 1,
            bytes,
            duration: Duration::from_millis(1),
        },
    }
}

/// A valid structured query plan.
pub(crate) fn plan() -> QueryPlan {
    QueryPlan {
        dialect: Dialect::MySql,
        summary: PlanSummary {
            estimated_rows: Some(1200),
        },
        plan: serde_json::json!({ "Node Type": "Seq Scan", "password": "hunter2" }),
    }
}

/// An analyzer with a fixed outcome.
#[derive(Debug)]
pub(crate) struct FakeAnalyzer {
    dialect: Dialect,
    outcome: AnalyzerOutcome,
}

#[derive(Debug, Clone)]
enum AnalyzerOutcome {
    Reading,
    Writing,
    Failing(AnalyzeError),
}

impl FakeAnalyzer {
    /// Creates an analyzer that returns safe read evidence.
    pub(crate) fn new(dialect: Dialect) -> Self {
        Self {
            dialect,
            outcome: AnalyzerOutcome::Reading,
        }
    }
    /// Creates an analyzer that returns write evidence.
    pub(crate) fn writing(dialect: Dialect) -> Self {
        Self {
            dialect,
            outcome: AnalyzerOutcome::Writing,
        }
    }
    /// Creates an analyzer that always fails.
    pub(crate) fn failing(error: AnalyzeError) -> Self {
        Self {
            dialect: Dialect::MySql,
            outcome: AnalyzerOutcome::Failing(error),
        }
    }
}

impl QueryAnalyzer for FakeAnalyzer {
    fn dialect(&self) -> Dialect {
        self.dialect
    }
    fn analyze(&self, request: QueryRequest) -> Result<AnalyzedQuery, AnalyzeError> {
        match &self.outcome {
            AnalyzerOutcome::Reading => Ok(AnalyzedQuery::new(request, analysis(self.dialect))),
            AnalyzerOutcome::Writing => {
                Ok(AnalyzedQuery::new(request, writing_analysis(self.dialect)))
            }
            AnalyzerOutcome::Failing(error) => Err(error.clone()),
        }
    }
}

/// An executor with a fixed delay or failure and observable call count.
#[derive(Debug)]
pub(crate) struct FakeExecutor {
    duration: Duration,
    failure: Option<ExecuteError>,
    result: ResultSet,
    calls: Arc<AtomicUsize>,
    observations: Mutex<Vec<(Instant, CancellationToken)>>,
    observed_limits: Mutex<Option<ExecutionLimits>>,
}

impl Default for FakeExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeExecutor {
    /// Creates an executor that immediately returns the fixture result.
    pub(crate) fn new() -> Self {
        Self {
            duration: Duration::ZERO,
            failure: None,
            result: result_set(),
            calls: Arc::new(AtomicUsize::new(0)),
            observations: Mutex::new(Vec::new()),
            observed_limits: Mutex::new(None),
        }
    }
    /// Creates an executor that takes the given duration.
    pub(crate) fn taking(duration: Duration) -> Self {
        Self {
            duration,
            ..Self::new()
        }
    }
    /// Creates an executor that always fails after its guard.
    pub(crate) fn failing(error: ExecuteError) -> Self {
        Self {
            failure: Some(error),
            ..Self::new()
        }
    }
    /// Creates an executor that returns the given normalized result.
    pub(crate) fn returning(result: ResultSet) -> Self {
        Self {
            result,
            ..Self::new()
        }
    }
    /// Creates an executor that exposes the authorized limits it receives.
    pub(crate) fn recording_limits() -> Self {
        Self::new()
    }
    /// Returns the number of calls made to the database port.
    pub(crate) fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
    /// Returns the deadline and cancellation token received by the latest call.
    pub(crate) fn latest_observation(&self) -> (Instant, CancellationToken) {
        self.observations.lock().unwrap().last().unwrap().clone()
    }
    /// Returns the limits carried by the latest authorized query.
    pub(crate) fn observed_limits(&self) -> Option<ExecutionLimits> {
        *self.observed_limits.lock().unwrap()
    }
}

impl QueryExecutor for FakeExecutor {
    fn execute_read_only<'a>(
        &'a self,
        query: &'a AuthorizedQuery,
        _permit: &'a QueryPermit,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> warden_ports::BoxFuture<'a, Result<ResultSet, ExecuteError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.observations
                .lock()
                .unwrap()
                .push((deadline, cancel.clone()));
            *self.observed_limits.lock().unwrap() = Some(query.limits());
            tokio::select! { () = sleep(self.duration) => {}, () = cancel.cancelled() => return Err(ExecuteError::Cancelled), () = sleep_until(deadline) => return Err(ExecuteError::Timeout) }
            match &self.failure {
                Some(error) => Err(error.clone()),
                None => Ok(self.result.clone()),
            }
        })
    }
}

/// An explainer with a fixed failure and observable call count.
#[derive(Debug)]
pub(crate) struct FakeExplainer {
    duration: Duration,
    failure: Option<ExplainError>,
    calls: Arc<AtomicUsize>,
    observations: Mutex<Vec<(Instant, CancellationToken)>>,
    observed_limits: Mutex<Option<ExecutionLimits>>,
}

impl Default for FakeExplainer {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeExplainer {
    /// Creates an explainer that immediately returns the fixture plan.
    pub(crate) fn new() -> Self {
        Self {
            duration: Duration::ZERO,
            failure: None,
            calls: Arc::new(AtomicUsize::new(0)),
            observations: Mutex::new(Vec::new()),
            observed_limits: Mutex::new(None),
        }
    }
    /// Creates an explainer that takes the given duration.
    pub(crate) fn taking(duration: Duration) -> Self {
        Self {
            duration,
            ..Self::new()
        }
    }
    /// Creates an explainer that always fails.
    pub(crate) fn failing(error: ExplainError) -> Self {
        Self {
            failure: Some(error),
            ..Self::new()
        }
    }
    /// Creates an explainer that exposes the authorized limits it receives.
    pub(crate) fn recording_limits() -> Self {
        Self::new()
    }
    /// Returns the number of calls made to the database port.
    pub(crate) fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }
    /// Returns the deadline and cancellation token received by the latest call.
    pub(crate) fn latest_observation(&self) -> (Instant, CancellationToken) {
        self.observations.lock().unwrap().last().unwrap().clone()
    }
    /// Returns the limits carried by the latest authorized query.
    pub(crate) fn observed_limits(&self) -> Option<ExecutionLimits> {
        *self.observed_limits.lock().unwrap()
    }
}

impl Explainer for FakeExplainer {
    fn explain<'a>(
        &'a self,
        query: &'a AuthorizedQuery,
        _permit: &'a QueryPermit,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> warden_ports::BoxFuture<'a, Result<QueryPlan, ExplainError>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.observations
                .lock()
                .unwrap()
                .push((deadline, cancel.clone()));
            *self.observed_limits.lock().unwrap() = Some(query.limits());
            tokio::select! { () = sleep(self.duration) => {}, () = cancel.cancelled() => return Err(ExplainError::Cancelled), () = sleep_until(deadline) => return Err(ExplainError::Timeout) }
            match &self.failure {
                Some(error) => Err(error.clone()),
                None => Ok(plan()),
            }
        })
    }
}

/// An inspector with a fixed rejection or failure.
#[derive(Debug, Default)]
pub(crate) struct FakeInspector {
    rejecting: bool,
    failure: Option<SchemaError>,
}

impl FakeInspector {
    /// Creates an inspector that returns empty valid schema answers.
    pub(crate) fn new() -> Self {
        Self::default()
    }
    /// Creates an inspector whose schema requests are rejected.
    pub(crate) fn rejecting() -> Self {
        Self {
            rejecting: true,
            failure: None,
        }
    }
    /// Creates an inspector that always fails.
    pub(crate) fn failing(error: SchemaError) -> Self {
        Self {
            rejecting: false,
            failure: Some(error),
        }
    }
    fn result(&self) -> Result<(), SchemaError> {
        if let Some(error) = &self.failure {
            return Err(error.clone());
        }
        if self.rejecting {
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
        _deadline: Instant,
        _cancel: CancellationToken,
    ) -> warden_ports::BoxFuture<'a, Result<SchemaSearchResult, SchemaError>> {
        Box::pin(async move {
            self.result()?;
            Ok(SchemaSearchResult {
                matches: Vec::new(),
                truncated: false,
            })
        })
    }
    fn describe_schema<'a>(
        &'a self,
        _request: &'a SchemaDescribeRequest,
        _filter: ObjectFilter<'a>,
        _deadline: Instant,
        _cancel: CancellationToken,
    ) -> warden_ports::BoxFuture<'a, Result<SchemaDescription, SchemaError>> {
        Box::pin(async move {
            self.result()?;
            Ok(SchemaDescription {
                schemas: Vec::new(),
            })
        })
    }
}

/// One event observed by [`FakeAuditSink`], preserving cross-phase order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FakeAuditEvent {
    /// An attempt write that succeeded.
    Attempt(AuditAttempt),
    /// An outcome write that was issued, including a write that then failed.
    Outcome(AuditOutcomeEvent),
}

#[derive(Debug, Default)]
struct FakeAuditRecords {
    attempts: Vec<AuditAttempt>,
    outcomes: Vec<AuditOutcomeEvent>,
    history: Vec<FakeAuditEvent>,
}

/// An audit sink that records each phase and can fail either one independently.
#[derive(Debug, Default)]
pub(crate) struct FakeAuditSink {
    records: Mutex<FakeAuditRecords>,
    broken_attempts: bool,
    broken_outcomes: bool,
    duration: Duration,
}

impl FakeAuditSink {
    /// Creates a sink that records both phases.
    pub(crate) fn new() -> Self {
        Self::default()
    }
    /// Creates a sink whose attempt writes fail.
    pub(crate) fn broken_attempts() -> Self {
        Self {
            broken_attempts: true,
            ..Self::default()
        }
    }
    /// Creates a sink whose outcome writes fail.
    pub(crate) fn broken_outcomes() -> Self {
        Self {
            broken_outcomes: true,
            ..Self::default()
        }
    }
    /// Creates a sink whose writes take the given duration.
    pub(crate) fn taking(duration: Duration) -> Self {
        Self {
            duration,
            ..Self::default()
        }
    }
    /// Returns recorded attempt events.
    pub(crate) fn attempts(&self) -> Vec<AuditAttempt> {
        self.records.lock().unwrap().attempts.clone()
    }
    /// Returns recorded outcome events.
    pub(crate) fn outcomes(&self) -> Vec<AuditOutcomeEvent> {
        self.records.lock().unwrap().outcomes.clone()
    }
    /// Returns every recorded phase in the order the sink observed it.
    pub(crate) fn history(&self) -> Vec<FakeAuditEvent> {
        self.records.lock().unwrap().history.clone()
    }
    fn failure() -> AuditError {
        AuditError::Unavailable {
            detail: "the fake sink is broken".to_owned(),
        }
    }
}

impl AuditSink for FakeAuditSink {
    fn record_attempt<'a>(
        &'a self,
        event: &'a AuditAttempt,
    ) -> warden_ports::BoxFuture<'a, Result<(), AuditError>> {
        Box::pin(async move {
            sleep(self.duration).await;
            if self.broken_attempts {
                return Err(Self::failure());
            }
            let mut records = self.records.lock().unwrap();
            records.attempts.push(event.clone());
            records.history.push(FakeAuditEvent::Attempt(event.clone()));
            Ok(())
        })
    }
    fn record_outcome<'a>(
        &'a self,
        event: &'a AuditOutcomeEvent,
    ) -> warden_ports::BoxFuture<'a, Result<(), AuditError>> {
        Box::pin(async move {
            sleep(self.duration).await;
            let mut records = self.records.lock().unwrap();
            records.outcomes.push(*event);
            records.history.push(FakeAuditEvent::Outcome(*event));
            drop(records);
            if self.broken_outcomes {
                return Err(Self::failure());
            }
            Ok(())
        })
    }
}

/// Swappable fixtures for a runtime's four ports.
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

impl FakeParts {
    /// Creates consistent default parts for a dialect.
    pub(crate) fn new(dialect: Dialect) -> Self {
        Self {
            metadata: connection(dialect),
            capabilities: capabilities(),
            limits: ExecutionLimits::default(),
            analyzer: Arc::new(FakeAnalyzer::new(dialect)),
            executor: Arc::new(FakeExecutor::new()),
            inspector: Arc::new(FakeInspector::new()),
            explainer: Arc::new(FakeExplainer::new()),
        }
    }
}

/// A runtime whose analyzer matches the connection dialect.
pub(crate) fn runtime(dialect: Dialect) -> ConnectionRuntime {
    runtime_from(FakeParts::new(dialect))
}

/// A runtime whose executor is observable by the caller.
pub(crate) fn runtime_with_executor(
    dialect: Dialect,
    executor: Arc<FakeExecutor>,
) -> ConnectionRuntime {
    let mut parts = FakeParts::new(dialect);
    parts.executor = executor;
    runtime_from(parts)
}

/// A runtime whose explainer is observable by the caller.
pub(crate) fn runtime_with_explainer(
    dialect: Dialect,
    explainer: Arc<FakeExplainer>,
) -> ConnectionRuntime {
    let mut parts = FakeParts::new(dialect);
    parts.explainer = explainer;
    runtime_from(parts)
}

/// A runtime with explicit execution limits.
pub(crate) fn runtime_with_limits(dialect: Dialect, limits: ExecutionLimits) -> ConnectionRuntime {
    let mut parts = FakeParts::new(dialect);
    parts.limits = limits;
    runtime_from(parts)
}

/// Authorizes the fixture statement against this runtime's own metadata and limits.
pub(crate) fn authorized(runtime: &ConnectionRuntime) -> AuthorizedQuery {
    engine()
        .authorize(
            &request_context(),
            runtime.metadata(),
            analyzed(runtime.metadata().dialect),
            runtime.limits(),
        )
        .unwrap()
}

/// A runtime built from port fixtures, allowing a test to replace exactly one port.
pub(crate) fn runtime_from(parts: FakeParts) -> ConnectionRuntime {
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

/// A registry holding the one MySQL fixture connection.
pub(crate) fn registry() -> StaticConnectionRegistry {
    StaticConnectionRegistry::new(vec![Arc::new(runtime(Dialect::MySql))]).unwrap()
}

/// Builds a parsed redactor for service tests.
pub(crate) fn redactor(columns: &[&str]) -> Arc<Redactor> {
    Arc::new(
        Redactor::new(&RedactionSettings {
            columns: columns.iter().map(|column| (*column).to_owned()).collect(),
            ..RedactionSettings::default()
        })
        .unwrap(),
    )
}

/// Swappable fixtures for query and explain services.
pub(crate) struct ServiceFakes {
    /// Per-connection execution limits.
    pub(crate) limits: ExecutionLimits,
    /// The analyzer port.
    pub(crate) analyzer: Arc<dyn QueryAnalyzer>,
    /// The executor port.
    pub(crate) executor: Arc<dyn QueryExecutor>,
    /// The explainer port.
    pub(crate) explainer: Arc<dyn Explainer>,
    /// The two-phase audit port.
    pub(crate) audit: Arc<dyn AuditSink>,
    /// Response redaction rules.
    pub(crate) redactor: Arc<Redactor>,
    /// Root shutdown signal.
    pub(crate) shutdown: CancellationToken,
}

impl Default for ServiceFakes {
    fn default() -> Self {
        Self {
            limits: ExecutionLimits::default(),
            analyzer: Arc::new(FakeAnalyzer::new(Dialect::MySql)),
            executor: Arc::new(FakeExecutor::new()),
            explainer: Arc::new(FakeExplainer::new()),
            audit: Arc::new(FakeAuditSink::new()),
            redactor: redactor(&[]),
            shutdown: CancellationToken::new(),
        }
    }
}

/// Builds one query service whose tests can replace one collaborator at a time.
pub(crate) fn query_service(fakes: ServiceFakes) -> QueryService {
    let mut parts = FakeParts::new(Dialect::MySql);
    parts.limits = fakes.limits;
    parts.analyzer = fakes.analyzer;
    parts.executor = fakes.executor;
    parts.explainer = fakes.explainer;
    let runtime = Arc::new(runtime_from(parts));
    let registry: Arc<dyn ConnectionRegistry> =
        Arc::new(StaticConnectionRegistry::new(vec![runtime]).unwrap());
    QueryService::new(
        registry,
        engine(),
        fakes.audit,
        fakes.redactor,
        fakes.shutdown,
    )
}

/// Builds one explain service whose tests can replace one collaborator at a time.
pub(crate) fn explain_service(fakes: ServiceFakes) -> ExplainService {
    let mut parts = FakeParts::new(Dialect::MySql);
    parts.limits = fakes.limits;
    parts.analyzer = fakes.analyzer;
    parts.executor = fakes.executor;
    parts.explainer = fakes.explainer;
    let runtime = Arc::new(runtime_from(parts));
    let registry: Arc<dyn ConnectionRegistry> =
        Arc::new(StaticConnectionRegistry::new(vec![runtime]).unwrap());
    ExplainService::new(
        registry,
        engine(),
        fakes.audit,
        fakes.redactor,
        fakes.shutdown,
    )
}

/// Builds a query service whose only connection has no free query slot.
pub(crate) async fn saturated_query_service() -> (QueryService, Arc<FakeAuditSink>, QueryPermit) {
    let limits = ExecutionLimits {
        max_concurrent_queries: 1,
        ..ExecutionLimits::default()
    };
    let mut parts = FakeParts::new(Dialect::MySql);
    parts.limits = limits;
    let runtime = Arc::new(runtime_from(parts));
    let held = runtime.acquire_query_permit().await.unwrap();
    let registry: Arc<dyn ConnectionRegistry> =
        Arc::new(StaticConnectionRegistry::new(vec![runtime]).unwrap());
    let sink = Arc::new(FakeAuditSink::new());
    let service = QueryService::new(
        registry,
        engine(),
        Arc::clone(&sink) as Arc<dyn AuditSink>,
        redactor(&[]),
        CancellationToken::new(),
    );
    (service, sink, held)
}

/// Builds an explain service whose only connection has no free query slot.
pub(crate) async fn saturated_explain_service() -> (ExplainService, Arc<FakeAuditSink>, QueryPermit)
{
    let limits = ExecutionLimits {
        max_concurrent_queries: 1,
        ..ExecutionLimits::default()
    };
    let mut parts = FakeParts::new(Dialect::MySql);
    parts.limits = limits;
    let runtime = Arc::new(runtime_from(parts));
    let held = runtime.acquire_query_permit().await.unwrap();
    let registry: Arc<dyn ConnectionRegistry> =
        Arc::new(StaticConnectionRegistry::new(vec![runtime]).unwrap());
    let sink = Arc::new(FakeAuditSink::new());
    let service = ExplainService::new(
        registry,
        engine(),
        Arc::clone(&sink) as Arc<dyn AuditSink>,
        redactor(&[]),
        CancellationToken::new(),
    );
    (service, sink, held)
}
