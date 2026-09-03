//! The MCP protocol, end to end, over an in-memory transport.
//!
//! rmcp's client is deliberately not used: every byte on the wire is under test, the same
//! choice `crates/warden-tracer/tests/mcp_stdio.rs` made for Milestone 0.5. What this
//! cannot cover is the composition root and a real database; `tests/mcp_database.rs` at the
//! workspace root does that with the real binary and real containers.
//!
//! # Fakes are built here, not imported
//!
//! `src/testing.rs` and `warden_ports::testing` are both `#[cfg(test)]`-gated, which an
//! integration test in `tests/` cannot see, and the milestone's global constraints forbid
//! reaching them through a Cargo feature instead — feature unification would expose the
//! fakes to every crate in the workspace (`docs/architecture.md` section 4.3). So this
//! file builds its own small set of port fakes, local to this test binary.
//! `warden-ports` and `warden-policy` are already dev-dependencies of this crate for
//! exactly this reason.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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
use warden_mcp::WardenServer;
use warden_policy::{AnalyzedQuery, AuthorizedQuery, ObjectFilter, PolicyEngine, PolicySettings};
use warden_ports::{
    AnalyzeError, AuditAttempt, AuditError, AuditOutcomeEvent, AuditSink, ConnectionRegistry,
    ConnectionRuntime, ConnectionRuntimeParts, ExecuteError, ExplainError, Explainer,
    QueryAnalyzer, QueryExecutor, QueryPermit, SchemaError, SchemaInspector,
};
use warden_service::{RedactionSettings, ServiceParts, Services, StaticConnectionRegistry};

// ---------------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------------

/// The one connection every test in this file calls against.
const CONNECTION: &str = "production-db";

/// The newest protocol version Warden implements (`server.rs`'s
/// `WARDEN_PROTOCOL_VERSIONS`), used by every test that does not care which one it gets.
const LATEST: &str = "2026-07-28";

fn connection_metadata() -> ConnectionMetadata {
    ConnectionMetadata {
        name: CONNECTION.parse().unwrap(),
        dialect: Dialect::MySql,
        environment: Environment::Production,
        database: "app".to_owned(),
    }
}

fn capabilities() -> Capabilities {
    Capabilities {
        read_only_transactions: true,
        structured_explain: true,
        server_statement_timeout: true,
        schema_search: true,
    }
}

fn result_set() -> ResultSet {
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
            bytes: 8,
            duration: Duration::from_millis(1),
        },
    }
}

fn plan() -> QueryPlan {
    QueryPlan {
        dialect: Dialect::MySql,
        summary: PlanSummary {
            estimated_rows: Some(1200),
        },
        plan: json!({ "query_block": { "select_id": 1 } }),
    }
}

fn schema_search_result() -> SchemaSearchResult {
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

fn schema_description() -> SchemaDescription {
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

/// Classifies a statement by keyword rather than by parsing it — this file has no
/// parser and needs none. `"SELECT..."` analyzes as safe read evidence the policy
/// engine allows; anything else analyzes as a `DELETE` the read-only-root policy
/// denies. That is enough to drive both the successful and the denied paths through
/// one fixed analyzer, exactly the way a real analyzer would decide from the text of
/// the two statements this file actually sends.
fn classify(sql: &str) -> StatementKind {
    if sql.trim_start().to_ascii_uppercase().starts_with("SELECT") {
        StatementKind::Select
    } else {
        StatementKind::Delete
    }
}

#[derive(Debug, Default)]
struct FakeAnalyzer;

impl QueryAnalyzer for FakeAnalyzer {
    fn dialect(&self) -> Dialect {
        Dialect::MySql
    }

    fn analyze(&self, request: QueryRequest) -> Result<AnalyzedQuery, AnalyzeError> {
        let root_kind = classify(request.sql());
        let analysis = QueryAnalysis::new(QueryAnalysisParts {
            dialect: Dialect::MySql,
            statement_count: NonZeroUsize::MIN,
            root_kind,
            nested_kinds: Vec::new(),
            objects: Vec::new(),
            functions: Vec::new(),
            risks: Vec::new(),
            has_locking_clause: false,
            has_side_effects: false,
            fingerprint: None,
        });
        Ok(AnalyzedQuery::new(request, analysis))
    }
}

#[derive(Debug, Default)]
struct FakeExecutor;

impl QueryExecutor for FakeExecutor {
    fn execute_read_only<'a>(
        &'a self,
        _query: &'a AuthorizedQuery,
        _permit: &'a QueryPermit,
        _deadline: Instant,
        _cancel: CancellationToken,
    ) -> warden_ports::BoxFuture<'a, Result<ResultSet, ExecuteError>> {
        Box::pin(async move { Ok(result_set()) })
    }
}

#[derive(Debug, Default)]
struct FakeExplainer;

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

#[derive(Debug, Default)]
struct FakeInspector;

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

/// An audit sink that records nothing. This file tests the wire, not the audit trail;
/// `Services::new` still requires one.
#[derive(Debug, Default)]
struct NullAuditSink;

impl AuditSink for NullAuditSink {
    fn record_attempt<'a>(
        &'a self,
        _event: &'a AuditAttempt,
    ) -> warden_ports::BoxFuture<'a, Result<(), AuditError>> {
        Box::pin(async move { Ok(()) })
    }

    fn record_outcome<'a>(
        &'a self,
        _event: &'a AuditOutcomeEvent,
    ) -> warden_ports::BoxFuture<'a, Result<(), AuditError>> {
        Box::pin(async move { Ok(()) })
    }
}

/// Builds a fresh set of services, wired to one connection whose four ports are the
/// fakes above. Every `exchange` call gets its own instance, so no test can observe
/// another test's state.
fn services() -> Arc<Services> {
    let runtime = ConnectionRuntime::new(ConnectionRuntimeParts {
        metadata: connection_metadata(),
        capabilities: capabilities(),
        limits: ExecutionLimits::default(),
        analyzer: Arc::new(FakeAnalyzer) as Arc<dyn QueryAnalyzer>,
        executor: Arc::new(FakeExecutor) as Arc<dyn QueryExecutor>,
        inspector: Arc::new(FakeInspector) as Arc<dyn SchemaInspector>,
        explainer: Arc::new(FakeExplainer) as Arc<dyn Explainer>,
    })
    .unwrap();
    let registry: Arc<dyn ConnectionRegistry> =
        Arc::new(StaticConnectionRegistry::new(vec![Arc::new(runtime)]).unwrap());
    Arc::new(
        Services::new(ServiceParts {
            registry,
            engine: Arc::new(PolicyEngine::with_defaults(&PolicySettings::default()).unwrap()),
            audit: Arc::new(NullAuditSink),
            redaction: RedactionSettings::default(),
            shutdown: CancellationToken::new(),
        })
        .unwrap(),
    )
}

// ---------------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------------

/// A process-wide counter so every request in this file gets its own JSON-RPC id, even
/// across concurrently running tests sharing the same test binary.
static NEXT_ID: AtomicI64 = AtomicI64::new(1);

fn next_id() -> i64 {
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

fn initialize(version: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": next_id(),
        "method": "initialize",
        "params": {
            "protocolVersion": version,
            "capabilities": {},
            "clientInfo": { "name": "warden-protocol-test", "version": "0.0.0" }
        }
    })
}

fn initialized() -> Value {
    json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })
}

fn list_tools() -> Value {
    json!({ "jsonrpc": "2.0", "id": next_id(), "method": "tools/list", "params": {} })
}

fn call(name: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": next_id(),
        "method": "tools/call",
        "params": { "name": name, "arguments": arguments }
    })
}

/// A session touching every response shape this file produces: every tool, a
/// successful `query`, and a denied one. Used by the test that scans the whole
/// transcript for a leak rather than one field.
///
/// Deliberately no `list_tools()`: every tool's JSON Schema carries a
/// `"$schema": "https://json-schema.org/..."` URI (see
/// `tests/snapshots/tools.json`), which would trip the `"://"` check below for a
/// reason that has nothing to do with a connection string leaking.
fn full_session() -> Vec<Value> {
    vec![
        initialize(LATEST),
        initialized(),
        call("list_connections", json!({})),
        call(
            "search_schema",
            json!({ "connection": CONNECTION, "query": "orders" }),
        ),
        call(
            "describe_schema",
            json!({ "connection": CONNECTION, "tables": ["app.orders"] }),
        ),
        call(
            "query",
            json!({ "connection": CONNECTION, "sql": "SELECT id FROM orders" }),
        ),
        call(
            "query",
            json!({ "connection": CONNECTION, "sql": "DELETE FROM orders" }),
        ),
        call(
            "explain",
            json!({ "connection": CONNECTION, "sql": "SELECT id FROM orders" }),
        ),
    ]
}

/// Spawns a server over one half of an in-memory duplex stream, writes every request
/// as its own line, and returns the response to every request that carried an `id`, in
/// the order those requests were sent — a notification (no `id`) contributes nothing to
/// the result, so `exchange(&[initialize(v), initialized(), list_tools()]).await[1]` is
/// the `tools/list` response, not `initialized`'s.
///
/// Every line read off the transport is asserted to parse as JSON with
/// `"jsonrpc": "2.0"` before anything else looks at it: the protocol-only invariant,
/// checked per line rather than on the transcript as a whole. Both the wait for
/// responses and the wait for the server to shut down are bounded, so a transport bug
/// fails this test instead of hanging the suite.
async fn exchange(requests: &[Value]) -> Vec<Value> {
    let (server_side, client_side) = tokio::io::duplex(1 << 20);
    let (read_half, mut write_half) = tokio::io::split(client_side);
    let shutdown = CancellationToken::new();
    let server = WardenServer::new(services());
    let serving = tokio::spawn(warden_mcp::serve_duplex(
        server,
        server_side,
        shutdown.clone(),
    ));

    let ids: Vec<Value> = requests
        .iter()
        .filter_map(|request| request.get("id").cloned())
        .collect();

    for request in requests {
        let mut line = serde_json::to_string(request).unwrap();
        line.push('\n');
        write_half.write_all(line.as_bytes()).await.unwrap();
    }
    write_half.flush().await.unwrap();

    let mut reader = BufReader::new(read_half);
    let mut responses: HashMap<String, Value> = HashMap::new();
    let read_all = async {
        let mut line = String::new();
        while responses.len() < ids.len() {
            line.clear();
            let bytes_read = reader
                .read_line(&mut line)
                .await
                .expect("reading a line from the in-memory transport");
            if bytes_read == 0 {
                panic!(
                    "transport closed after {} of {} responses",
                    responses.len(),
                    ids.len()
                );
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let value: Value = serde_json::from_str(trimmed).unwrap_or_else(|error| {
                panic!("a transport line did not parse as JSON ({error}): {trimmed:?}")
            });
            assert_eq!(
                value["jsonrpc"], "2.0",
                "a transport line was not JSON-RPC 2.0: {value}"
            );
            if let Some(id) = value.get("id") {
                responses.insert(id.to_string(), value);
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(5), read_all)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "received only {}/{} responses within five seconds",
                responses.len(),
                ids.len()
            )
        });

    drop(write_half);
    shutdown.cancel();
    // Only a panic (a lost task) is treated as a bug here. A refused `initialize`
    // legitimately ends `serve_duplex` with `Err(StdioError::Start(_))` even though the
    // JSON-RPC error response was already written to the wire and read above — `serve`
    // (`src/stdio.rs`) maps *any* handshake failure to `Start`, refusal included, so
    // that Result is not a second signal this helper needs to check.
    let _ = tokio::time::timeout(Duration::from_secs(5), serving)
        .await
        .expect("the server did not shut down within five seconds")
        .expect("the serving task panicked");

    ids.into_iter()
        .map(|id| {
            responses
                .remove(&id.to_string())
                .unwrap_or_else(|| panic!("no response ever arrived for request id {id}"))
        })
        .collect()
}

// ---------------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------------

#[tokio::test]
async fn initialization_reports_tools_and_echoes_the_requested_version() {
    for version in ["2025-11-25", "2026-07-28"] {
        let response = &exchange(&[initialize(version)]).await[0];
        assert!(response["error"].is_null(), "{response}");
        assert_eq!(response["result"]["protocolVersion"], version);
        assert!(
            !response["result"]["capabilities"]["tools"].is_null(),
            "{response}"
        );
        assert_eq!(response["result"]["serverInfo"]["name"], "warden");
    }
}

#[tokio::test]
async fn an_unimplemented_version_is_refused_with_the_supported_list() {
    // The behaviour ADR-0041 changed. Milestone 0.5 measured the SDK's silent
    // substitution; this test is what keeps it from coming back.
    let response = &exchange(&[initialize("2024-11-05")]).await[0];
    assert!(response["result"].is_null(), "{response}");
    assert_eq!(
        response["error"]["data"]["supported"],
        json!(["2025-11-25", "2026-07-28"])
    );
}

#[tokio::test]
async fn tool_discovery_returns_five_annotated_tools_with_output_schemas() {
    let response = &exchange(&[initialize(LATEST), initialized(), list_tools()]).await[1];
    let tools = response["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 5);
    for tool in tools {
        assert_eq!(tool["annotations"]["readOnlyHint"], json!(true), "{tool}");
        assert_eq!(
            tool["annotations"]["destructiveHint"],
            json!(false),
            "{tool}"
        );
        assert!(!tool["outputSchema"].is_null(), "{tool}");
        assert!(!tool["inputSchema"].is_null(), "{tool}");
    }
}

#[tokio::test]
async fn a_successful_call_carries_data_in_structured_content_and_counts_in_text() {
    // ADR-0040, on the wire: the rows are in structuredContent and the text block is a
    // summary. This is the assertion that would fail if someone switched a tool back to
    // rmcp's Json<T> wrapper for convenience.
    let response = &exchange(&[
        initialize(LATEST),
        initialized(),
        call(
            "query",
            json!({ "connection": "production-db", "sql": "SELECT id FROM orders" }),
        ),
    ])
    .await[1];
    let result = &response["result"];
    assert_eq!(result["isError"], json!(false));
    assert!(result["structuredContent"]["rows"].is_array(), "{result}");
    let text = result["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("row"), "{text}");
    assert!(
        !text.contains('['),
        "the text block repeats the rows: {text}"
    );
}

#[tokio::test]
async fn a_denied_statement_is_an_error_result_the_agent_can_read() {
    let response = &exchange(&[
        initialize(LATEST),
        initialized(),
        call(
            "query",
            json!({ "connection": "production-db", "sql": "DELETE FROM orders" }),
        ),
    ])
    .await[1];
    let result = &response["result"];
    assert_eq!(result["isError"], json!(true));
    assert_eq!(
        result["structuredContent"]["error"]["code"],
        json!("query_rejected")
    );
}

#[tokio::test]
async fn a_malformed_argument_is_a_protocol_error_and_not_a_silent_default() {
    // Not a top-level JSON-RPC `error`: rmcp 3.1.4's `into_tool_argument_error`
    // (`handler/server/router/tool.rs`) deliberately downgrades an INVALID_PARAMS
    // deserialization failure into an in-band `CallToolResult` with `isError: true`
    // instead of propagating it as a protocol error. Confirmed by reading that
    // function directly; the brief's own assumption of a protocol-level error does
    // not hold against the SDK actually vendored here. What this test can still pin
    // is the invariant the name is really about: a missing required field is refused
    // loudly, on whichever channel carries the refusal, rather than silently defaulted.
    let response = &exchange(&[
        initialize(LATEST),
        initialized(),
        call("query", json!({ "connection": "production-db" })),
    ])
    .await[1];
    assert!(response["error"].is_null(), "{response}");
    assert_eq!(response["result"]["isError"], json!(true), "{response}");
    let text = response["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("sql"), "{text}");
}

#[tokio::test]
async fn every_tool_answers_over_the_wire() {
    // docs/testing.md section 6 names all five by name, including the two whose MCP
    // coverage it explicitly defers to this milestone.
    let calls = vec![
        call("list_connections", json!({})),
        call(
            "search_schema",
            json!({ "connection": "production-db", "query": "orders" }),
        ),
        call(
            "describe_schema",
            json!({ "connection": "production-db", "tables": ["app.orders"] }),
        ),
        call(
            "query",
            json!({ "connection": "production-db", "sql": "SELECT id FROM orders" }),
        ),
        call(
            "explain",
            json!({ "connection": "production-db", "sql": "SELECT id FROM orders" }),
        ),
    ];
    let mut requests = vec![initialize(LATEST), initialized()];
    requests.extend(calls);
    let responses = exchange(&requests).await;
    // `responses[0]` answers `initialize`, not a tool call: it has no `result.isError`
    // at all, so checking every response uniformly would fail on that shape mismatch
    // rather than on anything this test is actually about. Skip it and check the five
    // tool-call responses that follow.
    for response in &responses[1..] {
        assert!(response["error"].is_null(), "{response}");
        assert_eq!(response["result"]["isError"], json!(false), "{response}");
    }
}

#[tokio::test]
async fn no_response_ever_carries_a_connection_string() {
    // SPEC section 6, invariant 20, asserted against the whole transcript rather than one
    // field, because a leak would arrive through whichever field nobody thought to check.
    let transcript = serde_json::to_string(&exchange(&full_session()).await).unwrap();
    for forbidden in ["://", "password", "dsn", "@localhost"] {
        assert!(!transcript.contains(forbidden), "{forbidden} in transcript");
    }
}
