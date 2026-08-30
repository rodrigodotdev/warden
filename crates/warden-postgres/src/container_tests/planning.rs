//! What only a real PostgreSQL server can prove about planning a query.
//!
//! Every test starts its own container, exactly as the execution and inspection
//! tests do. Fixture DDL goes through one scoped `BEGIN READ WRITE` transaction on a
//! held `control_pool` connection; the session default stays read-only
//! (`docs/testing.md` section 4).
//!
//! The runtime here wires the **real** four ports rather than stubs: by Milestone 10
//! every one of them exists, and holding a genuine permit from a genuine
//! `ConnectionRuntime` proves the concurrency bound applies to planning too
//! (ADR-0032).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use sqlx::{AssertSqlSafe, Connection, Row};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use warden_core::analysis::{QueryAnalysis, QueryAnalysisParts, StatementKind};
use warden_core::connection::{Capabilities, ConnectionMetadata, Environment};
use warden_core::context::RequestContext;
use warden_core::dialect::Dialect;
use warden_core::error::{PublicError, PublicErrorCode};
use warden_core::limits::ExecutionLimits;
use warden_core::parameter::ParameterValue;
use warden_core::query::{InputLimits, QueryRequest};
use warden_policy::{AnalyzedQuery, AuthorizedQuery, PolicyEngine, PolicySettings};
use warden_ports::error::ExplainError;
use warden_ports::{ConnectionRuntime, ConnectionRuntimeParts, QueryAnalyzer, QueryPermit};

use super::{config, dsn, start_postgres};
use crate::analyzer::PostgreSqlAnalyzer;
use crate::connection::PostgreSqlConnectionPools;
use crate::execute::PostgreSqlQueryExecutor;
use crate::explain::PostgreSqlExplainer;
use crate::inspector::PostgreSqlSchemaInspector;
use crate::query::agent_query;

/// A statement that would take three seconds if anything ran it.
///
/// The analyzer rightly denies `pg_sleep` — it carries `RiskFlag::DelayFunction` —
/// so this fixture builds the authorization from synthetic evidence, which is what
/// lets a test reach the explainer with it at all. That is the point: if `EXPLAIN`
/// ever executed, this is the statement that would show it.
const SLEEPING: &str = "SELECT pg_sleep(3)";

/// A per-request deadline that differs from the pool's own, so a leaked
/// `SET LOCAL statement_timeout` would be visible rather than identical.
const REQUEST_TIMEOUT: Duration = Duration::from_millis(1500);

/// Applies fixture DDL through one scoped read-write transaction.
async fn mutate(pools: &PostgreSqlConnectionPools, statement: &str) {
    let mut connection = pools.control().acquire().await.unwrap();
    let mut transaction = connection.begin_with("BEGIN READ WRITE").await.unwrap();
    sqlx::query(AssertSqlSafe(statement.to_owned()))
        .execute(&mut *transaction)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
}

async fn fixture(pools: &PostgreSqlConnectionPools) {
    for statement in [
        "CREATE TABLE orders (id int PRIMARY KEY, customer_id text)",
        "CREATE INDEX idx_orders_customer ON orders (customer_id)",
        "INSERT INTO orders VALUES (1, 'c-1'), (2, 'c-2'), (3, 'c-1')",
    ] {
        mutate(pools, statement).await;
    }
}

/// An authorized statement, built from synthetic evidence.
fn authorized(sql: &str, parameters: Vec<ParameterValue>) -> AuthorizedQuery {
    let request = QueryRequest::new(
        "production-db".parse().unwrap(),
        sql.to_owned(),
        parameters,
        &InputLimits::default(),
    )
    .unwrap();
    let analysis = QueryAnalysis::new(QueryAnalysisParts {
        dialect: Dialect::PostgreSql,
        statement_count: NonZeroUsize::MIN,
        root_kind: StatementKind::Select,
        nested_kinds: Vec::new(),
        objects: Vec::new(),
        functions: Vec::new(),
        risks: Vec::new(),
        has_locking_clause: false,
        has_side_effects: false,
        fingerprint: None,
    });
    engine()
        .authorize(
            &context(),
            &metadata(),
            AnalyzedQuery::new(request, analysis),
            limits(),
        )
        .unwrap()
}

fn engine() -> PolicyEngine {
    PolicyEngine::with_defaults(&PolicySettings::default()).unwrap()
}

fn context() -> RequestContext {
    RequestContext::new(
        "req-1".parse().unwrap(),
        "alice@example.com".parse().unwrap(),
        "Claude Code".parse().unwrap(),
    )
}

fn metadata() -> ConnectionMetadata {
    ConnectionMetadata {
        name: "production-db".parse().unwrap(),
        dialect: Dialect::PostgreSql,
        environment: Environment::Development,
        database: "postgres".to_owned(),
    }
}

fn limits() -> ExecutionLimits {
    ExecutionLimits {
        timeout: REQUEST_TIMEOUT,
        ..ExecutionLimits::default()
    }
}

/// A runtime over the real four ports, so a test can hold a real permit.
fn runtime(pools: Arc<PostgreSqlConnectionPools>) -> ConnectionRuntime {
    ConnectionRuntime::new(ConnectionRuntimeParts {
        metadata: metadata(),
        capabilities: Capabilities {
            read_only_transactions: true,
            structured_explain: true,
            server_statement_timeout: true,
            schema_search: true,
        },
        limits: limits(),
        analyzer: Arc::new(PostgreSqlAnalyzer::new()),
        executor: Arc::new(PostgreSqlQueryExecutor::new(Arc::clone(&pools))),
        inspector: Arc::new(PostgreSqlSchemaInspector::new(
            Arc::clone(&pools),
            "production-db".parse().unwrap(),
        )),
        explainer: Arc::new(PostgreSqlExplainer::new(pools)),
    })
    .unwrap()
}

async fn permit(runtime: &ConnectionRuntime) -> QueryPermit {
    runtime
        .acquire_query_permit()
        .await
        .expect("a fresh connection has permits")
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

/// The root plan node of a document, or a failure naming the document.
fn root_node(plan: &serde_json::Value) -> &serde_json::Value {
    plan.get(0)
        .and_then(|element| element.get("Plan"))
        .unwrap_or_else(|| panic!("not a one-element array carrying a root node: {plan}"))
}

/// The count of statements `pg_prepared_statements` currently names on `pool`.
///
/// `pg_prepared_statements` is session-local, and this read must not add to what it
/// counts: `sqlx::query_scalar` defaults to `persistent(true)`, which would name and
/// register *this very query* before it runs, making the assertion fail even when
/// the code under test leaked nothing. `agent_query`'s non-persistent default is what
/// keeps the read from polluting its own measurement (`crate::query` module docs).
async fn named_prepared_statements(pool: &sqlx::PgPool) -> i64 {
    agent_query("SELECT count(*) FROM pg_prepared_statements")
        .fetch_one(pool)
        .await
        .map(|row| row.try_get::<i64, _>(0).unwrap())
        .unwrap()
}

#[tokio::test]
async fn a_bound_select_produces_a_structured_plan_with_a_row_estimate() {
    // PostgreSQL states one `Plan Rows` for the root node, so unlike MySQL the
    // summary is populated (`docs/data-model.md` section 10).
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    fixture(&pools).await;
    let runtime = runtime(Arc::clone(&pools));
    let permit = permit(&runtime).await;

    let query = authorized(
        "SELECT id FROM orders WHERE customer_id = $1",
        vec![ParameterValue::String("c-1".to_owned())],
    );
    let plan = runtime
        .explainer()
        .explain(&query, &permit, deadline(), CancellationToken::new())
        .await
        .expect("a bound select plans");

    assert_eq!(plan.dialect, Dialect::PostgreSql);
    assert!(
        root_node(&plan.plan).get("Node Type").is_some(),
        "the engine's own document is passed through unchanged: {}",
        plan.plan
    );
    assert!(
        plan.summary.estimated_rows.is_some(),
        "the root node's Plan Rows must reach the summary: {}",
        plan.plan
    );

    drop(permit);
    pools.close().await;
}

#[tokio::test]
async fn planning_never_runs_the_statement() {
    // The milestone's central claim, measured rather than asserted.
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    let runtime = runtime(Arc::clone(&pools));
    let permit = permit(&runtime).await;
    let query = authorized(SLEEPING, Vec::new());

    let started = std::time::Instant::now();
    let plan = runtime
        .explainer()
        .explain(&query, &permit, deadline(), CancellationToken::new())
        .await
        .expect("a sleeping statement still plans");
    let elapsed = started.elapsed();

    assert!(
        elapsed < Duration::from_secs(2),
        "planning took {elapsed:?}; pg_sleep(3) appears to have run"
    );

    // The direct server-side proof that no `ANALYZE` was sent: these keys exist only
    // in an executed plan (SPEC section 6, invariant 11; ADR-0017).
    let root = root_node(&plan.plan);
    for executed_only in ["Actual Rows", "Actual Total Time", "Actual Loops"] {
        assert!(
            root.get(executed_only).is_none(),
            "the plan carries {executed_only}, so ANALYZE ran: {}",
            plan.plan
        );
    }

    drop(permit);
    pools.close().await;
}

#[tokio::test]
async fn the_read_only_transaction_is_not_what_refuses_a_write() {
    // Measured against a real server and documented rather than hidden: planning an
    // INSERT succeeds inside BEGIN READ ONLY, because planning writes nothing. What
    // keeps a write out of `explain` is the policy engine authorizing only SELECT
    // roots (ADR-0020), and this test pins that the refusal happens there.
    let request = QueryRequest::new(
        "production-db".parse().unwrap(),
        "INSERT INTO orders VALUES (99, 'x')".to_owned(),
        Vec::new(),
        &InputLimits::default(),
    )
    .unwrap();
    let analyzed = PostgreSqlAnalyzer::new()
        .analyze(request)
        .expect("the statement parses");

    let rejection = engine()
        .authorize(&context(), &metadata(), analyzed, limits())
        .expect_err("a write is never authorized, for query or for explain");

    assert_eq!(rejection.public_code(), PublicErrorCode::QueryRejected);
}

#[tokio::test]
async fn a_plan_leaves_no_prepared_statement_and_no_session_state_behind() {
    // The two facts ADR-0025 and `docs/operations.md` section 4 care about: nothing
    // named survives on `agent_pool`, and the per-request `SET LOCAL
    // statement_timeout` did not escape its transaction. The request limit is
    // deliberately 1500 ms while the pool's own is the 5 s default, so a leak would
    // be a different value rather than the same one.
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    fixture(&pools).await;
    let runtime = runtime(Arc::clone(&pools));
    let permit = permit(&runtime).await;

    for n in 0..20_i64 {
        let query = authorized(
            "SELECT id FROM orders WHERE id = $1",
            vec![ParameterValue::I64(n)],
        );
        runtime
            .explainer()
            .explain(&query, &permit, deadline(), CancellationToken::new())
            .await
            .expect("each plan succeeds");
    }

    let named = named_prepared_statements(pools.agent()).await;
    assert_eq!(
        named, 0,
        "the plan path retained a named prepared statement"
    );

    // `pg_settings.setting` reports `statement_timeout` as plain milliseconds, which
    // is why the M6 test asserts `"5000"`. The pool's own value is the 5 s default
    // and the request's is 1500 ms, so a leak reads as `"1500"` here.
    let effective = super::setting(pools.agent(), "statement_timeout").await;
    assert_eq!(
        effective, "5000",
        "the per-request statement_timeout escaped its transaction"
    );

    drop(permit);
    pools.close().await;
}

#[tokio::test]
async fn a_custom_result_type_in_the_inner_statement_still_plans() {
    // The measurement `bind::plan_statement`'s doc comment rests on: a user-defined
    // enum in the projection does not make SQLx resolve custom result metadata,
    // because a plan's only output column is `json`. If this ever fails, the
    // executor's named-statement and `DEALLOCATE ALL` machinery becomes necessary
    // here too, and this test is where that is discovered.
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    for statement in [
        "CREATE TYPE order_state AS ENUM ('new', 'done')",
        "CREATE TABLE tickets (id int PRIMARY KEY, state order_state)",
        "INSERT INTO tickets VALUES (1, 'new')",
    ] {
        mutate(&pools, statement).await;
    }
    let runtime = runtime(Arc::clone(&pools));
    let permit = permit(&runtime).await;

    let query = authorized(
        "SELECT state FROM tickets WHERE id = $1",
        vec![ParameterValue::I64(1)],
    );
    runtime
        .explainer()
        .explain(&query, &permit, deadline(), CancellationToken::new())
        .await
        .expect("a custom result type still plans through an unnamed statement");

    let named = named_prepared_statements(pools.agent()).await;
    assert_eq!(named, 0);

    drop(permit);
    pools.close().await;
}

#[tokio::test]
async fn a_cancelled_token_stops_planning() {
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    let runtime = runtime(Arc::clone(&pools));
    let permit = permit(&runtime).await;
    let query = authorized("SELECT 1", Vec::new());

    let cancel = CancellationToken::new();
    cancel.cancel();
    let error = runtime
        .explainer()
        .explain(&query, &permit, deadline(), cancel)
        .await
        .expect_err("a cancelled request must not plan");

    assert_eq!(error, ExplainError::Cancelled);
    assert_eq!(error.public_code(), PublicErrorCode::QueryCancelled);

    drop(permit);
    pools.close().await;
}

#[tokio::test]
async fn an_elapsed_deadline_stops_planning() {
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    let runtime = runtime(Arc::clone(&pools));
    let permit = permit(&runtime).await;
    let query = authorized("SELECT 1", Vec::new());

    let error = runtime
        .explainer()
        .explain(
            &query,
            &permit,
            Instant::now() - Duration::from_millis(1),
            CancellationToken::new(),
        )
        .await
        .expect_err("an elapsed deadline must not plan");

    assert_eq!(error, ExplainError::Timeout);

    drop(permit);
    pools.close().await;
}

#[tokio::test]
async fn a_missing_relation_fails_without_naming_the_server() {
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    let runtime = runtime(Arc::clone(&pools));
    let permit = permit(&runtime).await;
    let query = authorized("SELECT id FROM absent_relation", Vec::new());

    let error = runtime
        .explainer()
        .explain(&query, &permit, deadline(), CancellationToken::new())
        .await
        .expect_err("a missing relation cannot be planned");

    assert!(matches!(error, ExplainError::Database { .. }), "{error:?}");
    assert_eq!(error.public_code(), PublicErrorCode::ExplainError);
    assert_eq!(error.to_string(), "a plan could not be produced");
    assert!(
        !error.to_string().contains("absent_relation"),
        "the public text repeats the driver's message"
    );

    drop(permit);
    pools.close().await;
}

#[tokio::test]
async fn the_connection_is_reusable_after_a_failed_plan() {
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    fixture(&pools).await;
    let runtime = runtime(Arc::clone(&pools));
    let permit = permit(&runtime).await;

    let failing = authorized("SELECT id FROM absent_relation", Vec::new());
    let _expected = runtime
        .explainer()
        .explain(&failing, &permit, deadline(), CancellationToken::new())
        .await
        .expect_err("the relation is missing");

    let working = authorized("SELECT id FROM orders", Vec::new());
    runtime
        .explainer()
        .explain(&working, &permit, deadline(), CancellationToken::new())
        .await
        .expect("the pool must still serve after a failed plan");

    drop(permit);
    pools.close().await;
}
