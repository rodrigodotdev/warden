//! What only a real MySQL server can prove about planning a query.
//!
//! Every test starts its own container, for the same reason the execution tests do.
//!
//! The runtime here wires the **real** four ports rather than stubs: by Milestone 10
//! every one of them exists, and a test that holds a genuine permit from a genuine
//! `ConnectionRuntime` proves the concurrency bound applies to planning too
//! (ADR-0032).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use sqlx::{AssertSqlSafe, Row};
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
use warden_ports::{ConnectionRuntime, ConnectionRuntimeParts, QueryPermit};

use super::{config, dsn, start_mysql, tls};
use crate::analyzer::MySqlAnalyzer;
use crate::connection::MySqlConnectionPools;
use crate::execute::MySqlQueryExecutor;
use crate::explain::MySqlExplainer;
use crate::inspector::MySqlSchemaInspector;

/// A statement that would take three seconds if anything ran it.
///
/// The analyzer rightly denies `SLEEP` — it carries `RiskFlag::DelayFunction` — so
/// this fixture builds the authorization from synthetic evidence, which is what lets
/// a test reach the explainer with it at all. That is the point: if `EXPLAIN` ever
/// executed, this is the statement that would show it.
const SLEEPING: &str = "SELECT SLEEP(3)";

async fn fixture(pools: &MySqlConnectionPools) {
    for statement in [
        "CREATE TABLE orders (id INT PRIMARY KEY, customer_id VARCHAR(64), KEY idx_customer (customer_id))",
        "INSERT INTO orders VALUES (1, 'c-1'), (2, 'c-2'), (3, 'c-1')",
    ] {
        sqlx::query(AssertSqlSafe(statement.to_owned()))
            .execute(pools.control())
            .await
            .expect("the fixture must apply");
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
        dialect: Dialect::MySql,
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
    PolicyEngine::with_defaults(&PolicySettings::default())
        .unwrap()
        .authorize(
            &context(),
            &metadata(),
            AnalyzedQuery::new(request, analysis),
            ExecutionLimits::default(),
        )
        .unwrap()
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
        dialect: Dialect::MySql,
        environment: Environment::Development,
        database: "test".to_owned(),
    }
}

/// A runtime over the real four ports, so a test can hold a real permit.
fn runtime(pools: Arc<MySqlConnectionPools>) -> ConnectionRuntime {
    ConnectionRuntime::new(ConnectionRuntimeParts {
        metadata: metadata(),
        capabilities: Capabilities {
            read_only_transactions: true,
            structured_explain: true,
            server_statement_timeout: true,
            schema_search: true,
        },
        limits: ExecutionLimits::default(),
        analyzer: Arc::new(MySqlAnalyzer::new()),
        executor: Arc::new(MySqlQueryExecutor::new(Arc::clone(&pools))),
        inspector: Arc::new(MySqlSchemaInspector::new(
            Arc::clone(&pools),
            "production-db".parse().unwrap(),
        )),
        explainer: Arc::new(MySqlExplainer::new(pools)),
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

#[tokio::test]
async fn a_bound_select_produces_a_structured_plan() {
    let container = start_mysql().await;
    let pools = Arc::new(
        MySqlConnectionPools::connect(config(dsn(&container).await, tls()))
            .await
            .unwrap(),
    );
    fixture(&pools).await;
    let runtime = runtime(Arc::clone(&pools));
    let permit = permit(&runtime).await;

    let query = authorized(
        "SELECT id FROM orders WHERE customer_id = ?",
        vec![ParameterValue::String("c-1".to_owned())],
    );
    let plan = runtime
        .explainer()
        .explain(&query, &permit, deadline(), CancellationToken::new())
        .await
        .expect("a bound select plans");

    assert_eq!(plan.dialect, Dialect::MySql);
    assert!(
        plan.plan.get("query_block").is_some(),
        "the engine's own document is passed through unchanged: {}",
        plan.plan
    );
    // MySQL states no document-level row estimate, and Warden does not invent one
    // (`docs/architecture.md` section 11).
    assert_eq!(plan.summary.estimated_rows, None);

    drop(permit);
    pools.close().await;
}

#[tokio::test]
async fn planning_never_runs_the_statement() {
    // The milestone's central claim, measured rather than asserted: if `EXPLAIN`
    // executed anything, three seconds of `SLEEP` would be visible here.
    let container = start_mysql().await;
    let pools = Arc::new(
        MySqlConnectionPools::connect(config(dsn(&container).await, tls()))
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
        "planning took {elapsed:?}; SLEEP(3) appears to have run"
    );
    // `EXPLAIN ANALYZE` answers in TREE text, not JSON, so a document with a
    // `query_block` is itself evidence that the non-executing form was sent.
    assert!(plan.plan.get("query_block").is_some(), "{}", plan.plan);

    drop(permit);
    pools.close().await;
}

#[tokio::test]
async fn a_plan_leaves_no_prepared_statement_behind() {
    // `agent_pool` runs with `statement_cache_capacity(0)`, and the plan path uses
    // the same bound-statement builder the executor uses. Twenty plans must not
    // accumulate anything on the server (`docs/operations.md` section 4).
    let container = start_mysql().await;
    let pools = Arc::new(
        MySqlConnectionPools::connect(config(dsn(&container).await, tls()))
            .await
            .unwrap(),
    );
    fixture(&pools).await;
    let runtime = runtime(Arc::clone(&pools));
    let permit = permit(&runtime).await;

    let mut observer = pools.control().acquire().await.unwrap();
    async fn prepared_statements(connection: &mut sqlx::MySqlConnection) -> i64 {
        let row = sqlx::query("SHOW GLOBAL STATUS LIKE 'Prepared_stmt_count'")
            .fetch_one(&mut *connection)
            .await
            .unwrap();
        let value: String = row.try_get(1).unwrap();
        value.parse().unwrap()
    }
    let before = prepared_statements(&mut observer).await;

    for n in 0..20_i64 {
        let query = authorized(
            "SELECT id FROM orders WHERE id = ?",
            vec![ParameterValue::I64(n)],
        );
        runtime
            .explainer()
            .explain(&query, &permit, deadline(), CancellationToken::new())
            .await
            .expect("each plan succeeds");
    }

    assert_eq!(
        prepared_statements(&mut observer).await,
        before,
        "the plan path retained prepared statements"
    );

    drop(observer);
    drop(permit);
    pools.close().await;
}

#[tokio::test]
async fn a_cancelled_token_stops_planning() {
    let container = start_mysql().await;
    let pools = Arc::new(
        MySqlConnectionPools::connect(config(dsn(&container).await, tls()))
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
    let container = start_mysql().await;
    let pools = Arc::new(
        MySqlConnectionPools::connect(config(dsn(&container).await, tls()))
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
    let container = start_mysql().await;
    let pools = Arc::new(
        MySqlConnectionPools::connect(config(dsn(&container).await, tls()))
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
    let container = start_mysql().await;
    let pools = Arc::new(
        MySqlConnectionPools::connect(config(dsn(&container).await, tls()))
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
