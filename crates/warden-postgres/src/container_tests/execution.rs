//! What only a real PostgreSQL server can prove about executing a query.
//!
//! Every test starts its own container, exactly as the connection tests do: a test
//! that saturates a pool, exhausts a budget, or cancels a backend must not be able
//! to change another test's result.
//!
//! PostgreSQL's protocol has no row-level flow control — sqlx executes the portal
//! with `limit: 0` — so stopping early leaves rows in flight exactly as MySQL does,
//! and the executor issues a real `pg_cancel_backend` whenever it stops reading a
//! stream the server may still be writing. Task 4's tests prove that directly;
//! this file proves the query path itself: the read-only transaction, the
//! reinforcement inside it, the binding, the type table, and every way a value can
//! fail safely.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use sqlx::{AssertSqlSafe, Connection};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use warden_core::analysis::{QueryAnalysis, QueryAnalysisParts, StatementKind};
use warden_core::connection::{Capabilities, ConnectionMetadata, Environment};
use warden_core::context::RequestContext;
use warden_core::dialect::Dialect;
use warden_core::error::{PublicError, PublicErrorCode};
use warden_core::limits::ExecutionLimits;
use warden_core::parameter::ParameterValue;
use warden_core::pool::PoolSettings;
use warden_core::query::{InputLimits, QueryRequest};
use warden_core::result::{ResultSet, ResultValue};
use warden_policy::{AnalyzedQuery, AuthorizedQuery, PolicyEngine, PolicySettings};
use warden_ports::error::ExecuteError;
use warden_ports::{
    ConnectionRuntime, ConnectionRuntimeParts, QueryAnalyzer, QueryExecutor, QueryPermit,
};

use super::{config, dsn, setting, start_postgres};
use crate::analyzer::PostgreSqlAnalyzer;
use crate::connection::PostgreSqlConnectionPools;
use crate::execute::PostgreSqlQueryExecutor;
use crate::query::agent_query;

/// An authorized statement, built from synthetic evidence.
///
/// The evidence is synthetic on purpose. This file tests the **executor**, not the
/// analyzer, so most tests build an `AuthorizedQuery` directly rather than routing
/// SQL through `PostgreSqlAnalyzer` and `PolicyEngine` first. Two kinds of statement
/// need it: ones the real analyzer would rightly deny — `pg_sleep` carries
/// `RiskFlag::DelayFunction` and `nextval` carries sequence mutation, and building
/// them synthetically is what lets a test reach the *database's* refusal rather
/// than stopping at Warden's — and ones that would be authorized anyway but whose
/// test should not depend on the analyzer to say so. One test below goes through
/// `PostgreSqlAnalyzer` as well, so the real path is covered where it is the thing
/// under test.
fn authorized(
    sql: &str,
    parameters: Vec<ParameterValue>,
    limits: ExecutionLimits,
) -> AuthorizedQuery {
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
            limits,
        )
        .unwrap()
}

/// A runtime wrapping the executor, so a test can hold a real permit.
///
/// The inspector and the explainer are stubs that answer with an error: Milestones 9
/// and 10 own them, and `ConnectionRuntime::new` needs all four ports.
fn runtime(executor: Arc<PostgreSqlQueryExecutor>, limits: ExecutionLimits) -> ConnectionRuntime {
    ConnectionRuntime::new(ConnectionRuntimeParts {
        metadata: metadata(),
        capabilities: Capabilities {
            read_only_transactions: true,
            structured_explain: true,
            server_statement_timeout: true,
            schema_search: false,
        },
        limits,
        analyzer: Arc::new(PostgreSqlAnalyzer::new()),
        executor,
        inspector: Arc::new(stub::Inspector),
        explainer: Arc::new(stub::Planner),
    })
    .unwrap()
}

/// The default engine every deployment uses.
fn engine() -> PolicyEngine {
    PolicyEngine::with_defaults(&PolicySettings::default()).unwrap()
}

/// A fixed request identity.
fn context() -> RequestContext {
    RequestContext::new(
        "req-1".parse().unwrap(),
        "alice@example.com".parse().unwrap(),
        "Claude Code".parse().unwrap(),
    )
}

/// The connection every fixture targets.
///
/// The name matches the `QueryRequest` `authorized` builds, because
/// `PolicyEngine::authorize` compares the two and denies a mismatch.
fn metadata() -> ConnectionMetadata {
    ConnectionMetadata {
        name: "production-db".parse().unwrap(),
        dialect: Dialect::PostgreSql,
        environment: Environment::Development,
        database: "postgres".to_owned(),
    }
}

/// A generous client deadline, for the tests that are not about deadlines.
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(20)
}

/// Runs one authorized query to completion under the generous default deadline.
///
/// A shared helper because most tests below only care about the outcome, not about
/// threading a deadline and a fresh `CancellationToken` through every call site; the
/// tests that actually exercise a deadline or a cancellation call
/// `execute_read_only` directly instead.
async fn run(
    executor: &PostgreSqlQueryExecutor,
    permit: &QueryPermit,
    query: &AuthorizedQuery,
) -> Result<ResultSet, ExecuteError> {
    executor
        .execute_read_only(query, permit, deadline(), CancellationToken::new())
        .await
}

/// Everything the execution tests read, created through `control_pool`.
///
/// `control_pool` because this is Warden's own static SQL and `agent_pool`'s
/// read-only transaction would refuse the DDL anyway. `BEGIN READ WRITE` scopes
/// fixture writes to this transaction: unlike a session-level `SET`, it cannot relax
/// the hardened control connection after the fixture returns. Every column in
/// `docs/data-model.md` section 8.2's PostgreSQL list appears exactly once, so one
/// test can prove the whole table against a real server, and every nullable column
/// is NULL in the second row so another can prove that NULL survives whatever the
/// declared type is.
async fn fixture(pools: &PostgreSqlConnectionPools) {
    let mut connection = pools.control().acquire().await.unwrap();
    let mut transaction = connection.begin_with("BEGIN READ WRITE").await.unwrap();

    for statement in [
        "CREATE TYPE order_state AS ENUM ('new', 'paid')",
        "CREATE SEQUENCE sample_ids",
        "CREATE TABLE samples (
             id           bigint PRIMARY KEY,
             small        smallint,
             medium       integer,
             name         text,
             label        varchar(32),
             price        numeric(12,4),
             ratio        real,
             weight       double precision,
             flag         boolean,
             payload      jsonb,
             doc          json,
             identifier   uuid,
             created_on   date,
             created_at   timestamp,
             recorded_at  timestamptz,
             duration     time,
             blob_value   bytea,
             tags         text[],
             counts       integer[],
             amounts      numeric[],
             identifiers  uuid[],
             state        order_state
         )",
        "INSERT INTO samples VALUES (
             1, 7, 9, 'first', 'labelled', 10.5000, 2.5, 1.25, true,
             '{\"k\":1}'::jsonb, '{\"k\":2}'::json,
             '2f8a1d5e-1c4b-4a3e-9f60-0d2b7c5e4a91'::uuid,
             '2026-01-05', '2026-01-05 09:07:03', '2026-01-05 09:07:03+00',
             '01:02:03', '\\x000102'::bytea,
             ARRAY['a','b'], ARRAY[1,2,3], ARRAY[1.50, 2.25]::numeric[],
             ARRAY['2f8a1d5e-1c4b-4a3e-9f60-0d2b7c5e4a91'::uuid], 'new'
         )",
        "INSERT INTO samples (id) VALUES (2)",
    ] {
        sqlx::query(AssertSqlSafe(statement.to_owned()))
            .execute(&mut *transaction)
            .await
            .unwrap();
    }
    transaction.commit().await.unwrap();
}

#[tokio::test]
async fn fixture_keeps_the_control_pool_read_only() {
    let container = start_postgres().await;
    let mut connection_config = config(dsn(&container).await);
    connection_config.control_pool.max_connections = 1;
    let pools = PostgreSqlConnectionPools::connect(connection_config)
        .await
        .unwrap();

    fixture(&pools).await;

    assert_eq!(
        setting(pools.control(), "default_transaction_read_only").await,
        "on"
    );

    pools.close().await;
}

/// The two ports Milestones 9 and 10 own.
///
/// `ConnectionRuntime::new` needs all four, and these answer with an error rather
/// than panicking: `unimplemented!` is denied workspace-wide, and a panic in a stub
/// would read as a failure of the code under test.
mod stub {
    use tokio::time::Instant;
    use tokio_util::sync::CancellationToken;
    use warden_core::explain::QueryPlan;
    use warden_core::schema::{
        SchemaDescribeRequest, SchemaDescription, SchemaSearchRequest, SchemaSearchResult,
    };
    use warden_policy::AuthorizedQuery;
    use warden_ports::error::{ExplainError, SchemaError};
    use warden_ports::{BoxFuture, Explainer, QueryPermit, SchemaInspector};

    /// Answers every schema lookup with a timeout.
    #[derive(Debug)]
    pub(super) struct Inspector;

    impl SchemaInspector for Inspector {
        fn search_schema<'a>(
            &'a self,
            _request: &'a SchemaSearchRequest,
            _deadline: Instant,
            _cancel: CancellationToken,
        ) -> BoxFuture<'a, Result<SchemaSearchResult, SchemaError>> {
            Box::pin(async { Err(SchemaError::Timeout) })
        }

        fn describe_schema<'a>(
            &'a self,
            _request: &'a SchemaDescribeRequest,
            _deadline: Instant,
            _cancel: CancellationToken,
        ) -> BoxFuture<'a, Result<SchemaDescription, SchemaError>> {
            Box::pin(async { Err(SchemaError::Timeout) })
        }
    }

    /// Answers every plan request with a timeout. Named `Planner` so the type and
    /// the trait it implements do not share a name.
    #[derive(Debug)]
    pub(super) struct Planner;

    impl Explainer for Planner {
        fn explain<'a>(
            &'a self,
            _query: &'a AuthorizedQuery,
            _permit: &'a QueryPermit,
            _deadline: Instant,
            _cancel: CancellationToken,
        ) -> BoxFuture<'a, Result<QueryPlan, ExplainError>> {
            Box::pin(async { Err(ExplainError::Timeout) })
        }
    }
}

/// Opens the pools, creates the fixture, and hands back everything a test needs.
///
/// Returned rather than inlined because every test below repeats the same five
/// lines, and a helper that also holds the `ConnectionRuntime` alive is what keeps
/// the permit valid for the length of the test.
async fn harness(
    pools: Arc<PostgreSqlConnectionPools>,
    limits: ExecutionLimits,
) -> (Arc<PostgreSqlQueryExecutor>, ConnectionRuntime) {
    let executor = Arc::new(PostgreSqlQueryExecutor::new(Arc::clone(&pools)));
    let runtime = runtime(Arc::clone(&executor), limits);
    (executor, runtime)
}

#[tokio::test]
async fn a_bound_select_returns_normalized_rows() {
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    fixture(&pools).await;
    let (executor, runtime) = harness(Arc::clone(&pools), ExecutionLimits::default()).await;
    let permit = runtime.acquire_query_permit().await.unwrap();

    let query = authorized(
        "SELECT id, name, price, flag FROM samples WHERE name = $1",
        vec![ParameterValue::String("first".to_owned())],
        ExecutionLimits::default(),
    );
    let result = run(&executor, &permit, &query).await.unwrap();

    assert_eq!(result.rows.len(), 1);
    assert!(!result.truncated);
    assert_eq!(result.stats.rows_returned, 1);
    assert_eq!(
        result.rows[0],
        vec![
            ResultValue::I64(1),
            ResultValue::String("first".to_owned()),
            // The scale the column declares, preserved exactly: `to_plain_string`
            // rather than `Display`, and text rather than `f64`
            // (`docs/data-model.md` section 8.1, rule 1).
            ResultValue::Decimal("10.5000".to_owned()),
            ResultValue::Bool(true),
        ]
    );
    assert_eq!(result.columns[0].database_type, "INT8");
    assert_eq!(result.columns[2].database_type, "NUMERIC");
    // Neither driver reports nullability through a row, and nothing is invented.
    assert!(
        result
            .columns
            .iter()
            .all(|column| column.nullable.is_none())
    );

    pools.close().await;
}

#[tokio::test]
async fn every_documented_type_round_trips_through_a_real_server() {
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    fixture(&pools).await;
    let (executor, runtime) = harness(Arc::clone(&pools), ExecutionLimits::default()).await;
    let permit = runtime.acquire_query_permit().await.unwrap();

    let query = authorized(
        "SELECT small, medium, label, ratio, weight, payload, doc, identifier, created_on, created_at, recorded_at, duration, blob_value, tags, counts, amounts, identifiers FROM samples WHERE id = 1",
        Vec::new(),
        ExecutionLimits::default(),
    );
    let result = run(&executor, &permit, &query).await.unwrap();
    let row = &result.rows[0];
    let uuid = "2f8a1d5e-1c4b-4a3e-9f60-0d2b7c5e4a91";

    assert_eq!(row[0], ResultValue::I64(7), "int2 widens to i64");
    assert_eq!(row[1], ResultValue::I64(9), "int4 widens to i64");
    assert_eq!(row[2], ResultValue::String("labelled".to_owned()));
    // `float4` is decoded as `f32` and widened; reading its four bytes as an `f64`
    // would have produced a wrong number rather than an error.
    assert_eq!(row[3], ResultValue::F64(2.5));
    assert_eq!(row[4], ResultValue::F64(1.25));
    assert_eq!(row[5], ResultValue::Json(serde_json::json!({"k": 1})));
    assert_eq!(row[6], ResultValue::Json(serde_json::json!({"k": 2})));
    assert_eq!(row[7], ResultValue::Uuid(uuid.to_owned()));
    assert_eq!(row[8], ResultValue::Date("2026-01-05".to_owned()));
    // A `timestamp` states no offset because it has none; a `timestamptz` states
    // `+00:00` because PostgreSQL stores it in UTC and the offset is therefore known
    // rather than invented (`docs/architecture.md` section 11).
    assert_eq!(
        row[9],
        ResultValue::DateTime("2026-01-05 09:07:03".to_owned())
    );
    assert_eq!(
        row[10],
        ResultValue::DateTime("2026-01-05 09:07:03+00:00".to_owned())
    );
    assert_eq!(row[11], ResultValue::Time("01:02:03".to_owned()));
    assert_eq!(row[12], ResultValue::BytesBase64("AAEC".to_owned()));
    assert_eq!(
        row[13],
        ResultValue::array(vec![
            ResultValue::String("a".to_owned()),
            ResultValue::String("b".to_owned()),
        ])
        .unwrap()
    );
    assert_eq!(
        row[14],
        ResultValue::array(vec![
            ResultValue::I64(1),
            ResultValue::I64(2),
            ResultValue::I64(3),
        ])
        .unwrap()
    );
    assert_eq!(
        row[15],
        ResultValue::array(vec![
            ResultValue::Decimal("1.5000".to_owned()),
            ResultValue::Decimal("2.2500".to_owned()),
        ])
        .unwrap()
    );
    assert_eq!(
        row[16],
        ResultValue::array(vec![ResultValue::Uuid(uuid.to_owned())]).unwrap()
    );

    pools.close().await;
}

#[tokio::test]
async fn json_and_jsonb_preserve_large_integer_and_decimal_digits() {
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    let (executor, runtime) = harness(Arc::clone(&pools), ExecutionLimits::default()).await;
    let permit = runtime.acquire_query_permit().await.unwrap();

    let query = authorized(
        r#"SELECT
            '{"integer":18446744073709551616,"decimal":0.123456789012345678901234567890}'::json
                AS exact_json,
            '{"integer":18446744073709551616,"decimal":0.123456789012345678901234567890}'::jsonb
                AS exact_jsonb"#,
        Vec::new(),
        ExecutionLimits::default(),
    );
    let result = run(&executor, &permit, &query).await.unwrap();
    let expected = r#"{"decimal":0.123456789012345678901234567890,"integer":18446744073709551616}"#;

    assert_eq!(serde_json::to_string(&result.rows[0][0]).unwrap(), expected);
    assert_eq!(serde_json::to_string(&result.rows[0][1]).unwrap(), expected);
    assert_eq!(result.columns[0].database_type, "JSON");
    assert_eq!(result.columns[1].database_type, "JSONB");

    pools.close().await;
}

#[tokio::test]
async fn null_survives_whatever_the_columns_type_is() {
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    fixture(&pools).await;
    let (executor, runtime) = harness(Arc::clone(&pools), ExecutionLimits::default()).await;
    let permit = runtime.acquire_query_permit().await.unwrap();

    let query = authorized(
        "SELECT name, price, payload, identifier, created_at, recorded_at, blob_value, tags FROM samples WHERE id = 2",
        Vec::new(),
        ExecutionLimits::default(),
    );
    let result = run(&executor, &permit, &query).await.unwrap();
    assert!(
        result.rows[0]
            .iter()
            .all(|value| *value == ResultValue::Null),
        "{:?}",
        result.rows[0]
    );

    pools.close().await;
}

#[tokio::test]
async fn a_zero_row_result_is_empty_and_honest() {
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    fixture(&pools).await;
    let (executor, runtime) = harness(Arc::clone(&pools), ExecutionLimits::default()).await;
    let permit = runtime.acquire_query_permit().await.unwrap();

    let query = authorized(
        "SELECT id FROM samples WHERE id = -1",
        Vec::new(),
        ExecutionLimits::default(),
    );
    let result = run(&executor, &permit, &query).await.unwrap();

    assert!(result.rows.is_empty());
    assert!(!result.truncated);
    assert_eq!(result.stats.rows_returned, 0);
    // Column metadata comes from the first row, so a result with no rows has no
    // columns. The same is true on MySQL, and nothing is invented to fill the gap.
    assert!(result.columns.is_empty());
    result.validate().unwrap();

    pools.close().await;
}

#[tokio::test]
async fn an_unsigned_parameter_above_the_signed_range_binds_exactly() {
    // ADR-0035: PostgreSQL has no unsigned type, so anything above `i64::MAX` binds
    // as `numeric`. The round trip through `::text` is what proves it is exact
    // rather than wrapped into a negative `int8`.
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    let (executor, runtime) = harness(Arc::clone(&pools), ExecutionLimits::default()).await;
    let permit = runtime.acquire_query_permit().await.unwrap();

    let query = authorized(
        "SELECT $1::text AS shown",
        vec![ParameterValue::U64(u64::MAX)],
        ExecutionLimits::default(),
    );
    let result = run(&executor, &permit, &query).await.unwrap();
    assert_eq!(
        result.rows[0][0],
        ResultValue::String("18446744073709551615".to_owned())
    );

    pools.close().await;
}

#[tokio::test]
async fn the_analyzed_statement_is_the_executed_one() {
    // The one test that goes through the real analyzer and the real policy engine,
    // because "executed SQL is byte-for-byte the analyzed SQL" (SPEC section 6,
    // invariant 19) is a property of that whole path, not of the executor alone.
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    fixture(&pools).await;
    let (executor, runtime) = harness(Arc::clone(&pools), ExecutionLimits::default()).await;
    let permit = runtime.acquire_query_permit().await.unwrap();

    let sql = "SELECT count(*) AS total FROM samples WHERE id > $1";
    let request = QueryRequest::new(
        "production-db".parse().unwrap(),
        sql.to_owned(),
        vec![ParameterValue::I64(0)],
        &InputLimits::default(),
    )
    .unwrap();
    // `QueryAnalyzer::analyze` is synchronous and takes the whole `QueryRequest`,
    // returning an `AnalyzedQuery`: the analyzed statement and the statement that
    // will run are the same bytes by construction (SPEC section 6, invariant 19).
    let analyzed = PostgreSqlAnalyzer::new().analyze(request).unwrap();
    let query = engine()
        .authorize(
            &context(),
            &metadata(),
            analyzed,
            ExecutionLimits::default(),
        )
        .unwrap();
    assert_eq!(query.sql(), sql);

    let result = run(&executor, &permit, &query).await.unwrap();
    assert_eq!(result.rows[0][0], ResultValue::I64(2));

    pools.close().await;
}

#[tokio::test]
async fn the_set_local_deadline_can_only_tighten_the_connections_own() {
    // `docs/operations.md` section 5.1 keeps `SET LOCAL statement_timeout` inside the
    // transaction as reinforcement, and design decision 2 makes it a floor rather
    // than a ceiling: a request whose own limits were larger must not be able to
    // relax the server-side deadline the connection pinned at startup.
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    let (executor, runtime) = harness(Arc::clone(&pools), ExecutionLimits::default()).await;
    let permit = runtime.acquire_query_permit().await.unwrap();

    let tighter = ExecutionLimits {
        timeout: Duration::from_millis(1_500),
        ..ExecutionLimits::default()
    };
    let query = authorized(
        "SELECT current_setting('statement_timeout') AS value",
        Vec::new(),
        tighter,
    );
    let result = run(&executor, &permit, &query).await.unwrap();
    assert_eq!(
        result.rows[0][0],
        ResultValue::String("1500ms".to_owned()),
        "the request's own shorter deadline must reach the transaction"
    );

    let looser = ExecutionLimits {
        timeout: Duration::from_secs(30),
        ..ExecutionLimits::default()
    };
    let query = authorized(
        "SELECT current_setting('statement_timeout') AS value",
        Vec::new(),
        looser,
    );
    let result = run(&executor, &permit, &query).await.unwrap();
    assert_eq!(
        result.rows[0][0],
        ResultValue::String("5s".to_owned()),
        "a longer request deadline must not relax the connection's 5s startup value"
    );

    pools.close().await;
}

#[tokio::test]
async fn the_search_path_the_connection_pinned_is_the_one_the_query_resolves_in() {
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    let (executor, runtime) = harness(Arc::clone(&pools), ExecutionLimits::default()).await;
    let permit = runtime.acquire_query_permit().await.unwrap();

    let query = authorized(
        "SELECT current_setting('search_path') AS value",
        Vec::new(),
        ExecutionLimits::default(),
    );
    let result = run(&executor, &permit, &query).await.unwrap();
    assert_eq!(result.rows[0][0], ResultValue::String("public".to_owned()));

    pools.close().await;
}

/// Every write the read-only transaction must refuse, with the row from
/// `docs/security.md` section 3 that each one covers.
async fn refused(
    executor: &PostgreSqlQueryExecutor,
    permit: &QueryPermit,
    sql: &str,
) -> ExecuteError {
    let query = authorized(sql, Vec::new(), ExecutionLimits::default());
    run(executor, permit, &query)
        .await
        .expect_err("the read-only transaction accepted a write")
}

/// Reads the database's exact refusal from a hardened agent transaction.
///
/// `ExecuteError` deliberately retains only a sanitized public category, so this
/// companion check verifies that each statement reaches PostgreSQL's
/// `read_only_sql_transaction` branch rather than succeeding for an unrelated
/// parser, protocol, or fixture reason.
async fn read_only_sqlstate(pools: &PostgreSqlConnectionPools, sql: &str) -> String {
    let mut connection = pools.agent().acquire().await.unwrap();
    let mut transaction = connection.begin_with("BEGIN READ ONLY").await.unwrap();
    let error = agent_query(AssertSqlSafe(sql.to_owned()))
        .execute(&mut *transaction)
        .await
        .expect_err("the hardened agent session accepted a write");
    transaction.rollback().await.unwrap();
    match error {
        sqlx::Error::Database(database) => database
            .code()
            .map(|code| code.into_owned())
            .expect("the database refusal must include a SQLSTATE"),
        other => panic!("expected a database error, got {other:?}"),
    }
}

#[tokio::test]
async fn the_transaction_refuses_every_write_even_as_a_superuser() {
    // The container connects as `postgres`, which has every privilege. The barrier
    // under test is the session's own state — `BEGIN READ ONLY` plus
    // `default_transaction_read_only` — not the role's grants; Task 5 proves the
    // role separately, and the two are independent barriers rather than one
    // restated (`docs/operations.md` section 6.1).
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    fixture(&pools).await;
    let (executor, runtime) = harness(Arc::clone(&pools), ExecutionLimits::default()).await;
    let permit = runtime.acquire_query_permit().await.unwrap();

    for sql in [
        // Root DML and DDL.
        "INSERT INTO samples (id) VALUES (99) RETURNING id",
        "UPDATE samples SET name = 'x' WHERE id = 1 RETURNING id",
        "DELETE FROM samples WHERE id = 1 RETURNING id",
        "CREATE TABLE should_fail (id integer)",
        // A write hidden in a CTE, which is why nested-statement analysis exists —
        // and why the transaction is a second barrier under it.
        "WITH gone AS (DELETE FROM samples RETURNING id) SELECT count(*) FROM gone",
        // `SELECT INTO`, which creates a table.
        "SELECT id INTO copied FROM samples",
        // Sequence mutation, which PostgreSQL refuses in a read-only transaction.
        "SELECT nextval('sample_ids')",
        "SELECT setval('sample_ids', 10)",
    ] {
        assert_eq!(
            read_only_sqlstate(&pools, sql).await,
            "25006",
            "{sql} must reach PostgreSQL's read_only_sql_transaction refusal"
        );
        let error = refused(&executor, &permit, sql).await;
        assert!(
            matches!(error, ExecuteError::Database { .. }),
            "{sql} produced {error:?}"
        );
        // The agent learns that the statement failed and nothing about the server.
        assert_eq!(
            error.public_code(),
            PublicErrorCode::QueryExecutionError,
            "{sql}"
        );
        assert_eq!(
            error.to_string(),
            "the database rejected or failed the statement",
            "{sql}"
        );
    }

    pools.close().await;
}

#[tokio::test]
async fn the_connection_is_reusable_after_a_refused_write() {
    let container = start_postgres().await;
    let limits = ExecutionLimits {
        max_concurrent_queries: 1,
        ..ExecutionLimits::default()
    };
    let mut connection_config = config(dsn(&container).await);
    connection_config.limits = limits;
    connection_config.agent_pool = PoolSettings {
        max_connections: 1,
        ..PoolSettings::agent()
    };
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(connection_config)
            .await
            .unwrap(),
    );
    fixture(&pools).await;
    let (executor, runtime) = harness(Arc::clone(&pools), limits).await;
    let permit = runtime.acquire_query_permit().await.unwrap();

    let initial = authorized("SELECT pg_backend_pid() AS pid", Vec::new(), limits);
    let initial = run(&executor, &permit, &initial).await.unwrap();
    let initial_pid = match initial.rows[0][0] {
        ResultValue::I64(pid) => pid,
        ref other => panic!("expected the backend pid as int8, got {other:?}"),
    };

    // PostgreSQL aborts the whole transaction on any statement error, so a refused
    // write leaves a connection that accepts nothing but `ROLLBACK`. The executor
    // drops the transaction, which queues exactly that; if it did not, this second
    // query would fail with `25P02 in_failed_sql_transaction` rather than succeed.
    refused(&executor, &permit, "DELETE FROM samples RETURNING id").await;

    let query = authorized(
        "SELECT pg_backend_pid() AS pid, count(*) AS total FROM samples",
        Vec::new(),
        limits,
    );
    let result = run(&executor, &permit, &query).await.unwrap();
    assert_eq!(
        result.rows[0],
        vec![ResultValue::I64(initial_pid), ResultValue::I64(2)],
        "the executor must roll back and reuse the same failed-transaction session"
    );

    pools.close().await;
}

/// Runs one expression and returns the normalization failure it must produce.
async fn rejected(
    executor: &PostgreSqlQueryExecutor,
    permit: &QueryPermit,
    sql: &str,
) -> ExecuteError {
    let query = authorized(sql, Vec::new(), ExecutionLimits::default());
    run(executor, permit, &query)
        .await
        .expect_err("the value was normalized instead of refused")
}

#[tokio::test]
async fn an_unsupported_type_fails_with_a_cast_suggestion() {
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    fixture(&pools).await;
    let (executor, runtime) = harness(Arc::clone(&pools), ExecutionLimits::default()).await;
    let permit = runtime.acquire_query_permit().await.unwrap();

    // The exact example `docs/data-model.md` section 8.1 gives: a user-defined enum
    // reaches the agent as its own type name plus the cast that fixes it.
    let error = rejected(
        &executor,
        &permit,
        "SELECT state AS custom_state FROM samples WHERE id = 1",
    )
    .await;
    let rendered = error.to_string();
    assert!(rendered.contains("order_state"), "{error:?}");
    assert!(rendered.contains("custom_state::text"), "{error:?}");
    assert_eq!(
        error.public_code(),
        PublicErrorCode::QueryNormalizationError
    );

    // The same for the built-in types the table deliberately omits, and for the two
    // array shapes that cannot be decoded safely: a multi-dimensional array, which
    // sqlx refuses outright, and a calendar array, whose elements the overflow guard
    // cannot reach (design decision 7).
    for sql in [
        "SELECT '1 day'::interval AS span",
        "SELECT '09:07:03+02'::timetz AS moment",
        "SELECT '(1,2)'::point AS spot",
        "SELECT ARRAY[[1,2],[3,4]] AS grid",
        "SELECT ARRAY['2026-01-05'::date] AS days",
        "SELECT ARRAY['2026-01-05 09:07:03+00'::timestamptz] AS stamps",
    ] {
        let error = rejected(&executor, &permit, sql).await;
        assert_eq!(
            error.public_code(),
            PublicErrorCode::QueryNormalizationError,
            "{sql} produced {error:?}"
        );
        assert!(error.to_string().contains("::text"), "{sql}");
    }

    pools.close().await;
}

#[tokio::test]
async fn a_value_the_calendar_cannot_hold_is_an_error_and_never_a_panic() {
    // SPEC section 6, invariant 31. `sqlx`'s own date and timestamp decoders add the
    // wire integer to their epoch with `time`'s panicking `Add`, and PostgreSQL
    // produces four values that overflow it: both infinities, and any date or
    // timestamp beyond year 9999 — 294276 AD is an ordinary, insertable value here.
    // Without design decision 6's conversion these would abort the request task
    // instead of returning.
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    let (executor, runtime) = harness(Arc::clone(&pools), ExecutionLimits::default()).await;
    let permit = runtime.acquire_query_permit().await.unwrap();

    for sql in [
        "SELECT 'infinity'::timestamptz AS valid_until",
        "SELECT '-infinity'::timestamptz AS valid_from",
        "SELECT 'infinity'::timestamp AS valid_until",
        "SELECT 'infinity'::date AS valid_until",
        "SELECT '-infinity'::date AS valid_from",
        "SELECT '294276-01-01 00:00:00'::timestamp AS valid_until",
        "SELECT '5874897-12-31'::date AS valid_until",
        "SELECT 'NaN'::numeric AS score",
    ] {
        let error = rejected(&executor, &permit, sql).await;
        assert_eq!(
            error.public_code(),
            PublicErrorCode::QueryNormalizationError,
            "{sql} produced {error:?}"
        );
        let rendered = error.to_string();
        // The value is blamed, not the column's type: every other row of a
        // `timestamptz` column normalizes fine, and telling an agent the type is
        // unsupported would make it stop querying the column entirely.
        assert!(
            rendered.contains("no JSON representation"),
            "{sql}: {rendered}"
        );
        assert!(rendered.contains("::text"), "{sql}: {rendered}");
    }

    // A non-finite float is a different, older error, and stays that one.
    for sql in [
        "SELECT 'NaN'::float8 AS ratio",
        "SELECT 'Infinity'::float8 AS ratio",
        "SELECT 'Infinity'::float4 AS ratio",
    ] {
        let error = rejected(&executor, &permit, sql).await;
        assert!(error.to_string().contains("non-finite"), "{sql}: {error:?}");
    }

    // The connection survives all of it: a normalization failure is Warden's, not
    // the server's, so the session was never poisoned.
    let query = authorized("SELECT 1 AS ok", Vec::new(), ExecutionLimits::default());
    assert_eq!(
        run(&executor, &permit, &query).await.unwrap().rows[0][0],
        ResultValue::I64(1)
    );

    pools.close().await;
}
