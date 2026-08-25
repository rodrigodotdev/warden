//! What only a real MySQL server can prove about executing a query.
//!
//! Every test starts its own container, exactly as the connection tests do: a test
//! that saturates a pool, exhausts a budget, or kills a connection must not be able
//! to change another test's result.
//!
//! Task 4's review found a real defect in the truncated-result path and the fix
//! changed observable behaviour: MySQL streams result sets with `NO_CURSOR`, so
//! stopping early does not stop the server, and the executor now issues
//! `KILL QUERY` whenever it stops reading a stream the server may still be
//! writing — a truncated-but-successful result included, not only the failure
//! path. The tests below prove that directly, alongside the bounds, the
//! deadlines, and the cancellation the brief asked for.

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
use warden_core::result::{ResultSet, ResultValue};
use warden_policy::{AnalyzedQuery, AuthorizedQuery, PolicyEngine, PolicySettings};
use warden_ports::error::{ConnectionError, ExecuteError};
use warden_ports::{
    ConnectionRuntime, ConnectionRuntimeParts, QueryAnalyzer, QueryExecutor, QueryPermit,
};

use super::{config, dsn, start_mysql, tls};
use crate::analyzer::MySqlAnalyzer;
use crate::connection::MySqlConnectionPools;
use crate::execute::MySqlQueryExecutor;

/// An authorized statement, built from synthetic evidence.
///
/// The evidence is synthetic on purpose. This file tests the **executor**, and a
/// statement the analyzer would rightly deny — `SELECT SLEEP(30)`, or the
/// [`HEAVY_JOIN`] cross join — is what exercises paths the analyzer's own policy
/// would otherwise block. `SLEEP` does **not** prove the server deadline fires:
/// see `HEAVY_JOIN`'s own doc comment for why, and why `SLEEP` is kept only for
/// the cancellation tests, where a genuine `KILL QUERY` does terminate it. Two
/// tests below go through `MySqlAnalyzer` as well, so the real path is covered
/// where it is the thing under test.
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
fn runtime(executor: Arc<MySqlQueryExecutor>, limits: ExecutionLimits) -> ConnectionRuntime {
    ConnectionRuntime::new(ConnectionRuntimeParts {
        metadata: metadata(),
        capabilities: Capabilities {
            read_only_transactions: true,
            structured_explain: true,
            server_statement_timeout: true,
            schema_search: false,
        },
        limits,
        analyzer: Arc::new(MySqlAnalyzer::new()),
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
        dialect: Dialect::MySql,
        environment: Environment::Development,
        database: "test".to_owned(),
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
    executor: &MySqlQueryExecutor,
    permit: &QueryPermit,
    query: &AuthorizedQuery,
) -> Result<ResultSet, ExecuteError> {
    executor
        .execute_read_only(query, permit, deadline(), CancellationToken::new())
        .await
}

/// The table every execution test reads.
///
/// Created through `control_pool`: this is Warden's own static SQL, and
/// `agent_pool`'s read-only transaction would refuse the DDL anyway.
async fn fixture(pools: &MySqlConnectionPools) {
    for statement in [
        "CREATE TABLE samples (
             id BIGINT PRIMARY KEY,
             name VARCHAR(64),
             price DECIMAL(10,2),
             payload JSON,
             created_on DATE,
             created_at DATETIME,
             duration TIME,
             blob_value BLOB,
             flag BOOLEAN
         )",
        "INSERT INTO samples VALUES (1, 'first', 10.50, '{\"k\":1}', '2026-01-05', \
         '2026-01-05 09:07:03', '01:02:03', X'000102', 1)",
        // Every nullable column is NULL, so one test can prove that NULL survives as
        // `ResultValue::Null` whatever the column's declared type is.
        "INSERT INTO samples VALUES (2, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL)",
    ] {
        sqlx::query(AssertSqlSafe(statement.to_owned()))
            .execute(pools.control())
            .await
            .unwrap();
    }
}

/// A table with `rows` records, each carrying a `payload_bytes`-byte `TEXT` value.
///
/// Large and cheap to build (`REPEAT` runs server-side, so the statement itself
/// stays short): the truncation and mid-stream-failure tests below need a table
/// where stopping early leaves a measurable amount of data still in flight, which
/// is exactly what proves the executor's `KILL QUERY` is doing real work rather
/// than tidying up a stream that had already finished.
async fn wide_fixture(pools: &MySqlConnectionPools, rows: u32, payload_bytes: usize) {
    sqlx::query(AssertSqlSafe(
        "CREATE TABLE wide_rows (id BIGINT PRIMARY KEY, payload TEXT)".to_owned(),
    ))
    .execute(pools.control())
    .await
    .unwrap();

    let values: Vec<String> = (0..rows)
        .map(|id| format!("({id}, REPEAT('a', {payload_bytes}))"))
        .collect();
    sqlx::query(AssertSqlSafe(format!(
        "INSERT INTO wide_rows VALUES {}",
        values.join(",")
    )))
    .execute(pools.control())
    .await
    .unwrap();
}

/// SQL guaranteed to still be running past any deadline this file configures.
///
/// `SELECT SLEEP(n)` looks like the obvious choice, but a real MySQL 8.4 server
/// does not error it out when `MAX_EXECUTION_TIME` fires: `SLEEP` catches that
/// specific interrupt and simply returns `1` early, so a query built on it comes
/// back `Ok` rather than `Err(Timeout)` — confirmed against a container, not
/// assumed. This cross join has no such special case: it is real per-row
/// comparison work, and a MySQL 8.4 server genuinely fails it with
/// `ER_QUERY_TIMEOUT` once the deadline elapses. Needs `wide_fixture` with at
/// least `HEAVY_JOIN_ROWS` rows first. `KILL QUERY` (not a deadline) still stops
/// `SLEEP` correctly, which is why the cancellation tests below keep using it.
const HEAVY_JOIN: &str =
    "SELECT COUNT(*) FROM wide_rows a, wide_rows b WHERE a.payload <> b.payload";

/// Enough rows that [`HEAVY_JOIN`] reliably runs past a two-second deadline.
const HEAVY_JOIN_ROWS: u32 = 8_000;

/// How many times the server has executed a `KILL` statement.
///
/// `Com_kill` increments whenever the statement runs, whatever its target — a
/// structural proof that `MySqlQueryExecutor::kill` actually reached the server
/// rather than being silently dropped. (Against a real MySQL 8.4 server, a
/// *bound* `KILL QUERY ?` does not merely fail to decode a response: it does not
/// kill anything at all — `Com_kill` never increments and the target keeps
/// running — confirmed against a container, not assumed. `kill` sends the
/// connection id as a literal decimal string instead, built with `format!` from
/// a `u64` rather than passed through a bind API, which is what actually kills.)
async fn com_kill(pools: &MySqlConnectionPools) -> i64 {
    let row = sqlx::query("SHOW GLOBAL STATUS LIKE 'Com_kill'")
        .fetch_one(pools.control())
        .await
        .unwrap();
    let value: String = row.try_get(1).unwrap();
    value.parse().unwrap()
}

/// Polls, with a bound, until no server process is still running a statement whose
/// text contains `marker`.
///
/// A poll rather than a single check: `KILL QUERY` and the draining `ROLLBACK` have
/// already been awaited by the time `execute_read_only` returns, but MySQL's own
/// bookkeeping can lag a process's disappearance from `information_schema.processlist`
/// by a beat, and a flaky assertion here should get a generous, bounded retry rather
/// than be deleted.
///
/// `bound` is explicit, not a fixed constant, because it doubles as part of what
/// the caller is proving. A bound comfortably below the connection's own
/// `MAX_EXECUTION_TIME` (5s by default) means a pass can only be this poll's own
/// `KILL QUERY` clearing the marker — not the server's unrelated timeout doing it
/// on its own, which callers racing a long-running `SLEEP` or a heavy scan against
/// the default timeout must rule out explicitly (see `cancellation_reaches_the_server`).
async fn wait_until_nothing_runs(pools: &MySqlConnectionPools, marker: &str, bound: Duration) {
    let pattern = format!("%{marker}%");
    let deadline = std::time::Instant::now() + bound;
    loop {
        // Excludes this very connection's own row: MySQL echoes a prepared
        // statement's bound values into its own `information_schema.processlist`
        // entry while it runs, so a naive `LIKE` here would match this poll's own
        // in-flight statement, never reach zero, and time out every call.
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM information_schema.processlist \
             WHERE info LIKE ? AND id <> CONNECTION_ID()",
        )
        .bind(&pattern)
        .fetch_one(pools.control())
        .await
        .unwrap();
        if count == 0 {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "a query containing {marker:?} was still running after the bound"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
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

// ---------------------------------------------------------------------------------
// Step 2: the read-only transaction, binding, and the type table.
// ---------------------------------------------------------------------------------

#[tokio::test]
async fn a_bound_select_returns_normalized_rows() {
    let container = start_mysql().await;
    let pools = MySqlConnectionPools::connect(config(dsn(&container).await, tls()))
        .await
        .unwrap();
    fixture(&pools).await;

    let executor = Arc::new(MySqlQueryExecutor::new(Arc::new(pools)));
    let runtime = runtime(Arc::clone(&executor), ExecutionLimits::default());
    let permit = runtime.acquire_query_permit().await.unwrap();

    let query = authorized(
        "SELECT id, name, price, payload, created_on, created_at, duration, blob_value, \
         flag FROM samples WHERE id = ? ORDER BY id",
        vec![ParameterValue::I64(1)],
        ExecutionLimits::default(),
    );
    let result = executor
        .execute_read_only(&query, &permit, deadline(), CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(result.rows.len(), 1);
    assert!(!result.truncated);
    assert_eq!(result.stats.rows_returned, 1);
    assert!(result.stats.bytes > 0);
    result.validate().unwrap();

    // Every column, by the representation `docs/data-model.md` section 8.2 requires.
    // MySQL 8.4 may report `flag` as `TINYINT` rather than `BOOLEAN` — the driver
    // folds `TINYINT` into `BOOLEAN` only when the column's display width is 1 — in
    // which case this list, not `kind_of`, is what would need correcting.
    let types: Vec<&str> = result
        .columns
        .iter()
        .map(|column| column.database_type.as_str())
        .collect();
    assert_eq!(
        types,
        [
            "BIGINT", "VARCHAR", "DECIMAL", "JSON", "DATE", "DATETIME", "TIME", "BLOB", "BOOLEAN"
        ]
    );
    assert!(
        result
            .columns
            .iter()
            .all(|column| column.nullable.is_none())
    );

    let row = &result.rows[0];
    assert_eq!(row[0], ResultValue::I64(1));
    assert_eq!(row[1], ResultValue::String("first".to_owned()));
    // Preserved as text: the trailing zero would be lost by any float round trip.
    assert_eq!(row[2], ResultValue::Decimal("10.50".to_owned()));
    assert_eq!(row[3], ResultValue::Json(serde_json::json!({"k": 1})));
    assert_eq!(row[4], ResultValue::Date("2026-01-05".to_owned()));
    assert_eq!(
        row[5],
        ResultValue::DateTime("2026-01-05 09:07:03".to_owned())
    );
    assert_eq!(row[6], ResultValue::Time("01:02:03".to_owned()));
    assert_eq!(row[7], ResultValue::BytesBase64("AAEC".to_owned()));
    assert_eq!(row[8], ResultValue::Bool(true));
}

#[tokio::test]
async fn the_analyzed_statement_is_the_executed_one() {
    let container = start_mysql().await;
    let pools = Arc::new(
        MySqlConnectionPools::connect(config(dsn(&container).await, tls()))
            .await
            .unwrap(),
    );
    fixture(&pools).await;

    let executor = Arc::new(MySqlQueryExecutor::new(Arc::clone(&pools)));
    let runtime = runtime(Arc::clone(&executor), ExecutionLimits::default());
    let permit = runtime.acquire_query_permit().await.unwrap();

    let sql = "SELECT id, name FROM samples ORDER BY id";
    let request = QueryRequest::new(
        "production-db".parse().unwrap(),
        sql.to_owned(),
        Vec::new(),
        &InputLimits::default(),
    )
    .unwrap();
    let analyzed = MySqlAnalyzer::new().analyze(request).unwrap();
    let query = engine()
        .authorize(
            &context(),
            &metadata(),
            analyzed,
            ExecutionLimits::default(),
        )
        .unwrap();

    let result = run(&executor, &permit, &query).await.unwrap();

    // The same text, run directly, must describe the same rows: the statement the
    // executor ran is byte-for-byte the one the analyzer saw.
    let direct = sqlx::query(AssertSqlSafe(sql.to_owned()))
        .fetch_all(pools.control())
        .await
        .unwrap();
    assert_eq!(result.rows.len(), direct.len());
    for (row, expected) in result.rows.iter().zip(direct.iter()) {
        let id: i64 = expected.try_get(0).unwrap();
        // Row 2's `name` is NULL, by `fixture`'s own design.
        let name: Option<String> = expected.try_get(1).unwrap();
        assert_eq!(row[0], ResultValue::I64(id));
        assert_eq!(row[1], name.map_or(ResultValue::Null, ResultValue::String));
    }
}

#[tokio::test]
async fn null_survives_whatever_the_columns_type_is() {
    let container = start_mysql().await;
    let pools = Arc::new(
        MySqlConnectionPools::connect(config(dsn(&container).await, tls()))
            .await
            .unwrap(),
    );
    fixture(&pools).await;

    let executor = Arc::new(MySqlQueryExecutor::new(Arc::clone(&pools)));
    let runtime = runtime(Arc::clone(&executor), ExecutionLimits::default());
    let permit = runtime.acquire_query_permit().await.unwrap();

    let query = authorized(
        "SELECT id, name, price, payload, created_on, created_at, duration, blob_value, \
         flag FROM samples WHERE id = ?",
        vec![ParameterValue::I64(2)],
        ExecutionLimits::default(),
    );
    let result = run(&executor, &permit, &query).await.unwrap();

    assert_eq!(result.rows.len(), 1);
    let row = &result.rows[0];
    assert_eq!(row[0], ResultValue::I64(2), "the primary key is never NULL");
    // The other eight columns, including DATE and JSON, where a decode would
    // otherwise have been attempted.
    for (index, value) in row.iter().enumerate().skip(1) {
        assert_eq!(*value, ResultValue::Null, "column {index}");
    }
}

#[tokio::test]
async fn a_zero_row_result_is_empty_and_honest() {
    let container = start_mysql().await;
    let pools = Arc::new(
        MySqlConnectionPools::connect(config(dsn(&container).await, tls()))
            .await
            .unwrap(),
    );
    fixture(&pools).await;

    let executor = Arc::new(MySqlQueryExecutor::new(Arc::clone(&pools)));
    let runtime = runtime(Arc::clone(&executor), ExecutionLimits::default());
    let permit = runtime.acquire_query_permit().await.unwrap();

    let query = authorized(
        "SELECT id FROM samples WHERE 1 = 0",
        Vec::new(),
        ExecutionLimits::default(),
    );
    let result = run(&executor, &permit, &query).await.unwrap();

    assert!(result.rows.is_empty());
    assert!(result.columns.is_empty());
    assert!(!result.truncated);
    assert_eq!(result.stats.bytes, 0);
}

#[tokio::test]
async fn an_unsupported_type_fails_with_a_cast_suggestion() {
    let container = start_mysql().await;
    let pools = Arc::new(
        MySqlConnectionPools::connect(config(dsn(&container).await, tls()))
            .await
            .unwrap(),
    );

    let executor = Arc::new(MySqlQueryExecutor::new(Arc::clone(&pools)));
    let runtime = runtime(Arc::clone(&executor), ExecutionLimits::default());
    let permit = runtime.acquire_query_permit().await.unwrap();

    let query = authorized(
        "SELECT ST_GeomFromText('POINT(1 1)') AS shape",
        Vec::new(),
        ExecutionLimits::default(),
    );
    let error = run(&executor, &permit, &query).await.unwrap_err();

    assert!(matches!(error, ExecuteError::Normalization(_)), "{error:?}");
    let rendered = error.to_string();
    assert!(rendered.contains("GEOMETRY"), "{rendered}");
    assert!(rendered.contains("CAST(shape AS CHAR)"), "{rendered}");
    // The whole point of the mapping: nothing from the driver's own message, which
    // would have named the function, leaks into the text an agent sees.
    assert!(!rendered.contains("ST_GeomFromText"), "{rendered}");
}

// ---------------------------------------------------------------------------------
// Step 3: the read-only transaction is real.
// ---------------------------------------------------------------------------------

#[tokio::test]
async fn the_transaction_refuses_a_write_even_as_root() {
    // The session barrier, independent of the role's GRANT: this container's user is
    // root, so only `START TRANSACTION READ ONLY` can be refusing this
    // (`docs/operations.md` section 6.1). Task 6 proves the other barrier.
    let container = start_mysql().await;
    let pools = MySqlConnectionPools::connect(config(dsn(&container).await, tls()))
        .await
        .unwrap();
    fixture(&pools).await;

    let mut transaction = pools
        .agent()
        .begin_with("START TRANSACTION READ ONLY")
        .await
        .unwrap();
    let error = sqlx::query("INSERT INTO samples (id, name) VALUES (99, 'x')")
        .execute(&mut *transaction)
        .await
        .unwrap_err();
    let number = error
        .as_database_error()
        .and_then(|database| database.try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>())
        .map(sqlx::mysql::MySqlDatabaseError::number);
    // ER_CANT_EXECUTE_IN_READ_ONLY_TRANSACTION
    assert_eq!(number, Some(1792), "{error:?}");

    transaction.rollback().await.unwrap();
}

#[tokio::test]
async fn the_connection_is_reusable_after_a_refused_write() {
    let container = start_mysql().await;
    let pools = Arc::new(
        MySqlConnectionPools::connect(config(dsn(&container).await, tls()))
            .await
            .unwrap(),
    );
    fixture(&pools).await;

    let mut transaction = pools
        .agent()
        .begin_with("START TRANSACTION READ ONLY")
        .await
        .unwrap();
    let _refused = sqlx::query("INSERT INTO samples (id, name) VALUES (99, 'x')")
        .execute(&mut *transaction)
        .await
        .unwrap_err();
    transaction.rollback().await.unwrap();

    let executor = Arc::new(MySqlQueryExecutor::new(Arc::clone(&pools)));
    let runtime = runtime(Arc::clone(&executor), ExecutionLimits::default());
    let permit = runtime.acquire_query_permit().await.unwrap();
    let query = authorized(
        "SELECT id FROM samples ORDER BY id",
        Vec::new(),
        ExecutionLimits::default(),
    );
    let result = run(&executor, &permit, &query).await.unwrap();
    assert_eq!(result.rows.len(), 2);
}

// ---------------------------------------------------------------------------------
// Step 4: each bound, one test per bound.
// ---------------------------------------------------------------------------------

#[tokio::test]
async fn the_row_bound_truncates_the_result() {
    let container = start_mysql().await;
    let pools = Arc::new(
        MySqlConnectionPools::connect(config(dsn(&container).await, tls()))
            .await
            .unwrap(),
    );
    wide_fixture(&pools, 10, 5).await;

    let executor = Arc::new(MySqlQueryExecutor::new(Arc::clone(&pools)));
    let limits = ExecutionLimits {
        max_rows: 3,
        ..ExecutionLimits::default()
    };
    let runtime = runtime(Arc::clone(&executor), limits);
    let permit = runtime.acquire_query_permit().await.unwrap();

    let query = authorized("SELECT id FROM wide_rows ORDER BY id", Vec::new(), limits);
    let result = run(&executor, &permit, &query).await.unwrap();

    assert_eq!(result.rows.len(), 3);
    assert!(result.truncated);
    assert_eq!(result.stats.rows_returned, 3);
}

#[tokio::test]
async fn the_total_byte_bound_truncates_the_result() {
    let container = start_mysql().await;
    let pools = Arc::new(
        MySqlConnectionPools::connect(config(dsn(&container).await, tls()))
            .await
            .unwrap(),
    );
    // Each row encodes to 56 bytes: two brackets and a comma (3), a one-digit id
    // (1), and a 50-character string quoted (52).
    wide_fixture(&pools, 5, 50).await;

    let executor = Arc::new(MySqlQueryExecutor::new(Arc::clone(&pools)));
    let limits = ExecutionLimits {
        max_value_bytes: 60,
        max_result_bytes: 60,
        ..ExecutionLimits::default()
    };
    let runtime = runtime(Arc::clone(&executor), limits);
    let permit = runtime.acquire_query_permit().await.unwrap();

    let query = authorized(
        "SELECT id, payload FROM wide_rows ORDER BY id",
        Vec::new(),
        limits,
    );
    let result = run(&executor, &permit, &query).await.unwrap();

    assert_eq!(result.rows.len(), 1);
    assert!(result.truncated);
}

#[tokio::test]
async fn the_per_value_bound_fails_the_whole_result() {
    let container = start_mysql().await;
    let pools = Arc::new(
        MySqlConnectionPools::connect(config(dsn(&container).await, tls()))
            .await
            .unwrap(),
    );
    sqlx::query(AssertSqlSafe(
        "CREATE TABLE text_col (id BIGINT PRIMARY KEY, note TEXT)".to_owned(),
    ))
    .execute(pools.control())
    .await
    .unwrap();
    sqlx::query(AssertSqlSafe(
        "INSERT INTO text_col VALUES (1, REPEAT('x', 4096))".to_owned(),
    ))
    .execute(pools.control())
    .await
    .unwrap();

    let executor = Arc::new(MySqlQueryExecutor::new(Arc::clone(&pools)));
    let limits = ExecutionLimits {
        max_value_bytes: 64,
        ..ExecutionLimits::default()
    };
    let runtime = runtime(Arc::clone(&executor), limits);
    let permit = runtime.acquire_query_permit().await.unwrap();

    let query = authorized("SELECT note FROM text_col WHERE id = 1", Vec::new(), limits);
    let error = run(&executor, &permit, &query).await.unwrap_err();

    assert_eq!(error, ExecuteError::ResultTooLarge { limit: 64 });
    assert_eq!(error.public_code(), PublicErrorCode::QueryResultTooLarge);
}

#[tokio::test]
async fn nothing_fits_fails_rather_than_truncates_to_empty() {
    let container = start_mysql().await;
    let pools = Arc::new(
        MySqlConnectionPools::connect(config(dsn(&container).await, tls()))
            .await
            .unwrap(),
    );
    sqlx::query(AssertSqlSafe(
        "CREATE TABLE nothing_fits (id BIGINT PRIMARY KEY, note VARCHAR(50))".to_owned(),
    ))
    .execute(pools.control())
    .await
    .unwrap();
    sqlx::query(AssertSqlSafe(
        "INSERT INTO nothing_fits VALUES (1, 'hello world')".to_owned(),
    ))
    .execute(pools.control())
    .await
    .unwrap();

    let executor = Arc::new(MySqlQueryExecutor::new(Arc::clone(&pools)));
    // The row encodes to 17 bytes; 15 is below that but still large enough that the
    // per-value budget (13 bytes for `"hello world"`) is not what trips first.
    let limits = ExecutionLimits {
        max_value_bytes: 15,
        max_result_bytes: 15,
        ..ExecutionLimits::default()
    };
    let runtime = runtime(Arc::clone(&executor), limits);
    let permit = runtime.acquire_query_permit().await.unwrap();

    let query = authorized(
        "SELECT id, note FROM nothing_fits WHERE id = 1",
        Vec::new(),
        limits,
    );
    let error = run(&executor, &permit, &query).await.unwrap_err();

    assert_eq!(error, ExecuteError::ResultTooLarge { limit: 15 });
}

// ---------------------------------------------------------------------------------
// Beyond the brief: the truncated-result kill, proven both ways it can trigger, and
// its two counterparts — a complete result that must never kill, and a mid-stream
// value failure that must.
// ---------------------------------------------------------------------------------

#[tokio::test]
async fn a_row_truncated_result_is_ok_and_kills_the_orphaned_query() {
    let container = start_mysql().await;
    let pools = Arc::new(
        MySqlConnectionPools::connect(config(dsn(&container).await, tls()))
            .await
            .unwrap(),
    );
    wide_fixture(&pools, 500, 20).await;

    let executor = Arc::new(MySqlQueryExecutor::new(Arc::clone(&pools)));
    let limits = ExecutionLimits {
        max_rows: 5,
        ..ExecutionLimits::default()
    };
    let runtime = runtime(Arc::clone(&executor), limits);
    let permit = runtime.acquire_query_permit().await.unwrap();

    let query = authorized(
        "SELECT /* row_trunc_marker */ id, payload FROM wide_rows ORDER BY id",
        Vec::new(),
        limits,
    );

    let before = com_kill(&pools).await;
    let result = run(&executor, &permit, &query).await.unwrap();
    let after = com_kill(&pools).await;

    assert!(result.truncated);
    assert_eq!(result.rows.len(), 5);
    assert_eq!(result.stats.rows_returned, 5);
    assert!(
        after > before,
        "a truncated result must issue KILL QUERY for the 495 rows still in flight"
    );
    wait_until_nothing_runs(&pools, "row_trunc_marker", Duration::from_secs(5)).await;
}

#[tokio::test]
async fn a_byte_truncated_result_is_ok_and_kills_the_orphaned_query() {
    let container = start_mysql().await;
    let pools = Arc::new(
        MySqlConnectionPools::connect(config(dsn(&container).await, tls()))
            .await
            .unwrap(),
    );
    wide_fixture(&pools, 500, 2000).await;

    let executor = Arc::new(MySqlQueryExecutor::new(Arc::clone(&pools)));
    // One row encodes to roughly 2008 bytes; the budget below fits exactly one.
    let limits = ExecutionLimits {
        max_value_bytes: 2100,
        max_result_bytes: 2100,
        ..ExecutionLimits::default()
    };
    let runtime = runtime(Arc::clone(&executor), limits);
    let permit = runtime.acquire_query_permit().await.unwrap();

    let query = authorized(
        "SELECT /* byte_trunc_marker */ id, payload FROM wide_rows ORDER BY id",
        Vec::new(),
        limits,
    );

    let before = com_kill(&pools).await;
    let result = run(&executor, &permit, &query).await.unwrap();
    let after = com_kill(&pools).await;

    assert!(result.truncated);
    assert_eq!(result.rows.len(), 1);
    assert!(
        after > before,
        "a byte-truncated result must issue KILL QUERY for the ~499 rows still in flight"
    );
    wait_until_nothing_runs(&pools, "byte_trunc_marker", Duration::from_secs(5)).await;
}

#[tokio::test]
async fn a_complete_result_fires_no_kill() {
    let container = start_mysql().await;
    let pools = Arc::new(
        MySqlConnectionPools::connect(config(dsn(&container).await, tls()))
            .await
            .unwrap(),
    );
    wide_fixture(&pools, 20, 20).await;

    let executor = Arc::new(MySqlQueryExecutor::new(Arc::clone(&pools)));
    let runtime = runtime(Arc::clone(&executor), ExecutionLimits::default());
    let permit = runtime.acquire_query_permit().await.unwrap();

    let query = authorized(
        "SELECT id, payload FROM wide_rows ORDER BY id",
        Vec::new(),
        ExecutionLimits::default(),
    );

    let before = com_kill(&pools).await;
    let result = run(&executor, &permit, &query).await.unwrap();
    let after = com_kill(&pools).await;

    assert!(!result.truncated);
    assert_eq!(result.rows.len(), 20);
    assert_eq!(
        after, before,
        "a complete, undrained-of-nothing result must never trigger KILL QUERY"
    );
}

#[tokio::test]
async fn a_mid_stream_value_too_large_kills_the_orphaned_query() {
    let container = start_mysql().await;
    let pools = Arc::new(
        MySqlConnectionPools::connect(config(dsn(&container).await, tls()))
            .await
            .unwrap(),
    );
    sqlx::query(AssertSqlSafe(
        "CREATE TABLE spike_rows (id BIGINT PRIMARY KEY, payload TEXT)".to_owned(),
    ))
    .execute(pools.control())
    .await
    .unwrap();
    let mut values: Vec<String> = (1..=99)
        .map(|id| format!("({id}, REPEAT('x', 5))"))
        .collect();
    values.push("(100, REPEAT('y', 5000))".to_owned());
    values.extend((101..=200).map(|id| format!("({id}, REPEAT('x', 5))")));
    sqlx::query(AssertSqlSafe(format!(
        "INSERT INTO spike_rows VALUES {}",
        values.join(",")
    )))
    .execute(pools.control())
    .await
    .unwrap();

    let executor = Arc::new(MySqlQueryExecutor::new(Arc::clone(&pools)));
    let limits = ExecutionLimits {
        max_value_bytes: 1024,
        ..ExecutionLimits::default()
    };
    let runtime = runtime(Arc::clone(&executor), limits);
    let permit = runtime.acquire_query_permit().await.unwrap();

    let query = authorized(
        "SELECT /* spike_marker */ id, payload FROM spike_rows ORDER BY id",
        Vec::new(),
        limits,
    );

    let before = com_kill(&pools).await;
    let error = run(&executor, &permit, &query).await.unwrap_err();
    let after = com_kill(&pools).await;

    assert_eq!(error, ExecuteError::ResultTooLarge { limit: 1024 });
    assert!(
        after > before,
        "a value that fails mid-stream must issue KILL QUERY for the 100 rows still \
         in flight"
    );
    wait_until_nothing_runs(&pools, "spike_marker", Duration::from_secs(5)).await;

    // The pool must not hand out a connection still wedged on the killed statement.
    let follow_up = authorized(
        "SELECT COUNT(*) AS n FROM spike_rows",
        Vec::new(),
        ExecutionLimits::default(),
    );
    let result = run(&executor, &permit, &follow_up).await.unwrap();
    assert_eq!(result.rows[0][0], ResultValue::I64(200));
}

#[tokio::test]
async fn the_connection_is_reusable_after_a_truncation() {
    let container = start_mysql().await;
    let mut settings = config(dsn(&container).await, tls());
    // Exactly one connection in the pool. This alone does not prove the follow-up
    // below reuses the connection the truncation touched: sqlx's
    // `test_before_acquire` defaults on (`execute.rs` leans on exactly that fact
    // to discard a wedged connection), so a bad connection would be silently
    // replaced within the same budget of one and the follow-up would still
    // succeed either way. Pinning to one connection only makes the
    // `SELECT CONNECTION_ID()` check below meaningful: with more than one
    // connection available, "the id matches" could just mean the pool happened
    // to hand back the same one, not that no replacement was needed.
    settings.agent_pool.max_connections = 1;
    settings.limits = ExecutionLimits {
        max_rows: 5,
        max_concurrent_queries: 1,
        ..ExecutionLimits::default()
    };
    let limits = settings.limits;
    let pools = Arc::new(MySqlConnectionPools::connect(settings).await.unwrap());
    wide_fixture(&pools, 300, 30).await;

    let executor = Arc::new(MySqlQueryExecutor::new(Arc::clone(&pools)));
    let runtime = runtime(Arc::clone(&executor), limits);
    let permit = runtime.acquire_query_permit().await.unwrap();

    let id_query = authorized("SELECT CONNECTION_ID()", Vec::new(), limits);
    let before = run(&executor, &permit, &id_query).await.unwrap();

    let truncated = authorized(
        "SELECT id, payload FROM wide_rows ORDER BY id",
        Vec::new(),
        limits,
    );
    let result = run(&executor, &permit, &truncated).await.unwrap();
    assert!(result.truncated);

    // On this path the `ROLLBACK` is what drains the killed stream, typically
    // observing the discarded `ER_QUERY_INTERRUPTED`. Asking for the connection
    // id again — rather than only running a query that happens to succeed — is
    // what proves the *same* connection served both: if it had been wedged and
    // `test_before_acquire` had discarded and replaced it, this would come back
    // with a different id instead of failing outright.
    let after = run(&executor, &permit, &id_query).await.unwrap();
    assert_eq!(
        before.rows[0][0], after.rows[0][0],
        "the follow-up ran on a different connection, so this proves nothing \
         about the one the truncation touched"
    );

    let follow_up = authorized("SELECT id FROM wide_rows WHERE id = 0", Vec::new(), limits);
    let second = run(&executor, &permit, &follow_up).await.unwrap();
    assert_eq!(second.rows.len(), 1);
    assert_eq!(second.rows[0][0], ResultValue::I64(0));
}

// ---------------------------------------------------------------------------------
// Step 5: the deadlines, the cancellation, and the concurrency bound.
// ---------------------------------------------------------------------------------

#[tokio::test]
async fn the_server_deadline_fires_before_the_client_one() {
    // `docs/operations.md` section 5.3: with the server deadline strictly first, the
    // ordinary timeout is a clean server error and the connection returns to the
    // pool intact. Asserting the elapsed time is what distinguishes that from the
    // client's `timeout_at` firing, which would look identical in the error alone.
    let container = start_mysql().await;
    let limits = ExecutionLimits {
        timeout: Duration::from_secs(2),
        ..ExecutionLimits::default()
    };
    let mut settings = config(dsn(&container).await, tls());
    settings.limits = limits;
    let pools = Arc::new(MySqlConnectionPools::connect(settings).await.unwrap());
    wide_fixture(&pools, HEAVY_JOIN_ROWS, 20).await;

    let executor = Arc::new(MySqlQueryExecutor::new(Arc::clone(&pools)));
    let runtime = runtime(Arc::clone(&executor), limits);
    let permit = runtime.acquire_query_permit().await.unwrap();
    let query = authorized(HEAVY_JOIN, Vec::new(), limits);

    let started = std::time::Instant::now();
    let error = executor
        .execute_read_only(
            &query,
            &permit,
            Instant::now() + limits.client_timeout(),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    let elapsed = started.elapsed();

    // `error` alone only shows the port's own shape; the elapsed-time assertion
    // below is what rules out the *client's* `timeout_at` producing the same
    // `ExecuteError::Timeout` and leaves the server's own `ER_QUERY_TIMEOUT` as
    // the only source it could be.
    assert_eq!(error, ExecuteError::Timeout);
    assert!(
        elapsed < limits.client_timeout(),
        "waited {elapsed:?}; the client deadline is {:?}, so the server did not \
         abort first",
        limits.client_timeout()
    );

    // The number itself, pinned directly as ADR-0033 requires: the identical
    // statement, run raw on the same pool so it inherits the same 2s
    // `MAX_EXECUTION_TIME`, fails with the server's own numbered error.
    let raw_error = sqlx::query(AssertSqlSafe(HEAVY_JOIN.to_owned()))
        .execute(pools.agent())
        .await
        .unwrap_err();
    let number = raw_error
        .as_database_error()
        .and_then(|database| database.try_downcast_ref::<sqlx::mysql::MySqlDatabaseError>())
        .map(sqlx::mysql::MySqlDatabaseError::number);
    // ER_QUERY_TIMEOUT
    assert_eq!(number, Some(3024), "{raw_error:?}");
}

#[tokio::test]
async fn cancellation_reaches_the_server() {
    // The test that tells `KILL QUERY` actually reached and stopped the *right*
    // connection, rather than a dropped future that merely looks the same from
    // the caller's side, or a `kill(wrong_id)` that still increments `Com_kill`
    // without touching the target. Both of those weaker failures are ruled out by
    // the same fact: the connection's own `MAX_EXECUTION_TIME` is
    // `ExecutionLimits::default().timeout` (5s), so `wait_until_nothing_runs`
    // below is given a 2s bound — comfortably enough for a real, correctly
    // targeted kill, but strictly less than the 5s the server's own timeout would
    // need to clear the marker on its own. A pass within 2s can only be this
    // test's own `KILL QUERY`. (`Cancelled` itself is produced client-side by the
    // token below, not by classifying a database error — see
    // `a_kill_from_outside_the_token_still_maps_to_cancelled` for the container
    // test that exercises the `ER_QUERY_INTERRUPTED` (1317) mapping arm
    // directly.)
    let container = start_mysql().await;
    let pools = Arc::new(
        MySqlConnectionPools::connect(config(dsn(&container).await, tls()))
            .await
            .unwrap(),
    );

    let executor = Arc::new(MySqlQueryExecutor::new(Arc::clone(&pools)));
    let runtime = runtime(Arc::clone(&executor), ExecutionLimits::default());
    let permit = runtime.acquire_query_permit().await.unwrap();
    let query = authorized(
        "SELECT /* cancel_marker */ SLEEP(30)",
        Vec::new(),
        ExecutionLimits::default(),
    );

    let cancel = CancellationToken::new();
    let before = com_kill(&pools).await;

    let call = executor.execute_read_only(&query, &permit, deadline(), cancel.clone());
    let canceller = async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        cancel.cancel();
    };
    let (outcome, ()) = tokio::join!(call, canceller);

    // Produced by the `CancellationToken` branch, client-side.
    assert_eq!(outcome.unwrap_err(), ExecuteError::Cancelled);

    let after = com_kill(&pools).await;
    assert!(after > before, "KILL QUERY never reached the server");
    wait_until_nothing_runs(&pools, "cancel_marker", Duration::from_secs(2)).await;
}

#[tokio::test]
async fn a_kill_from_outside_the_token_still_maps_to_cancelled() {
    // ADR-0033 promises a container test pinning `ER_QUERY_INTERRUPTED` (1317) to
    // `ExecuteError::Cancelled`. `cancellation_reaches_the_server` does not do
    // that: its `Cancelled` comes from the `CancellationToken` branch in
    // `collect`, client-side, before the database is ever asked anything — the
    // one place a real 1317 is observed, the draining `ROLLBACK`, deliberately
    // discards it (see `execute.rs`'s own comment on that discard). This test
    // never touches the token at all, so the only way `Cancelled` can come back
    // is through `execute_error`'s `ER_QUERY_INTERRUPTED => ExecuteError::Cancelled`
    // arm classifying a genuine database error the row stream itself observed.
    //
    // `HEAVY_JOIN`, not `SLEEP`: `SLEEP` absorbs a real `KILL` the same way it
    // absorbs `MAX_EXECUTION_TIME` (confirmed the same way — see `HEAVY_JOIN`'s
    // own doc comment) and returns a row instead of erroring, which would make
    // this test pass on a query that never actually interrupted.
    let container = start_mysql().await;
    let pools = Arc::new(
        MySqlConnectionPools::connect(config(dsn(&container).await, tls()))
            .await
            .unwrap(),
    );
    wide_fixture(&pools, HEAVY_JOIN_ROWS, 20).await;

    let executor = Arc::new(MySqlQueryExecutor::new(Arc::clone(&pools)));
    let runtime = runtime(Arc::clone(&executor), ExecutionLimits::default());
    let permit = runtime.acquire_query_permit().await.unwrap();
    let query = authorized(
        "SELECT /* external_kill_marker */ COUNT(*) FROM wide_rows a, wide_rows b \
         WHERE a.payload <> b.payload",
        Vec::new(),
        ExecutionLimits::default(),
    );

    // Never cancelled — the only handle proving that below is this value's own
    // absence of a `.cancel()` call anywhere in this test.
    let never_cancelled = CancellationToken::new();

    let call = executor.execute_read_only(&query, &permit, deadline(), never_cancelled);
    let killer = async {
        // Finds the statement from a second connection, exactly as an operator
        // running `KILL QUERY` by hand would, then kills it — well within the
        // 5s default `MAX_EXECUTION_TIME`, so nothing else could be the cause.
        let bound = std::time::Instant::now() + Duration::from_secs(3);
        let id: u64 = loop {
            let found: Option<u64> = sqlx::query_scalar(
                "SELECT id FROM information_schema.processlist \
                 WHERE info LIKE '%external_kill_marker%' AND id <> CONNECTION_ID()",
            )
            .fetch_optional(pools.control())
            .await
            .unwrap();
            if let Some(id) = found {
                break id;
            }
            assert!(
                std::time::Instant::now() < bound,
                "the marked query never showed up in the processlist"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        sqlx::query(AssertSqlSafe(format!("KILL QUERY {id}")))
            .execute(pools.control())
            .await
            .unwrap();
    };

    let (outcome, ()) = tokio::join!(call, killer);
    assert_eq!(
        outcome.unwrap_err(),
        ExecuteError::Cancelled,
        "a real ER_QUERY_INTERRUPTED (1317) must classify as Cancelled"
    );
}

#[tokio::test]
async fn the_pool_survives_a_timeout_a_cancellation_and_a_database_error() {
    let container = start_mysql().await;
    let limits = ExecutionLimits {
        timeout: Duration::from_secs(2),
        ..ExecutionLimits::default()
    };
    let mut settings = config(dsn(&container).await, tls());
    settings.limits = limits;
    let pools = Arc::new(MySqlConnectionPools::connect(settings).await.unwrap());
    wide_fixture(&pools, HEAVY_JOIN_ROWS, 20).await;

    let executor = Arc::new(MySqlQueryExecutor::new(Arc::clone(&pools)));
    let runtime = runtime(Arc::clone(&executor), limits);
    let permit = runtime.acquire_query_permit().await.unwrap();

    // 1. A server-side timeout. Real per-row work, not `SLEEP`, for the reason
    // `HEAVY_JOIN` documents.
    let timeout_query = authorized(HEAVY_JOIN, Vec::new(), limits);
    let error = executor
        .execute_read_only(
            &timeout_query,
            &permit,
            Instant::now() + limits.client_timeout(),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    assert_eq!(error, ExecuteError::Timeout);

    // 2. A cancellation.
    let cancel = CancellationToken::new();
    let cancel_query = authorized("SELECT SLEEP(30)", Vec::new(), limits);
    let call = executor.execute_read_only(&cancel_query, &permit, deadline(), cancel.clone());
    let canceller = async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        cancel.cancel();
    };
    let (outcome, ()) = tokio::join!(call, canceller);
    assert_eq!(outcome.unwrap_err(), ExecuteError::Cancelled);

    // 3. A genuine database error.
    let bad_query = authorized("SELECT * FROM does_not_exist", Vec::new(), limits);
    let error = run(&executor, &permit, &bad_query).await.unwrap_err();
    assert!(matches!(error, ExecuteError::Database { .. }), "{error:?}");

    // The pool must still be usable after all three.
    let plain = authorized("SELECT 1", Vec::new(), limits);
    let result = run(&executor, &permit, &plain).await.unwrap();
    assert_eq!(result.rows[0][0], ResultValue::I64(1));
    pools.health_check(deadline()).await.unwrap();
}

#[tokio::test]
async fn no_session_state_leaks_between_requests() {
    let container = start_mysql().await;
    let pools = Arc::new(
        MySqlConnectionPools::connect(config(dsn(&container).await, tls()))
            .await
            .unwrap(),
    );

    let executor = Arc::new(MySqlQueryExecutor::new(Arc::clone(&pools)));
    let runtime = runtime(Arc::clone(&executor), ExecutionLimits::default());
    let permit = runtime.acquire_query_permit().await.unwrap();

    // A first query sets nothing session-scoped.
    let first = authorized("SELECT 1", Vec::new(), ExecutionLimits::default());
    run(&executor, &permit, &first).await.unwrap();

    // A second query, through the real analyzer and policy engine so the genuine
    // path is covered too, reads the two connection-time session settings back.
    let sql = "SELECT CAST(@@SESSION.MAX_EXECUTION_TIME AS SIGNED), \
               CAST(@@SESSION.transaction_read_only AS SIGNED)";
    let request = QueryRequest::new(
        "production-db".parse().unwrap(),
        sql.to_owned(),
        Vec::new(),
        &InputLimits::default(),
    )
    .unwrap();
    let analyzed = MySqlAnalyzer::new().analyze(request).unwrap();
    let second_query = engine()
        .authorize(
            &context(),
            &metadata(),
            analyzed,
            ExecutionLimits::default(),
        )
        .unwrap();
    let result = run(&executor, &permit, &second_query).await.unwrap();

    let expected_ms =
        i64::try_from(ExecutionLimits::default().server_timeout().as_millis()).unwrap();
    assert_eq!(result.rows[0][0], ResultValue::I64(expected_ms));
    assert_eq!(result.rows[0][1], ResultValue::I64(0));

    // Neither request altered `control_pool`'s own connection-time settings either.
    let control_time: i64 =
        sqlx::query_scalar("SELECT CAST(@@SESSION.MAX_EXECUTION_TIME AS SIGNED)")
            .fetch_one(pools.control())
            .await
            .unwrap();
    assert_eq!(control_time, expected_ms);
    let control_read_only: i64 =
        sqlx::query_scalar("SELECT CAST(@@SESSION.transaction_read_only AS SIGNED)")
            .fetch_one(pools.control())
            .await
            .unwrap();
    assert_eq!(control_read_only, 0);
}

#[tokio::test]
async fn concurrency_is_bounded_on_a_real_executor() {
    // SPEC section 6, invariants 16 and 17 pair, measured on a runtime that
    // actually holds a MySQL executor rather than a fake one.
    let container = start_mysql().await;
    let limits = ExecutionLimits {
        max_concurrent_queries: 1,
        max_queue_wait: Duration::from_secs(1),
        ..ExecutionLimits::default()
    };
    let mut settings = config(dsn(&container).await, tls());
    settings.limits = limits;
    let pools = MySqlConnectionPools::connect(settings).await.unwrap();

    let executor = Arc::new(MySqlQueryExecutor::new(Arc::new(pools)));
    let runtime = runtime(Arc::clone(&executor), limits);

    let held = runtime.acquire_query_permit().await.unwrap();

    let started = std::time::Instant::now();
    let error = runtime.acquire_query_permit().await.unwrap_err();
    let elapsed = started.elapsed();
    assert!(matches!(error, ConnectionError::Busy { .. }), "{error:?}");
    assert!(
        elapsed >= Duration::from_millis(900) && elapsed < Duration::from_secs(3),
        "waited {elapsed:?}; max_queue_wait is 1s"
    );

    drop(held);
    let reacquired = runtime.acquire_query_permit().await.unwrap();
    let query = authorized("SELECT 1", Vec::new(), limits);
    let result = run(&executor, &reacquired, &query).await.unwrap();
    assert_eq!(result.rows[0][0], ResultValue::I64(1));
}
