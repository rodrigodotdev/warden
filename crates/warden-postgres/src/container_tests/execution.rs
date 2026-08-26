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
use warden_ports::error::{ConnectionError, ExecuteError};
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

/// A statement that keeps producing rows long after Warden stops reading.
///
/// A modest payload forces PostgreSQL to flush the first bounded batch promptly;
/// tiny rows can remain buffered long enough that the client has not seen its
/// sentinel even though `pg_stat_activity` already proves the query is active.
/// `pg_sleep` per row keeps the query alive for minutes without a cancel. If the
/// cancel regresses, the five-second server deadline still limits this fixture to
/// roughly 200 KiB rather than an unbounded response.
///
/// The alias is the marker [`wait_until_nothing_runs`] looks for in
/// `pg_stat_activity`. Warden's real analyzer would deny this statement —
/// `pg_sleep` carries `RiskFlag::DelayFunction` — which is exactly why the test
/// builds it as an `AuthorizedQuery` directly: the property under test lives below
/// the policy engine.
const SLOW_STREAM: &str = "SELECT repeat('x', 2048) || i::text AS warden_orphan_marker \
     FROM generate_series(1, 100000) i \
     CROSS JOIN LATERAL (SELECT pg_sleep(0.05) WHERE i IS NOT NULL) AS delayed";

/// A statement with real per-row work, guaranteed to outlive a two-second deadline.
const HEAVY_COUNT: &str =
    "SELECT count(*) AS warden_heavy_marker FROM generate_series(1, 2000000000) i";

/// Bound for observing that a query reached, or left, the server.
const SERVER_OBSERVATION_TIMEOUT: Duration = Duration::from_secs(2);

/// Aggregate post-query budget: cancel, rollback, and deallocation get two seconds
/// each and can run sequentially.
const EXECUTOR_CLEANUP_BUDGET: Duration = Duration::from_secs(6);

/// Polls, with a bound, until no backend is still running a statement whose text
/// contains `marker`.
///
/// A poll rather than a single check: the cancel request and the draining `ROLLBACK`
/// have both been awaited by the time `execute_read_only` returns, but
/// `pg_stat_activity` can lag a backend leaving the `active` state by a beat, and a
/// flaky assertion here should get a generous, bounded retry rather than be deleted.
///
/// `deadline` bounds only this server-side observation. Callers poll concurrently
/// with executor cleanup, so the cancellation proof is not delayed by rollback or
/// statement deallocation. For cancellation tests it is comfortably below the
/// connection's own `statement_timeout` (5 s by default), which means a pass can
/// only be Warden's own `pg_cancel_backend` clearing the marker — not the server's
/// unrelated timeout doing it on its own.
///
/// The marker travels as a bound parameter, so this poll's own row in
/// `pg_stat_activity` never contains it; `pid <> pg_backend_pid()` is belt and
/// braces.
async fn wait_until_nothing_runs(
    pools: &PostgreSqlConnectionPools,
    marker: &str,
    deadline: Instant,
) {
    let pattern = format!("%{marker}%");
    loop {
        let running: i64 = tokio::time::timeout_at(
            deadline,
            sqlx::query_scalar(
                "SELECT count(*) FROM pg_stat_activity \
                 WHERE query LIKE $1 AND state = 'active' AND pid <> pg_backend_pid()",
            )
            .bind(&pattern)
            .fetch_one(pools.control()),
        )
        .await
        .unwrap_or_else(|_| panic!("timed out observing {marker:?} after cancellation"))
        .unwrap();
        assert!(
            Instant::now() < deadline,
            "observation of {marker:?} completed after its cancellation deadline"
        );
        if running == 0 {
            return;
        }
        tokio::time::timeout_at(deadline, tokio::time::sleep(Duration::from_millis(50)))
            .await
            .unwrap_or_else(|_| {
                panic!("a backend running {marker:?} was still active at its cancellation deadline")
            });
    }
}

/// The pid of the one backend running a statement containing `marker`, once it
/// appears.
async fn backend_running(
    pools: &PostgreSqlConnectionPools,
    marker: &str,
    deadline: Instant,
) -> i32 {
    let pattern = format!("%{marker}%");
    loop {
        let found: Option<i32> = tokio::time::timeout_at(
            deadline,
            sqlx::query_scalar(
                "SELECT pid FROM pg_stat_activity \
                 WHERE query LIKE $1 AND state = 'active' AND pid <> pg_backend_pid() \
                 LIMIT 1",
            )
            .bind(&pattern)
            .fetch_optional(pools.control()),
        )
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {marker:?} to start"))
        .unwrap();
        assert!(
            Instant::now() < deadline,
            "observation of {marker:?} completed after its startup deadline"
        );
        if let Some(pid) = found {
            return pid;
        }
        tokio::time::timeout_at(deadline, tokio::time::sleep(Duration::from_millis(50)))
            .await
            .unwrap_or_else(|_| {
                panic!("no backend started running {marker:?} before its deadline")
            });
    }
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

#[tokio::test]
async fn no_session_state_leaks_between_requests() {
    // PostgreSQL undoes a session-level `SET` made inside a transaction when that
    // transaction rolls back, and every agent statement runs inside one, so the
    // executor's `ROLLBACK` is what makes this true rather than a hope. The pid
    // assertion is what makes the test meaningful: without it, a pool that handed
    // out a second connection would pass vacuously.
    let container = start_postgres().await;
    let limits = ExecutionLimits {
        max_concurrent_queries: 1,
        ..ExecutionLimits::default()
    };
    let mut settings = config(dsn(&container).await);
    settings.limits = limits;
    settings.agent_pool.max_connections = 1;
    let pools = Arc::new(PostgreSqlConnectionPools::connect(settings).await.unwrap());
    let (executor, runtime) = harness(Arc::clone(&pools), limits).await;
    let permit = runtime.acquire_query_permit().await.unwrap();

    let first = authorized(
        "SELECT set_config('warden.leak', 'yes', false) AS written, \
         pg_backend_pid() AS pid",
        Vec::new(),
        limits,
    );
    let result = run(&executor, &permit, &first).await.unwrap();
    assert_eq!(result.rows[0][0], ResultValue::String("yes".to_owned()));
    let first_pid = result.rows[0][1].clone();

    let second = authorized(
        "SELECT current_setting('warden.leak', true) AS leaked, \
         current_setting('statement_timeout') AS deadline, \
         pg_backend_pid() AS pid",
        Vec::new(),
        limits,
    );
    let result = run(&executor, &permit, &second).await.unwrap();
    assert_eq!(
        result.rows[0][2], first_pid,
        "the two requests must share a connection for this test to mean anything"
    );
    assert_eq!(
        result.rows[0][0],
        // PostgreSQL preserves a custom GUC's placeholder after a rolled-back
        // `set_config`, so its missing value is empty rather than SQL NULL. The
        // security property is that the request's `yes` value did not survive.
        ResultValue::String(String::new()),
        "a session setting written by one request survived into the next"
    );
    assert_eq!(
        result.rows[0][1],
        ResultValue::String("5s".to_owned()),
        "the previous request's SET LOCAL survived its own transaction"
    );

    // `control_pool` was never touched either.
    let control: String = sqlx::query_scalar("SELECT current_setting('statement_timeout')")
        .fetch_one(pools.control())
        .await
        .unwrap();
    assert_eq!(control, "5s");

    pools.close().await;
}

#[tokio::test]
async fn concurrency_is_bounded_on_a_real_executor() {
    // SPEC section 6, invariants 16 and 17 pair, measured on a runtime that
    // actually holds a PostgreSQL executor rather than a fake one.
    let container = start_postgres().await;
    let limits = ExecutionLimits {
        max_concurrent_queries: 1,
        max_queue_wait: Duration::from_secs(1),
        ..ExecutionLimits::default()
    };
    let mut settings = config(dsn(&container).await);
    settings.limits = limits;
    let pools = Arc::new(PostgreSqlConnectionPools::connect(settings).await.unwrap());
    let (executor, runtime) = harness(Arc::clone(&pools), limits).await;

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
    let query = authorized("SELECT 1 AS ok", Vec::new(), limits);
    let result = run(&executor, &reacquired, &query).await.unwrap();
    assert_eq!(result.rows[0][0], ResultValue::I64(1));

    pools.close().await;
}

#[tokio::test]
async fn the_server_deadline_fires_before_the_client_one() {
    // ADR-0024 and `docs/operations.md` section 5.3: with the server deadline
    // shorter, the normal path is a clean server error and an intact pooled
    // connection, and `tokio::time::timeout_at` is only a safety net. A client
    // timeout during row streaming would instead force sqlx to discard the
    // connection, which drains a pool of five under repeated slow queries.
    let container = start_postgres().await;
    let limits = ExecutionLimits {
        timeout: Duration::from_secs(2),
        max_concurrent_queries: 1,
        ..ExecutionLimits::default()
    };
    let mut settings = config(dsn(&container).await);
    settings.limits = limits;
    settings.agent_pool.max_connections = 1;
    let pools = Arc::new(PostgreSqlConnectionPools::connect(settings).await.unwrap());
    let (executor, runtime) = harness(Arc::clone(&pools), limits).await;
    let permit = runtime.acquire_query_permit().await.unwrap();

    let pid_query = authorized("SELECT pg_backend_pid() AS pid", Vec::new(), limits);
    let initial_pid = run(&executor, &permit, &pid_query).await.unwrap().rows[0][0].clone();
    let query = authorized(HEAVY_COUNT, Vec::new(), limits);
    let client_deadline = Instant::now() + limits.client_timeout();
    let activity_deadline = Instant::now() + Duration::from_secs(1);
    let cleanup_deadline = client_deadline + EXECUTOR_CLEANUP_BUDGET;
    let call = tokio::time::timeout_at(
        cleanup_deadline,
        executor.execute_read_only(
            &query,
            &permit,
            // The client deadline is `timeout + margin`, which
            // `ExecutionLimits::client_timeout` derives and validation keeps
            // strictly longer than the server one.
            client_deadline,
            CancellationToken::new(),
        ),
    );
    let query_phase = async {
        let observed_pid = backend_running(&pools, "warden_heavy_marker", activity_deadline).await;
        assert_eq!(
            initial_pid,
            ResultValue::I64(i64::from(observed_pid)),
            "the deadline query must run on the pinned agent backend"
        );
        // This observes the query leaving PostgreSQL before the client deadline
        // while rollback and statement deallocation are still free to continue.
        wait_until_nothing_runs(&pools, "warden_heavy_marker", client_deadline).await;
    };
    let (outcome, ()) = tokio::join!(call, query_phase);
    let error = outcome
        .unwrap_or_else(|_| panic!("executor cleanup exceeded its aggregate budget"))
        .unwrap_err();

    assert_eq!(error, ExecuteError::Timeout);
    assert_eq!(error.public_code(), PublicErrorCode::QueryTimeout);

    // The same physical session came back intact: a replacement could also run
    // `SELECT 1`, while the identical backend PID proves server timeout cleanup did
    // not retire the connection. The per-request deadline remains transaction-local.
    let plain = authorized(
        "SELECT pg_backend_pid() AS pid, current_setting('statement_timeout') AS deadline",
        Vec::new(),
        limits,
    );
    assert_eq!(
        run(&executor, &permit, &plain).await.unwrap().rows[0],
        vec![initial_pid, ResultValue::String("2s".to_owned())]
    );

    pools.close().await;
}

#[tokio::test]
async fn cancellation_reaches_the_server() {
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    let (executor, runtime) = harness(Arc::clone(&pools), ExecutionLimits::default()).await;
    let permit = runtime.acquire_query_permit().await.unwrap();

    let cancel = CancellationToken::new();
    let query = authorized(
        "SELECT pg_sleep(30) AS warden_cancel_marker",
        Vec::new(),
        ExecutionLimits::default(),
    );
    let activity_deadline = Instant::now() + SERVER_OBSERVATION_TIMEOUT;
    let cleanup_deadline = activity_deadline + EXECUTOR_CLEANUP_BUDGET;
    let call = tokio::time::timeout_at(
        cleanup_deadline,
        executor.execute_read_only(&query, &permit, deadline(), cancel.clone()),
    );
    let canceller = async {
        // The backend marker is server-observable synchronization: the test never
        // races cancellation against connection checkout or query dispatch.
        backend_running(&pools, "warden_cancel_marker", activity_deadline).await;
        let cancellation_deadline = Instant::now() + SERVER_OBSERVATION_TIMEOUT;
        cancel.cancel();
        // Observe the query phase separately. Rollback and deallocation continue
        // concurrently and are awaited by `call` under their aggregate budget.
        wait_until_nothing_runs(&pools, "warden_cancel_marker", cancellation_deadline).await;
    };
    let (outcome, ()) = tokio::join!(call, canceller);

    // The token's own arm wins the `biased` select, so the agent sees `Cancelled`
    // rather than the `57014` the server will report a moment later.
    assert_eq!(
        outcome
            .unwrap_or_else(|_| panic!("executor cleanup exceeded its aggregate budget"))
            .unwrap_err(),
        ExecuteError::Cancelled
    );

    pools.close().await;
}

#[tokio::test]
async fn a_cancel_from_outside_the_token_is_reported_as_a_timeout() {
    // ADR-0034's documented consequence, pinned so it is a decision rather than a
    // surprise: PostgreSQL reports a statement timeout and a cancel request under
    // the same `57014`, and Warden maps that code to `Timeout` because the server
    // deadline is the designed ordinary path. A DBA cancelling a backend therefore
    // reaches the agent as `query_timeout`.
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    let (executor, runtime) = harness(Arc::clone(&pools), ExecutionLimits::default()).await;
    let permit = runtime.acquire_query_permit().await.unwrap();

    let query = authorized(
        "SELECT pg_sleep(30) AS warden_external_marker",
        Vec::new(),
        ExecutionLimits::default(),
    );
    let activity_deadline = Instant::now() + SERVER_OBSERVATION_TIMEOUT;
    let cleanup_deadline = activity_deadline + EXECUTOR_CLEANUP_BUDGET;
    let call = tokio::time::timeout_at(cleanup_deadline, run(&executor, &permit, &query));
    let outsider = async {
        let pid = backend_running(&pools, "warden_external_marker", activity_deadline).await;
        let cancellation_deadline = Instant::now() + SERVER_OBSERVATION_TIMEOUT;
        let cancelled: bool = tokio::time::timeout_at(
            cancellation_deadline,
            sqlx::query_scalar("SELECT pg_cancel_backend($1)")
                .bind(pid)
                .fetch_one(pools.control()),
        )
        .await
        .unwrap_or_else(|_| panic!("pg_cancel_backend did not finish before its deadline"))
        .unwrap();
        assert!(
            cancelled,
            "pg_cancel_backend did not deliver a signal to pid {pid}"
        );
        wait_until_nothing_runs(&pools, "warden_external_marker", cancellation_deadline).await;
    };
    let (outcome, ()) = tokio::join!(call, outsider);

    let error = outcome
        .unwrap_or_else(|_| panic!("executor cleanup exceeded its aggregate budget"))
        .unwrap_err();
    assert_eq!(error, ExecuteError::Timeout, "ADR-0034");
    assert_eq!(error.public_code(), PublicErrorCode::QueryTimeout);

    pools.close().await;
}

#[tokio::test]
async fn the_pool_survives_a_timeout_a_cancellation_and_a_database_error() {
    let container = start_postgres().await;
    let limits = ExecutionLimits {
        timeout: Duration::from_secs(2),
        ..ExecutionLimits::default()
    };
    let mut settings = config(dsn(&container).await);
    settings.limits = limits;
    let pools = Arc::new(PostgreSqlConnectionPools::connect(settings).await.unwrap());
    let (executor, runtime) = harness(Arc::clone(&pools), limits).await;
    let permit = runtime.acquire_query_permit().await.unwrap();

    // 1. A server-side timeout.
    let timeout_query = authorized(HEAVY_COUNT, Vec::new(), limits);
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

    // 2. A cancellation, after the server confirms the statement is in flight.
    let cancel = CancellationToken::new();
    let cancel_query = authorized("SELECT pg_sleep(30)", Vec::new(), limits);
    let call = executor.execute_read_only(&cancel_query, &permit, deadline(), cancel.clone());
    let canceller = async {
        backend_running(
            &pools,
            "SELECT pg_sleep(30)",
            Instant::now() + Duration::from_secs(2),
        )
        .await;
        cancel.cancel();
    };
    let (outcome, ()) = tokio::join!(call, canceller);
    assert_eq!(outcome.unwrap_err(), ExecuteError::Cancelled);

    // 3. A genuine database error.
    let bad_query = authorized("SELECT * FROM does_not_exist", Vec::new(), limits);
    let error = run(&executor, &permit, &bad_query).await.unwrap_err();
    assert!(matches!(error, ExecuteError::Database { .. }), "{error:?}");

    // The pool must still be usable after all three.
    let plain = authorized("SELECT 1 AS ok", Vec::new(), limits);
    let result = run(&executor, &permit, &plain).await.unwrap();
    assert_eq!(result.rows[0][0], ResultValue::I64(1));
    pools.health_check(deadline()).await.unwrap();

    pools.close().await;
}

#[tokio::test]
async fn the_row_bound_truncates_the_result() {
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    let limits = ExecutionLimits {
        max_rows: 5,
        ..ExecutionLimits::default()
    };
    let (executor, runtime) = harness(Arc::clone(&pools), limits).await;
    let permit = runtime.acquire_query_permit().await.unwrap();

    let query = authorized(
        "SELECT i FROM generate_series(1, 100) i",
        Vec::new(),
        limits,
    );
    let result = run(&executor, &permit, &query).await.unwrap();

    assert_eq!(result.rows.len(), 5);
    assert!(result.truncated);
    assert_eq!(result.stats.rows_returned, 5);

    pools.close().await;
}

#[tokio::test]
async fn an_unrepresentable_row_sentinel_cannot_replace_valid_rows_with_an_error() {
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    let limits = ExecutionLimits {
        max_rows: 2,
        ..ExecutionLimits::default()
    };
    let (executor, runtime) = harness(Arc::clone(&pools), limits).await;
    let permit = runtime.acquire_query_permit().await.unwrap();

    let query = authorized(
        "SELECT CASE WHEN i <= 2 THEN i::numeric ELSE 'NaN'::numeric END AS value \
         FROM generate_series(1, 3) i ORDER BY i",
        Vec::new(),
        limits,
    );
    let result = run(&executor, &permit, &query).await.unwrap();

    assert_eq!(
        result.rows,
        vec![
            vec![ResultValue::Decimal("1".to_owned())],
            vec![ResultValue::Decimal("2".to_owned())],
        ]
    );
    assert!(result.truncated);
    assert_eq!(result.stats.rows_returned, 2);

    pools.close().await;
}

#[tokio::test]
async fn the_total_byte_bound_truncates_the_result() {
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    let limits = ExecutionLimits {
        max_value_bytes: 512,
        max_result_bytes: 512,
        ..ExecutionLimits::default()
    };
    let (executor, runtime) = harness(Arc::clone(&pools), limits).await;
    let permit = runtime.acquire_query_permit().await.unwrap();

    let query = authorized(
        "SELECT repeat('a', 100) AS payload FROM generate_series(1, 50) i",
        Vec::new(),
        limits,
    );
    let result = run(&executor, &permit, &query).await.unwrap();

    assert!(result.truncated);
    assert!(!result.rows.is_empty(), "at least one row must be returned");
    assert!(result.rows.len() < 50, "{}", result.rows.len());
    assert!(result.stats.bytes <= 512, "{}", result.stats.bytes);

    pools.close().await;
}

#[tokio::test]
async fn the_per_value_bound_fails_the_whole_result() {
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    let limits = ExecutionLimits {
        max_value_bytes: 64,
        ..ExecutionLimits::default()
    };
    let (executor, runtime) = harness(Arc::clone(&pools), limits).await;
    let permit = runtime.acquire_query_permit().await.unwrap();

    // An error, not a substitution: `ResultValue` has no "omitted" variant, and
    // inventing one would put a value in the agent's context the database never
    // returned (`docs/data-model.md` section 7).
    let query = authorized("SELECT repeat('a', 200) AS payload", Vec::new(), limits);
    let error = run(&executor, &permit, &query).await.unwrap_err();
    assert!(
        matches!(error, ExecuteError::ResultTooLarge { limit: 64 }),
        "{error:?}"
    );
    assert_eq!(error.public_code(), PublicErrorCode::QueryResultTooLarge);

    pools.close().await;
}

#[tokio::test]
async fn nothing_fits_fails_rather_than_truncates_to_empty() {
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    // The value fits its own budget; the first row alone does not fit the result
    // budget. Truncating to zero rows would report success for a result the agent
    // never received any of.
    let limits = ExecutionLimits {
        max_value_bytes: 32,
        max_result_bytes: 32,
        ..ExecutionLimits::default()
    };
    let (executor, runtime) = harness(Arc::clone(&pools), limits).await;
    let permit = runtime.acquire_query_permit().await.unwrap();

    let query = authorized("SELECT repeat('a', 30) AS payload", Vec::new(), limits);
    let error = run(&executor, &permit, &query).await.unwrap_err();
    assert!(
        matches!(error, ExecuteError::ResultTooLarge { limit: 32 }),
        "{error:?}"
    );

    pools.close().await;
}

#[tokio::test]
async fn a_truncated_result_is_ok_and_cancels_the_orphaned_query() {
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    let limits = ExecutionLimits {
        max_rows: 5,
        ..ExecutionLimits::default()
    };
    let (executor, runtime) = harness(Arc::clone(&pools), limits).await;
    let permit = runtime.acquire_query_permit().await.unwrap();

    let query = authorized(SLOW_STREAM, Vec::new(), limits);
    let activity_deadline = Instant::now() + SERVER_OBSERVATION_TIMEOUT;
    let cleanup_deadline = activity_deadline + EXECUTOR_CLEANUP_BUDGET;
    let call = tokio::time::timeout_at(
        cleanup_deadline,
        executor.execute_read_only(&query, &permit, deadline(), CancellationToken::new()),
    );
    let query_phase = async {
        backend_running(&pools, "warden_orphan_marker", activity_deadline).await;
        let cancellation_deadline = Instant::now() + SERVER_OBSERVATION_TIMEOUT;
        wait_until_nothing_runs(&pools, "warden_orphan_marker", cancellation_deadline).await;
    };
    let (outcome, ()) = tokio::join!(call, query_phase);
    let result = outcome
        .unwrap_or_else(|_| panic!("executor cleanup exceeded its aggregate budget"))
        .unwrap();

    // Truncation is a success, not a failure: the agent gets rows and is told to
    // narrow the query (`docs/mcp.md` section 1.3).
    assert_eq!(result.rows.len(), 5);
    assert!(result.truncated);

    pools.close().await;
}

#[tokio::test]
async fn a_byte_truncated_result_cancels_the_orphaned_query_too() {
    // The byte bound reaches the same `RowOutcome::Truncated` by a different route,
    // and the cancel must fire on both. `docs/operations.md` section 6.2 records
    // that "stopped reading early" is its own event, separate from success or
    // failure.
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    let limits = ExecutionLimits {
        max_value_bytes: 4_096,
        max_result_bytes: 4_096,
        ..ExecutionLimits::default()
    };
    let (executor, runtime) = harness(Arc::clone(&pools), limits).await;
    let permit = runtime.acquire_query_permit().await.unwrap();

    let query = authorized(SLOW_STREAM, Vec::new(), limits);
    let activity_deadline = Instant::now() + SERVER_OBSERVATION_TIMEOUT;
    let cleanup_deadline = activity_deadline + EXECUTOR_CLEANUP_BUDGET;
    let call = tokio::time::timeout_at(
        cleanup_deadline,
        executor.execute_read_only(&query, &permit, deadline(), CancellationToken::new()),
    );
    let query_phase = async {
        backend_running(&pools, "warden_orphan_marker", activity_deadline).await;
        let cancellation_deadline = Instant::now() + SERVER_OBSERVATION_TIMEOUT;
        wait_until_nothing_runs(&pools, "warden_orphan_marker", cancellation_deadline).await;
    };
    let (outcome, ()) = tokio::join!(call, query_phase);
    let result = outcome
        .unwrap_or_else(|_| panic!("executor cleanup exceeded its aggregate budget"))
        .unwrap();
    assert!(result.truncated);
    assert!(!result.rows.is_empty());

    pools.close().await;
}

#[tokio::test]
async fn a_mid_stream_value_too_large_cancels_the_orphaned_query() {
    // The failure path's cancel, which is unconditional rather than limited to a
    // timeout or a cancellation: a budget failure discovered mid-stream leaves rows
    // in flight exactly as a truncation does.
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    let limits = ExecutionLimits {
        max_value_bytes: 4_096,
        ..ExecutionLimits::default()
    };
    let (executor, runtime) = harness(Arc::clone(&pools), limits).await;
    let permit = runtime.acquire_query_permit().await.unwrap();

    // Row 1 is stored and large enough to flush promptly; row 2 exceeds the
    // per-value budget, so the call fails partway through a stream the server is
    // still writing.
    let query = authorized(
        "SELECT CASE WHEN i = 1 THEN repeat('s', 2048) ELSE repeat('a', 8192) END \
         AS warden_orphan_marker FROM generate_series(1, 100000) i \
         CROSS JOIN LATERAL (SELECT pg_sleep(0.05) WHERE i IS NOT NULL) AS delayed",
        Vec::new(),
        limits,
    );
    let activity_deadline = Instant::now() + SERVER_OBSERVATION_TIMEOUT;
    let cleanup_deadline = activity_deadline + EXECUTOR_CLEANUP_BUDGET;
    let call = tokio::time::timeout_at(
        cleanup_deadline,
        executor.execute_read_only(&query, &permit, deadline(), CancellationToken::new()),
    );
    let query_phase = async {
        backend_running(&pools, "warden_orphan_marker", activity_deadline).await;
        let cancellation_deadline = Instant::now() + SERVER_OBSERVATION_TIMEOUT;
        wait_until_nothing_runs(&pools, "warden_orphan_marker", cancellation_deadline).await;
    };
    let (outcome, ()) = tokio::join!(call, query_phase);
    let error = outcome
        .unwrap_or_else(|_| panic!("executor cleanup exceeded its aggregate budget"))
        .unwrap_err();
    assert!(
        matches!(error, ExecuteError::ResultTooLarge { .. }),
        "{error:?}"
    );

    pools.close().await;
}

#[tokio::test]
async fn a_complete_result_leaves_the_connection_immediately_reusable() {
    // The negative of the three tests above. PostgreSQL offers no counter that says
    // "no cancel was sent", so the property is asserted where it would actually
    // break: a spurious `pg_cancel_backend` racing the `ROLLBACK` would abort the
    // transaction and surface on the very next statement over the same pool.
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    let (executor, runtime) = harness(Arc::clone(&pools), ExecutionLimits::default()).await;
    let permit = runtime.acquire_query_permit().await.unwrap();

    for _ in 0..10 {
        let query = authorized(
            "SELECT i FROM generate_series(1, 20) i",
            Vec::new(),
            ExecutionLimits::default(),
        );
        let result = run(&executor, &permit, &query).await.unwrap();
        assert_eq!(result.rows.len(), 20);
        assert!(!result.truncated);
    }
    pools
        .health_check(Instant::now() + Duration::from_secs(5))
        .await
        .unwrap();

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
