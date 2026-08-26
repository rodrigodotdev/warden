//! Real-server lifecycle checks for the temporary named executor statement.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use sqlx::Row as _;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner};
use tokio::time::{Instant, sleep, timeout};
use tokio_util::sync::CancellationToken;
use warden_core::analysis::{QueryAnalysis, QueryAnalysisParts, StatementKind};
use warden_core::connection::{ConnectionMetadata, Environment};
use warden_core::context::RequestContext;
use warden_core::dialect::Dialect;
use warden_core::limits::ExecutionLimits;
use warden_core::parameter::ParameterValue;
use warden_core::pool::PoolSettings;
use warden_core::query::{InputLimits, QueryRequest};
use warden_core::secret::Dsn;
use warden_core::tls::{TlsMode, TlsSettings};
use warden_policy::{AnalyzedQuery, AuthorizedQuery, PolicyEngine, PolicySettings};
use warden_ports::error::ExecuteError;

use super::PostgreSqlQueryExecutor;
use crate::connection::{PostgreSqlConnectionConfig, PostgreSqlConnectionPools, SearchPath};
use crate::query::agent_query;

const PG_TAG: &str = "17-alpine";

async fn start_postgres() -> ContainerAsync<Postgres> {
    Postgres::default()
        .with_tag(PG_TAG)
        .start()
        .await
        .expect("failed to start the PostgreSQL container")
}

async fn dsn(container: &ContainerAsync<Postgres>) -> Dsn {
    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let mut value = String::from("postgres://postgres:postgres@");
    value.push_str(&host.to_string());
    value.push(':');
    value.push_str(&port.to_string());
    value.push_str("/postgres");
    value.parse().expect("the container DSN should be valid")
}

fn limits() -> ExecutionLimits {
    ExecutionLimits {
        max_concurrent_queries: 1,
        ..ExecutionLimits::default()
    }
}

fn config(dsn: Dsn) -> PostgreSqlConnectionConfig {
    PostgreSqlConnectionConfig {
        dsn,
        environment: Environment::Development,
        limits: limits(),
        agent_pool: PoolSettings {
            max_connections: 1,
            min_connections: 0,
            ..PoolSettings::agent()
        },
        control_pool: PoolSettings::control(),
        tls: TlsSettings {
            mode: TlsMode::Disabled,
            root_certificate: None,
        },
        search_path: SearchPath::new(["public"]).unwrap(),
    }
}

fn authorized(sql: &str, parameters: Vec<ParameterValue>) -> AuthorizedQuery {
    let request = QueryRequest::new(
        "cleanup-db".parse().unwrap(),
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
    let context = RequestContext::new(
        "cleanup-request".parse().unwrap(),
        "alice@example.com".parse().unwrap(),
        "cleanup test".parse().unwrap(),
    );
    let metadata = ConnectionMetadata {
        name: "cleanup-db".parse().unwrap(),
        dialect: Dialect::PostgreSql,
        environment: Environment::Development,
        database: "postgres".to_owned(),
    };
    PolicyEngine::with_defaults(&PolicySettings::default())
        .unwrap()
        .authorize(
            &context,
            &metadata,
            AnalyzedQuery::new(request, analysis),
            limits(),
        )
        .unwrap()
}

async fn session_state(pools: &PostgreSqlConnectionPools) -> (i32, i64) {
    let mut connection = pools.agent().acquire().await.unwrap();
    let pid = agent_query("SELECT pg_backend_pid()")
        .fetch_one(&mut *connection)
        .await
        .unwrap()
        .try_get(0)
        .unwrap();
    let prepared = agent_query("SELECT count(*) FROM pg_prepared_statements")
        .fetch_one(&mut *connection)
        .await
        .unwrap()
        .try_get(0)
        .unwrap();
    (pid, prepared)
}

async fn assert_clean_on_same_session(pools: &PostgreSqlConnectionPools, expected_pid: i32) {
    let (pid, prepared) = session_state(pools).await;
    assert_eq!(
        pid, expected_pid,
        "cleanup unexpectedly replaced a healthy session"
    );
    assert_eq!(
        prepared, 0,
        "the session retained {prepared} named statements"
    );
}

async fn assert_no_named_statement_is_reusable(pools: &PostgreSqlConnectionPools) -> i32 {
    let (pid, prepared) = session_state(pools).await;
    assert_eq!(
        prepared, 0,
        "the session available after cleanup retained {prepared} named statements"
    );
    pid
}

/// Waits until the control session sees the bound persistent statement executing.
///
/// `pg_prepared_statements` is session-local, so it cannot inspect the busy agent
/// session. Seeing this exact long-running agent SQL in `pg_stat_activity` proves the
/// extended-query execution reached PostgreSQL; the binder's persistent statement has
/// therefore been prepared before a test cancels or drops the task.
async fn wait_for_agent_statement(pools: &PostgreSqlConnectionPools, backend_pid: i32) {
    timeout(Duration::from_secs(2), async {
        loop {
            let active: bool = agent_query(
                "SELECT state = 'active' AND query LIKE 'SELECT pg_sleep(3)%' \
                 FROM pg_stat_activity WHERE pid = $1",
            )
            .bind(backend_pid)
            .fetch_one(pools.control())
            .await
            .unwrap()
            .try_get(0)
            .unwrap();
            if active {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the persistent agent statement did not reach PostgreSQL");
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(4)
}

#[tokio::test]
async fn confirmed_cleanup_leaves_no_named_statement_after_success_or_errors() {
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    let executor = PostgreSqlQueryExecutor::new(Arc::clone(&pools));
    let cancel = CancellationToken::new();
    let (pid, prepared) = session_state(&pools).await;
    assert_eq!(prepared, 0);

    executor
        .run(
            &authorized("SELECT $1::int4 AS value", vec![ParameterValue::I64(1)]),
            deadline(),
            &cancel,
        )
        .await
        .unwrap();
    assert_clean_on_same_session(&pools, pid).await;

    let execution_error = executor
        .run(&authorized("SELECT 1 / 0", Vec::new()), deadline(), &cancel)
        .await
        .expect_err("division by zero must reach the executor error path");
    assert!(matches!(execution_error, ExecuteError::Database { .. }));
    assert_clean_on_same_session(&pools, pid).await;

    let normalization_error = executor
        .run(
            &authorized("SELECT '1 day'::interval AS span", Vec::new()),
            deadline(),
            &cancel,
        )
        .await
        .expect_err("interval must be refused by the closed normalizer");
    assert!(matches!(
        normalization_error,
        ExecuteError::Normalization(_)
    ));
    assert_clean_on_same_session(&pools, pid).await;

    pools.close().await;
}

#[tokio::test]
async fn confirmed_cleanup_leaves_no_named_statement_after_cancellation() {
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    let executor = Arc::new(PostgreSqlQueryExecutor::new(Arc::clone(&pools)));
    let (pid, prepared) = session_state(&pools).await;
    assert_eq!(prepared, 0);
    let cancel = CancellationToken::new();
    let running = tokio::spawn({
        let executor = Arc::clone(&executor);
        let query = authorized("SELECT pg_sleep(3)", Vec::new());
        let cancellation = cancel.clone();
        async move { executor.run(&query, deadline(), &cancellation).await }
    });
    wait_for_agent_statement(&pools, pid).await;
    cancel.cancel();

    let error = running
        .await
        .unwrap()
        .expect_err("the token must stop the in-flight query");
    assert_eq!(error, ExecuteError::Cancelled);
    let reusable_pid = assert_no_named_statement_is_reusable(&pools).await;
    if reusable_pid == pid {
        assert_clean_on_same_session(&pools, pid).await;
    }

    pools.close().await;
}

#[tokio::test]
async fn dropping_after_a_named_agent_statement_starts_retires_its_session() {
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    let (pid, prepared) = session_state(&pools).await;
    assert_eq!(prepared, 0);
    let executor = Arc::new(PostgreSqlQueryExecutor::new(Arc::clone(&pools)));
    let running = tokio::spawn({
        let executor = Arc::clone(&executor);
        let query = authorized("SELECT pg_sleep(3)", Vec::new());
        async move {
            executor
                .run(&query, deadline(), &CancellationToken::new())
                .await
        }
    });
    wait_for_agent_statement(&pools, pid).await;
    running.abort();
    let aborted = running
        .await
        .expect_err("aborting the executor task must cancel it");
    assert!(aborted.is_cancelled());

    let (replacement_pid, replacement_prepared) = session_state(&pools).await;
    assert_ne!(
        replacement_pid, pid,
        "a dropped executor task returned its named-statement session to the pool"
    );
    assert_eq!(
        replacement_prepared, 0,
        "the replacement session inherited named statements"
    );

    pools.close().await;
}

#[tokio::test]
async fn an_unconfirmed_cleanup_retires_the_session_instead_of_reusing_it() {
    let container = start_postgres().await;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(config(dsn(&container).await))
            .await
            .unwrap(),
    );
    let (pid, prepared) = session_state(&pools).await;
    assert_eq!(prepared, 0);
    let executor = PostgreSqlQueryExecutor::with_unconfirmed_cleanup(Arc::clone(&pools));

    executor
        .run(
            &authorized("SELECT $1::int4 AS value", vec![ParameterValue::I64(1)]),
            deadline(),
            &CancellationToken::new(),
        )
        .await
        .unwrap();

    let (replacement_pid, replacement_prepared) = session_state(&pools).await;
    assert_ne!(
        replacement_pid, pid,
        "an unconfirmed session returned to the pool"
    );
    assert_eq!(
        replacement_prepared, 0,
        "the replacement session inherited named statements"
    );

    pools.close().await;
}
