//! DISPOSABLE—Milestone 0.5 PostgreSQL probe.
//!
//! Confirms that the selected features can connect and read, startup options reach a
//! real server, `default_transaction_read_only` is an independent write barrier, and
//! SQLx's TLS path is compiled and active.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use sqlx::postgres::{PgConnectOptions, PgConnection, PgPoolOptions, PgSslMode};
use sqlx::{AssertSqlSafe, Pool, Postgres as PgDriver};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner};

/// Production startup settings from `docs/operations.md` sections 3 and 5.1.
const STATEMENT_TIMEOUT_MS: &str = "5000";
const IDLE_IN_TRANSACTION_TIMEOUT_MS: &str = "10000";
const LOCK_TIMEOUT_MS: &str = "1000";
const SEARCH_PATH: &str = "app,public";

/// The module defaults to EOL `11-alpine`; testing requires a supported release.
const PG_TAG: &str = "17-alpine";

async fn start_postgres() -> ContainerAsync<Postgres> {
    Postgres::default()
        .with_tag(PG_TAG)
        .start()
        .await
        .expect("failed to start the PostgreSQL container")
}

async fn base_options(container: &ContainerAsync<Postgres>) -> PgConnectOptions {
    let host = container.get_host().await.unwrap().to_string();
    let port = container.get_host_port_ipv4(5432).await.unwrap();

    PgConnectOptions::new()
        .host(&host)
        .port(port)
        .username("postgres")
        .password("postgres")
        .database("postgres")
}

/// Agent-pool shape prescribed by `docs/architecture.md` section 6.1.
async fn agent_pool(options: PgConnectOptions) -> Pool<PgDriver> {
    PgPoolOptions::new()
        .max_connections(2)
        .min_connections(0)
        .acquire_timeout(Duration::from_secs(3))
        .connect_with(
            // Statement cache capacity belongs to connect options, not pool options.
            options.statement_cache_capacity(0),
        )
        .await
        .expect("failed to connect to PostgreSQL")
}

#[tokio::test]
async fn selects_one_with_the_configured_feature_set() {
    let container = start_postgres().await;
    let pool = agent_pool(base_options(&container).await.ssl_mode(PgSslMode::Disable)).await;

    let one: i32 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(one, 1);

    pool.close().await;
}

#[tokio::test]
async fn startup_options_actually_reach_the_server() {
    let container = start_postgres().await;

    let options = base_options(&container)
        .await
        .ssl_mode(PgSslMode::Disable)
        .options([
            ("statement_timeout", STATEMENT_TIMEOUT_MS),
            (
                "idle_in_transaction_session_timeout",
                IDLE_IN_TRANSACTION_TIMEOUT_MS,
            ),
            ("lock_timeout", LOCK_TIMEOUT_MS),
            ("default_transaction_read_only", "on"),
            ("search_path", SEARCH_PATH),
        ]);

    let pool = agent_pool(options).await;

    async fn setting(pool: &Pool<PgDriver>, name: &str) -> String {
        sqlx::query_scalar("SELECT current_setting($1)")
            .bind(name)
            .fetch_one(pool)
            .await
            .unwrap_or_else(|e| panic!("failed to read current_setting('{name}'): {e}"))
    }

    // PostgreSQL may normalize the unit when reading the setting.
    let statement_timeout = setting(&pool, "statement_timeout").await;
    assert!(
        matches!(statement_timeout.as_str(), "5s" | "5000ms"),
        "statement_timeout did not reach the server: {statement_timeout:?}"
    );

    let lock_timeout = setting(&pool, "lock_timeout").await;
    assert!(
        matches!(lock_timeout.as_str(), "1s" | "1000ms"),
        "lock_timeout did not reach the server: {lock_timeout:?}"
    );

    assert_eq!(setting(&pool, "default_transaction_read_only").await, "on");

    let search_path = setting(&pool, "search_path").await;
    assert!(
        search_path.contains("app") && search_path.contains("public"),
        "search_path was not fixed: {search_path:?}"
    );

    pool.close().await;
}

#[tokio::test]
async fn default_transaction_read_only_blocks_writes_at_the_server() {
    // No Warden policy runs here; the server itself must enforce the fourth barrier.
    let container = start_postgres().await;

    let options = base_options(&container)
        .await
        .ssl_mode(PgSslMode::Disable)
        .options([("default_transaction_read_only", "on")]);

    let pool = agent_pool(options).await;

    let error = sqlx::query("CREATE TABLE should_fail (id integer)")
        .execute(&pool)
        .await
        .expect_err("server accepted DDL in a read-only session");

    let code = match &error {
        sqlx::Error::Database(db) => db.code().map(|c| c.into_owned()).unwrap_or_default(),
        other => panic!("expected a database error, got: {other:?}"),
    };
    // 25006 = read_only_sql_transaction
    assert_eq!(code, "25006", "unexpected SQLSTATE; full error: {error}");

    pool.close().await;
}

#[tokio::test]
async fn statement_cache_is_disabled_on_the_agent_pool() {
    // Keep each phase on one physical connection because pg_prepared_statements is
    // session-local. Phase 1 reproduces the named-statement leak with SQLx's default
    // persistence; phase 2 uses a fresh session and proves `.persistent(false)`
    // prevents it. The full mechanism is documented in operations section 4.

    async fn run_queries(conn: &mut PgConnection, persistent: bool) {
        for n in 0..20_i32 {
            // The only interpolated value is this test-controlled integer.
            let value: i32 = sqlx::query_scalar(AssertSqlSafe(format!("SELECT {n}")))
                .persistent(persistent)
                .fetch_one(&mut *conn)
                .await
                .unwrap();
            assert_eq!(value, n);
        }
    }

    async fn count_prepared(conn: &mut PgConnection) -> i64 {
        // Otherwise the count query's own named statement would count itself.
        sqlx::query_scalar("SELECT count(*) FROM pg_prepared_statements")
            .persistent(false)
            .fetch_one(conn)
            .await
            .unwrap()
    }

    let container = start_postgres().await;

    // Phase 1 reproduces the leak.
    let leaked = {
        let pool = agent_pool(base_options(&container).await.ssl_mode(PgSslMode::Disable)).await;
        let mut conn = pool.acquire().await.unwrap();
        run_queries(&mut conn, true).await;
        let leaked = count_prepared(&mut conn).await;
        drop(conn);
        pool.close().await;
        leaked
    };
    assert!(
        leaked > 0,
        "phase 1 expected prepared > 0 but measured {leaked}; if SQLx changed, \
         review docs/operations.md section 4"
    );
    eprintln!(
        "statement_cache_is_disabled_on_the_agent_pool: phase 1 retained {leaked} \
         prepared statements without .persistent(false)"
    );

    // Phase 2 proves the fix on a fresh session.
    let pool = agent_pool(base_options(&container).await.ssl_mode(PgSslMode::Disable)).await;
    let mut conn = pool.acquire().await.unwrap();
    run_queries(&mut conn, false).await;
    let prepared = count_prepared(&mut conn).await;
    assert_eq!(
        prepared, 0,
        "{prepared} prepared statements remained; \
         statement_cache_capacity(0) plus persistent(false) was ineffective"
    );
    drop(conn);
    pool.close().await;
}

#[tokio::test]
async fn tls_path_is_compiled_in_and_active() {
    // The official image has SSL disabled, so Require must reach TLS negotiation and
    // reject the server. Private-CA VerifyFull coverage belongs to Milestone 6.
    let container = start_postgres().await;

    let error = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(base_options(&container).await.ssl_mode(PgSslMode::Require))
        .await
        .expect_err("connected with ssl_mode=Require to a server without SSL");

    // Match the negotiation-specific error, not a generic TLS backend failure.
    let rendered = error.to_string().to_lowercase();
    assert!(
        rendered.contains("server does not support tls"),
        "expected TLS negotiation rejection (\"server does not support tls\"); \
         full error: {error}"
    );
}
