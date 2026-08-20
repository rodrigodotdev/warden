//! DISPOSABLE—Milestone 0.5 MySQL probe.
//!
//! Validates a real TLS handshake, server-side `MAX_EXECUTION_TIME` configured
//! through `after_connect`, and the effect of keeping `mysql-rsa` disabled.
//!
//! Empirical deviation from the original brief: on MySQL 8.4.11, `BENCHMARK` stops
//! at `MAX_EXECUTION_TIME` but swallows the interruption and returns `0`. The deadline
//! test therefore uses a real Cartesian-product read that propagates
//! `ER_QUERY_TIMEOUT`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;

use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions, MySqlSslMode};
use sqlx::{MySql, Pool};
use testcontainers_modules::mysql::Mysql;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner};

/// `docs/testing.md` section 4 requires MySQL 8.4; the module defaults to 8.1.
const MYSQL_TAG: &str = "8.4";

/// Concrete MySQL value from `docs/operations.md` section 5.2.
const MAX_EXECUTION_TIME_MS: i64 = 5000;

/// Password-bearing user used to exercise `caching_sha2_password` key exchange.
const INIT_SQL: &str = "\
CREATE USER 'warden_probe'@'%' IDENTIFIED WITH caching_sha2_password BY 'probe-secret';
GRANT SELECT ON test.* TO 'warden_probe'@'%';
FLUSH PRIVILEGES;
";

async fn start_mysql() -> ContainerAsync<Mysql> {
    Mysql::default()
        .with_init_sql(INIT_SQL.as_bytes().to_vec())
        .with_tag(MYSQL_TAG)
        .start()
        .await
        .expect("failed to start the MySQL container")
}

async fn options(
    container: &ContainerAsync<Mysql>,
    user: &str,
    password: &str,
) -> MySqlConnectOptions {
    let host = container.get_host().await.unwrap().to_string();
    let port = container.get_host_port_ipv4(3306).await.unwrap();

    MySqlConnectOptions::new()
        .host(&host)
        .port(port)
        .username(user)
        .password(password)
        .database("test")
}

/// Agent-pool shape from `docs/architecture.md` section 6.1, with the
/// `after_connect` hook from `docs/operations.md` section 5.2.
async fn agent_pool(options: MySqlConnectOptions) -> Pool<MySql> {
    MySqlPoolOptions::new()
        .max_connections(2)
        .min_connections(0)
        .acquire_timeout(Duration::from_secs(10))
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                sqlx::query("SET SESSION MAX_EXECUTION_TIME = ?")
                    .bind(MAX_EXECUTION_TIME_MS)
                    .execute(conn)
                    .await?;
                Ok(())
            })
        })
        .connect_with(options.statement_cache_capacity(0))
        .await
        .expect("failed to connect to MySQL")
}

#[tokio::test]
async fn selects_one_over_a_real_tls_handshake() {
    let container = start_mysql().await;
    let pool = agent_pool(
        options(&container, "root", "")
            .await
            .ssl_mode(MySqlSslMode::Required),
    )
    .await;

    let one: i64 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(one, 1);

    // `Ssl_cipher` proves encryption rather than mere acceptance of the TLS option.
    let (_name, cipher): (String, String) = sqlx::query_as("SHOW STATUS LIKE 'Ssl_cipher'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        !cipher.is_empty(),
        "Ssl_cipher is empty; the connection is not using TLS despite ssl_mode=Required"
    );
    eprintln!("selects_one_over_a_real_tls_handshake: Ssl_cipher = {cipher}");

    pool.close().await;
}

#[tokio::test]
async fn after_connect_applies_the_server_side_deadline() {
    let container = start_mysql().await;
    let pool = agent_pool(
        options(&container, "root", "")
            .await
            .ssl_mode(MySqlSslMode::Required),
    )
    .await;

    // CAST bridges the server's unsigned BIGINT to this test's signed constant.
    let configured: i64 = sqlx::query_scalar("SELECT CAST(@@SESSION.MAX_EXECUTION_TIME AS SIGNED)")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(configured, MAX_EXECUTION_TIME_MS);
    eprintln!(
        "after_connect_applies_the_server_side_deadline: @@SESSION.MAX_EXECUTION_TIME = {configured}"
    );

    pool.close().await;
}

#[tokio::test]
async fn the_server_side_deadline_actually_aborts_a_slow_read() {
    // Avoid `SLEEP` and `BENCHMARK`: MySQL special-cases both and may return success
    // after interruption. This 10^7-row Cartesian product with chained SHA2 took
    // about 18.9s without a limit and failed after about 5.1s with the configured
    // deadline on MySQL 8.4.11.
    let container = start_mysql().await;
    let pool = agent_pool(
        options(&container, "root", "")
            .await
            .ssl_mode(MySqlSslMode::Required),
    )
    .await;

    let heavy_read = "\
        SELECT COUNT(*) FROM \
        (SELECT 1 n UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9 UNION ALL SELECT 10) t1 \
        CROSS JOIN (SELECT 1 n UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9 UNION ALL SELECT 10) t2 \
        CROSS JOIN (SELECT 1 n UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9 UNION ALL SELECT 10) t3 \
        CROSS JOIN (SELECT 1 n UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9 UNION ALL SELECT 10) t4 \
        CROSS JOIN (SELECT 1 n UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9 UNION ALL SELECT 10) t5 \
        CROSS JOIN (SELECT 1 n UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9 UNION ALL SELECT 10) t6 \
        CROSS JOIN (SELECT 1 n UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9 UNION ALL SELECT 10) t7 \
        WHERE SHA2(SHA2(SHA2(CONCAT(t1.n,t2.n,t3.n,t4.n,t5.n,t6.n,t7.n),512),512),512) LIKE '00%'";

    let started = std::time::Instant::now();
    let error = sqlx::query_scalar::<_, i64>(heavy_read)
        .fetch_one(&pool)
        .await
        .expect_err("query completed despite MAX_EXECUTION_TIME = 5000");

    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(20),
        "server took {elapsed:?} to abort; MAX_EXECUTION_TIME had no effect. Error: {error}"
    );

    // Server error 3024 is ER_QUERY_TIMEOUT with SQLSTATE HY000 on MySQL 8.4.11.
    if let sqlx::Error::Database(db) = &error {
        assert_eq!(
            db.code().map(|c| c.into_owned()).unwrap_or_default(),
            "HY000",
            "unexpected SQLSTATE; expected HY000 / ER_QUERY_TIMEOUT: {error}"
        );
    } else {
        panic!("expected a database error, got: {error:?}");
    }
    eprintln!(
        "the_server_side_deadline_actually_aborts_a_slow_read: aborted after {elapsed:?}: {error}"
    );

    pool.close().await;
}

#[tokio::test]
async fn plaintext_password_auth_without_mysql_rsa() {
    // Proves the docs/operations.md section 2.2 claim about disabled RSA exchange.
    let container = start_mysql().await;

    let result = MySqlPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(10))
        .connect_with(
            options(&container, "warden_probe", "probe-secret")
                .await
                .ssl_mode(MySqlSslMode::Disabled),
        )
        .await;

    let error = result.expect_err(
        "connected with caching_sha2_password over cleartext; the documented \
         behavior of disabled `mysql-rsa` must be corrected",
    );
    eprintln!("plaintext_password_auth_without_mysql_rsa: cleartext rejected: {error}");

    // Match the stable mechanism name without pinning SQLx's complete wording.
    let rendered = error.to_string();
    assert!(
        rendered.to_lowercase().contains("rsa"),
        "connection error does not mention RSA, so it does not prove rejection by \
         the disabled key-exchange backend. Full error: {rendered}"
    );

    // The same credentials must work over TLS, isolating cleartext as the cause.
    let pool = agent_pool(
        options(&container, "warden_probe", "probe-secret")
            .await
            .ssl_mode(MySqlSslMode::Required),
    )
    .await;
    let one: i64 = sqlx::query_scalar("SELECT 1")
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("credentials failed over TLS: {e}. Cleartext error: {error}"));
    assert_eq!(one, 1);

    pool.close().await;
}
