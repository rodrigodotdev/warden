//! What only a real PostgreSQL server can prove.
//!
//! These run under `cargo test -p warden-postgres --features docker`, never under
//! the `cargo test --workspace` gate, and they are unit tests rather than
//! integration tests because they need the crate-private pool accessors and
//! `agent_query`.
//!
//! Every test starts its own container, so a test that saturates a pool cannot
//! change another test's result.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod execution;

use std::time::Duration;

use sqlx::{AssertSqlSafe, Row};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner};
use tokio::time::Instant;
use warden_core::connection::Environment;
use warden_core::limits::ExecutionLimits;
use warden_core::pool::PoolSettings;
use warden_core::secret::{Dsn, DsnError};
use warden_core::tls::{TlsMode, TlsSettings};

use crate::connection::{PostgreSqlConnectionConfig, PostgreSqlConnectionPools, SearchPath};
use crate::error::ConnectError;
use crate::query::agent_query;

/// The module defaults to an end-of-life release; testing needs a supported one.
const PG_TAG: &str = "17-alpine";

async fn start_postgres() -> ContainerAsync<Postgres> {
    Postgres::default()
        .with_tag(PG_TAG)
        .start()
        .await
        .expect("failed to start the PostgreSQL container")
}

/// The connection string for the container, with an explicit database as Warden
/// requires and an optional suffix for the DSNs that must be refused.
async fn connection_string(container: &ContainerAsync<Postgres>, suffix: &str) -> String {
    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    format!("postgres://postgres:postgres@{host}:{port}/postgres{suffix}")
}

/// A DSN for the container.
async fn dsn(container: &ContainerAsync<Postgres>) -> Dsn {
    connection_string(container, "")
        .await
        .parse()
        .expect("the container DSN should be valid")
}

/// The official PostgreSQL image serves no TLS. Cleartext is therefore allowed only
/// in development; Task 1's TLS policy rejects the same settings elsewhere.
fn config(dsn: Dsn) -> PostgreSqlConnectionConfig {
    PostgreSqlConnectionConfig {
        dsn,
        environment: Environment::Development,
        limits: ExecutionLimits::default(),
        agent_pool: PoolSettings::agent(),
        control_pool: PoolSettings::control(),
        tls: TlsSettings {
            mode: TlsMode::Disabled,
            root_certificate: None,
        },
        search_path: SearchPath::new(["public"]).unwrap(),
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

/// Reads one setting from `pg_settings` on the given pool.
async fn setting(pool: &sqlx::PgPool, name: &str) -> String {
    agent_query("SELECT setting FROM pg_settings WHERE name = $1")
        .bind(name)
        .fetch_one(pool)
        .await
        .map(|row| row.try_get::<String, _>("setting").unwrap())
        .unwrap_or_else(|error| panic!("failed to read {name}: {error}"))
}

#[tokio::test]
async fn the_startup_options_reach_the_server_on_both_pools() {
    let container = start_postgres().await;
    let pools = PostgreSqlConnectionPools::connect(config(dsn(&container).await))
        .await
        .unwrap();

    pools.verify_session_settings(deadline()).await.unwrap();

    // Assert the values directly too: `verify_session_settings` returning `Ok` would
    // also be consistent with it comparing something against itself.
    for pool in [pools.agent(), pools.control()] {
        assert_eq!(setting(pool, "statement_timeout").await, "5000");
        assert_eq!(
            setting(pool, "idle_in_transaction_session_timeout").await,
            "10000"
        );
        assert_eq!(setting(pool, "lock_timeout").await, "1000");
        assert_eq!(setting(pool, "default_transaction_read_only").await, "on");
        assert_eq!(setting(pool, "search_path").await, "public");
        assert_eq!(setting(pool, "application_name").await, "warden");
    }

    pools.close().await;
}

#[tokio::test]
async fn a_dsn_that_would_relax_the_startup_options_never_reaches_this_server() {
    // The end of the path ADR-0031 closes. `PgConnectOptions::options` appends and
    // PostgreSQL applies `-c` assignments in order, so a DSN that reached the driver
    // could add settings Warden pins nothing against — `row_security` is the one that
    // matters. It is refused while it is still a string.
    let container = start_postgres().await;
    let hostile = connection_string(
        &container,
        "?options=-c%20statement_timeout%3D0%20-c%20row_security%3Doff",
    )
    .await;
    assert_eq!(
        hostile.parse::<Dsn>().unwrap_err(),
        DsnError::UnsupportedParameter
    );

    // The same target without the parameter connects, and the server reports the
    // settings Warden pinned, so the refusal is about the parameter and not about an
    // unreachable server.
    let pools = PostgreSqlConnectionPools::connect(config(dsn(&container).await))
        .await
        .expect("connect should succeed without the parameter");
    assert_eq!(setting(pools.agent(), "statement_timeout").await, "5000");
    assert_eq!(
        setting(pools.agent(), "default_transaction_read_only").await,
        "on"
    );
    pools.verify_session_settings(deadline()).await.unwrap();

    pools.close().await;
}

#[tokio::test]
async fn the_server_refuses_a_write_in_the_hardened_session() {
    // The fourth independent write barrier of ADR-0024, after the parser, the policy
    // engine and the read-only transaction. No Warden policy runs here.
    let container = start_postgres().await;
    let pools = PostgreSqlConnectionPools::connect(config(dsn(&container).await))
        .await
        .unwrap();

    let error = agent_query("CREATE TABLE should_fail (id integer)")
        .execute(pools.agent())
        .await
        .expect_err("the server accepted DDL in a read-only session");

    let code = match &error {
        sqlx::Error::Database(database) => database
            .code()
            .map(|code| code.into_owned())
            .unwrap_or_default(),
        other => panic!("expected a database error, got {other:?}"),
    };
    // 25006 is read_only_sql_transaction.
    assert_eq!(code, "25006", "unexpected SQLSTATE; full error: {error}");

    pools.close().await;
}

#[tokio::test]
async fn the_agent_pool_retains_no_prepared_statements() {
    // `pg_prepared_statements` is session-local, so the whole exercise stays on one
    // pinned connection. `agent_query` is what changes that behaviour.
    let container = start_postgres().await;
    let pools = PostgreSqlConnectionPools::connect(config(dsn(&container).await))
        .await
        .unwrap();

    let mut connection = pools.agent().acquire().await.unwrap();

    for n in 0..20_i32 {
        // The only interpolated value is this test-controlled integer.
        let value: i32 = agent_query(AssertSqlSafe(format!("SELECT {n}")))
            .fetch_one(&mut *connection)
            .await
            .map(|row| row.try_get::<i32, _>(0).unwrap())
            .unwrap();
        assert_eq!(value, n);
    }

    let retained: i64 = agent_query("SELECT count(*) FROM pg_prepared_statements")
        .fetch_one(&mut *connection)
        .await
        .map(|row| row.try_get::<i64, _>(0).unwrap())
        .unwrap();
    assert_eq!(
        retained, 0,
        "the agent pool retained {retained} prepared statements; \
         statement_cache_capacity(0) plus persistent(false) was ineffective"
    );

    drop(connection);
    pools.close().await;
}

#[tokio::test]
async fn the_pool_ceiling_and_acquire_timeout_bound_the_sixth_caller() {
    let container = start_postgres().await;
    let pools = PostgreSqlConnectionPools::connect(config(dsn(&container).await))
        .await
        .unwrap();

    // SQLx exposes the live pool's options through Debug but no individual pool
    // getters. Pin all three limits here, then prove the maximum and timeout again by
    // saturating the server-backed pool below.
    let configured = format!("{:?}", pools.agent());
    assert!(configured.contains("max_connections: 5"), "{configured}");
    assert!(configured.contains("min_connections: 0"), "{configured}");
    assert!(configured.contains("connect_timeout: 3s"), "{configured}");

    let mut held = Vec::new();
    for _ in 0..5 {
        held.push(pools.agent().acquire().await.expect("five must fit"));
    }
    assert_eq!(pools.agent().size(), 5);

    let started = std::time::Instant::now();
    let error = pools
        .agent()
        .acquire()
        .await
        .expect_err("the sixth caller must not get a connection");
    let elapsed = started.elapsed();

    assert!(
        matches!(error, sqlx::Error::PoolTimedOut),
        "expected a pool timeout, got {error:?}"
    );
    assert!(
        elapsed >= Duration::from_secs(3) && elapsed < Duration::from_secs(6),
        "waited {elapsed:?}; the acquire timeout is 3s"
    );

    drop(held);
    pools.close().await;
}

#[tokio::test]
async fn the_health_check_survives_a_saturated_agent_pool() {
    let container = start_postgres().await;
    let pools = PostgreSqlConnectionPools::connect(config(dsn(&container).await))
        .await
        .unwrap();

    let mut held = Vec::new();
    for _ in 0..5 {
        held.push(pools.agent().acquire().await.unwrap());
    }

    pools
        .health_check(Instant::now() + Duration::from_secs(2))
        .await
        .expect("readiness must not depend on the agent pool");

    drop(held);
    pools.close().await;
}

#[tokio::test]
async fn required_tls_refuses_a_server_without_tls() {
    // `PgSslMode::Prefer` — the driver's default — would have connected in
    // cleartext and reported nothing. `Required` is legal only in development under
    // ADR-0030 because it does not verify a certificate; the assertion still proves
    // it cannot silently fall back when the server offers no TLS.
    let container = start_postgres().await;
    let cleartext = PostgreSqlConnectionPools::connect(config(dsn(&container).await))
        .await
        .expect("the TLS-less container must accept the disabled-mode control");
    cleartext
        .health_check(deadline())
        .await
        .expect("the disabled-mode control connection must be usable");
    cleartext.close().await;

    let mut required = config(dsn(&container).await);
    required.tls = TlsSettings {
        mode: TlsMode::Required,
        root_certificate: None,
    };

    let error = PostgreSqlConnectionPools::connect(required)
        .await
        .expect_err("connected to a server without TLS while requiring it");
    let detail = match &error {
        ConnectError::Driver { detail } => detail,
        other => panic!("expected a TLS driver error, got {other:?}"),
    };
    assert!(
        detail
            .to_ascii_lowercase()
            .contains("server does not support tls"),
        "expected the driver's TLS-refusal detail, got {detail:?}"
    );
    assert_eq!(
        error.to_string(),
        "the database connection could not be established"
    );
}

#[tokio::test]
async fn a_closed_pool_reports_a_failed_health_check_rather_than_hanging() {
    let container = start_postgres().await;
    let pools = PostgreSqlConnectionPools::connect(config(dsn(&container).await))
        .await
        .unwrap();

    pools.health_check(deadline()).await.unwrap();
    pools.close().await;

    let error = pools
        .health_check(deadline())
        .await
        .expect_err("a closed pool cannot be healthy");
    assert!(matches!(error, ConnectError::Driver { .. }), "{error:?}");
}
