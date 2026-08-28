//! What only a real MySQL server can prove.
//!
//! These run under `cargo test -p warden-mysql --features docker`, never under the
//! `cargo test --workspace` gate, and they are unit tests rather than integration
//! tests because they need the crate-private pool accessors — the accessors that
//! exist so no SQLx type reaches the public surface.
//!
//! Every test starts its own container. That is slower than sharing one and it is
//! what keeps a test that saturates a pool or exhausts prepared statements from
//! changing another test's result.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod execution;
mod inspection;
mod privileges;

use std::path::{Path, PathBuf};
use std::time::Duration;

use sqlx::{AssertSqlSafe, Row};
use testcontainers_modules::mysql::Mysql;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner};
use tokio::time::Instant;
use warden_core::connection::Environment;
use warden_core::limits::ExecutionLimits;
use warden_core::pool::PoolSettings;
use warden_core::secret::{Dsn, DsnError};
use warden_core::tls::{TlsMode, TlsSettings};

use crate::connection::{MySqlConnectionConfig, MySqlConnectionPools};
use crate::error::ConnectError;

/// `docs/testing.md` section 4 requires MySQL 8.4; the module defaults to 8.1.
const MYSQL_TAG: &str = "8.4";

/// The server's auto-generated certificate authority, created on first start.
const CONTAINER_CA_PATH: &str = "/var/lib/mysql/ca.pem";

async fn start_mysql() -> ContainerAsync<Mysql> {
    Mysql::default()
        .with_tag(MYSQL_TAG)
        .start()
        .await
        .expect("failed to start the MySQL container")
}

/// The connection string for the container, with an explicit database as Warden
/// requires and an optional suffix for the DSNs that must be refused.
async fn connection_string(container: &ContainerAsync<Mysql>, suffix: &str) -> String {
    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(3306).await.unwrap();
    format!("mysql://root@{host}:{port}/test{suffix}")
}

/// A DSN for the container.
async fn dsn(container: &ContainerAsync<Mysql>) -> Dsn {
    connection_string(container, "")
        .await
        .parse()
        .expect("the container DSN should be valid")
}

fn config(dsn: Dsn, tls: TlsSettings) -> MySqlConnectionConfig {
    MySqlConnectionConfig {
        dsn,
        // `Required` deliberately omits certificate verification, so ADR-0030
        // confines it to development. The verification tests below add the
        // container's generated CA and exercise the stricter modes separately.
        environment: Environment::Development,
        limits: ExecutionLimits::default(),
        agent_pool: PoolSettings::agent(),
        control_pool: PoolSettings::control(),
        tls,
    }
}

/// A copied container certificate removed on both success and panic paths.
#[derive(Debug)]
struct TemporaryCertificate {
    path: PathBuf,
}

impl TemporaryCertificate {
    /// Copies the container's own certificate authority to a local file.
    async fn from_container(container: &ContainerAsync<Mysql>) -> Self {
        let bytes = container
            .copy_file_from(CONTAINER_CA_PATH, Vec::new())
            .await
            .expect("failed to read the container's CA certificate");
        let path = std::env::temp_dir().join(format!(
            "warden-m6-mysql-ca-{}-{:?}.pem",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, bytes).expect("failed to write the CA certificate");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryCertificate {
    fn drop(&mut self) {
        // Drop runs during test unwinding too, so a failing assertion does not leave
        // an extracted authority behind in the host's temporary directory.
        let _ignored = std::fs::remove_file(&self.path);
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

/// The TLS settings both submodules use.
///
/// Certificate verification has its own tests above; execution and privilege tests
/// only need the handshake to happen.
fn tls() -> TlsSettings {
    TlsSettings {
        mode: TlsMode::Required,
        root_certificate: None,
    }
}

#[tokio::test]
async fn connects_over_a_real_tls_handshake() {
    let container = start_mysql().await;
    let pools = MySqlConnectionPools::connect(config(
        dsn(&container).await,
        TlsSettings {
            mode: TlsMode::Required,
            root_certificate: None,
        },
    ))
    .await
    .expect("connect should succeed with TLS required");

    for pool in [pools.agent(), pools.control()] {
        let row = sqlx::query("SHOW STATUS LIKE 'Ssl_cipher'")
            .fetch_one(pool)
            .await
            .unwrap();
        let cipher: String = row.try_get(1).unwrap();
        assert!(!cipher.is_empty(), "the connection is not using TLS");
    }

    pools.close().await;
}

#[tokio::test]
async fn a_dsn_that_would_downgrade_tls_never_reaches_this_server() {
    // The end of the path ADR-0031 closes: this exact string, against this exact
    // running server, is the one an operator pastes to turn TLS off. It is refused
    // while it is still a string, so the driver never sees a downgrade to ignore.
    let container = start_mysql().await;
    let hostile = connection_string(&container, "?ssl-mode=disabled").await;
    assert_eq!(
        hostile.parse::<Dsn>().unwrap_err(),
        DsnError::UnsupportedParameter
    );

    // The same target without the parameter connects, and connects over TLS, so the
    // refusal above is about the parameter and not about an unreachable server.
    let pools = MySqlConnectionPools::connect(config(
        dsn(&container).await,
        TlsSettings {
            mode: TlsMode::Required,
            root_certificate: None,
        },
    ))
    .await
    .expect("connect should succeed without the parameter");
    let row = sqlx::query("SHOW STATUS LIKE 'Ssl_cipher'")
        .fetch_one(pools.agent())
        .await
        .unwrap();
    let cipher: String = row.try_get(1).unwrap();
    assert!(!cipher.is_empty(), "the connection is not using TLS");

    pools.close().await;
}

#[tokio::test]
async fn a_private_root_certificate_is_honored() {
    let container = start_mysql().await;
    let ca = TemporaryCertificate::from_container(&container).await;

    let pools = MySqlConnectionPools::connect(config(
        dsn(&container).await,
        TlsSettings {
            mode: TlsMode::VerifyCa,
            root_certificate: Some(ca.path().to_path_buf()),
        },
    ))
    .await
    .expect("connect should succeed against the container's own CA");

    pools.health_check(deadline()).await.unwrap();
    pools.close().await;
}

#[tokio::test]
async fn identity_verification_rejects_a_hostname_mismatch() {
    let container = start_mysql().await;
    let ca = TemporaryCertificate::from_container(&container).await;

    // The same container and CA must first pass chain verification. That isolates
    // the next failure to hostname identity rather than a bad authority or server.
    let chain_verified = MySqlConnectionPools::connect(config(
        dsn(&container).await,
        TlsSettings {
            mode: TlsMode::VerifyCa,
            root_certificate: Some(ca.path().to_path_buf()),
        },
    ))
    .await
    .expect("the copied container CA should verify its own certificate");
    chain_verified.health_check(deadline()).await.unwrap();
    chain_verified.close().await;

    let error = MySqlConnectionPools::connect(config(
        dsn(&container).await,
        TlsSettings {
            mode: TlsMode::VerifyIdentity,
            root_certificate: Some(ca.path().to_path_buf()),
        },
    ))
    .await
    .expect_err("identity verification should reject the generated certificate");

    assert!(matches!(error, ConnectError::Driver { .. }), "{error:?}");
    assert_eq!(
        error.to_string(),
        "the database connection could not be established"
    );
}

#[tokio::test]
async fn the_server_side_deadline_reaches_both_pools() {
    let container = start_mysql().await;
    let pools = MySqlConnectionPools::connect(config(
        dsn(&container).await,
        TlsSettings {
            mode: TlsMode::Required,
            root_certificate: None,
        },
    ))
    .await
    .unwrap();

    pools.verify_session_settings(deadline()).await.unwrap();

    for pool in [pools.agent(), pools.control()] {
        let configured: i64 =
            sqlx::query_scalar("SELECT CAST(@@SESSION.MAX_EXECUTION_TIME AS SIGNED)")
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(configured, 5_000);
    }

    pools.close().await;
}

#[tokio::test]
async fn the_agent_pool_retains_no_prepared_statements() {
    let container = start_mysql().await;
    let pools = MySqlConnectionPools::connect(config(
        dsn(&container).await,
        TlsSettings {
            mode: TlsMode::Required,
            root_certificate: None,
        },
    ))
    .await
    .unwrap();

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
        let value: i64 = sqlx::query_scalar(AssertSqlSafe(format!("SELECT {n}")))
            .fetch_one(pools.agent())
            .await
            .unwrap();
        assert_eq!(value, n);
    }

    let after = prepared_statements(&mut observer).await;
    assert_eq!(
        after,
        before,
        "the agent pool retained {} prepared statements; \
         statement_cache_capacity(0) was ineffective",
        after - before
    );

    drop(observer);
    pools.close().await;
}

#[tokio::test]
async fn the_pool_ceiling_and_acquire_timeout_bound_the_sixth_caller() {
    let container = start_mysql().await;
    let pools = MySqlConnectionPools::connect(config(
        dsn(&container).await,
        TlsSettings {
            mode: TlsMode::Required,
            root_certificate: None,
        },
    ))
    .await
    .unwrap();

    // SQLx exposes the live pool's options through Debug but no individual pool
    // getters. Pin all three limits here, then prove the max and timeout again by
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
    let container = start_mysql().await;
    let pools = MySqlConnectionPools::connect(config(
        dsn(&container).await,
        TlsSettings {
            mode: TlsMode::Required,
            root_certificate: None,
        },
    ))
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
async fn a_closed_pool_reports_a_failed_health_check_rather_than_hanging() {
    let container = start_mysql().await;
    let pools = MySqlConnectionPools::connect(config(
        dsn(&container).await,
        TlsSettings {
            mode: TlsMode::Required,
            root_certificate: None,
        },
    ))
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
