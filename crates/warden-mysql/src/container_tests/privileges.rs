//! What the database itself refuses, with every Warden layer removed.
//!
//! These tests deliberately bypass the analyzer, the policy engine and the executor.
//! They open Warden's own pools with Warden's own role and send the write directly,
//! because the property under test is ADR-0016: the role has no write privilege, and
//! that is true whether or not anything above it works. A test that asserted "policy
//! denied it" would pass on a deployment whose role could drop the table.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use sqlx::AssertSqlSafe;
use sqlx::mysql::MySqlDatabaseError;
use testcontainers_modules::mysql::Mysql;
use testcontainers_modules::testcontainers::ContainerAsync;
use warden_core::connection::{ConnectionMetadata, Environment};
use warden_core::context::RequestContext;
use warden_core::dialect::Dialect;
use warden_core::limits::ExecutionLimits;
use warden_core::query::{InputLimits, QueryRequest};
use warden_core::secret::Dsn;
use warden_policy::{PolicyEngine, PolicySettings};
use warden_ports::QueryAnalyzer;

use super::{config, dsn, start_mysql, tls};
use crate::analyzer::MySqlAnalyzer;
use crate::connection::MySqlConnectionPools;

/// The account Warden connects as in these tests.
const ROLE: &str = "warden_ro";
/// Its password. A container-local literal; no production value is involved.
const ROLE_PASSWORD: &str = "warden-ro-password";

/// Creates the reporting fixture and the least-privilege role that may read part of
/// it.
///
/// The grant is the shape `docs/security.md` section 4 recommends: `SELECT` on the
/// tables the agent needs, nothing else, and no `FILE` privilege at all. `secrets`
/// exists to prove the point ADR-0023 makes — the read boundary is the `GRANT`, not
/// Warden's allowlist.
async fn provision(root: &MySqlConnectionPools) {
    for statement in [
        "CREATE TABLE orders (id BIGINT PRIMARY KEY, total DECIMAL(10,2))",
        "CREATE TABLE secrets (id BIGINT PRIMARY KEY, token VARCHAR(64))",
        "INSERT INTO orders (id, total) VALUES (1, 10.50)",
        "INSERT INTO secrets (id, token) VALUES (1, 'not-for-the-agent')",
    ] {
        sqlx::query(statement)
            .execute(root.control())
            .await
            .unwrap();
    }
    for statement in [
        format!("CREATE USER '{ROLE}'@'%' IDENTIFIED BY '{ROLE_PASSWORD}'"),
        format!("GRANT SELECT ON test.orders TO '{ROLE}'@'%'"),
    ] {
        sqlx::query(AssertSqlSafe(statement))
            .execute(root.control())
            .await
            .unwrap();
    }
}

/// The MySQL error number behind a driver failure, when there is one.
///
/// The number, not the SQLSTATE: `ER_TABLEACCESS_DENIED_ERROR` and
/// `ER_SPECIFIC_ACCESS_DENIED_ERROR` share `42000` and `HY000` respectively with
/// unrelated failures, and a test that accepted either would pass on the wrong
/// refusal (ADR-0033).
fn mysql_error_number(error: &sqlx::Error) -> Option<u16> {
    error
        .as_database_error()
        .and_then(|database| database.try_downcast_ref::<MySqlDatabaseError>())
        .map(MySqlDatabaseError::number)
}

/// The container's DSN with Warden's least-privilege role in place of root.
///
/// Built as a string and parsed into a `Dsn` so that even a test fixture goes
/// through ADR-0031's validation rather than around it.
async fn role_dsn(container: &ContainerAsync<Mysql>) -> Dsn {
    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(3306).await.unwrap();
    format!("mysql://{ROLE}:{ROLE_PASSWORD}@{host}:{port}/test")
        .parse()
        .unwrap()
}

/// Every write statement Warden's analyzer and policy engine already deny, kept in
/// one place so the container test and the both-barriers test below exercise
/// exactly the same list.
const DENIED_WRITES: [&str; 5] = [
    "INSERT INTO orders (id, total) VALUES (2, 1.00)",
    "UPDATE orders SET total = 0",
    "DELETE FROM orders",
    "CREATE TABLE scratch (id INT)",
    "DROP TABLE orders",
];

/// A fixed request identity, matching `execution.rs`'s own fixture.
fn context() -> RequestContext {
    RequestContext::new(
        "req-1".parse().unwrap(),
        "alice@example.com".parse().unwrap(),
        "Claude Code".parse().unwrap(),
    )
}

/// The connection every fixture targets, matching the `QueryRequest` below.
fn metadata() -> ConnectionMetadata {
    ConnectionMetadata {
        name: "production-db".parse().unwrap(),
        dialect: Dialect::MySql,
        environment: Environment::Development,
        database: "test".to_owned(),
    }
}

/// The default engine every deployment uses.
fn engine() -> PolicyEngine {
    PolicyEngine::with_defaults(&PolicySettings::default()).unwrap()
}

#[tokio::test]
async fn the_role_refuses_every_write_warden_never_sends() {
    let container = start_mysql().await;
    let root = MySqlConnectionPools::connect(config(dsn(&container).await, tls()))
        .await
        .unwrap();
    provision(&root).await;

    let warden = MySqlConnectionPools::connect(config(role_dsn(&container).await, tls()))
        .await
        .unwrap();

    // Each of these is a statement Warden's analyzer and policy engine already deny.
    // They are sent anyway, from Warden's own account: if the layers above ever fail,
    // this is the barrier that has to hold (ADR-0016).
    for statement in DENIED_WRITES {
        let error = sqlx::query(AssertSqlSafe(statement.to_owned()))
            .execute(warden.agent())
            .await
            .unwrap_err();
        let number = mysql_error_number(&error);
        // ER_TABLEACCESS_DENIED_ERROR or ER_DBACCESS_DENIED_ERROR
        assert!(
            matches!(number, Some(1142 | 1044)),
            "{statement} was not refused by the role: {error:?}"
        );
    }

    // The same account still reads what it was granted, so the refusals above are
    // about privileges and not about an unusable connection.
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM orders")
        .fetch_one(warden.agent())
        .await
        .unwrap();
    assert_eq!(total, 1);
}

#[tokio::test]
async fn the_grant_is_the_read_boundary_and_the_allowlist_is_not() {
    // SPEC section 7 and ADR-0023 both say this in prose. This is the test that makes
    // it true of a running deployment: `secrets` is not in any Warden configuration,
    // and the role simply cannot see it.
    let container = start_mysql().await;
    let root = MySqlConnectionPools::connect(config(dsn(&container).await, tls()))
        .await
        .unwrap();
    provision(&root).await;
    let warden = MySqlConnectionPools::connect(config(role_dsn(&container).await, tls()))
        .await
        .unwrap();

    let error = sqlx::query("SELECT token FROM secrets")
        .fetch_one(warden.agent())
        .await
        .unwrap_err();
    assert_eq!(mysql_error_number(&error), Some(1142), "{error:?}");
}

#[tokio::test]
async fn file_access_is_refused_by_privileges_as_well_as_by_policy() {
    // SPEC section 6, invariant 9 is enforced by the analyzer, which denies these
    // before they are sent. `docs/security.md` section 3 requires the second barrier
    // to be tested too: no FILE privilege.
    let container = start_mysql().await;
    let root = MySqlConnectionPools::connect(config(dsn(&container).await, tls()))
        .await
        .unwrap();
    provision(&root).await;
    let warden = MySqlConnectionPools::connect(config(role_dsn(&container).await, tls()))
        .await
        .unwrap();

    let outfile = sqlx::query("SELECT id FROM orders INTO OUTFILE '/tmp/warden-test'")
        .execute(warden.agent())
        .await
        .unwrap_err();
    // ER_SPECIFIC_ACCESS_DENIED_ERROR
    assert_eq!(mysql_error_number(&outfile), Some(1227), "{outfile:?}");

    // LOAD_FILE returns NULL rather than failing without FILE, which is why the
    // analyzer denying it is the primary control and this is reinforcement.
    let loaded: Option<Vec<u8>> = sqlx::query_scalar("SELECT LOAD_FILE('/etc/hostname')")
        .fetch_one(warden.agent())
        .await
        .unwrap();
    assert_eq!(loaded, None);
}

#[tokio::test]
async fn the_analyzer_and_policy_engine_deny_every_statement_before_it_is_ever_sent() {
    // The role's own refusal is proven above with every Warden layer removed. This
    // is the other half: the same statements are denied *before* execution too, so
    // the milestone shows both barriers rather than only the lower one.
    let outfile = "SELECT id FROM orders INTO OUTFILE '/tmp/warden-test'";
    for sql in DENIED_WRITES.into_iter().chain([outfile]) {
        let request = QueryRequest::new(
            "production-db".parse().unwrap(),
            sql.to_owned(),
            Vec::new(),
            &InputLimits::default(),
        )
        .unwrap();
        let analyzed = MySqlAnalyzer::new().analyze(request).unwrap();
        let outcome = engine().authorize(
            &context(),
            &metadata(),
            analyzed,
            ExecutionLimits::default(),
        );
        assert!(
            outcome.is_err(),
            "{sql} was not denied by the policy engine"
        );
    }
}
