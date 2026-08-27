//! What the database itself refuses, with every Warden layer removed.
//!
//! These tests deliberately bypass the analyzer, the policy engine and the executor.
//! They open Warden's own pools with Warden's own role and send the write directly,
//! because the property under test is ADR-0016: the role has no write privilege, and
//! that is true whether or not anything above it works. A test that asserted "policy
//! denied it" would pass on a deployment whose role could drop the table.
//!
//! PostgreSQL needs one more layer removed than MySQL did. Warden pins
//! `default_transaction_read_only = on` at connect time, so an `INSERT` sent through
//! a hardened pool is refused as `25006 read_only_sql_transaction` before the
//! server ever consults the role's grants — the session barrier would mask the
//! privilege barrier, and the test would prove the wrong one. The write tests below
//! therefore turn that session default off on one pinned connection first, so the
//! `GRANT` is the only thing left standing. That is the point: the two barriers are
//! independent, and this file measures the lower one.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use sqlx::{AssertSqlSafe, Connection, Row};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ContainerAsync;
use warden_core::analysis::{FunctionClassification, RiskFlag, StatementKind};
use warden_core::connection::{ConnectionMetadata, Environment};
use warden_core::context::RequestContext;
use warden_core::dialect::Dialect;
use warden_core::limits::ExecutionLimits;
use warden_core::query::{InputLimits, QueryRequest};
use warden_core::secret::Dsn;
use warden_policy::{DenyCode, PolicyEngine, PolicySettings};
use warden_ports::QueryAnalyzer;

use super::{config, dsn, start_postgres};
use crate::analyzer::PostgreSqlAnalyzer;
use crate::connection::PostgreSqlConnectionPools;
use crate::query::agent_query;

/// The account Warden connects as in these tests.
const ROLE: &str = "warden_ro";
/// Its password. A container-local literal; no production value is involved.
const ROLE_PASSWORD: &str = "warden-ro-password";

/// Exact analyzer evidence and policy result expected for one denied statement.
#[derive(Debug, Clone, Copy)]
struct DeniedStatement {
    sql: &'static str,
    root_kind: StatementKind,
    nested_kinds: &'static [StatementKind],
    function: Option<(&'static str, FunctionClassification)>,
    risks: &'static [RiskFlag],
    primary_denial: DenyCode,
}

/// Every direct write attempt and its independently expected Warden evidence.
///
/// The direct privilege test below uses the first seven entries. The remaining
/// entries prove that policy recognizes both sequence mutation functions, the one
/// explicitly revoked function, and the two write-shaped SELECT variants.
const DENIED_STATEMENTS: [DeniedStatement; 12] = [
    DeniedStatement {
        sql: "INSERT INTO orders (id, owner, total) VALUES (3, 'warden_ro', 1.00)",
        root_kind: StatementKind::Insert,
        nested_kinds: &[],
        function: None,
        risks: &[RiskFlag::WriteStatement],
        primary_denial: DenyCode::WriteStatement,
    },
    DeniedStatement {
        sql: "UPDATE orders SET total = 0",
        root_kind: StatementKind::Update,
        nested_kinds: &[],
        function: None,
        risks: &[RiskFlag::WriteStatement],
        primary_denial: DenyCode::WriteStatement,
    },
    DeniedStatement {
        sql: "DELETE FROM orders",
        root_kind: StatementKind::Delete,
        nested_kinds: &[],
        function: None,
        risks: &[RiskFlag::WriteStatement],
        primary_denial: DenyCode::WriteStatement,
    },
    DeniedStatement {
        sql: "CREATE TABLE scratch (id integer)",
        root_kind: StatementKind::Ddl,
        nested_kinds: &[],
        function: None,
        risks: &[RiskFlag::Ddl],
        primary_denial: DenyCode::Ddl,
    },
    DeniedStatement {
        sql: "CREATE TEMP TABLE temporary_escape (id integer)",
        root_kind: StatementKind::Ddl,
        nested_kinds: &[],
        function: None,
        risks: &[RiskFlag::Ddl],
        primary_denial: DenyCode::Ddl,
    },
    DeniedStatement {
        sql: "DROP TABLE orders",
        root_kind: StatementKind::Ddl,
        nested_kinds: &[],
        function: None,
        risks: &[RiskFlag::Ddl],
        primary_denial: DenyCode::Ddl,
    },
    DeniedStatement {
        sql: "TRUNCATE orders",
        root_kind: StatementKind::Ddl,
        nested_kinds: &[],
        function: None,
        risks: &[RiskFlag::Ddl],
        primary_denial: DenyCode::Ddl,
    },
    DeniedStatement {
        sql: "SELECT nextval('order_ids')",
        root_kind: StatementKind::Select,
        nested_kinds: &[],
        function: Some(("nextval", FunctionClassification::KnownDangerous)),
        risks: &[RiskFlag::SequenceMutation],
        primary_denial: DenyCode::WriteStatement,
    },
    DeniedStatement {
        sql: "SELECT setval('order_ids', 10)",
        root_kind: StatementKind::Select,
        nested_kinds: &[],
        function: Some(("setval", FunctionClassification::KnownDangerous)),
        risks: &[RiskFlag::SequenceMutation],
        primary_denial: DenyCode::WriteStatement,
    },
    DeniedStatement {
        sql: "SELECT pg_sleep(0)",
        root_kind: StatementKind::Select,
        nested_kinds: &[],
        function: Some(("pg_sleep", FunctionClassification::KnownDangerous)),
        risks: &[RiskFlag::DelayFunction],
        primary_denial: DenyCode::DangerousFunction,
    },
    DeniedStatement {
        sql: "WITH gone AS (DELETE FROM orders RETURNING id) SELECT count(*) FROM gone",
        root_kind: StatementKind::Select,
        nested_kinds: &[StatementKind::Delete],
        function: Some(("count", FunctionClassification::KnownSafe)),
        risks: &[RiskFlag::WriteStatement, RiskFlag::DataModifyingCte],
        primary_denial: DenyCode::WriteStatement,
    },
    DeniedStatement {
        sql: "SELECT id INTO copied FROM orders",
        root_kind: StatementKind::Select,
        nested_kinds: &[],
        function: None,
        risks: &[RiskFlag::SelectInto],
        primary_denial: DenyCode::Ddl,
    },
];

/// Creates the reporting fixture and the least-privilege role that may read part of
/// it.
///
/// The grant is the shape `docs/security.md` section 4.2 recommends: `CONNECT` on
/// the database, `USAGE` on the approved schema, `SELECT` on the approved tables,
/// and nothing else — no schema `CREATE`, no database `TEMPORARY`, no table writes,
/// and no sequence privilege. `secrets` exists to prove ADR-0023's point twice over: the
/// role cannot read it at all, and a view the role *is* granted can read it anyway,
/// which is why the table allowlist is not a read-scope boundary.
///
/// Row Level Security on `orders` is the extra layer `docs/security.md` section 4.2
/// names. The policy is deliberately simple and role-derived so no session variable
/// has to be set for it to apply.
async fn provision(root: &PostgreSqlConnectionPools) {
    // The default transaction setting is correctly pinned on the control pool too.
    // Fixture administration is therefore an explicit, transaction-local exception:
    // it cannot weaken the session that returns to this pool, and it never touches
    // Warden's agent pool.
    let mut connection = root.control().acquire().await.unwrap();
    let mut transaction = connection.begin_with("BEGIN READ WRITE").await.unwrap();
    for statement in [
        "CREATE TABLE orders (id bigint PRIMARY KEY, owner text NOT NULL, total numeric(10,2))",
        "CREATE TABLE secrets (id bigint PRIMARY KEY, token text)",
        "CREATE SEQUENCE order_ids",
        "INSERT INTO orders VALUES (1, 'warden_ro', 10.50), (2, 'someone_else', 99.99)",
        "INSERT INTO secrets VALUES (1, 'not-for-the-agent')",
        "CREATE VIEW secret_peek AS SELECT token FROM secrets",
        "ALTER TABLE orders ENABLE ROW LEVEL SECURITY",
        "CREATE POLICY orders_own ON orders FOR SELECT USING (owner = current_user)",
        // PostgreSQL grants database CONNECT/TEMPORARY and function EXECUTE to
        // PUBLIC by default. Revoke the database defaults, then grant the role only
        // CONNECT below. Functions need individual, audited revokes: this fixture
        // proves only its explicit pg_sleep restriction, not a blanket function ban.
        "REVOKE CONNECT, TEMPORARY ON DATABASE postgres FROM PUBLIC",
        "REVOKE EXECUTE ON FUNCTION pg_sleep(double precision) FROM PUBLIC",
    ] {
        sqlx::query(AssertSqlSafe(statement.to_owned()))
            .execute(&mut *transaction)
            .await
            .unwrap();
    }
    for statement in [
        format!(
            "CREATE ROLE {ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE \
             NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD '{ROLE_PASSWORD}'"
        ),
        format!("GRANT CONNECT ON DATABASE postgres TO {ROLE}"),
        format!("GRANT USAGE ON SCHEMA public TO {ROLE}"),
        format!("GRANT SELECT ON orders TO {ROLE}"),
        format!("GRANT SELECT ON secret_peek TO {ROLE}"),
    ] {
        sqlx::query(AssertSqlSafe(statement))
            .execute(&mut *transaction)
            .await
            .unwrap();
    }
    transaction.commit().await.unwrap();

    let default_read_only: String = sqlx::query_scalar("SHOW default_transaction_read_only")
        .fetch_one(&mut *connection)
        .await
        .unwrap();
    assert_eq!(
        default_read_only, "on",
        "the scoped fixture transaction weakened its control-pool session"
    );
}

/// The SQLSTATE behind a driver failure, when there is one.
fn sqlstate(error: &sqlx::Error) -> Option<String> {
    error
        .as_database_error()
        .and_then(|database| database.code())
        .map(|code| code.into_owned())
}

/// `insufficient_privilege`: the role's `GRANT` refused the statement.
const INSUFFICIENT_PRIVILEGE: &str = "42501";
/// `read_only_sql_transaction`: the session or the transaction refused it first.
const READ_ONLY_TRANSACTION: &str = "25006";

/// The container's DSN with Warden's least-privilege role in place of the superuser.
async fn role_dsn(container: &ContainerAsync<Postgres>) -> Dsn {
    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    format!("postgres://{ROLE}:{ROLE_PASSWORD}@{host}:{port}/postgres")
        .parse()
        .unwrap()
}

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
        dialect: Dialect::PostgreSql,
        environment: Environment::Development,
        database: "postgres".to_owned(),
    }
}

/// The default engine every deployment uses.
fn engine() -> PolicyEngine {
    PolicyEngine::with_defaults(&PolicySettings::default()).unwrap()
}

#[tokio::test]
async fn the_session_refuses_a_write_before_the_role_is_even_consulted() {
    let container = start_postgres().await;
    let root = PostgreSqlConnectionPools::connect(config(dsn(&container).await))
        .await
        .unwrap();
    provision(&root).await;
    let warden = PostgreSqlConnectionPools::connect(config(role_dsn(&container).await))
        .await
        .unwrap();

    let error = agent_query("INSERT INTO orders (id, owner) VALUES (3, 'warden_ro')")
        .execute(warden.agent())
        .await
        .unwrap_err();
    assert_eq!(
        sqlstate(&error).as_deref(),
        Some(READ_ONLY_TRANSACTION),
        "{error:?}"
    );

    warden.close().await;
    root.close().await;
}

#[tokio::test]
async fn the_role_refuses_every_write_warden_never_sends() {
    let container = start_postgres().await;
    let root = PostgreSqlConnectionPools::connect(config(dsn(&container).await))
        .await
        .unwrap();
    provision(&root).await;
    let warden = PostgreSqlConnectionPools::connect(config(role_dsn(&container).await))
        .await
        .unwrap();

    let mut connection = warden.agent().acquire().await.unwrap();
    let role: String = agent_query("SELECT current_user")
        .fetch_one(&mut *connection)
        .await
        .unwrap()
        .try_get(0)
        .unwrap();
    assert_eq!(role, ROLE, "the pinned connection used the wrong role");
    let backend_pid: i32 = agent_query("SELECT pg_backend_pid()")
        .fetch_one(&mut *connection)
        .await
        .unwrap()
        .try_get(0)
        .unwrap();

    agent_query("SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE")
        .execute(&mut *connection)
        .await
        .unwrap();
    let default_read_only: String = agent_query("SHOW default_transaction_read_only")
        .fetch_one(&mut *connection)
        .await
        .unwrap()
        .try_get(0)
        .unwrap();
    assert_eq!(
        default_read_only, "off",
        "the pinned backend {backend_pid} retained Warden's session barrier"
    );

    for statement in DENIED_STATEMENTS.iter().take(7) {
        let error = agent_query(AssertSqlSafe(statement.sql.to_owned()))
            .execute(&mut *connection)
            .await
            .unwrap_err();
        assert_eq!(
            sqlstate(&error).as_deref(),
            Some(INSUFFICIENT_PRIVILEGE),
            "{} was not refused by the role: {error:?}",
            statement.sql
        );
    }

    // Sequence mutation is the PostgreSQL-specific row of docs/security.md section
    // 3. nextval needs sequence USAGE and setval needs UPDATE. PostgreSQL normally
    // grants function EXECUTE to PUBLIC, so this fixture proves only that its
    // explicitly revoked pg_sleep function cannot be called; deployments must audit
    // and revoke each unsafe function they expose.
    for statement in DENIED_STATEMENTS.iter().skip(7).take(3) {
        let error = agent_query(statement.sql)
            .fetch_one(&mut *connection)
            .await
            .unwrap_err();
        assert_eq!(
            sqlstate(&error).as_deref(),
            Some(INSUFFICIENT_PRIVILEGE),
            "{} was not refused by the role: {error:?}",
            statement.sql
        );
    }

    let total: i64 = agent_query("SELECT count(*) FROM orders")
        .fetch_one(&mut *connection)
        .await
        .unwrap()
        .try_get(0)
        .unwrap();
    assert_eq!(
        total, 1,
        "row-level security restricts this count to one row"
    );

    drop(connection);
    warden.close().await;
    root.close().await;
}

#[tokio::test]
async fn the_grant_is_the_read_boundary_and_the_allowlist_is_not() {
    let container = start_postgres().await;
    let root = PostgreSqlConnectionPools::connect(config(dsn(&container).await))
        .await
        .unwrap();
    provision(&root).await;
    let warden = PostgreSqlConnectionPools::connect(config(role_dsn(&container).await))
        .await
        .unwrap();

    let error = agent_query("SELECT token FROM secrets")
        .fetch_one(warden.agent())
        .await
        .unwrap_err();
    assert_eq!(
        sqlstate(&error).as_deref(),
        Some(INSUFFICIENT_PRIVILEGE),
        "{error:?}"
    );

    let token: String = agent_query("SELECT token FROM secret_peek")
        .fetch_one(warden.agent())
        .await
        .unwrap()
        .try_get(0)
        .unwrap();
    assert_eq!(token, "not-for-the-agent");

    warden.close().await;
    root.close().await;
}

#[tokio::test]
async fn row_level_security_restricts_what_the_role_can_read() {
    let container = start_postgres().await;
    let root = PostgreSqlConnectionPools::connect(config(dsn(&container).await))
        .await
        .unwrap();
    provision(&root).await;
    let warden = PostgreSqlConnectionPools::connect(config(role_dsn(&container).await))
        .await
        .unwrap();

    let owners: Vec<String> = agent_query("SELECT owner FROM orders ORDER BY id")
        .fetch_all(warden.agent())
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.try_get(0).unwrap())
        .collect();
    assert_eq!(owners, vec!["warden_ro".to_owned()]);

    let all: i64 = sqlx::query_scalar("SELECT count(*) FROM orders")
        .fetch_one(root.control())
        .await
        .unwrap();
    assert_eq!(all, 2);

    warden.close().await;
    root.close().await;
}

#[tokio::test]
async fn the_analyzer_and_policy_engine_deny_every_statement_before_it_is_ever_sent() {
    for expected in DENIED_STATEMENTS {
        let request = QueryRequest::new(
            "production-db".parse().unwrap(),
            expected.sql.to_owned(),
            Vec::new(),
            &InputLimits::default(),
        )
        .unwrap();
        let analyzed = PostgreSqlAnalyzer::new().analyze(request).unwrap();
        let analysis = analyzed.analysis();
        assert_eq!(analysis.root_kind(), expected.root_kind, "{}", expected.sql);
        assert_eq!(
            analysis.nested_kinds(),
            expected.nested_kinds,
            "{}",
            expected.sql
        );
        assert_eq!(analysis.risks(), expected.risks, "{}", expected.sql);
        match expected.function {
            Some((name, classification)) => {
                assert_eq!(analysis.functions().len(), 1, "{}", expected.sql);
                let function = &analysis.functions()[0];
                assert_eq!(function.name.value(), name, "{}", expected.sql);
                assert_eq!(function.classification, classification, "{}", expected.sql);
            }
            None => assert!(analysis.functions().is_empty(), "{}", expected.sql),
        }

        let rejection = engine()
            .authorize(
                &context(),
                &metadata(),
                analyzed,
                ExecutionLimits::default(),
            )
            .unwrap_err();
        assert!(
            rejection
                .reasons()
                .iter()
                .all(|reason| reason.code() != DenyCode::UnknownConstruct),
            "{} reached the residual unknown-construct denial: {rejection:?}",
            expected.sql
        );
        assert_eq!(
            rejection.primary_code(),
            expected.primary_denial,
            "{}",
            expected.sql
        );
    }
}
