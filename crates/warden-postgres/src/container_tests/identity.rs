//! What PostgreSQL's function resolution does to an unqualified call, and what
//! Warden does about it.
//!
//! `lower(1)` with `app.lower(integer)` on the `search_path` resolves to the user
//! function even though `pg_catalog` is implicitly first: candidates of *different*
//! argument types are considered on an equal footing regardless of path position, and
//! an exact match wins (PostgreSQL 17, "Function Type Resolution"). The analyzer cannot
//! see that; the connection can, once, at startup (ADR-0053).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use sqlx::{AssertSqlSafe, Connection, Row};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ContainerAsync;
use warden_core::secret::Dsn;

use super::{config, deadline, dsn, start_postgres};
use crate::connection::{PostgreSqlConnectionConfig, PostgreSqlConnectionPools, SearchPath};
use crate::error::ConnectError;
use crate::query::agent_query;

const ROLE: &str = "warden_ro";
const ROLE_PASSWORD: &str = "warden-ro-password";
/// `insufficient_privilege`.
const INSUFFICIENT_PRIVILEGE: &str = "42501";

/// A schema on the role's `search_path` holding a function that shadows `lower`.
///
/// `EXECUTE` is deliberately left at PostgreSQL's default — granted to `PUBLIC` —
/// because that default is the whole reason this test exists.
async fn provision(root: &PostgreSqlConnectionPools) {
    let mut connection = root.control().acquire().await.unwrap();
    let mut transaction = connection.begin_with("BEGIN READ WRITE").await.unwrap();
    for statement in [
        "CREATE SCHEMA app".to_owned(),
        "CREATE FUNCTION app.lower(integer) RETURNS text LANGUAGE sql IMMUTABLE \
         AS $$ SELECT 'custom-overload' $$"
            .to_owned(),
        "REVOKE CONNECT, TEMPORARY ON DATABASE postgres FROM PUBLIC".to_owned(),
        format!(
            "CREATE ROLE {ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE \
             NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD '{ROLE_PASSWORD}'"
        ),
        format!("GRANT CONNECT ON DATABASE postgres TO {ROLE}"),
        format!("GRANT USAGE ON SCHEMA public TO {ROLE}"),
        format!("GRANT USAGE ON SCHEMA app TO {ROLE}"),
    ] {
        sqlx::query(AssertSqlSafe(statement))
            .execute(&mut *transaction)
            .await
            .unwrap();
    }
    transaction.commit().await.unwrap();
}

/// `citext` installed in `public` by the superuser connection, plus a role that can
/// reach it unqualified.
///
/// PostgreSQL grants `EXECUTE` on a newly created function to `PUBLIC` by default,
/// `CREATE EXTENSION` included, so the role needs no separate `GRANT EXECUTE`: this
/// is the same default the shadowing test above exploits, now exercised by extension
/// code instead of a hand-written function.
async fn provision_citext(root: &PostgreSqlConnectionPools) {
    let mut connection = root.control().acquire().await.unwrap();
    let mut transaction = connection.begin_with("BEGIN READ WRITE").await.unwrap();
    for statement in [
        "CREATE EXTENSION citext".to_owned(),
        "REVOKE CONNECT, TEMPORARY ON DATABASE postgres FROM PUBLIC".to_owned(),
        format!(
            "CREATE ROLE {ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE \
             NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD '{ROLE_PASSWORD}'"
        ),
        format!("GRANT CONNECT ON DATABASE postgres TO {ROLE}"),
        format!("GRANT USAGE ON SCHEMA public TO {ROLE}"),
    ] {
        sqlx::query(AssertSqlSafe(statement))
            .execute(&mut *transaction)
            .await
            .unwrap();
    }
    transaction.commit().await.unwrap();
}

async fn revoke_execute(root: &PostgreSqlConnectionPools) {
    let mut connection = root.control().acquire().await.unwrap();
    let mut transaction = connection.begin_with("BEGIN READ WRITE").await.unwrap();
    sqlx::query(AssertSqlSafe(
        "REVOKE EXECUTE ON FUNCTION app.lower(integer) FROM PUBLIC".to_owned(),
    ))
    .execute(&mut *transaction)
    .await
    .unwrap();
    transaction.commit().await.unwrap();
}

async fn role_dsn(container: &ContainerAsync<Postgres>) -> Dsn {
    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    format!("postgres://{ROLE}:{ROLE_PASSWORD}@{host}:{port}/postgres")
        .parse()
        .unwrap()
}

fn config_with_path(dsn: Dsn, schemas: &[&str]) -> PostgreSqlConnectionConfig {
    PostgreSqlConnectionConfig {
        search_path: SearchPath::new(schemas).unwrap(),
        ..config(dsn)
    }
}

fn sqlstate(error: &sqlx::Error) -> Option<String> {
    error
        .as_database_error()
        .and_then(|database| database.code())
        .map(|code| code.into_owned())
}

#[tokio::test]
async fn an_unqualified_call_resolves_to_the_shadowing_function_and_startup_refuses_it() {
    let container = start_postgres().await;
    let root = PostgreSqlConnectionPools::connect(config(dsn(&container).await))
        .await
        .unwrap();
    provision(&root).await;
    let warden = PostgreSqlConnectionPools::connect(config_with_path(
        role_dsn(&container).await,
        &["app", "public"],
    ))
    .await
    .unwrap();

    // The premise, measured: the server picks the user function.
    let row = agent_query("SELECT lower(1) AS resolved")
        .fetch_one(warden.agent())
        .await
        .unwrap();
    let resolved: String = row.try_get("resolved").unwrap();
    assert_eq!(resolved, "custom-overload");

    // What Warden does about it.
    let error = warden
        .verify_function_identity(deadline())
        .await
        .unwrap_err();
    assert_eq!(
        error,
        ConnectError::ShadowedBuiltins {
            functions: vec!["app.lower(integer)".to_owned()],
        }
    );
    assert!(error.to_string().contains("app.lower(integer)"), "{error}");

    // The documented remediation, and proof that it closes the hole rather than
    // silently falling back to the built-in.
    revoke_execute(&root).await;
    warden.verify_function_identity(deadline()).await.unwrap();
    let refused = agent_query("SELECT lower(1) AS resolved")
        .fetch_one(warden.agent())
        .await
        .unwrap_err();
    assert_eq!(sqlstate(&refused).as_deref(), Some(INSUFFICIENT_PRIVILEGE));

    warden.close().await;
    root.close().await;
}

#[tokio::test]
async fn a_shadowing_function_outside_the_search_path_is_not_reachable_and_not_reported() {
    let container = start_postgres().await;
    let root = PostgreSqlConnectionPools::connect(config(dsn(&container).await))
        .await
        .unwrap();
    provision(&root).await;
    // `config` pins `search_path = public`: `app.lower` exists but is unreachable
    // unqualified, so it is neither a hole nor a finding.
    let warden = PostgreSqlConnectionPools::connect(config(role_dsn(&container).await))
        .await
        .unwrap();

    let row = agent_query("SELECT lower('ABC') AS resolved")
        .fetch_one(warden.agent())
        .await
        .unwrap();
    let resolved: String = row.try_get("resolved").unwrap();
    assert_eq!(resolved, "abc");
    warden.verify_function_identity(deadline()).await.unwrap();

    warden.close().await;
    root.close().await;
}

#[tokio::test]
async fn an_extension_owned_overload_does_not_trip_the_preflight() {
    // `CREATE EXTENSION citext` installs `replace`, `strpos`, `split_part`,
    // `translate`, `regexp_*(citext, …)` and `min`/`max(citext)` in `public`, every
    // one of them a name the `SAFE` registry trusts unqualified. Unlike
    // `app.lower(integer)` above, this is not the adversary the preflight targets —
    // it is a superuser installing a trusted contrib extension — so it must not fail
    // the connection.
    let container = start_postgres().await;
    let root = PostgreSqlConnectionPools::connect(config(dsn(&container).await))
        .await
        .unwrap();
    provision_citext(&root).await;
    let warden = PostgreSqlConnectionPools::connect(config_with_path(
        role_dsn(&container).await,
        &["public"],
    ))
    .await
    .unwrap();

    warden.verify_function_identity(deadline()).await.unwrap();

    warden.close().await;
    root.close().await;
}
