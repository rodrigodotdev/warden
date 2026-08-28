//! What only a real PostgreSQL catalog can prove about schema inspection.
//!
//! Every property starts its own PostgreSQL 17 container. Catalog privilege
//! visibility, search-path resolution, identifier folding, metadata decoding, and
//! pool isolation are server properties rather than behaviors a mock can establish.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use sqlx::{AssertSqlSafe, Connection, Row};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ContainerAsync;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use warden_core::connection::{ConnectionMetadata, ConnectionName, Environment};
use warden_core::context::RequestContext;
use warden_core::dialect::Dialect;
use warden_core::pool::AGENT_POOL_MAX_CONNECTIONS;
use warden_core::schema::cache::{SCHEMA_CACHE_CAPACITY, SchemaCache};
use warden_core::schema::{MatchReason, SchemaDescribeRequest, SchemaSearchRequest, TableKind};
use warden_core::secret::Dsn;
use warden_policy::{
    DenyCode, ObjectFilter, ObjectRules, PolicyContext, PolicyEngine, PolicySettings,
};
use warden_ports::SchemaInspector;
use warden_ports::error::SchemaError;

use super::{config, dsn, start_postgres};
use crate::connection::{PostgreSqlConnectionConfig, PostgreSqlConnectionPools, SearchPath};
use crate::inspector::PostgreSqlSchemaInspector;

const ROLE: &str = "warden_inspector";
const ROLE_PASSWORD: &str = "warden-inspector-password";

fn name() -> ConnectionName {
    "production-db".parse().unwrap()
}

fn context() -> RequestContext {
    RequestContext::new(
        "req-1".parse().unwrap(),
        "alice@example.com".parse().unwrap(),
        "Claude Code".parse().unwrap(),
    )
}

fn metadata() -> ConnectionMetadata {
    ConnectionMetadata {
        name: name(),
        dialect: Dialect::PostgreSql,
        environment: Environment::Development,
        database: "postgres".to_owned(),
    }
}

fn engine(settings: &PolicySettings) -> PolicyEngine {
    PolicyEngine::with_defaults(settings).unwrap()
}

fn inspection_config(dsn: Dsn, schemas: &[&str]) -> PostgreSqlConnectionConfig {
    let mut connection = config(dsn);
    connection.search_path = SearchPath::new(schemas).unwrap();
    connection
}

async fn role_dsn(container: &ContainerAsync<Postgres>) -> Dsn {
    let host = container.get_host().await.unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    format!("postgres://{ROLE}:{ROLE_PASSWORD}@{host}:{port}/postgres")
        .parse()
        .unwrap()
}

async fn fixture(pools: &PostgreSqlConnectionPools) {
    let mut connection = pools.control().acquire().await.unwrap();
    let mut transaction = connection.begin_with("BEGIN READ WRITE").await.unwrap();

    for statement in [
        format!(
            "CREATE ROLE {ROLE} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE \
             NOINHERIT NOREPLICATION NOBYPASSRLS PASSWORD '{ROLE_PASSWORD}'"
        ),
        "CREATE SCHEMA app".to_owned(),
        "CREATE SCHEMA vault".to_owned(),
        "CREATE TABLE app.customers (
             id BIGINT PRIMARY KEY,
             email TEXT NOT NULL
         )"
        .to_owned(),
        "CREATE TABLE app.orders (
             tenant_id BIGINT NOT NULL,
             id BIGINT NOT NULL,
             customer_id BIGINT REFERENCES app.customers(id),
             status TEXT NOT NULL DEFAULT 'new',
             notes TEXT,
             PRIMARY KEY (tenant_id, id)
         )"
        .to_owned(),
        "COMMENT ON COLUMN app.orders.notes IS 'free-form operator notes'".to_owned(),
        "CREATE INDEX orders_lower_status ON app.orders ((lower(status)))".to_owned(),
        "CREATE VIEW app.order_report AS
             SELECT o.tenant_id, o.id, c.email AS customer_email
               FROM app.orders AS o
               JOIN app.customers AS c ON c.id = o.customer_id"
            .to_owned(),
        "CREATE MATERIALIZED VIEW app.revenue_by_month AS
             SELECT status, count(*)::bigint AS order_count
               FROM app.orders
              GROUP BY status"
            .to_owned(),
        "CREATE TABLE app.\"Orders\" (id BIGINT PRIMARY KEY)".to_owned(),
        "CREATE TABLE app.invisible (id BIGINT PRIMARY KEY)".to_owned(),
        "CREATE TABLE vault.secrets (id BIGINT PRIMARY KEY, token TEXT NOT NULL)".to_owned(),
        format!("GRANT CONNECT ON DATABASE postgres TO {ROLE}"),
        format!("GRANT USAGE ON SCHEMA app, vault TO {ROLE}"),
        format!("GRANT SELECT ON ALL TABLES IN SCHEMA app, vault TO {ROLE}"),
        format!("REVOKE SELECT ON app.invisible FROM {ROLE}"),
    ] {
        sqlx::query(AssertSqlSafe(statement))
            .execute(&mut *transaction)
            .await
            .unwrap();
    }
    transaction.commit().await.unwrap();

    let default_read_only: String =
        sqlx::query_scalar("SELECT current_setting('default_transaction_read_only')")
            .fetch_one(&mut *connection)
            .await
            .unwrap();
    assert_eq!(
        default_read_only, "on",
        "the scoped fixture transaction weakened the same physical control-pool session"
    );
}

async fn connect(
    container: &ContainerAsync<Postgres>,
    search_path: &[&str],
) -> (PostgreSqlConnectionPools, Arc<PostgreSqlConnectionPools>) {
    let root = PostgreSqlConnectionPools::connect(inspection_config(
        dsn(container).await,
        &["app", "public"],
    ))
    .await
    .unwrap();
    fixture(&root).await;
    let restricted = Arc::new(
        PostgreSqlConnectionPools::connect(inspection_config(
            role_dsn(container).await,
            search_path,
        ))
        .await
        .unwrap(),
    );
    (root, restricted)
}

async fn mutate(root: &PostgreSqlConnectionPools, statement: &str) {
    let mut connection = root.control().acquire().await.unwrap();
    let mut transaction = connection.begin_with("BEGIN READ WRITE").await.unwrap();
    sqlx::query(AssertSqlSafe(statement.to_owned()))
        .execute(&mut *transaction)
        .await
        .unwrap();
    transaction.commit().await.unwrap();
}

fn filter<'a>(
    engine: &'a PolicyEngine,
    context: &'a RequestContext,
    connection: &'a ConnectionMetadata,
) -> ObjectFilter<'a> {
    ObjectFilter::new(engine, PolicyContext::new(context, connection))
}

async fn close(root: PostgreSqlConnectionPools, restricted: Arc<PostgreSqlConnectionPools>) {
    restricted.close().await;
    root.close().await;
}

#[tokio::test]
async fn a_described_table_carries_its_columns_keys_and_indexes() {
    let container = start_postgres().await;
    let (root, pools) = connect(&container, &["app", "public"]).await;
    let inspector = PostgreSqlSchemaInspector::new(Arc::clone(&pools), name());
    let engine = engine(&PolicySettings::default());
    let connection = metadata();
    let context = context();
    let request = SchemaDescribeRequest::new(name(), vec!["app.orders".parse().unwrap()]).unwrap();

    let described = inspector
        .describe_schema(
            &request,
            filter(&engine, &context, &connection),
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();

    let table = &described.schemas[0].tables[0];
    assert_eq!(table.schema, "app");
    assert_eq!(table.name, "orders");
    assert_eq!(table.kind, TableKind::Table);
    assert_eq!(table.primary_key, ["tenant_id", "id"]);

    let status = table
        .columns
        .iter()
        .find(|column| column.name == "status")
        .unwrap();
    assert_eq!(status.database_type, "text");
    assert!(!status.nullable);
    assert_eq!(status.default.as_deref(), Some("'new'::text"));

    let notes = table
        .columns
        .iter()
        .find(|column| column.name == "notes")
        .unwrap();
    assert!(notes.nullable);
    assert_eq!(notes.comment.as_deref(), Some("free-form operator notes"));

    let foreign = &table.foreign_keys[0];
    assert_eq!(foreign.columns, ["customer_id"]);
    assert_eq!(foreign.referenced_schema, "app");
    assert_eq!(foreign.referenced_table, "customers");
    assert_eq!(foreign.referenced_columns, ["id"]);
    assert!(
        table
            .indexes
            .iter()
            .any(|index| index.primary && index.unique)
    );
    // The expression index has a key part with no column name. Warden drops the part
    // and says the description is partial rather than inventing a name for it.
    assert!(table.truncated);
    assert!(table.indexes.iter().all(|index| !index.columns.is_empty()));

    close(root, pools).await;
}

#[tokio::test]
async fn an_unqualified_selector_resolves_through_the_search_path() {
    let container = start_postgres().await;
    let (root, pools) = connect(&container, &["app", "public"]).await;
    let inspector = PostgreSqlSchemaInspector::new(Arc::clone(&pools), name());
    let engine = engine(&PolicySettings::default());
    let connection = metadata();
    let context = context();
    let request = SchemaDescribeRequest::new(name(), vec!["orders".parse().unwrap()]).unwrap();

    let described = inspector
        .describe_schema(
            &request,
            filter(&engine, &context, &connection),
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();

    assert_eq!(described.schemas[0].name, "app");
    assert_eq!(described.schemas[0].tables[0].schema, "app");
    assert_eq!(described.schemas[0].tables[0].name, "orders");
    close(root, pools).await;
}

#[tokio::test]
async fn a_view_and_a_materialized_view_keep_their_own_kinds() {
    let container = start_postgres().await;
    let (root, pools) = connect(&container, &["app", "public"]).await;
    let inspector = PostgreSqlSchemaInspector::new(Arc::clone(&pools), name());
    let engine = engine(&PolicySettings::default());
    let connection = metadata();
    let context = context();
    let request = SchemaDescribeRequest::new(
        name(),
        vec![
            "app.order_report".parse().unwrap(),
            "app.revenue_by_month".parse().unwrap(),
        ],
    )
    .unwrap();

    let described = inspector
        .describe_schema(
            &request,
            filter(&engine, &context, &connection),
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();

    assert_eq!(described.schemas[0].tables[0].kind, TableKind::View);
    assert_eq!(
        described.schemas[0].tables[1].kind,
        TableKind::MaterializedView
    );
    close(root, pools).await;
}

#[tokio::test]
async fn a_relation_the_role_cannot_select_is_invisible() {
    let container = start_postgres().await;
    let (root, pools) = connect(&container, &["app", "public"]).await;
    let inspector = PostgreSqlSchemaInspector::new(Arc::clone(&pools), name());
    let engine = engine(&PolicySettings::default());
    let connection = metadata();
    let context = context();
    let search = SchemaSearchRequest::new(name(), "invisible", 10).unwrap();

    let found = inspector
        .search_schema(
            &search,
            filter(&engine, &context, &connection),
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(found.matches.is_empty());

    let describe =
        SchemaDescribeRequest::new(name(), vec!["app.invisible".parse().unwrap()]).unwrap();
    let described = inspector
        .describe_schema(
            &describe,
            filter(&engine, &context, &connection),
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(described.schemas.is_empty());
    close(root, pools).await;
}

#[tokio::test]
async fn a_quoted_relation_is_not_reached_by_a_lowercase_rule() {
    let container = start_postgres().await;
    let (root, pools) = connect(&container, &["app", "public"]).await;
    let inspector = PostgreSqlSchemaInspector::new(Arc::clone(&pools), name());
    let settings = PolicySettings {
        objects: ObjectRules {
            deny_tables: vec!["app.orders".to_owned()],
            ..ObjectRules::default()
        },
        ..PolicySettings::default()
    };
    let engine = engine(&settings);
    let connection = metadata();
    let context = context();
    let search = SchemaSearchRequest::new(name(), "orders", 10).unwrap();

    let found = inspector
        .search_schema(
            &search,
            filter(&engine, &context, &connection),
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(
        found
            .matches
            .iter()
            .any(|matched| matched.schema == "app" && matched.table == "Orders")
    );
    assert!(
        found
            .matches
            .iter()
            .all(|matched| !(matched.schema == "app" && matched.table == "orders"))
    );

    // Plain text carries no quoting marker. The mandatory written-selector check
    // therefore folds `app.Orders` and fails closed before catalog resolution.
    for selector in ["app.Orders", "app.orders"] {
        let request = SchemaDescribeRequest::new(name(), vec![selector.parse().unwrap()]).unwrap();
        let error = inspector
            .describe_schema(
                &request,
                filter(&engine, &context, &connection),
                super::deadline(),
                CancellationToken::new(),
            )
            .await
            .unwrap_err();
        let SchemaError::Rejected(rejection) = error else {
            panic!("expected {selector} to fail its written-selector check");
        };
        assert_eq!(rejection.primary_code(), DenyCode::ObjectNotAllowed);
    }
    close(root, pools).await;
}

#[tokio::test]
async fn a_denied_table_is_invisible_to_search_and_refused_by_describe() {
    let container = start_postgres().await;
    let (root, pools) = connect(&container, &["app", "public"]).await;
    let inspector = PostgreSqlSchemaInspector::new(Arc::clone(&pools), name());
    let settings = PolicySettings {
        objects: ObjectRules {
            deny_tables: vec!["vault.secrets".to_owned()],
            ..ObjectRules::default()
        },
        ..PolicySettings::default()
    };
    let engine = engine(&settings);
    let connection = metadata();
    let context = context();
    let search = SchemaSearchRequest::new(name(), "secrets", 10).unwrap();

    let found = inspector
        .search_schema(
            &search,
            filter(&engine, &context, &connection),
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(found.matches.is_empty());

    let describe =
        SchemaDescribeRequest::new(name(), vec!["vault.secrets".parse().unwrap()]).unwrap();
    let error = inspector
        .describe_schema(
            &describe,
            filter(&engine, &context, &connection),
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    let SchemaError::Rejected(rejection) = error else {
        panic!("expected an object-policy rejection");
    };
    assert_eq!(rejection.primary_code(), DenyCode::ObjectNotAllowed);
    close(root, pools).await;
}

#[tokio::test]
async fn an_unqualified_selector_cannot_reach_a_denied_schema() {
    let container = start_postgres().await;
    let (root, pools) = connect(&container, &["vault", "app", "public"]).await;
    let inspector = PostgreSqlSchemaInspector::new(Arc::clone(&pools), name());
    let settings = PolicySettings {
        objects: ObjectRules {
            schemas: Some(vec!["app".to_owned()]),
            ..ObjectRules::default()
        },
        ..PolicySettings::default()
    };
    let engine = engine(&settings);
    let connection = metadata();
    let context = context();
    let request = SchemaDescribeRequest::new(name(), vec!["secrets".parse().unwrap()]).unwrap();

    let error = inspector
        .describe_schema(
            &request,
            filter(&engine, &context, &connection),
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    let SchemaError::Rejected(rejection) = error else {
        panic!("expected the resolved schema to be rejected");
    };
    assert_eq!(rejection.primary_code(), DenyCode::ObjectNotAllowed);
    close(root, pools).await;
}

#[tokio::test]
async fn search_ranks_an_exact_table_above_a_prefix_and_a_column() {
    let container = start_postgres().await;
    let (root, pools) = connect(&container, &["app", "public"]).await;
    let inspector = PostgreSqlSchemaInspector::new(Arc::clone(&pools), name());
    let settings = PolicySettings {
        objects: ObjectRules {
            deny_tables: vec!["app.Orders".to_owned()],
            ..ObjectRules::default()
        },
        ..PolicySettings::default()
    };
    let engine = engine(&settings);
    let connection = metadata();
    let context = context();
    let request = SchemaSearchRequest::new(name(), "orders customer", 10).unwrap();

    let found = inspector
        .search_schema(
            &request,
            filter(&engine, &context, &connection),
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();

    assert_eq!(found.matches[0].table, "orders");
    assert_eq!(found.matches[0].reason, MatchReason::ExactTable);
    assert_eq!(found.matches[1].table, "customers");
    assert_eq!(found.matches[1].reason, MatchReason::TablePrefix);
    assert_eq!(found.matches[2].table, "order_report");
    assert_eq!(found.matches[2].reason, MatchReason::ColumnMatch);
    close(root, pools).await;
}

#[tokio::test]
async fn search_never_returns_more_than_the_requested_limit() {
    let container = start_postgres().await;
    let (root, pools) = connect(&container, &["app", "public"]).await;
    let inspector = PostgreSqlSchemaInspector::new(Arc::clone(&pools), name());
    let engine = engine(&PolicySettings::default());
    let connection = metadata();
    let context = context();
    let request = SchemaSearchRequest::new(name(), "order", 1).unwrap();

    let found = inspector
        .search_schema(
            &request,
            filter(&engine, &context, &connection),
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();

    assert_eq!(found.matches.len(), 1);
    assert!(found.truncated);
    close(root, pools).await;
}

#[tokio::test]
async fn a_second_call_is_served_from_the_cache() {
    let container = start_postgres().await;
    let (root, pools) = connect(&container, &["app", "public"]).await;
    let inspector = PostgreSqlSchemaInspector::new(Arc::clone(&pools), name());
    let permissive_engine = engine(&PolicySettings::default());
    let denied_engine = engine(&PolicySettings {
        objects: ObjectRules {
            schemas: Some(vec!["vault".to_owned()]),
            ..ObjectRules::default()
        },
        ..PolicySettings::default()
    });
    let connection = metadata();
    let context = context();
    let request = SchemaDescribeRequest::new(name(), vec!["orders".parse().unwrap()]).unwrap();

    let first = inspector
        .describe_schema(
            &request,
            filter(&permissive_engine, &context, &connection),
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    mutate(
        &root,
        "ALTER TABLE app.orders ADD COLUMN cache_probe BIGINT",
    )
    .await;
    let second = inspector
        .describe_schema(
            &request,
            filter(&permissive_engine, &context, &connection),
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();

    assert_eq!(second, first);
    assert!(
        second.schemas[0].tables[0]
            .columns
            .iter()
            .all(|column| column.name != "cache_probe")
    );

    let error = inspector
        .describe_schema(
            &request,
            filter(&denied_engine, &context, &connection),
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    let SchemaError::Rejected(rejection) = error else {
        panic!("expected the cached resolved object to be rejected");
    };
    assert_eq!(rejection.primary_code(), DenyCode::ObjectNotAllowed);

    mutate(&root, "ALTER TABLE app.orders RENAME TO orders_hidden").await;
    let no_longer_visible = inspector
        .describe_schema(
            &request,
            filter(&permissive_engine, &context, &connection),
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(no_longer_visible.schemas.is_empty());
    close(root, pools).await;
}

#[tokio::test]
async fn an_expired_cache_entry_is_refetched() {
    let container = start_postgres().await;
    let (root, pools) = connect(&container, &["app", "public"]).await;
    let inspector = PostgreSqlSchemaInspector::with_cache_for_tests(
        Arc::clone(&pools),
        name(),
        SchemaCache::new(Duration::ZERO, SCHEMA_CACHE_CAPACITY),
    );
    let engine = engine(&PolicySettings::default());
    let connection = metadata();
    let context = context();
    let request = SchemaDescribeRequest::new(name(), vec!["app.orders".parse().unwrap()]).unwrap();

    let first = inspector
        .describe_schema(
            &request,
            filter(&engine, &context, &connection),
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    mutate(
        &root,
        "ALTER TABLE app.orders ADD COLUMN expired_probe BIGINT",
    )
    .await;
    let second = inspector
        .describe_schema(
            &request,
            filter(&engine, &context, &connection),
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();

    assert_ne!(second, first);
    assert!(
        second.schemas[0].tables[0]
            .columns
            .iter()
            .any(|column| column.name == "expired_probe")
    );
    close(root, pools).await;
}

#[tokio::test]
async fn a_cancelled_token_stops_a_catalog_read() {
    let container = start_postgres().await;
    let (root, pools) = connect(&container, &["app", "public"]).await;
    let inspector = PostgreSqlSchemaInspector::new(Arc::clone(&pools), name());
    let engine = engine(&PolicySettings::default());
    let connection = metadata();
    let context = context();
    let request = SchemaDescribeRequest::new(name(), vec!["orders".parse().unwrap()]).unwrap();
    let cancel = CancellationToken::new();
    cancel.cancel();

    let error = inspector
        .describe_schema(
            &request,
            filter(&engine, &context, &connection),
            super::deadline(),
            cancel,
        )
        .await
        .unwrap_err();

    assert_eq!(error, SchemaError::Cancelled);
    close(root, pools).await;
}

#[tokio::test]
async fn an_elapsed_deadline_stops_a_catalog_read() {
    let container = start_postgres().await;
    let (root, pools) = connect(&container, &["app", "public"]).await;
    let inspector = PostgreSqlSchemaInspector::new(Arc::clone(&pools), name());
    let engine = engine(&PolicySettings::default());
    let connection = metadata();
    let context = context();
    let request = SchemaDescribeRequest::new(name(), vec!["orders".parse().unwrap()]).unwrap();

    let error = inspector
        .describe_schema(
            &request,
            filter(&engine, &context, &connection),
            Instant::now(),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();

    assert_eq!(error, SchemaError::Timeout);
    close(root, pools).await;
}

#[tokio::test]
async fn the_catalog_statements_never_touch_the_agent_pool() {
    let container = start_postgres().await;
    let (root, pools) = connect(&container, &["app", "public"]).await;
    let inspector = PostgreSqlSchemaInspector::new(Arc::clone(&pools), name());
    let engine = engine(&PolicySettings::default());
    let connection = metadata();
    let context = context();
    let search_request = SchemaSearchRequest::new(name(), "orders", 10).unwrap();
    let describe_request =
        SchemaDescribeRequest::new(name(), vec!["orders".parse().unwrap()]).unwrap();

    let mut held = Vec::new();
    for _ in 0..AGENT_POOL_MAX_CONNECTIONS {
        held.push(pools.agent().acquire().await.unwrap());
    }

    let found = inspector
        .search_schema(
            &search_request,
            filter(&engine, &context, &connection),
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(
        found
            .matches
            .iter()
            .any(|matched| matched.table == "orders")
    );

    let described = inspector
        .describe_schema(
            &describe_request,
            filter(&engine, &context, &connection),
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(described.schemas[0].tables[0].name, "orders");

    drop(held);
    close(root, pools).await;
}

#[tokio::test]
async fn no_session_state_survives_a_catalog_read() {
    let container = start_postgres().await;
    let root = PostgreSqlConnectionPools::connect(inspection_config(
        dsn(&container).await,
        &["app", "public"],
    ))
    .await
    .unwrap();
    fixture(&root).await;
    let mut restricted_config = inspection_config(role_dsn(&container).await, &["app", "public"]);
    restricted_config.control_pool.max_connections = 1;
    restricted_config.control_pool.min_connections = 1;
    let pools = Arc::new(
        PostgreSqlConnectionPools::connect(restricted_config)
            .await
            .unwrap(),
    );
    let inspector = PostgreSqlSchemaInspector::new(Arc::clone(&pools), name());
    let engine = engine(&PolicySettings::default());
    let connection = metadata();
    let context = context();

    let mut before = pools.control().acquire().await.unwrap();
    let before_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *before)
        .await
        .unwrap();
    drop(before);

    let search = SchemaSearchRequest::new(name(), "orders", 10).unwrap();
    inspector
        .search_schema(
            &search,
            filter(&engine, &context, &connection),
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let describe = SchemaDescribeRequest::new(name(), vec!["orders".parse().unwrap()]).unwrap();
    inspector
        .describe_schema(
            &describe,
            filter(&engine, &context, &connection),
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();

    let mut after = pools.control().acquire().await.unwrap();
    let row = sqlx::query(
        "SELECT pg_backend_pid() AS pid, \
                current_setting('statement_timeout') AS statement_timeout, \
                current_setting('default_transaction_read_only') AS read_only, \
                current_setting('search_path') AS search_path",
    )
    .fetch_one(&mut *after)
    .await
    .unwrap();
    assert_eq!(row.try_get::<i32, _>("pid").unwrap(), before_pid);
    assert_eq!(row.try_get::<String, _>("statement_timeout").unwrap(), "5s");
    assert_eq!(row.try_get::<String, _>("read_only").unwrap(), "on");
    assert_eq!(
        row.try_get::<String, _>("search_path").unwrap(),
        "app,public"
    );
    drop(after);

    close(root, pools).await;
}
