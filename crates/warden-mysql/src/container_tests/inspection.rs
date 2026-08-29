//! What only a real MySQL catalog can prove about schema inspection.
//!
//! Every test starts its own container. Catalog visibility, default-database
//! resolution, metadata decoding, and pool isolation are server properties rather
//! than behaviors a mock can establish.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use sqlx::AssertSqlSafe;
use testcontainers_modules::mysql::Mysql;
use testcontainers_modules::testcontainers::ContainerAsync;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use warden_core::connection::{ConnectionMetadata, ConnectionName, Environment};
use warden_core::context::RequestContext;
use warden_core::dialect::Dialect;
use warden_core::pool::AGENT_POOL_MAX_CONNECTIONS;
use warden_core::schema::cache::{SCHEMA_CACHE_CAPACITY, SchemaCache};
use warden_core::schema::{
    MAX_INDEXED_COLUMNS, MatchReason, SchemaDescribeRequest, SchemaSearchRequest, TableKind,
};
use warden_policy::{
    DenyCode, ObjectFilter, ObjectRules, PolicyContext, PolicyEngine, PolicySettings,
};
use warden_ports::SchemaInspector;
use warden_ports::error::SchemaError;

use super::{config, connection_string, dsn, start_mysql, tls};
use crate::connection::MySqlConnectionPools;
use crate::inspector::MySqlSchemaInspector;

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

fn metadata(database: &str) -> ConnectionMetadata {
    ConnectionMetadata {
        name: name(),
        dialect: Dialect::MySql,
        environment: Environment::Development,
        database: database.to_owned(),
    }
}

fn engine(settings: &PolicySettings) -> PolicyEngine {
    PolicyEngine::with_defaults(settings).unwrap()
}

async fn database_dsn(
    container: &ContainerAsync<Mysql>,
    database: &str,
) -> warden_core::secret::Dsn {
    let root = connection_string(container, "").await;
    format!("{}{database}", root.strip_suffix("test").unwrap())
        .parse()
        .unwrap()
}

async fn connect(container: &ContainerAsync<Mysql>, database: &str) -> MySqlConnectionPools {
    let bootstrap = MySqlConnectionPools::connect(config(dsn(container).await, tls()))
        .await
        .unwrap();
    for statement in [
        "CREATE DATABASE IF NOT EXISTS shop",
        "CREATE DATABASE IF NOT EXISTS vault",
    ] {
        sqlx::query(AssertSqlSafe(statement.to_owned()))
            .execute(bootstrap.control())
            .await
            .unwrap();
    }
    bootstrap.close().await;

    MySqlConnectionPools::connect(config(database_dsn(container, database).await, tls()))
        .await
        .unwrap()
}

async fn fixture(pools: &MySqlConnectionPools) {
    for statement in [
        "CREATE DATABASE IF NOT EXISTS shop",
        "CREATE DATABASE IF NOT EXISTS vault",
        "CREATE TABLE shop.customers (
             id BIGINT PRIMARY KEY,
             email VARCHAR(255) NOT NULL
         )",
        "CREATE UNIQUE INDEX customers_email ON shop.customers(email)",
        "CREATE TABLE shop.fk_source (
             id BIGINT PRIMARY KEY,
             target_id BIGINT,
             CONSTRAINT fk_source_target FOREIGN KEY (target_id)
                 REFERENCES shop.customers(id)
         )",
        "CREATE TABLE shop.orders (
             tenant_id BIGINT NOT NULL,
             id BIGINT NOT NULL,
             customer_id BIGINT,
             notes TEXT COMMENT 'free-form operator notes',
             status VARCHAR(16) NOT NULL DEFAULT 'new',
             created_at DATETIME,
             PRIMARY KEY (tenant_id, id),
             CONSTRAINT orders_customer FOREIGN KEY (customer_id)
                 REFERENCES shop.customers(id)
         )",
        "CREATE INDEX orders_created_at ON shop.orders(created_at)",
        "CREATE VIEW shop.order_report AS
             SELECT o.tenant_id, o.id, c.email AS customer_email
               FROM shop.orders AS o
               JOIN shop.customers AS c ON c.id = o.customer_id",
        "CREATE TABLE vault.secrets (
             id BIGINT PRIMARY KEY,
             token VARCHAR(255) NOT NULL
         )",
    ] {
        sqlx::query(AssertSqlSafe(statement.to_owned()))
            .execute(pools.control())
            .await
            .unwrap();
    }
    let mut wide_columns: Vec<String> = (0..MAX_INDEXED_COLUMNS)
        .map(|index| format!("column_{index} BIGINT"))
        .collect();
    wide_columns.push("omitted_tail_marker BIGINT".to_owned());
    let wide_table = format!(
        "CREATE TABLE shop.wide_catalog ({})",
        wide_columns.join(", ")
    );
    sqlx::query(AssertSqlSafe(wide_table))
        .execute(pools.control())
        .await
        .unwrap();
}

#[tokio::test]
async fn a_described_table_carries_its_columns_keys_and_indexes() {
    let container = start_mysql().await;
    let pools = Arc::new(connect(&container, "shop").await);
    fixture(&pools).await;
    let inspector = MySqlSchemaInspector::new(Arc::clone(&pools), name());

    let engine = engine(&PolicySettings::default());
    let connection = metadata("shop");
    let context = context();
    let filter = ObjectFilter::new(&engine, PolicyContext::new(&context, &connection));
    let request = SchemaDescribeRequest::new(name(), vec!["shop.orders".parse().unwrap()]).unwrap();

    let described = inspector
        .describe_schema(
            &request,
            filter,
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();

    let table = &described.schemas[0].tables[0];
    assert_eq!(table.schema, "shop");
    assert_eq!(table.name, "orders");
    assert_eq!(table.kind, TableKind::Table);
    assert_eq!(table.primary_key, ["tenant_id", "id"]);
    assert!(!table.truncated);

    let status = table
        .columns
        .iter()
        .find(|column| column.name == "status")
        .unwrap();
    assert_eq!(status.database_type, "varchar(16)");
    assert!(!status.nullable);
    assert_eq!(status.default.as_deref(), Some("new"));

    let notes = table
        .columns
        .iter()
        .find(|column| column.name == "notes")
        .unwrap();
    assert!(notes.nullable);
    assert_eq!(notes.comment.as_deref(), Some("free-form operator notes"));

    let foreign = &table.foreign_keys[0];
    assert_eq!(foreign.columns, ["customer_id"]);
    assert_eq!(foreign.referenced_schema, "shop");
    assert_eq!(foreign.referenced_table, "customers");
    assert_eq!(foreign.referenced_columns, ["id"]);

    assert!(
        table
            .indexes
            .iter()
            .any(|index| index.primary && index.unique)
    );
    assert!(
        table
            .indexes
            .iter()
            .any(|index| index.name == "orders_created_at" && !index.unique)
    );

    pools.close().await;
}

#[tokio::test]
async fn foreign_key_target_policy_is_reapplied_on_cold_and_warm_cache_reads() {
    let container = start_mysql().await;
    let pools = Arc::new(connect(&container, "shop").await);
    fixture(&pools).await;
    let inspector = MySqlSchemaInspector::new(Arc::clone(&pools), name());
    let denied_engine = engine(&PolicySettings {
        objects: ObjectRules {
            deny_tables: vec!["shop.customers".to_owned()],
            ..ObjectRules::default()
        },
        ..PolicySettings::default()
    });
    let permissive_engine = engine(&PolicySettings::default());
    let connection = metadata("shop");
    let context = context();
    let request =
        SchemaDescribeRequest::new(name(), vec!["shop.fk_source".parse().unwrap()]).unwrap();

    let cold_denied = inspector
        .describe_schema(
            &request,
            ObjectFilter::new(&denied_engine, PolicyContext::new(&context, &connection)),
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let cold_table = &cold_denied.schemas[0].tables[0];
    assert!(cold_table.foreign_keys.is_empty());
    assert!(cold_table.truncated);

    let warm_permitted = inspector
        .describe_schema(
            &request,
            ObjectFilter::new(
                &permissive_engine,
                PolicyContext::new(&context, &connection),
            ),
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(warm_permitted.schemas[0].tables[0].foreign_keys.len(), 1);

    let warm_denied = inspector
        .describe_schema(
            &request,
            ObjectFilter::new(&denied_engine, PolicyContext::new(&context, &connection)),
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let warm_table = &warm_denied.schemas[0].tables[0];
    assert!(warm_table.foreign_keys.is_empty());
    assert!(warm_table.truncated);
    pools.close().await;
}

#[tokio::test]
async fn an_unqualified_selector_resolves_through_the_default_database() {
    let container = start_mysql().await;
    let pools = Arc::new(connect(&container, "shop").await);
    fixture(&pools).await;
    let inspector = MySqlSchemaInspector::new(Arc::clone(&pools), name());
    let engine = engine(&PolicySettings::default());
    let connection = metadata("shop");
    let context = context();
    let filter = ObjectFilter::new(&engine, PolicyContext::new(&context, &connection));
    let request = SchemaDescribeRequest::new(name(), vec!["orders".parse().unwrap()]).unwrap();

    let described = inspector
        .describe_schema(
            &request,
            filter,
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();

    assert_eq!(described.schemas[0].name, "shop");
    assert_eq!(described.schemas[0].tables[0].schema, "shop");
    assert_eq!(described.schemas[0].tables[0].name, "orders");
    pools.close().await;
}

#[tokio::test]
async fn a_view_is_described_as_a_view() {
    let container = start_mysql().await;
    let pools = Arc::new(connect(&container, "shop").await);
    fixture(&pools).await;
    let inspector = MySqlSchemaInspector::new(Arc::clone(&pools), name());
    let engine = engine(&PolicySettings::default());
    let connection = metadata("shop");
    let context = context();
    let filter = ObjectFilter::new(&engine, PolicyContext::new(&context, &connection));
    let request =
        SchemaDescribeRequest::new(name(), vec!["shop.order_report".parse().unwrap()]).unwrap();

    let described = inspector
        .describe_schema(
            &request,
            filter,
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();

    assert_eq!(described.schemas[0].tables[0].kind, TableKind::View);
    pools.close().await;
}

#[tokio::test]
async fn a_relation_the_role_cannot_see_is_skipped_rather_than_reported() {
    let container = start_mysql().await;
    let pools = Arc::new(connect(&container, "shop").await);
    fixture(&pools).await;
    let inspector = MySqlSchemaInspector::new(Arc::clone(&pools), name());
    let engine = engine(&PolicySettings::default());
    let connection = metadata("shop");
    let context = context();
    let filter = ObjectFilter::new(&engine, PolicyContext::new(&context, &connection));
    let request = SchemaDescribeRequest::new(
        name(),
        vec!["shop.not_visible_to_the_role".parse().unwrap()],
    )
    .unwrap();

    let described = inspector
        .describe_schema(
            &request,
            filter,
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();

    assert!(described.schemas.is_empty());
    pools.close().await;
}

#[tokio::test]
async fn search_ranks_an_exact_table_above_a_prefix_and_a_column() {
    let container = start_mysql().await;
    let pools = Arc::new(connect(&container, "shop").await);
    fixture(&pools).await;
    let inspector = MySqlSchemaInspector::new(Arc::clone(&pools), name());
    let engine = engine(&PolicySettings::default());
    let connection = metadata("shop");
    let context = context();
    let filter = ObjectFilter::new(&engine, PolicyContext::new(&context, &connection));
    let request = SchemaSearchRequest::new(name(), "orders customer", 10).unwrap();

    let found = inspector
        .search_schema(
            &request,
            filter,
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
    pools.close().await;
}

#[tokio::test]
async fn search_never_returns_more_than_the_requested_limit() {
    let container = start_mysql().await;
    let pools = Arc::new(connect(&container, "shop").await);
    fixture(&pools).await;
    let inspector = MySqlSchemaInspector::new(Arc::clone(&pools), name());
    let engine = engine(&PolicySettings::default());
    let connection = metadata("shop");
    let context = context();
    let filter = ObjectFilter::new(&engine, PolicyContext::new(&context, &connection));
    let request = SchemaSearchRequest::new(name(), "customer", 1).unwrap();

    let found = inspector
        .search_schema(
            &request,
            filter,
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();

    assert_eq!(found.matches.len(), 1);
    assert!(found.truncated);
    pools.close().await;
}

#[tokio::test]
async fn search_reports_truncation_when_only_an_omitted_column_matches() {
    let container = start_mysql().await;
    let pools = Arc::new(connect(&container, "shop").await);
    fixture(&pools).await;
    let inspector = MySqlSchemaInspector::new(Arc::clone(&pools), name());
    let engine = engine(&PolicySettings::default());
    let connection = metadata("shop");
    let context = context();
    let request = SchemaSearchRequest::new(name(), "omitted_tail_marker", 10).unwrap();

    let found = inspector
        .search_schema(
            &request,
            ObjectFilter::new(&engine, PolicyContext::new(&context, &connection)),
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();

    assert!(found.matches.is_empty());
    assert!(found.truncated);
    pools.close().await;
}

#[tokio::test]
async fn a_denied_table_is_invisible_to_search_and_refused_by_describe() {
    let container = start_mysql().await;
    let pools = Arc::new(connect(&container, "shop").await);
    fixture(&pools).await;
    let inspector = MySqlSchemaInspector::new(Arc::clone(&pools), name());
    let settings = PolicySettings {
        objects: ObjectRules {
            deny_tables: vec!["vault.secrets".to_owned()],
            ..ObjectRules::default()
        },
        ..PolicySettings::default()
    };
    let engine = engine(&settings);
    let connection = metadata("shop");
    let context = context();
    let search_filter = ObjectFilter::new(&engine, PolicyContext::new(&context, &connection));
    let search = SchemaSearchRequest::new(name(), "secrets", 10).unwrap();

    let found = inspector
        .search_schema(
            &search,
            search_filter,
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(found.matches.is_empty());

    let describe_filter = ObjectFilter::new(&engine, PolicyContext::new(&context, &connection));
    let describe =
        SchemaDescribeRequest::new(name(), vec!["vault.secrets".parse().unwrap()]).unwrap();
    let error = inspector
        .describe_schema(
            &describe,
            describe_filter,
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();

    let SchemaError::Rejected(rejection) = error else {
        panic!("expected an object-policy rejection");
    };
    assert_eq!(rejection.primary_code(), DenyCode::ObjectNotAllowed);
    pools.close().await;
}

#[tokio::test]
async fn an_unqualified_selector_cannot_reach_a_denied_schema() {
    let container = start_mysql().await;
    let pools = Arc::new(connect(&container, "vault").await);
    fixture(&pools).await;
    let inspector = MySqlSchemaInspector::new(Arc::clone(&pools), name());
    let settings = PolicySettings {
        objects: ObjectRules {
            schemas: Some(vec!["shop".to_owned()]),
            ..ObjectRules::default()
        },
        ..PolicySettings::default()
    };
    let engine = engine(&settings);
    let connection = metadata("vault");
    let context = context();
    let filter = ObjectFilter::new(&engine, PolicyContext::new(&context, &connection));
    let request = SchemaDescribeRequest::new(name(), vec!["secrets".parse().unwrap()]).unwrap();

    let error = inspector
        .describe_schema(
            &request,
            filter,
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();

    let SchemaError::Rejected(rejection) = error else {
        panic!("expected the resolved schema to be rejected");
    };
    assert_eq!(rejection.primary_code(), DenyCode::ObjectNotAllowed);
    pools.close().await;
}

#[tokio::test]
async fn a_second_call_is_served_from_the_cache() {
    let container = start_mysql().await;
    let pools = Arc::new(connect(&container, "shop").await);
    fixture(&pools).await;
    let inspector = MySqlSchemaInspector::new(Arc::clone(&pools), name());
    let permissive_engine = engine(&PolicySettings::default());
    let denied_engine = engine(&PolicySettings {
        objects: ObjectRules {
            schemas: Some(vec!["vault".to_owned()]),
            ..ObjectRules::default()
        },
        ..PolicySettings::default()
    });
    let connection = metadata("shop");
    let context = context();
    let request = SchemaDescribeRequest::new(name(), vec!["orders".parse().unwrap()]).unwrap();

    let first = inspector
        .describe_schema(
            &request,
            ObjectFilter::new(
                &permissive_engine,
                PolicyContext::new(&context, &connection),
            ),
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    // Keep the relation resolvable: describe must repeat visibility resolution before
    // consulting the cache, so only metadata changes distinguish a hit from a fetch.
    sqlx::query(AssertSqlSafe(
        "ALTER TABLE shop.orders ADD COLUMN cache_probe BIGINT".to_owned(),
    ))
    .execute(pools.control())
    .await
    .unwrap();
    let second = inspector
        .describe_schema(
            &request,
            ObjectFilter::new(
                &permissive_engine,
                PolicyContext::new(&context, &connection),
            ),
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

    // A cache hit cannot bypass live resolution and its resolved-object policy
    // check. The written selector is unqualified, so only that second check knows it
    // resolved into the now-denied `shop` schema.
    let error = inspector
        .describe_schema(
            &request,
            ObjectFilter::new(&denied_engine, PolicyContext::new(&context, &connection)),
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
    let SchemaError::Rejected(rejection) = error else {
        panic!("expected the cached resolved object to be rejected");
    };
    assert_eq!(rejection.primary_code(), DenyCode::ObjectNotAllowed);

    // The cache also cannot replace live database visibility. Renaming keeps the
    // relation itself intact while making the cached selector unresolvable.
    sqlx::query(AssertSqlSafe(
        "RENAME TABLE shop.orders TO shop.orders_hidden".to_owned(),
    ))
    .execute(pools.control())
    .await
    .unwrap();
    let no_longer_visible = inspector
        .describe_schema(
            &request,
            ObjectFilter::new(
                &permissive_engine,
                PolicyContext::new(&context, &connection),
            ),
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert!(no_longer_visible.schemas.is_empty());
    pools.close().await;
}

#[tokio::test]
async fn an_expired_cache_entry_is_refetched() {
    let container = start_mysql().await;
    let pools = Arc::new(connect(&container, "shop").await);
    fixture(&pools).await;
    let inspector = MySqlSchemaInspector::with_cache_for_tests(
        Arc::clone(&pools),
        name(),
        SchemaCache::new(Duration::ZERO, SCHEMA_CACHE_CAPACITY),
    );
    let engine = engine(&PolicySettings::default());
    let connection = metadata("shop");
    let context = context();
    let request = SchemaDescribeRequest::new(name(), vec!["shop.orders".parse().unwrap()]).unwrap();

    let first = inspector
        .describe_schema(
            &request,
            ObjectFilter::new(&engine, PolicyContext::new(&context, &connection)),
            super::deadline(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    // The same resolvable relation now changes shape; zero TTL must expose that
    // post-mutation description instead of the cached snapshot.
    sqlx::query(AssertSqlSafe(
        "ALTER TABLE shop.orders ADD COLUMN expired_probe BIGINT".to_owned(),
    ))
    .execute(pools.control())
    .await
    .unwrap();
    let second = inspector
        .describe_schema(
            &request,
            ObjectFilter::new(&engine, PolicyContext::new(&context, &connection)),
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
    pools.close().await;
}

#[tokio::test]
async fn a_cancelled_token_stops_a_catalog_read() {
    let container = start_mysql().await;
    let pools = Arc::new(connect(&container, "shop").await);
    fixture(&pools).await;
    let inspector = MySqlSchemaInspector::new(Arc::clone(&pools), name());
    let engine = engine(&PolicySettings::default());
    let connection = metadata("shop");
    let context = context();
    let filter = ObjectFilter::new(&engine, PolicyContext::new(&context, &connection));
    let request = SchemaDescribeRequest::new(name(), vec!["orders".parse().unwrap()]).unwrap();
    let cancel = CancellationToken::new();
    cancel.cancel();

    let error = inspector
        .describe_schema(&request, filter, super::deadline(), cancel)
        .await
        .unwrap_err();

    assert_eq!(error, SchemaError::Cancelled);
    pools.close().await;
}

#[tokio::test]
async fn an_elapsed_deadline_stops_a_catalog_read() {
    let container = start_mysql().await;
    let pools = Arc::new(connect(&container, "shop").await);
    fixture(&pools).await;
    let inspector = MySqlSchemaInspector::new(Arc::clone(&pools), name());
    let engine = engine(&PolicySettings::default());
    let connection = metadata("shop");
    let context = context();
    let filter = ObjectFilter::new(&engine, PolicyContext::new(&context, &connection));
    let request = SchemaDescribeRequest::new(name(), vec!["orders".parse().unwrap()]).unwrap();

    let error = inspector
        .describe_schema(&request, filter, Instant::now(), CancellationToken::new())
        .await
        .unwrap_err();

    assert_eq!(error, SchemaError::Timeout);
    pools.close().await;
}

#[tokio::test]
async fn the_catalog_statements_never_touch_the_agent_pool() {
    let container = start_mysql().await;
    let pools = Arc::new(connect(&container, "shop").await);
    fixture(&pools).await;
    let inspector = MySqlSchemaInspector::new(Arc::clone(&pools), name());
    let engine = engine(&PolicySettings::default());
    let connection = metadata("shop");
    let context = context();
    let filter = ObjectFilter::new(&engine, PolicyContext::new(&context, &connection));
    let search_request = SchemaSearchRequest::new(name(), "orders", 10).unwrap();
    let describe_request =
        SchemaDescribeRequest::new(name(), vec!["orders".parse().unwrap()]).unwrap();

    {
        let mut held = Vec::new();
        for _ in 0..AGENT_POOL_MAX_CONNECTIONS {
            held.push(pools.agent().acquire().await.unwrap());
        }
        let found = inspector
            .search_schema(
                &search_request,
                filter,
                super::deadline(),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(found.matches[0].table, "orders");

        let described = inspector
            .describe_schema(
                &describe_request,
                filter,
                super::deadline(),
                CancellationToken::new(),
            )
            .await
            .unwrap();
        assert_eq!(described.schemas[0].tables[0].name, "orders");
    }

    pools.close().await;
}
