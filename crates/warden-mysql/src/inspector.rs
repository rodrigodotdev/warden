//! MySQL's `SchemaInspector`: catalog reads, object rules, bounds, and a cache.
//!
//! ```text
//! search_schema    cache hit? ─ no ─> INDEX_SQL on control_pool ─> group ─> cache
//!                       │
//!                       └─> CatalogIndex::search(terms, limit, filter.permits)
//!
//! describe_schema  filter.check(written selector)
//!                       ↓ RESOLVE_SQL            default database fills the gap
//!                  filter.check(resolved name)   the schema is only known now
//!                       ↓ cache hit? ─ no ─> columns + indexes + foreign keys
//! ```
//!
//! Every statement runs on `control_pool` (ADR-0025) and every one is a constant
//! from [`crate::catalog`] with bound parameters.

use std::future::Future;
use std::sync::Arc;
use std::time::Instant as StdInstant;

use sqlx::Row as _;
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;
use warden_core::analysis::{ObjectKind, ObjectRef, SqlIdentifier};
use warden_core::connection::ConnectionName;
use warden_core::schema::cache::SchemaCache;
use warden_core::schema::search::CatalogIndex;
use warden_core::schema::{
    MAX_CATALOG_ROWS, MAX_DESCRIBED_COLUMNS, MAX_DESCRIBED_FOREIGN_KEYS, MAX_DESCRIBED_INDEXES,
    Schema, SchemaDescribeRequest, SchemaDescription, SchemaSearchRequest, SchemaSearchResult,
    Table, TableSelector,
};
use warden_policy::ObjectFilter;
use warden_ports::error::SchemaError;
use warden_ports::{BoxFuture, SchemaInspector};

use crate::catalog;
use crate::connection::MySqlConnectionPools;

/// Reads bounded schema metadata for one MySQL connection.
#[derive(Debug)]
pub struct MySqlSchemaInspector {
    pools: Arc<MySqlConnectionPools>,
    connection: ConnectionName,
    cache: SchemaCache,
}

impl MySqlSchemaInspector {
    /// Builds an inspector over one connection's pools.
    ///
    /// The connection name is the cache key's first component, so an inspector can
    /// never answer for a database it does not serve
    /// (`docs/data-model.md` section 9.2).
    #[must_use]
    pub fn new(pools: Arc<MySqlConnectionPools>, connection: ConnectionName) -> Self {
        Self {
            pools,
            connection,
            cache: SchemaCache::default(),
        }
    }

    /// Builds an inspector with an explicit cache for expiry tests.
    #[cfg(all(test, feature = "docker"))]
    pub(crate) fn with_cache_for_tests(
        pools: Arc<MySqlConnectionPools>,
        connection: ConnectionName,
        cache: SchemaCache,
    ) -> Self {
        Self {
            pools,
            connection,
            cache,
        }
    }

    async fn search(
        &self,
        request: &SchemaSearchRequest,
        filter: ObjectFilter<'_>,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<SchemaSearchResult, SchemaError> {
        let now = StdInstant::now();
        let index = match self.cache.catalog(&self.connection, now) {
            Some(cached) => cached,
            None => {
                let rows = guarded(
                    sqlx::query(catalog::INDEX_SQL)
                        .bind(MAX_CATALOG_ROWS as i64)
                        .fetch_all(self.pools.control()),
                    deadline,
                    cancel,
                )
                .await?;
                let bounded = rows.len() == MAX_CATALOG_ROWS;
                let rows = rows
                    .into_iter()
                    .map(|row| {
                        Ok(catalog::IndexRow {
                            schema: row.try_get("table_schema").map_err(database_error)?,
                            table: row.try_get("table_name").map_err(database_error)?,
                            table_type: row.try_get("table_type").map_err(database_error)?,
                            column: row.try_get("column_name").map_err(database_error)?,
                        })
                    })
                    .collect::<Result<Vec<_>, SchemaError>>()?;
                let index = Arc::new(CatalogIndex::new(catalog::group_index(rows), bounded));
                self.cache
                    .store_catalog(&self.connection, Arc::clone(&index), now);
                index
            }
        };

        Ok(index.search(request.terms(), request.limit(), |relation| {
            filter.permits(&object_ref(&relation.schema, &relation.name))
        }))
    }

    async fn describe(
        &self,
        request: &SchemaDescribeRequest,
        filter: ObjectFilter<'_>,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<SchemaDescription, SchemaError> {
        let now = StdInstant::now();
        let mut schemas: Vec<Schema> = Vec::new();

        for selector in request.tables() {
            filter.check(&selector_ref(selector))?;

            let Some((schema, name, kind)) = self.resolve(selector, deadline, cancel).await? else {
                continue;
            };

            filter.check(&object_ref(&schema, &name))?;

            let table = match self.cache.table(&self.connection, &schema, &name, now) {
                Some(cached) => cached,
                None => {
                    let described = Arc::new(
                        self.describe_one(&schema, &name, kind, deadline, cancel)
                            .await?,
                    );
                    self.cache
                        .store_table(&self.connection, Arc::clone(&described), now);
                    described
                }
            };

            if let Some(group) = schemas.iter_mut().find(|group| group.name == schema) {
                group.tables.push(table.as_ref().clone());
            } else {
                schemas.push(Schema {
                    name: schema,
                    tables: vec![table.as_ref().clone()],
                });
            }
        }

        Ok(SchemaDescription { schemas })
    }

    async fn resolve(
        &self,
        selector: &TableSelector,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<Option<(String, String, warden_core::schema::TableKind)>, SchemaError> {
        let row = guarded(
            sqlx::query(catalog::RESOLVE_SQL)
                .bind(selector.schema())
                .bind(selector.name())
                .fetch_optional(self.pools.control()),
            deadline,
            cancel,
        )
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };

        let table_type: String = row.try_get("table_type").map_err(database_error)?;
        let Some(kind) = catalog::table_kind(&table_type) else {
            return Ok(None);
        };

        Ok(Some((
            row.try_get("table_schema").map_err(database_error)?,
            row.try_get("table_name").map_err(database_error)?,
            kind,
        )))
    }

    async fn describe_one(
        &self,
        schema: &str,
        name: &str,
        kind: warden_core::schema::TableKind,
        deadline: Instant,
        cancel: &CancellationToken,
    ) -> Result<Table, SchemaError> {
        let column_rows = guarded(
            sqlx::query(catalog::COLUMNS_SQL)
                .bind(schema)
                .bind(name)
                .bind(MAX_DESCRIBED_COLUMNS as i64)
                .fetch_all(self.pools.control()),
            deadline,
            cancel,
        )
        .await?;
        let columns_bounded = column_rows.len() == MAX_DESCRIBED_COLUMNS;
        let columns = column_rows
            .into_iter()
            .map(|row| {
                Ok(catalog::column(
                    row.try_get("column_name").map_err(database_error)?,
                    row.try_get("column_type").map_err(database_error)?,
                    row.try_get("is_nullable").map_err(database_error)?,
                    row.try_get("column_default").map_err(database_error)?,
                    row.try_get("column_comment").map_err(database_error)?,
                ))
            })
            .collect::<Result<Vec<_>, SchemaError>>()?;

        let index_rows = guarded(
            sqlx::query(catalog::INDEXES_SQL)
                .bind(schema)
                .bind(name)
                .bind(MAX_DESCRIBED_INDEXES as i64)
                .fetch_all(self.pools.control()),
            deadline,
            cancel,
        )
        .await?;
        let indexes_bounded = index_rows.len() == MAX_DESCRIBED_INDEXES;
        let index_rows = index_rows
            .into_iter()
            .map(|row| {
                Ok(catalog::IndexPartRow {
                    index: row.try_get("index_name").map_err(database_error)?,
                    column: row.try_get("column_name").map_err(database_error)?,
                    non_unique: row.try_get("non_unique").map_err(database_error)?,
                })
            })
            .collect::<Result<Vec<_>, SchemaError>>()?;
        let (primary_key, indexes, indexes_truncated) =
            catalog::group_indexes(index_rows, indexes_bounded);

        let foreign_key_rows = guarded(
            sqlx::query(catalog::FOREIGN_KEYS_SQL)
                .bind(schema)
                .bind(name)
                .bind(MAX_DESCRIBED_FOREIGN_KEYS as i64)
                .fetch_all(self.pools.control()),
            deadline,
            cancel,
        )
        .await?;
        let foreign_keys_bounded = foreign_key_rows.len() == MAX_DESCRIBED_FOREIGN_KEYS;
        let foreign_key_rows = foreign_key_rows
            .into_iter()
            .map(|row| {
                Ok(catalog::ForeignKeyRow {
                    constraint: row.try_get("constraint_name").map_err(database_error)?,
                    column: row.try_get("column_name").map_err(database_error)?,
                    referenced_schema: row.try_get("referenced_schema").map_err(database_error)?,
                    referenced_table: row.try_get("referenced_table").map_err(database_error)?,
                    referenced_column: row.try_get("referenced_column").map_err(database_error)?,
                })
            })
            .collect::<Result<Vec<_>, SchemaError>>()?;
        let foreign_keys = catalog::group_foreign_keys(foreign_key_rows);

        Ok(Table {
            schema: schema.to_owned(),
            name: name.to_owned(),
            kind,
            columns,
            primary_key,
            foreign_keys,
            indexes,
            truncated: columns_bounded || indexes_truncated || foreign_keys_bounded,
        })
    }
}

impl SchemaInspector for MySqlSchemaInspector {
    fn search_schema<'a>(
        &'a self,
        request: &'a SchemaSearchRequest,
        filter: ObjectFilter<'a>,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<SchemaSearchResult, SchemaError>> {
        Box::pin(async move { self.search(request, filter, deadline, &cancel).await })
    }

    fn describe_schema<'a>(
        &'a self,
        request: &'a SchemaDescribeRequest,
        filter: ObjectFilter<'a>,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<SchemaDescription, SchemaError>> {
        Box::pin(async move { self.describe(request, filter, deadline, &cancel).await })
    }
}

/// Races one catalog statement against the deadline and the token.
///
/// `CancellationToken::run_until_cancelled` rather than `tokio::select!`: this crate
/// depends on `tokio` with the `time` feature only, and reaching for `select!` would
/// enable `macros` for a race the token already expresses.
///
/// The server-side bound already exists — `MAX_EXECUTION_TIME` is pinned in this
/// connection's session hardening and applies to `SELECT`, which every statement
/// here is — so losing this race leaves at most that bound running, not an
/// unbounded query (ADR-0024).
async fn guarded<T>(
    future: impl Future<Output = Result<T, sqlx::Error>>,
    deadline: Instant,
    cancel: &CancellationToken,
) -> Result<T, SchemaError> {
    let Some(result) = cancel
        .run_until_cancelled(timeout_at(deadline, future))
        .await
    else {
        return Err(SchemaError::Cancelled);
    };
    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(database_error(error)),
        Err(_elapsed) => Err(SchemaError::Timeout),
    }
}

/// Maps a driver or decoder failure to the schema port's typed error.
fn database_error(error: sqlx::Error) -> SchemaError {
    SchemaError::Database {
        detail: error.to_string(),
    }
}

/// The `ObjectRef` a catalog name becomes for a policy comparison.
///
/// Unquoted on MySQL: `warden_policy::folding` ignores quoting for this dialect and
/// compares case-insensitively, which is the fail-closed reading `docs/security.md`
/// section 5.1 fixes, so the flag would change nothing and claiming the catalog
/// "quoted" a name would be a fact this crate does not have.
fn object_ref(schema: &str, name: &str) -> ObjectRef {
    ObjectRef {
        catalog: None,
        schema: Some(SqlIdentifier::unquoted(schema)),
        name: SqlIdentifier::unquoted(name),
        kind: ObjectKind::Table,
    }
}

/// The `ObjectRef` the selector the agent wrote becomes for its first policy check.
fn selector_ref(selector: &TableSelector) -> ObjectRef {
    ObjectRef {
        catalog: None,
        schema: selector.schema().map(SqlIdentifier::unquoted),
        name: SqlIdentifier::unquoted(selector.name()),
        kind: ObjectKind::Table,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::Arc;

    use warden_core::connection::ConnectionName;
    use warden_core::dialect::Dialect;
    use warden_core::schema::TableSelector;
    use warden_policy::folding::rule_matches;
    use warden_ports::SchemaInspector;

    use super::{MySqlSchemaInspector, object_ref, selector_ref};
    use crate::connection::MySqlConnectionPools;

    #[test]
    fn catalog_object_references_are_unquoted_and_match_mysql_rules() {
        let object = object_ref("App", "Orders");

        assert!(object.catalog.is_none());
        let schema = object
            .schema
            .as_ref()
            .expect("catalog objects have schemas");
        assert!(rule_matches(Dialect::MySql, "app", schema));
        assert!(rule_matches(Dialect::MySql, "orders", &object.name));
    }

    #[test]
    fn an_unqualified_selector_stays_schema_free_for_policy() {
        let selector: TableSelector = "orders".parse().expect("valid selector");
        let object = selector_ref(&selector);

        assert!(object.catalog.is_none());
        assert!(object.schema.is_none());
        assert!(rule_matches(Dialect::MySql, "orders", &object.name));
    }

    #[test]
    fn the_inspector_is_send_sync_and_coerces_to_its_port() {
        fn assert_send_sync<T: Send + Sync>() {}
        fn as_schema_inspector(inspector: Arc<MySqlSchemaInspector>) -> Arc<dyn SchemaInspector> {
            inspector
        }

        assert_send_sync::<MySqlSchemaInspector>();
        let _ = as_schema_inspector as fn(Arc<MySqlSchemaInspector>) -> Arc<dyn SchemaInspector>;
    }

    #[tokio::test]
    async fn a_new_inspector_starts_with_an_empty_cache() {
        let pools = Arc::new(MySqlConnectionPools::lazy_for_tests());
        let connection: ConnectionName = "production-mysql".parse().expect("valid connection");
        let inspector = MySqlSchemaInspector::new(pools, connection);

        assert!(inspector.cache.is_empty());
    }
}
