//! PostgreSQL's `pg_catalog`, as five static statements.
//!
//! This is trusted internal SQL (`docs/security.md` section 12.1): Warden wrote
//! every character, an agent supplies only bound parameters, and none of it passes
//! through the policy pipeline. There is no `format!` in this file and no reachable
//! way to add one — every variable part is a `$n` parameter.
//!
//! Search and resolution filter on `pg_catalog.has_table_privilege(c.oid, 'SELECT')`
//! and `has_schema_privilege(n.oid, 'USAGE')`. Detail statements consume only an
//! exact pair resolution already cleared, while foreign keys repeat those checks for
//! `fc`/`fn`, the referenced table and schema. Unlike MySQL's `information_schema`,
//! PostgreSQL's catalog is world-readable, so these predicates bind discovery to the
//! same `GRANT` that bounds reading (ADR-0023).

use warden_core::schema::search::IndexedRelation;
use warden_core::schema::{
    ColumnDescription, ForeignKey, IndexDescription, MAX_INDEXED_COLUMNS, SchemaMetadataBudget,
    TableKind,
};

/// One row per visible relation column, ordered so grouping is linear.
pub(crate) const INDEX_SQL: &str = "\
SELECT n.nspname AS table_schema, \
       c.relname AS table_name, \
       c.relkind::text AS relkind, \
       a.attname AS column_name \
  FROM pg_catalog.pg_class AS c \
  JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace \
  LEFT JOIN pg_catalog.pg_attribute AS a \
    ON a.attrelid = c.oid AND a.attnum > 0 AND NOT a.attisdropped \
 WHERE c.relkind IN ('r', 'p', 'v', 'm') \
   AND n.nspname NOT IN ('pg_catalog', 'information_schema') \
   AND n.nspname NOT LIKE 'pg\\_toast%' \
   AND n.nspname NOT LIKE 'pg\\_temp%' \
   AND pg_catalog.has_schema_privilege(n.oid, 'USAGE') \
   AND pg_catalog.has_table_privilege(c.oid, 'SELECT') \
 ORDER BY n.nspname, c.relname, a.attnum \
 LIMIT $1";

/// Resolves a selector. With no schema, `current_schemas(false)` reproduces the
/// server's own `search_path` order, so Warden resolves the name the way the query
/// would (`docs/security.md` section 5.1 bypass 2, closed at connect time).
pub(crate) const RESOLVE_SQL: &str = "\
SELECT n.nspname AS table_schema, c.relname AS table_name, c.relkind::text AS relkind \
  FROM pg_catalog.pg_class AS c \
  JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace \
 WHERE c.relname = $2 \
   AND c.relkind IN ('r', 'p', 'v', 'm') \
   AND ($1::text IS NULL OR n.nspname = $1::text) \
   AND ($1::text IS NOT NULL OR n.nspname = ANY (pg_catalog.current_schemas(false))) \
   AND pg_catalog.has_schema_privilege(n.oid, 'USAGE') \
   AND pg_catalog.has_table_privilege(c.oid, 'SELECT') \
 ORDER BY array_position(pg_catalog.current_schemas(false), n.nspname) \
 LIMIT 1";

/// The three detail statements deliberately do not repeat the privilege predicates:
/// [`RESOLVE_SQL`] already cleared their exact `(schema, table)` pair.
/// `left` fetches one sentinel character beyond the byte limit before driver
/// decoding; core applies the exact UTF-8 byte and accumulated response bounds and
/// uses that sentinel to report truncation.
pub(crate) const COLUMNS_SQL: &str = "\
SELECT a.attname AS column_name, \
       pg_catalog.format_type(a.atttypid, a.atttypmod) AS data_type, \
       NOT a.attnotnull AS is_nullable, \
       pg_catalog.left(pg_catalog.pg_get_expr(d.adbin, d.adrelid), $4::integer) AS column_default, \
       pg_catalog.left(pg_catalog.col_description(c.oid, a.attnum), $4::integer) AS column_comment \
  FROM pg_catalog.pg_class AS c \
  JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace \
  JOIN pg_catalog.pg_attribute AS a ON a.attrelid = c.oid \
  LEFT JOIN pg_catalog.pg_attrdef AS d ON d.adrelid = c.oid AND d.adnum = a.attnum \
 WHERE n.nspname = $1 AND c.relname = $2 \
   AND a.attnum > 0 AND NOT a.attisdropped \
 ORDER BY a.attnum \
 LIMIT $3";

/// Indexes and the primary key in one pass. `unnest(indkey) WITH ORDINALITY` keeps
/// the key columns in index order; an expression part has `attnum = 0`, so its
/// `attname` is NULL and the row is dropped rather than named.
pub(crate) const INDEXES_SQL: &str = "\
SELECT ic.relname AS index_name, \
       i.indisunique AS is_unique, \
       i.indisprimary AS is_primary, \
       a.attname AS column_name \
  FROM pg_catalog.pg_class AS c \
  JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace \
  JOIN pg_catalog.pg_index AS i ON i.indrelid = c.oid \
  JOIN pg_catalog.pg_class AS ic ON ic.oid = i.indexrelid \
  JOIN LATERAL pg_catalog.unnest(i.indkey) WITH ORDINALITY AS k(attnum, ord) ON true \
  LEFT JOIN pg_catalog.pg_attribute AS a ON a.attrelid = c.oid AND a.attnum = k.attnum \
 WHERE n.nspname = $1 AND c.relname = $2 AND i.indislive \
 ORDER BY ic.relname, k.ord \
 LIMIT $3";

/// Returns visible FK parts plus a name-free sentinel when any target is hidden.
///
/// The sentinel lets the response report partiality without disclosing which
/// constraint or target the role cannot see.
pub(crate) const FOREIGN_KEYS_SQL: &str = "\
WITH visible_foreign_keys AS ( \
    SELECT con.conname AS constraint_name, \
           k.ord AS position, \
           a.attname AS column_name, \
           fn.nspname AS referenced_schema, \
           fc.relname AS referenced_table, \
           fa.attname AS referenced_column \
      FROM pg_catalog.pg_constraint AS con \
      JOIN pg_catalog.pg_class AS c ON c.oid = con.conrelid \
      JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace \
      JOIN pg_catalog.pg_class AS fc ON fc.oid = con.confrelid \
      JOIN pg_catalog.pg_namespace AS fn ON fn.oid = fc.relnamespace \
      JOIN LATERAL ROWS FROM (pg_catalog.unnest(con.conkey), pg_catalog.unnest(con.confkey)) \
           WITH ORDINALITY AS k(att, fatt, ord) ON true \
      JOIN pg_catalog.pg_attribute AS a ON a.attrelid = c.oid AND a.attnum = k.att \
      JOIN pg_catalog.pg_attribute AS fa ON fa.attrelid = fc.oid AND fa.attnum = k.fatt \
     WHERE n.nspname = $1 AND c.relname = $2 AND con.contype = 'f' \
       AND pg_catalog.has_schema_privilege(fn.oid, 'USAGE') \
       AND pg_catalog.has_table_privilege(fc.oid, 'SELECT') \
), hidden_target AS ( \
    SELECT EXISTS ( \
        SELECT 1 \
          FROM pg_catalog.pg_constraint AS con \
          JOIN pg_catalog.pg_class AS c ON c.oid = con.conrelid \
          JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace \
          JOIN pg_catalog.pg_class AS fc ON fc.oid = con.confrelid \
          JOIN pg_catalog.pg_namespace AS fn ON fn.oid = fc.relnamespace \
         WHERE n.nspname = $1 AND c.relname = $2 AND con.contype = 'f' \
           AND NOT (pg_catalog.has_schema_privilege(fn.oid, 'USAGE') \
                    AND pg_catalog.has_table_privilege(fc.oid, 'SELECT')) \
    ) AS omitted \
) \
SELECT constraint_name, position, column_name, referenced_schema, referenced_table, \
       referenced_column, false AS metadata_truncated \
  FROM visible_foreign_keys \
UNION ALL \
SELECT NULL, NULL, NULL, NULL, NULL, NULL, true AS metadata_truncated \
  FROM hidden_target \
 WHERE omitted \
 ORDER BY metadata_truncated DESC, constraint_name, position \
 LIMIT $3";

/// `relkind` to the core model.
///
/// `r` and `p` are both tables: a partitioned parent is a table an agent queries
/// like any other, and inventing a third kind for it would be a distinction the
/// core model does not carry. `_` maps to `None`, denied by omission, which is the
/// same wildcard discipline the analyzer follows (ADR-0011).
pub(crate) fn table_kind(relkind: &str) -> Option<TableKind> {
    match relkind {
        "r" | "p" => Some(TableKind::Table),
        "v" => Some(TableKind::View),
        "m" => Some(TableKind::MaterializedView),
        _ => None,
    }
}

/// One decoded row of [`INDEX_SQL`].
pub(crate) struct IndexRow {
    pub(crate) schema: String,
    pub(crate) table: String,
    pub(crate) relkind: String,
    pub(crate) column: Option<String>,
}

/// Groups ordered index rows and bounds each relation's column list independently.
pub(crate) fn group_index(rows: Vec<IndexRow>) -> Vec<IndexedRelation> {
    let mut relations: Vec<IndexedRelation> = Vec::new();
    for row in rows {
        let Some(kind) = table_kind(&row.relkind) else {
            continue;
        };
        match relations.last_mut() {
            Some(last) if last.schema == row.schema && last.name == row.table => {
                if let Some(column) = row.column {
                    if last.columns.len() < MAX_INDEXED_COLUMNS {
                        last.columns.push(column);
                    } else {
                        last.truncated = true;
                    }
                }
            }
            _ => relations.push(IndexedRelation {
                schema: row.schema,
                name: row.table,
                kind,
                columns: row.column.into_iter().collect(),
                truncated: false,
            }),
        }
    }
    relations
}

/// One decoded row of [`INDEXES_SQL`].
pub(crate) struct IndexPartRow {
    pub(crate) index: String,
    pub(crate) column: Option<String>,
    pub(crate) is_unique: bool,
    pub(crate) is_primary: bool,
}

/// The primary key and the index list, plus whether anything was left out.
///
/// A functional index part has a NULL `column_name`. Warden drops it and reports
/// truncation rather than inventing a name for an expression the catalog did not
/// name (`docs/architecture.md` section 11).
pub(crate) fn group_indexes(
    rows: Vec<IndexPartRow>,
    bounded: bool,
) -> (Vec<String>, Vec<IndexDescription>, bool) {
    let mut indexes: Vec<IndexDescription> = Vec::new();
    let mut truncated = bounded;
    for row in rows {
        let Some(column) = row.column else {
            truncated = true;
            continue;
        };
        match indexes.last_mut() {
            Some(last) if last.name == row.index => last.columns.push(column),
            _ => indexes.push(IndexDescription {
                primary: row.is_primary,
                unique: row.is_unique,
                name: row.index,
                columns: vec![column],
            }),
        }
    }
    let primary_key = indexes
        .iter()
        .find(|index| index.primary)
        .map(|index| index.columns.clone())
        .unwrap_or_default();
    (primary_key, indexes, truncated)
}

/// One decoded row of [`FOREIGN_KEYS_SQL`].
pub(crate) struct ForeignKeyRow {
    pub(crate) constraint: String,
    pub(crate) column: String,
    pub(crate) referenced_schema: String,
    pub(crate) referenced_table: String,
    pub(crate) referenced_column: String,
}

/// Groups ordered key-column rows into constraints.
pub(crate) fn group_foreign_keys(rows: Vec<ForeignKeyRow>) -> Vec<ForeignKey> {
    let mut keys: Vec<ForeignKey> = Vec::new();
    for row in rows {
        match keys.last_mut() {
            Some(last) if last.name.as_deref() == Some(row.constraint.as_str()) => {
                last.columns.push(row.column);
                last.referenced_columns.push(row.referenced_column);
            }
            _ => keys.push(ForeignKey {
                name: Some(row.constraint),
                columns: vec![row.column],
                referenced_schema: row.referenced_schema,
                referenced_table: row.referenced_table,
                referenced_columns: vec![row.referenced_column],
            }),
        }
    }
    keys
}

/// PostgreSQL exposes nullability as a boolean catalog expression.
pub(crate) fn column(
    name: String,
    column_type: String,
    is_nullable: bool,
    default: Option<String>,
    comment: Option<String>,
    budget: &mut SchemaMetadataBudget,
) -> ColumnDescription {
    ColumnDescription {
        name,
        database_type: column_type,
        nullable: is_nullable,
        default: budget.bound(default),
        comment: budget.bound(comment.filter(|value| !value.is_empty())),
    }
}

#[cfg(test)]
mod tests {
    use warden_core::schema::TableKind;

    use super::{
        COLUMNS_SQL, FOREIGN_KEYS_SQL, ForeignKeyRow, INDEX_SQL, INDEXES_SQL, IndexPartRow,
        IndexRow, RESOLVE_SQL, column, group_foreign_keys, group_index, group_indexes, table_kind,
    };
    use warden_core::schema::search::IndexedRelation;
    use warden_core::schema::{
        ForeignKey, IndexDescription, MAX_INDEXED_COLUMNS, MAX_SCHEMA_DESCRIPTION_BYTES,
        MAX_SCHEMA_VALUE_BYTES, SchemaMetadataBudget,
    };

    #[test]
    fn index_rows_group_by_adjacent_schema_and_table() {
        let relations = group_index(vec![
            IndexRow {
                schema: "app".to_owned(),
                table: "orders".to_owned(),
                relkind: "r".to_owned(),
                column: Some("id".to_owned()),
            },
            IndexRow {
                schema: "app".to_owned(),
                table: "orders".to_owned(),
                relkind: "r".to_owned(),
                column: Some("customer_id".to_owned()),
            },
            IndexRow {
                schema: "app".to_owned(),
                table: "order_summary".to_owned(),
                relkind: "v".to_owned(),
                column: Some("total".to_owned()),
            },
        ]);

        assert_eq!(
            relations,
            vec![
                IndexedRelation {
                    schema: "app".to_owned(),
                    name: "orders".to_owned(),
                    kind: TableKind::Table,
                    columns: vec!["id".to_owned(), "customer_id".to_owned()],
                    truncated: false,
                },
                IndexedRelation {
                    schema: "app".to_owned(),
                    name: "order_summary".to_owned(),
                    kind: TableKind::View,
                    columns: vec!["total".to_owned()],
                    truncated: false,
                },
            ]
        );
    }

    #[test]
    fn a_relation_without_visible_columns_stays_in_the_catalog() {
        let relations = group_index(vec![IndexRow {
            schema: "app".to_owned(),
            table: "empty".to_owned(),
            relkind: "r".to_owned(),
            column: None,
        }]);

        assert_eq!(
            relations,
            vec![IndexedRelation {
                schema: "app".to_owned(),
                name: "empty".to_owned(),
                kind: TableKind::Table,
                columns: Vec::new(),
                truncated: false,
            }]
        );
    }

    #[test]
    fn index_rows_stop_at_the_indexed_column_limit() {
        let rows = (0..=MAX_INDEXED_COLUMNS)
            .map(|_| IndexRow {
                schema: "app".to_owned(),
                table: "wide".to_owned(),
                relkind: "r".to_owned(),
                column: Some("column".to_owned()),
            })
            .collect();

        let relations = group_index(rows);

        assert_eq!(relations[0].columns.len(), MAX_INDEXED_COLUMNS);
        assert!(relations[0].truncated);
    }

    #[test]
    fn index_rows_drop_an_unmapped_relation_kind() {
        let relations = group_index(vec![IndexRow {
            schema: "app".to_owned(),
            table: "index_backed".to_owned(),
            relkind: "i".to_owned(),
            column: Some("id".to_owned()),
        }]);

        assert!(relations.is_empty());
    }

    #[test]
    fn a_functional_index_part_marks_the_description_truncated() {
        let (primary_key, indexes, truncated) = group_indexes(
            vec![IndexPartRow {
                index: "by_expression".to_owned(),
                column: None,
                is_unique: false,
                is_primary: false,
            }],
            false,
        );

        assert!(primary_key.is_empty());
        assert!(indexes.is_empty());
        assert!(truncated);
    }

    #[test]
    fn composite_primary_keys_preserve_sequence_order() {
        let (primary_key, indexes, truncated) = group_indexes(
            vec![
                IndexPartRow {
                    index: "orders_pkey".to_owned(),
                    column: Some("account_id".to_owned()),
                    is_unique: true,
                    is_primary: true,
                },
                IndexPartRow {
                    index: "orders_pkey".to_owned(),
                    column: Some("order_id".to_owned()),
                    is_unique: true,
                    is_primary: true,
                },
            ],
            false,
        );

        assert_eq!(primary_key, vec!["account_id", "order_id"]);
        assert_eq!(
            indexes,
            vec![IndexDescription {
                name: "orders_pkey".to_owned(),
                columns: vec!["account_id".to_owned(), "order_id".to_owned()],
                unique: true,
                primary: true,
            }]
        );
        assert!(!truncated);
    }

    #[test]
    fn foreign_key_columns_stay_positionally_paired() {
        let keys = group_foreign_keys(vec![
            ForeignKeyRow {
                constraint: "line_item_order".to_owned(),
                column: "tenant_id".to_owned(),
                referenced_schema: "app".to_owned(),
                referenced_table: "orders".to_owned(),
                referenced_column: "tenant_id".to_owned(),
            },
            ForeignKeyRow {
                constraint: "line_item_order".to_owned(),
                column: "order_id".to_owned(),
                referenced_schema: "app".to_owned(),
                referenced_table: "orders".to_owned(),
                referenced_column: "id".to_owned(),
            },
        ]);

        assert_eq!(
            keys,
            vec![ForeignKey {
                name: Some("line_item_order".to_owned()),
                columns: vec!["tenant_id".to_owned(), "order_id".to_owned()],
                referenced_schema: "app".to_owned(),
                referenced_table: "orders".to_owned(),
                referenced_columns: vec!["tenant_id".to_owned(), "id".to_owned()],
            }]
        );
    }

    #[test]
    fn nullable_boolean_and_empty_comments_are_normalized() {
        let mut budget = SchemaMetadataBudget::default();
        let nullable = column(
            "optional".to_owned(),
            "character varying(255)".to_owned(),
            true,
            None,
            Some(String::new()),
            &mut budget,
        );
        let required = column(
            "required".to_owned(),
            "integer".to_owned(),
            false,
            None,
            None,
            &mut budget,
        );

        assert!(nullable.nullable);
        assert_eq!(nullable.comment, None);
        assert!(!required.nullable);
    }

    #[test]
    fn large_defaults_and_comments_are_cut_on_utf8_boundaries() {
        let oversized = "🙂".repeat(MAX_SCHEMA_VALUE_BYTES / "🙂".len() + 1);
        let mut default_budget = SchemaMetadataBudget::default();
        let with_default = column(
            "with_default".to_owned(),
            "text".to_owned(),
            true,
            Some(oversized.clone()),
            None,
            &mut default_budget,
        );
        let mut comment_budget = SchemaMetadataBudget::default();
        let with_comment = column(
            "with_comment".to_owned(),
            "text".to_owned(),
            true,
            None,
            Some(oversized),
            &mut comment_budget,
        );

        assert_eq!(
            with_default.default.as_deref().map(str::len),
            Some(MAX_SCHEMA_VALUE_BYTES)
        );
        assert_eq!(
            with_comment.comment.as_deref().map(str::len),
            Some(MAX_SCHEMA_VALUE_BYTES)
        );
        assert!(default_budget.truncated());
        assert!(comment_budget.truncated());
    }

    #[test]
    fn column_mapping_obeys_the_accumulated_description_budget() {
        let mut budget = SchemaMetadataBudget::default();
        let columns: Vec<_> = (0..3)
            .map(|index| {
                column(
                    index.to_string(),
                    "text".to_owned(),
                    true,
                    Some("d".repeat(MAX_SCHEMA_VALUE_BYTES)),
                    Some("c".repeat(MAX_SCHEMA_VALUE_BYTES)),
                    &mut budget,
                )
            })
            .collect();

        let retained_bytes: usize = columns
            .iter()
            .flat_map(|column| [column.default.as_ref(), column.comment.as_ref()])
            .flatten()
            .map(String::len)
            .sum();
        assert_eq!(retained_bytes, MAX_SCHEMA_DESCRIPTION_BYTES);
        assert!(budget.truncated());
    }

    #[test]
    fn a_partitioned_parent_is_a_table_and_an_index_is_nothing() {
        assert_eq!(table_kind("p"), Some(TableKind::Table));
        assert_eq!(table_kind("m"), Some(TableKind::MaterializedView));
        assert_eq!(table_kind("i"), None);
        assert_eq!(table_kind("S"), None);
    }

    #[test]
    fn every_catalog_statement_checks_both_privileges() {
        for sql in [INDEX_SQL, RESOLVE_SQL] {
            assert!(sql.contains("has_table_privilege"), "{sql}");
            assert!(sql.contains("has_schema_privilege"), "{sql}");
        }
        for sql in [
            INDEX_SQL,
            RESOLVE_SQL,
            COLUMNS_SQL,
            INDEXES_SQL,
            FOREIGN_KEYS_SQL,
        ] {
            assert!(!sql.contains('{'), "{sql}");
        }
    }

    #[test]
    fn foreign_key_targets_require_schema_usage_and_table_select() {
        assert!(
            FOREIGN_KEYS_SQL.contains("has_schema_privilege(fn.oid, 'USAGE')"),
            "{FOREIGN_KEYS_SQL}"
        );
        assert!(
            FOREIGN_KEYS_SQL.contains("has_table_privilege(fc.oid, 'SELECT')"),
            "{FOREIGN_KEYS_SQL}"
        );
    }
}
