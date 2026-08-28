//! MySQL's `information_schema`, as five static statements.
//!
//! This is trusted internal SQL (`docs/security.md` section 12.1): Warden wrote
//! every character, an agent supplies only bound parameters, and none of it passes
//! through the policy pipeline. There is no `format!` in this file and no reachable
//! way to add one — every variable part is a `?`.
//!
//! `information_schema` on MySQL 8 already hides objects the connected account has
//! no privilege on, so the `GRANT` bounds discovery here exactly as it bounds
//! reading (ADR-0023). Warden adds the system-schema exclusion on top, because
//! `information_schema` itself is readable by everyone and describes nothing an
//! agent investigating an application needs.

use warden_core::schema::search::IndexedRelation;
use warden_core::schema::{
    ColumnDescription, ForeignKey, IndexDescription, MAX_INDEXED_COLUMNS, TableKind,
};

/// One row per column of every visible relation, ordered so grouping is linear.
///
/// The system-schema list is written out in both statements that need it rather than
/// shared through a constant: `concat!` accepts only literals, and building the
/// statement any other way would put a runtime string operation into a file whose
/// whole claim is that it contains none.
pub(crate) const INDEX_SQL: &str = "\
SELECT t.TABLE_SCHEMA AS table_schema, \
       t.TABLE_NAME AS table_name, \
       t.TABLE_TYPE AS table_type, \
       c.COLUMN_NAME AS column_name \
  FROM information_schema.TABLES AS t \
  JOIN information_schema.COLUMNS AS c \
    ON c.TABLE_SCHEMA = t.TABLE_SCHEMA AND c.TABLE_NAME = t.TABLE_NAME \
 WHERE t.TABLE_SCHEMA NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys') \
   AND t.TABLE_TYPE IN ('BASE TABLE', 'VIEW') \
 ORDER BY t.TABLE_SCHEMA, t.TABLE_NAME, c.ORDINAL_POSITION \
 LIMIT ?";

/// Resolves a selector to one relation, using the default database when the agent
/// wrote no schema.
pub(crate) const RESOLVE_SQL: &str = "\
SELECT TABLE_SCHEMA AS table_schema, TABLE_NAME AS table_name, \
       TABLE_TYPE AS table_type \
  FROM information_schema.TABLES \
 WHERE TABLE_SCHEMA = COALESCE(?, DATABASE()) \
   AND TABLE_NAME = ? \
   AND TABLE_SCHEMA NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys') \
   AND TABLE_TYPE IN ('BASE TABLE', 'VIEW') \
 LIMIT 1";

pub(crate) const COLUMNS_SQL: &str = "SELECT COLUMN_NAME AS column_name, \
            COLUMN_TYPE AS column_type, \
            IS_NULLABLE AS is_nullable, \
            COLUMN_DEFAULT AS column_default, \
            COLUMN_COMMENT AS column_comment \
       FROM information_schema.COLUMNS \
      WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? \
      ORDER BY ORDINAL_POSITION \
      LIMIT ?";

/// Indexes and the primary key in one pass: on MySQL the primary key **is** the
/// index named `PRIMARY`, so a second query would read the same rows again.
pub(crate) const INDEXES_SQL: &str = "SELECT INDEX_NAME AS index_name, \
            SEQ_IN_INDEX AS position, \
            COLUMN_NAME AS column_name, \
            NON_UNIQUE AS non_unique \
       FROM information_schema.STATISTICS \
      WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? \
      ORDER BY INDEX_NAME, SEQ_IN_INDEX \
      LIMIT ?";

pub(crate) const FOREIGN_KEYS_SQL: &str = "SELECT CONSTRAINT_NAME AS constraint_name, \
            ORDINAL_POSITION AS position, \
            COLUMN_NAME AS column_name, \
            REFERENCED_TABLE_SCHEMA AS referenced_schema, \
            REFERENCED_TABLE_NAME AS referenced_table, \
            REFERENCED_COLUMN_NAME AS referenced_column \
       FROM information_schema.KEY_COLUMN_USAGE \
      WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ? \
        AND REFERENCED_TABLE_NAME IS NOT NULL \
      ORDER BY CONSTRAINT_NAME, ORDINAL_POSITION \
      LIMIT ?";

/// `TABLE_TYPE` to the core model.
///
/// MySQL has no materialized views, so [`TableKind::MaterializedView`] has no
/// producer here. That is the parity rule, not an omission
/// (`docs/architecture.md` section 11). Anything else — `SYSTEM VIEW`, a future
/// value — is not described at all; the queries above already exclude it, and this
/// returning `None` is the second barrier.
pub(crate) fn table_kind(table_type: &str) -> Option<TableKind> {
    match table_type {
        "BASE TABLE" => Some(TableKind::Table),
        "VIEW" => Some(TableKind::View),
        _ => None,
    }
}

/// One decoded row of [`INDEX_SQL`].
pub(crate) struct IndexRow {
    pub(crate) schema: String,
    pub(crate) table: String,
    pub(crate) table_type: String,
    pub(crate) column: String,
}

/// Groups ordered index rows into relations, bounding the column list.
pub(crate) fn group_index(rows: Vec<IndexRow>) -> Vec<IndexedRelation> {
    let mut relations: Vec<IndexedRelation> = Vec::new();
    for row in rows {
        let Some(kind) = table_kind(&row.table_type) else {
            continue;
        };
        match relations.last_mut() {
            Some(last) if last.schema == row.schema && last.name == row.table => {
                if last.columns.len() < MAX_INDEXED_COLUMNS {
                    last.columns.push(row.column);
                }
            }
            _ => relations.push(IndexedRelation {
                schema: row.schema,
                name: row.table,
                kind,
                columns: vec![row.column],
            }),
        }
    }
    relations
}

/// One decoded row of [`INDEXES_SQL`].
pub(crate) struct IndexPartRow {
    pub(crate) index: String,
    pub(crate) column: Option<String>,
    pub(crate) non_unique: i64,
}

/// The primary key and the index list, plus whether anything was left out.
///
/// A functional index part has a NULL `COLUMN_NAME`. Warden drops it and reports
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
                primary: row.index == "PRIMARY",
                unique: row.non_unique == 0,
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

/// `IS_NULLABLE` is `'YES'`/`'NO'` text, not a boolean column.
pub(crate) fn column(
    name: String,
    column_type: String,
    is_nullable: &str,
    default: Option<String>,
    comment: Option<String>,
) -> ColumnDescription {
    ColumnDescription {
        name,
        database_type: column_type,
        nullable: is_nullable.eq_ignore_ascii_case("YES"),
        default,
        comment: comment.filter(|value| !value.is_empty()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use warden_core::schema::search::IndexedRelation;
    use warden_core::schema::{ForeignKey, IndexDescription, MAX_INDEXED_COLUMNS, TableKind};

    use super::{
        COLUMNS_SQL, FOREIGN_KEYS_SQL, ForeignKeyRow, INDEX_SQL, INDEXES_SQL, IndexPartRow,
        IndexRow, RESOLVE_SQL, column, group_foreign_keys, group_index, group_indexes,
    };

    #[test]
    fn index_rows_group_by_adjacent_schema_and_table() {
        let relations = group_index(vec![
            IndexRow {
                schema: "app".to_owned(),
                table: "orders".to_owned(),
                table_type: "BASE TABLE".to_owned(),
                column: "id".to_owned(),
            },
            IndexRow {
                schema: "app".to_owned(),
                table: "orders".to_owned(),
                table_type: "BASE TABLE".to_owned(),
                column: "customer_id".to_owned(),
            },
            IndexRow {
                schema: "app".to_owned(),
                table: "order_summary".to_owned(),
                table_type: "VIEW".to_owned(),
                column: "total".to_owned(),
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
                },
                IndexedRelation {
                    schema: "app".to_owned(),
                    name: "order_summary".to_owned(),
                    kind: TableKind::View,
                    columns: vec!["total".to_owned()],
                },
            ]
        );
    }

    #[test]
    fn index_rows_stop_at_the_indexed_column_limit() {
        let rows = (0..=MAX_INDEXED_COLUMNS)
            .map(|_| IndexRow {
                schema: "app".to_owned(),
                table: "wide".to_owned(),
                table_type: "BASE TABLE".to_owned(),
                column: "column".to_owned(),
            })
            .collect();

        let relations = group_index(rows);

        assert_eq!(relations[0].columns.len(), MAX_INDEXED_COLUMNS);
    }

    #[test]
    fn index_rows_drop_a_system_view() {
        let relations = group_index(vec![IndexRow {
            schema: "app".to_owned(),
            table: "future_system_view".to_owned(),
            table_type: "SYSTEM VIEW".to_owned(),
            column: "id".to_owned(),
        }]);

        assert!(relations.is_empty());
    }

    #[test]
    fn a_functional_index_part_marks_the_description_truncated() {
        let (primary_key, indexes, truncated) = group_indexes(
            vec![IndexPartRow {
                index: "by_expression".to_owned(),
                column: None,
                non_unique: 1,
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
                    index: "PRIMARY".to_owned(),
                    column: Some("account_id".to_owned()),
                    non_unique: 0,
                },
                IndexPartRow {
                    index: "PRIMARY".to_owned(),
                    column: Some("order_id".to_owned()),
                    non_unique: 0,
                },
            ],
            false,
        );

        assert_eq!(primary_key, vec!["account_id", "order_id"]);
        assert_eq!(
            indexes,
            vec![IndexDescription {
                name: "PRIMARY".to_owned(),
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
    fn nullable_text_is_parsed_case_insensitively() {
        let nullable = column(
            "optional".to_owned(),
            "varchar(255)".to_owned(),
            "yes",
            None,
            Some(String::new()),
        );
        let required = column("required".to_owned(), "int".to_owned(), "NO", None, None);

        assert!(nullable.nullable);
        assert_eq!(nullable.comment, None);
        assert!(!required.nullable);
    }

    #[test]
    fn no_catalog_statement_can_carry_an_interpolated_value() {
        for sql in [
            INDEX_SQL,
            RESOLVE_SQL,
            COLUMNS_SQL,
            INDEXES_SQL,
            FOREIGN_KEYS_SQL,
        ] {
            assert!(!sql.contains('{'), "{sql}");
            assert!(sql.contains('?'), "{sql}");
        }
    }
}
