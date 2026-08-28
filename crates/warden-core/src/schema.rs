//! Schema discovery models.
//!
//! Schema discovery is a product capability, not an implementation detail: the
//! agent must be able to learn tables, columns, keys, indexes, and types before it
//! writes a query (`docs/data-model.md` section 9).
//!
//! Nothing here can hold connection data. Redaction still applies to these values
//! in Milestone 9 because column defaults and comments can contain secrets
//! (`docs/security.md` section 8).

pub mod cache;
pub mod search;

use std::fmt;
use std::str::FromStr;

use crate::connection::ConnectionName;
use crate::error::{PublicError, PublicErrorCode};

/// The largest number of tables one `describe_schema` call may name.
pub const MAX_DESCRIBE_TABLES: usize = 20;

/// The largest number of catalog rows one search-index query may read.
///
/// The index is one row per column, so this bounds a join, not a relation count. A
/// catalog larger than this yields a `CatalogIndex` marked `truncated`, which the
/// search response then repeats, rather than a silently partial answer.
pub const MAX_CATALOG_ROWS: usize = 20_000;

/// The largest number of column names kept per relation in the search index.
pub const MAX_INDEXED_COLUMNS: usize = 64;

/// The largest number of matches one `search_schema` response may carry.
///
/// A ceiling above the request's own `limit`: a broad search must never return the
/// whole catalog (`docs/mcp.md` section 2), whatever limit the caller asked for.
pub const MAX_SEARCH_RESULTS: usize = 50;

/// The largest number of columns one described relation may carry.
pub const MAX_DESCRIBED_COLUMNS: usize = 512;

/// The largest number of indexes one described relation may carry.
pub const MAX_DESCRIBED_INDEXES: usize = 128;

/// The largest number of foreign keys one described relation may carry.
pub const MAX_DESCRIBED_FOREIGN_KEYS: usize = 128;

/// The largest number of terms one `search_schema` call may carry.
pub const MAX_SEARCH_TERMS: usize = 10;

/// The largest accepted length of a single identifier part.
///
/// PostgreSQL truncates identifiers at 63 bytes and MySQL at 64, so anything longer
/// cannot name a real object.
pub const MAX_IDENTIFIER_PART_LEN: usize = 64;

/// A schema-tool request that cannot be served as written.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SchemaRequestError {
    /// The request named no tables or carried no terms.
    #[error("{what} is empty")]
    Empty {
        /// Which part was empty.
        what: &'static str,
    },
    /// The request exceeded its cap.
    #[error("{what} carries {actual} entries; the maximum is {max}")]
    TooMany {
        /// Which part was too large.
        what: &'static str,
        /// Number of entries supplied.
        actual: usize,
        /// Configured maximum.
        max: usize,
    },
    /// A qualified name could not be split into schema and table parts.
    #[error("{reason}")]
    MalformedName {
        /// Why the name was rejected. Never quotes the whole value.
        reason: &'static str,
    },
}

impl PublicError for SchemaRequestError {
    fn public_code(&self) -> PublicErrorCode {
        PublicErrorCode::SchemaLookupError
    }
}

/// A `schema.table` or bare `table` selector supplied by an agent.
///
/// Parsing splits the parts and validates their shape; it does **not** fold case.
/// Folding is dialect-specific and belongs to policy comparison in the adapters
/// (`docs/security.md` section 5.1).
///
/// Quoted names containing a dot are not supported in v0.1. That is an accepted
/// limitation, not an oversight: supporting them means implementing each engine's
/// quoting rules outside its parser.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TableSelector {
    schema: Option<String>,
    name: String,
}

impl TableSelector {
    /// The schema qualifier, when the agent supplied one.
    #[must_use]
    pub fn schema(&self) -> Option<&str> {
        self.schema.as_deref()
    }

    /// The table name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl TryFrom<String> for TableSelector {
    type Error = SchemaRequestError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let malformed = |reason| SchemaRequestError::MalformedName { reason };
        let mut parts = value.split('.');
        let (schema, name) = match (parts.next(), parts.next(), parts.next()) {
            (Some(name), None, None) => (None, name),
            (Some(schema), Some(name), None) => (Some(schema), name),
            _ => return Err(malformed("table name has more than two parts")),
        };

        for part in [schema.unwrap_or("x"), name] {
            if part.is_empty() {
                return Err(malformed("table name has an empty part"));
            }
            if part.len() > MAX_IDENTIFIER_PART_LEN {
                return Err(malformed("table name part is longer than 64 bytes"));
            }
            if part.chars().any(|c| c.is_control() || c == '"' || c == '`') {
                return Err(malformed(
                    "table name part contains an unsupported character",
                ));
            }
        }

        Ok(Self {
            schema: schema.map(str::to_owned),
            name: name.to_owned(),
        })
    }
}

impl FromStr for TableSelector {
    type Err = SchemaRequestError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value.to_owned())
    }
}

impl fmt::Display for TableSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.schema {
            Some(schema) => write!(f, "{schema}.{}", self.name),
            None => f.write_str(&self.name),
        }
    }
}

/// A bounded `describe_schema` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaDescribeRequest {
    connection: ConnectionName,
    tables: Vec<TableSelector>,
}

impl SchemaDescribeRequest {
    /// Validates the table cap from `docs/mcp.md` section 2.
    pub fn new(
        connection: ConnectionName,
        tables: Vec<TableSelector>,
    ) -> Result<Self, SchemaRequestError> {
        if tables.is_empty() {
            return Err(SchemaRequestError::Empty { what: "tables" });
        }
        if tables.len() > MAX_DESCRIBE_TABLES {
            return Err(SchemaRequestError::TooMany {
                what: "tables",
                actual: tables.len(),
                max: MAX_DESCRIBE_TABLES,
            });
        }
        Ok(Self { connection, tables })
    }

    /// The connection to describe.
    #[must_use]
    pub fn connection(&self) -> &ConnectionName {
        &self.connection
    }

    /// The requested tables.
    #[must_use]
    pub fn tables(&self) -> &[TableSelector] {
        &self.tables
    }
}

/// A bounded `search_schema` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaSearchRequest {
    connection: ConnectionName,
    terms: Vec<String>,
    limit: usize,
}

impl SchemaSearchRequest {
    /// Splits free text into terms and bounds both the term count and the result
    /// count, because a broad search must never return the whole catalog
    /// (`docs/mcp.md` section 2).
    pub fn new(
        connection: ConnectionName,
        query: &str,
        limit: usize,
    ) -> Result<Self, SchemaRequestError> {
        let terms: Vec<String> = query
            .split_whitespace()
            .map(str::to_owned)
            .filter(|term| term.len() <= MAX_IDENTIFIER_PART_LEN)
            .collect();
        if terms.is_empty() {
            return Err(SchemaRequestError::Empty {
                what: "search terms",
            });
        }
        if terms.len() > MAX_SEARCH_TERMS {
            return Err(SchemaRequestError::TooMany {
                what: "search terms",
                actual: terms.len(),
                max: MAX_SEARCH_TERMS,
            });
        }
        if limit == 0 {
            return Err(SchemaRequestError::Empty {
                what: "result limit",
            });
        }
        if limit > MAX_SEARCH_RESULTS {
            return Err(SchemaRequestError::TooMany {
                what: "result limit",
                actual: limit,
                max: MAX_SEARCH_RESULTS,
            });
        }
        Ok(Self {
            connection,
            terms,
            limit,
        })
    }

    /// The connection to search.
    #[must_use]
    pub fn connection(&self) -> &ConnectionName {
        &self.connection
    }

    /// The normalized search terms.
    #[must_use]
    pub fn terms(&self) -> &[String] {
        &self.terms
    }

    /// The largest number of matches to return.
    #[must_use]
    pub fn limit(&self) -> usize {
        self.limit
    }
}

/// Why a match ranked where it did.
///
/// Variants are declared in ranking order, so the derived `Ord` **is** the ranking
/// (`docs/data-model.md` section 9.1). Embeddings are unnecessary in v0.x;
/// Milestone 9 implements the comparison itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchReason {
    /// The table name matched exactly.
    ExactTable,
    /// The table name started with the term.
    TablePrefix,
    /// The table name contained the term.
    TableSubstring,
    /// A column name matched.
    ColumnMatch,
    /// The schema name matched.
    SchemaName,
    /// A configured human description matched.
    Description,
}

/// One search hit.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SchemaMatch {
    /// The schema holding the object.
    pub schema: String,
    /// The object's name.
    pub table: String,
    /// What kind of relation it is.
    pub kind: TableKind,
    /// Why it matched.
    pub reason: MatchReason,
}

/// A bounded search response.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SchemaSearchResult {
    /// Hits in ranking order.
    pub matches: Vec<SchemaMatch>,
    /// Whether the limit stopped collection early.
    pub truncated: bool,
}

/// What kind of relation a discovered object is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TableKind {
    /// A base table.
    Table,
    /// A view.
    View,
    /// A materialized view.
    MaterializedView,
}

/// One column of a discovered relation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ColumnDescription {
    /// The column name.
    pub name: String,
    /// The database type name.
    pub database_type: String,
    /// Whether the column accepts `NULL`.
    pub nullable: bool,
    /// The column default, when one exists and survives redaction.
    pub default: Option<String>,
    /// The column comment, when one exists and survives redaction.
    pub comment: Option<String>,
}

/// A foreign-key constraint.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ForeignKey {
    /// The constraint name, when the engine reports one.
    pub name: Option<String>,
    /// The referencing columns.
    pub columns: Vec<String>,
    /// The referenced schema.
    pub referenced_schema: String,
    /// The referenced table.
    pub referenced_table: String,
    /// The referenced columns, positionally aligned with `columns`.
    pub referenced_columns: Vec<String>,
}

/// An index on a discovered relation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct IndexDescription {
    /// The index name.
    pub name: String,
    /// The indexed columns, in order.
    pub columns: Vec<String>,
    /// Whether the index enforces uniqueness.
    pub unique: bool,
    /// Whether the index backs the primary key.
    pub primary: bool,
}

/// A discovered relation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Table {
    /// The schema holding this relation.
    pub schema: String,
    /// The relation name.
    pub name: String,
    /// What kind of relation it is.
    pub kind: TableKind,
    /// Its columns, in ordinal order.
    pub columns: Vec<ColumnDescription>,
    /// Primary-key column names, in key order.
    pub primary_key: Vec<String>,
    /// Foreign keys declared on this relation.
    pub foreign_keys: Vec<ForeignKey>,
    /// Indexes on this relation.
    pub indexes: Vec<IndexDescription>,
    /// Whether any of this relation's metadata was left out.
    ///
    /// Set when a bound above cut a list, and when the engine described a key part
    /// that has no column name — a functional index on MySQL, an expression index on
    /// PostgreSQL. Warden omits such a part rather than inventing a name for it
    /// (`docs/architecture.md` section 11), and says so here, because an agent that
    /// believed it had seen every column would write a wrong query.
    pub truncated: bool,
}

/// One schema and the relations the role may see.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Schema {
    /// The schema name.
    pub name: String,
    /// The relations in it.
    pub tables: Vec<Table>,
}

/// The `describe_schema` response.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SchemaDescription {
    /// The described schemas.
    pub schemas: Vec<Schema>,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn connection() -> ConnectionName {
        "production-postgres".parse().unwrap()
    }

    fn selector(value: &str) -> TableSelector {
        value.parse().unwrap()
    }

    #[test]
    fn selectors_split_qualified_names_without_folding_them() {
        let bare = selector("orders");
        assert_eq!(bare.schema(), None);
        assert_eq!(bare.name(), "orders");

        let qualified = selector("App.Orders");
        assert_eq!(qualified.schema(), Some("App"));
        assert_eq!(qualified.name(), "Orders");
        assert_eq!(qualified.to_string(), "App.Orders");
    }

    #[test]
    fn selectors_reject_malformed_names() {
        for value in [
            "",
            "app.",
            ".orders",
            "a.b.c",
            "app.or\"ders",
            "app.or\nders",
        ] {
            assert!(
                value.parse::<TableSelector>().is_err(),
                "accepted {value:?}"
            );
        }
        assert!("a".repeat(65).parse::<TableSelector>().is_err());
    }

    #[test]
    fn describe_requests_are_capped_at_twenty_tables() {
        let tables: Vec<TableSelector> = (0..MAX_DESCRIBE_TABLES)
            .map(|i| selector(&format!("app.t{i}")))
            .collect();
        assert!(SchemaDescribeRequest::new(connection(), tables.clone()).is_ok());

        let mut too_many = tables;
        too_many.push(selector("app.extra"));
        assert_eq!(
            SchemaDescribeRequest::new(connection(), too_many).unwrap_err(),
            SchemaRequestError::TooMany {
                what: "tables",
                actual: MAX_DESCRIBE_TABLES + 1,
                max: MAX_DESCRIBE_TABLES,
            }
        );
        assert_eq!(
            SchemaDescribeRequest::new(connection(), Vec::new()).unwrap_err(),
            SchemaRequestError::Empty { what: "tables" }
        );
    }

    #[test]
    fn search_requests_split_and_bound_their_terms() {
        let request =
            SchemaSearchRequest::new(connection(), "  customer   invoice\tsubscription ", 25)
                .unwrap();
        assert_eq!(request.terms(), ["customer", "invoice", "subscription"]);
        assert_eq!(request.limit(), 25);

        assert!(SchemaSearchRequest::new(connection(), "   ", 25).is_err());
        assert!(SchemaSearchRequest::new(connection(), "customer", 0).is_err());

        let many = ["term"; MAX_SEARCH_TERMS + 1].join(" ");
        assert!(SchemaSearchRequest::new(connection(), &many, 25).is_err());
    }

    #[test]
    fn a_search_limit_above_the_ceiling_is_refused() {
        assert_eq!(
            SchemaSearchRequest::new(connection(), "orders", MAX_SEARCH_RESULTS + 1).unwrap_err(),
            SchemaRequestError::TooMany {
                what: "result limit",
                actual: MAX_SEARCH_RESULTS + 1,
                max: MAX_SEARCH_RESULTS,
            }
        );
        assert!(SchemaSearchRequest::new(connection(), "orders", MAX_SEARCH_RESULTS).is_ok());
    }

    #[test]
    fn ranking_order_is_the_declaration_order() {
        let mut reasons = vec![
            MatchReason::Description,
            MatchReason::TableSubstring,
            MatchReason::ExactTable,
            MatchReason::SchemaName,
            MatchReason::ColumnMatch,
            MatchReason::TablePrefix,
        ];
        reasons.sort();
        assert_eq!(
            reasons,
            [
                MatchReason::ExactTable,
                MatchReason::TablePrefix,
                MatchReason::TableSubstring,
                MatchReason::ColumnMatch,
                MatchReason::SchemaName,
                MatchReason::Description,
            ]
        );
    }

    #[test]
    fn a_description_serializes_without_any_connection_detail() {
        let description = SchemaDescription {
            schemas: vec![Schema {
                name: "app".to_owned(),
                tables: vec![Table {
                    schema: "app".to_owned(),
                    name: "orders".to_owned(),
                    kind: TableKind::Table,
                    columns: vec![ColumnDescription {
                        name: "id".to_owned(),
                        database_type: "bigint".to_owned(),
                        nullable: false,
                        default: None,
                        comment: None,
                    }],
                    primary_key: vec!["id".to_owned()],
                    foreign_keys: Vec::new(),
                    indexes: Vec::new(),
                    truncated: false,
                }],
            }],
        };
        let json = serde_json::to_string(&description).unwrap();
        assert!(json.contains(r#""kind":"table""#), "{json}");
        for forbidden in ["dsn", "password", "host", "user"] {
            assert!(!json.contains(forbidden), "{json}");
        }
    }
}
