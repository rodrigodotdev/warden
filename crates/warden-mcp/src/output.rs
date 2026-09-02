//! What a tool actually returns, and why it is not the domain type.
//!
//! `warden-core`'s result, plan, and schema models are already `Serialize`, so mirroring
//! them here looks redundant until you ask which crate owns `schemars`.
//! `docs/architecture.md` section 3 gives the core serde, thiserror, secrecy, and url —
//! adding a JSON-Schema derive to the domain would put a protocol concern in the layer
//! that must hold none. These types are the protocol's, they live in the protocol's crate,
//! and `tests/tool_schema.rs` snapshots what they generate.
//!
//! # The response is structure plus a summary, not structure plus a copy (ADR-0040)
//!
//! rmcp's `Json<T>` wrapper sets `structured_content` and then pushes the whole document
//! into a text block. Warden does not: `docs/security.md` section 9 adopts structured
//! content precisely so database rows stop being free text indistinguishable from
//! instructions, and a duplicate text block would forfeit that and double what reaches
//! model context — against the combined `rows + columns` bound
//! `docs/data-model.md` section 7 asks this milestone to design for. Every summary here
//! states counts and flags. None of them states a value.

use std::fmt;

use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::schemars::JsonSchema;
use warden_core::connection::ConnectionMetadata;
use warden_core::dialect::Dialect;
use warden_core::explain::{PlanSummary, QueryPlan};
use warden_core::result::{QueryStats, ResultColumn, ResultSet, ResultValue};
use warden_core::schema::{
    ColumnDescription, ForeignKey, IndexDescription, MatchReason, SchemaDescription, SchemaMatch,
    SchemaSearchResult, Table, TableKind,
};

/// The dialect, as a closed wire enum rather than an open `String`.
///
/// [`Dialect`] is a closed set, so the derived schema can state the two legal values
/// (`docs/mcp.md` section 1.2 treats the derived schema as a verifiable contract, not
/// prose) instead of an unconstrained string a client cannot validate against. The
/// variant names are chosen so `#[serde(rename_all = "snake_case")]` reproduces
/// `Dialect`'s own `#[serde(rename_all = "lowercase")]` spelling exactly: `Mysql` has no
/// internal case transition, so snake_case lowers it to `"mysql"`, matching
/// `Dialect::as_str()`; likewise `Postgresql` to `"postgresql"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[schemars(crate = "rmcp::schemars")]
pub enum WireDialect {
    /// MySQL. Placeholders are positional `?`.
    Mysql,
    /// PostgreSQL. Placeholders are numbered `$1`.
    Postgresql,
}

impl WireDialect {
    /// The same spelling this type serializes as, for use inside a `summary()` string.
    fn as_str(self) -> &'static str {
        match self {
            Self::Mysql => "mysql",
            Self::Postgresql => "postgresql",
        }
    }
}

impl From<Dialect> for WireDialect {
    fn from(dialect: Dialect) -> Self {
        match dialect {
            Dialect::MySql => Self::Mysql,
            Dialect::PostgreSql => Self::Postgresql,
        }
    }
}

/// What kind of relation a discovered object is, as a closed wire enum.
///
/// Mirrors [`TableKind`]'s variant names exactly, so its own
/// `#[serde(rename_all = "snake_case")]` reproduces `TableKind`'s spelling by
/// construction rather than by a hand-copied match arm that could drift from it. The
/// core enum has no `Display` to delegate to instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[schemars(crate = "rmcp::schemars")]
pub enum WireTableKind {
    /// A base table.
    Table,
    /// A view.
    View,
    /// A materialized view.
    MaterializedView,
}

impl From<TableKind> for WireTableKind {
    fn from(kind: TableKind) -> Self {
        match kind {
            TableKind::Table => Self::Table,
            TableKind::View => Self::View,
            TableKind::MaterializedView => Self::MaterializedView,
        }
    }
}

/// Why a search hit ranked where it did, as a closed wire enum.
///
/// Mirrors [`MatchReason`]'s variant names exactly, for the same reason
/// [`WireTableKind`] mirrors [`TableKind`]'s.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[schemars(crate = "rmcp::schemars")]
pub enum WireMatchReason {
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

impl From<MatchReason> for WireMatchReason {
    fn from(reason: MatchReason) -> Self {
        match reason {
            MatchReason::ExactTable => Self::ExactTable,
            MatchReason::TablePrefix => Self::TablePrefix,
            MatchReason::TableSubstring => Self::TableSubstring,
            MatchReason::ColumnMatch => Self::ColumnMatch,
            MatchReason::SchemaName => Self::SchemaName,
            MatchReason::Description => Self::Description,
        }
    }
}

/// Renders a count with the correct singular or plural noun.
///
/// A summary is read by the agent on every call; six characters of correct English is
/// worth a shared helper instead of six inline `if`s that can drift.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "reachable once Task 5 wires ToolResponse into a #[tool] method"
    )
)]
fn count_phrase(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("1 {singular}")
    } else {
        format!("{count} {plural}")
    }
}

/// Turns one output type into the `CallToolResult` a tool method returns.
///
/// `summary` is the one line that reaches `content`; `into_result` is the one place that
/// builds the result, so no `#[tool]` method can accidentally duplicate a row into text.
///
/// Every impl below satisfies this trait already, but nothing calls `into_result` or
/// `summary` outside this module's own tests yet: Task 5 wires the five `#[tool]` methods
/// to it. The dead-code guard is on the trait alone, not each impl, because an unused
/// trait already carries every method that only exists to satisfy it.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by Task 5's #[tool] methods via ToolResponse::into_result"
    )
)]
pub(crate) trait ToolResponse: serde::Serialize {
    /// One line stating counts and flags. Never a value (ADR-0040).
    fn summary(&self) -> String;

    /// Builds the result through the constructor and then replaces the content, because
    /// `CallToolResult` is `#[non_exhaustive]` and cannot be written as a literal from
    /// this crate.
    fn into_result(self) -> CallToolResult
    where
        Self: Sized,
    {
        let summary = self.summary();
        match serde_json::to_value(&self) {
            Ok(value) => {
                let mut result = CallToolResult::structured(value);
                // The constructor put the whole document in `content`. ADR-0040 replaces
                // it with one line that counts rather than quotes.
                result.content = vec![ContentBlock::text(summary)];
                result
            }
            Err(error) => {
                tracing::error!(target: "warden.mcp", %error, "a response could not be serialized");
                crate::error::failure(warden_core::error::PublicErrorCode::InternalError)
            }
        }
    }
}

// ---------------------------------------------------------------------------------
// list_connections
// ---------------------------------------------------------------------------------

/// The `list_connections` response.
#[derive(Debug, serde::Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ConnectionsOutput {
    /// Every connection this deployment is configured to reach.
    pub connections: Vec<ConnectionSummary>,
}

/// One configured connection.
///
/// No field a DSN could hide in: this mirrors [`ConnectionMetadata`], which cannot hold
/// one either (SPEC section 6, invariant 20).
#[derive(Debug, serde::Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ConnectionSummary {
    /// The name an agent passes to every tool.
    pub name: String,
    /// The dialect; determines placeholder syntax.
    pub dialect: WireDialect,
    /// The deployment environment, e.g. `"production"`.
    ///
    /// A `String`, not a closed wire enum like `dialect`: the core
    /// [`warden_core::connection::Environment`] it comes from has an open
    /// `Other(String)` variant for operator-defined environments, so no closed schema
    /// could represent every legal value.
    pub environment: String,
    /// The default database or catalog, for the agent's orientation.
    pub database: String,
}

impl From<&ConnectionMetadata> for ConnectionSummary {
    fn from(metadata: &ConnectionMetadata) -> Self {
        Self {
            name: metadata.name.to_string(),
            dialect: WireDialect::from(metadata.dialect),
            environment: metadata.environment.to_string(),
            database: metadata.database.clone(),
        }
    }
}

impl ConnectionsOutput {
    /// Builds the `list_connections` response from every configured connection's public
    /// metadata.
    pub fn from_metadata(connections: &[ConnectionMetadata]) -> Self {
        Self {
            connections: connections.iter().map(ConnectionSummary::from).collect(),
        }
    }
}

impl ToolResponse for ConnectionsOutput {
    fn summary(&self) -> String {
        count_phrase(self.connections.len(), "connection", "connections")
    }
}

// ---------------------------------------------------------------------------------
// query
// ---------------------------------------------------------------------------------

/// The `query` response.
#[derive(Debug, serde::Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct QueryOutput {
    /// Column metadata, in positional order.
    pub columns: Vec<ColumnSummary>,
    /// Rows, each positionally aligned with `columns`.
    pub rows: Vec<Vec<CellValue>>,
    /// Whether a limit stopped collection early. Refine the query rather than repeat it.
    pub truncated: bool,
    /// Counters for this execution.
    pub stats: StatsSummary,
}

/// One column's metadata.
#[derive(Debug, serde::Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ColumnSummary {
    /// The name the database reported, duplicates included.
    pub name: String,
    /// The database type name, preserved so the agent keeps the original meaning.
    pub database_type: String,
    /// Nullability, when the driver reports it.
    pub nullable: Option<bool>,
}

impl From<&ResultColumn> for ColumnSummary {
    fn from(column: &ResultColumn) -> Self {
        Self {
            name: column.name.clone(),
            database_type: column.database_type.clone(),
            nullable: column.nullable,
        }
    }
}

/// Counters for one execution.
#[derive(Debug, serde::Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct StatsSummary {
    /// Rows returned after any truncation.
    pub rows_returned: usize,
    /// Normalized size of the result in bytes.
    pub bytes: usize,
    /// Wall-clock execution time, in whole milliseconds.
    pub duration_ms: u64,
}

impl From<&QueryStats> for StatsSummary {
    fn from(stats: &QueryStats) -> Self {
        Self {
            rows_returned: stats.rows_returned,
            bytes: stats.bytes,
            // Mirrors `warden_core::result`'s own duration_ms serialization: whole
            // milliseconds, saturating instead of panicking if a duration ever exceeded
            // u64::MAX milliseconds (it never will in practice).
            duration_ms: u64::try_from(stats.duration.as_millis()).unwrap_or(u64::MAX),
        }
    }
}

/// One normalized cell.
///
/// Built once, by `serde_json::to_value(result_value)`, and carried through unchanged;
/// see the hand-written [`JsonSchema`] impl below for why the schema cannot be derived.
#[derive(serde::Serialize)]
#[serde(transparent)]
pub struct CellValue(serde_json::Value);

/// Prints shape, never content.
///
/// A cell is a value that came out of a database row. Mirrors
/// [`crate::input::ParameterInput`]'s own hand-written `Debug` so a
/// `tracing::debug!(?output, ..)` on a `QueryOutput` cannot print a row back out in
/// plaintext, the same leak Task 3 closed for bound parameters.
impl fmt::Debug for CellValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            serde_json::Value::Null => f.write_str("Null"),
            serde_json::Value::Bool(_) => f.write_str("Bool(<redacted>)"),
            serde_json::Value::Number(_) => f.write_str("Number(<redacted>)"),
            serde_json::Value::String(value) => {
                write!(f, "String(<redacted {} bytes>)", value.len())
            }
            serde_json::Value::Array(_) => f.write_str("Array(<redacted>)"),
            serde_json::Value::Object(_) => f.write_str("Object(<redacted>)"),
        }
    }
}

impl JsonSchema for CellValue {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "CellValue".into()
    }

    fn inline_schema() -> bool {
        true
    }

    fn json_schema(_generator: &mut rmcp::schemars::SchemaGenerator) -> rmcp::schemars::Schema {
        // Hand-written because no Rust type expresses this union. `ResultValue`'s
        // `Serialize` quotes an `I64`/`U64` outside ±2^53 as a decimal string so a
        // JavaScript client cannot silently round it (`docs/data-model.md` section 8.1,
        // rule 6), and `crates/warden-core/src/result.rs` asks Milestone 12 to declare the
        // affected fields as both representations. A derived schema would claim `integer`
        // alone and be wrong for exactly the values that matter most.
        rmcp::schemars::json_schema!({
            "type": ["integer", "string", "number", "boolean", "null", "array", "object"],
            "description": "One normalized cell. An integer outside ±2^53 arrives as a \
                            decimal string so no client rounds it; the column's own type \
                            is in `columns[i].database_type`."
        })
    }
}

/// Serializes one [`ResultValue`] into a [`CellValue`].
///
/// Practically infallible: adapters call `ResultSet::validate` before a result leaves
/// `warden-core`, which already rejects the one case (a non-finite float) that could make
/// this serializer's output surprising, and every other variant serializes
/// unconditionally. The fallback logs and returns `null` rather than panicking — no
/// `unwrap`/`expect` on the request path (`AGENTS.md`) — trading a fabricated `null` for
/// the alternative of crashing the request on a case that should be unreachable.
fn to_cell(value: &ResultValue) -> CellValue {
    match serde_json::to_value(value) {
        Ok(json) => CellValue(json),
        Err(error) => {
            tracing::error!(target: "warden.mcp", %error, "a result cell could not be serialized");
            CellValue(serde_json::Value::Null)
        }
    }
}

impl From<&ResultSet> for QueryOutput {
    fn from(result: &ResultSet) -> Self {
        Self {
            columns: result.columns.iter().map(ColumnSummary::from).collect(),
            rows: result
                .rows
                .iter()
                .map(|row| row.iter().map(to_cell).collect())
                .collect(),
            truncated: result.truncated,
            stats: StatsSummary::from(&result.stats),
        }
    }
}

impl ToolResponse for QueryOutput {
    fn summary(&self) -> String {
        format!(
            "{}, {}, truncated: {}, {} bytes, {} ms",
            count_phrase(self.rows.len(), "row", "rows"),
            count_phrase(self.columns.len(), "column", "columns"),
            self.truncated,
            self.stats.bytes,
            self.stats.duration_ms,
        )
    }
}

// ---------------------------------------------------------------------------------
// explain
// ---------------------------------------------------------------------------------

/// The `explain` response.
#[derive(Debug, serde::Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ExplainOutput {
    /// The dialect that produced the plan.
    pub dialect: WireDialect,
    /// The comparable summary.
    pub summary: PlanSummaryOutput,
    /// The engine's own plan document, passed through unchanged.
    pub plan: PlanDocument,
}

/// The engine-independent part of a plan.
///
/// There is no cost field, for the same reason `warden-core`'s own [`PlanSummary`] has
/// none: MySQL and PostgreSQL cost units are not comparable (`docs/architecture.md`
/// section 11).
#[derive(Debug, serde::Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct PlanSummaryOutput {
    /// The planner's row estimate, when it reports one.
    ///
    /// PostgreSQL fills this; MySQL leaves it `null` rather than borrowing one of its
    /// own per-step estimates, which would be Warden stating a number the server never
    /// stated (`docs/architecture.md` section 11; `docs/open-questions.md` item 20).
    pub estimated_rows: Option<u64>,
}

impl From<&PlanSummary> for PlanSummaryOutput {
    fn from(summary: &PlanSummary) -> Self {
        Self {
            estimated_rows: summary.estimated_rows,
        }
    }
}

/// The engine's own plan document, unchanged.
///
/// `docs/mcp.md` section 2: engine-specific detail belongs to the engine's own document,
/// not to a shape Warden invents, so the schema accepts anything.
#[derive(Debug, serde::Serialize)]
#[serde(transparent)]
pub struct PlanDocument(serde_json::Value);

impl JsonSchema for PlanDocument {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "PlanDocument".into()
    }

    fn inline_schema() -> bool {
        true
    }

    fn json_schema(_generator: &mut rmcp::schemars::SchemaGenerator) -> rmcp::schemars::Schema {
        rmcp::schemars::json_schema!(true)
    }
}

impl From<&QueryPlan> for ExplainOutput {
    fn from(plan: &QueryPlan) -> Self {
        Self {
            dialect: WireDialect::from(plan.dialect),
            summary: PlanSummaryOutput::from(&plan.summary),
            plan: PlanDocument(plan.plan.clone()),
        }
    }
}

impl ExplainOutput {
    /// The planner's row estimate, when the engine reported one.
    ///
    /// A thin accessor kept separate from `summary` so the omission rule
    /// (`docs/architecture.md` section 11: MySQL states no statement-level estimate) has
    /// its own name to test.
    pub fn summary_estimated_rows(&self) -> Option<u64> {
        self.summary.estimated_rows
    }
}

impl ToolResponse for ExplainOutput {
    fn summary(&self) -> String {
        match self.summary_estimated_rows() {
            Some(rows) => format!("{} plan, estimated rows: {rows}", self.dialect.as_str()),
            None => format!("{} plan", self.dialect.as_str()),
        }
    }
}

// ---------------------------------------------------------------------------------
// search_schema
// ---------------------------------------------------------------------------------

/// The `search_schema` response.
#[derive(Debug, serde::Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct SearchOutput {
    /// Hits in ranking order.
    pub matches: Vec<MatchSummary>,
    /// Whether the limit stopped collection early.
    pub truncated: bool,
}

/// One search hit.
#[derive(Debug, serde::Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct MatchSummary {
    /// The schema holding the object.
    pub schema: String,
    /// The object's name.
    pub table: String,
    /// What kind of relation it is.
    pub kind: WireTableKind,
    /// Why it matched: `"exact_table"`, `"table_prefix"`, `"table_substring"`,
    /// `"column_match"`, `"schema_name"`, or `"description"`, in ranking order.
    pub reason: WireMatchReason,
}

impl From<&SchemaMatch> for MatchSummary {
    fn from(hit: &SchemaMatch) -> Self {
        Self {
            schema: hit.schema.clone(),
            table: hit.table.clone(),
            kind: WireTableKind::from(hit.kind),
            reason: WireMatchReason::from(hit.reason),
        }
    }
}

impl From<&SchemaSearchResult> for SearchOutput {
    fn from(result: &SchemaSearchResult) -> Self {
        Self {
            matches: result.matches.iter().map(MatchSummary::from).collect(),
            truncated: result.truncated,
        }
    }
}

impl ToolResponse for SearchOutput {
    fn summary(&self) -> String {
        format!(
            "{}, truncated: {}",
            count_phrase(self.matches.len(), "match", "matches"),
            self.truncated,
        )
    }
}

// ---------------------------------------------------------------------------------
// describe_schema
// ---------------------------------------------------------------------------------

/// The `describe_schema` response.
#[derive(Debug, serde::Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct DescribeOutput {
    /// The described schemas.
    pub schemas: Vec<SchemaSummary>,
}

/// One schema and the relations the role may see.
#[derive(Debug, serde::Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct SchemaSummary {
    /// The schema name.
    pub name: String,
    /// The relations in it.
    pub tables: Vec<TableSummary>,
}

/// A discovered relation.
#[derive(Debug, serde::Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct TableSummary {
    /// The relation name.
    pub name: String,
    /// What kind of relation it is.
    pub kind: WireTableKind,
    /// Its columns, in ordinal order.
    pub columns: Vec<ColumnDetail>,
    /// Primary-key column names, in key order.
    pub primary_key: Vec<String>,
    /// Foreign keys declared on this relation.
    pub foreign_keys: Vec<ForeignKeySummary>,
    /// Indexes on this relation.
    pub indexes: Vec<IndexSummary>,
    /// Whether any of this relation's metadata was left out.
    ///
    /// Set when a bound cuts a list or catalog text, when an engine reports a key part
    /// without a column name, and when a foreign-key target is hidden by policy or
    /// database privileges. Warden omits unavailable metadata rather than inventing or
    /// exposing it, and says the result is partial.
    pub truncated: bool,
}

/// One column of a discovered relation.
#[derive(Debug, serde::Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ColumnDetail {
    /// The column name.
    pub name: String,
    /// The database type name.
    pub database_type: String,
    /// Whether the column accepts `NULL`.
    pub nullable: bool,
    /// The bounded column default, when one exists.
    pub default: Option<String>,
    /// The bounded column comment, when one exists.
    pub comment: Option<String>,
}

impl From<&ColumnDescription> for ColumnDetail {
    fn from(column: &ColumnDescription) -> Self {
        Self {
            name: column.name.clone(),
            database_type: column.database_type.clone(),
            nullable: column.nullable,
            default: column.default.clone(),
            comment: column.comment.clone(),
        }
    }
}

/// A foreign-key constraint.
#[derive(Debug, serde::Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct ForeignKeySummary {
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

impl From<&ForeignKey> for ForeignKeySummary {
    fn from(key: &ForeignKey) -> Self {
        Self {
            name: key.name.clone(),
            columns: key.columns.clone(),
            referenced_schema: key.referenced_schema.clone(),
            referenced_table: key.referenced_table.clone(),
            referenced_columns: key.referenced_columns.clone(),
        }
    }
}

/// An index on a discovered relation.
#[derive(Debug, serde::Serialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct IndexSummary {
    /// The index name.
    pub name: String,
    /// The indexed columns, in order.
    pub columns: Vec<String>,
    /// Whether the index enforces uniqueness.
    pub unique: bool,
    /// Whether the index backs the primary key.
    pub primary: bool,
}

impl From<&IndexDescription> for IndexSummary {
    fn from(index: &IndexDescription) -> Self {
        Self {
            name: index.name.clone(),
            columns: index.columns.clone(),
            unique: index.unique,
            primary: index.primary,
        }
    }
}

impl From<&Table> for TableSummary {
    fn from(table: &Table) -> Self {
        Self {
            name: table.name.clone(),
            // `table.schema` is deliberately dropped: both inspectors set it from the
            // same variable they group relations by (`warden-mysql/src/inspector.rs`'s
            // `describe_one` and `warden-postgres/src/inspector.rs`'s equivalent), so it
            // is invariantly equal to the containing `SchemaSummary.name` and repeating
            // it here would be redundant wire noise.
            kind: WireTableKind::from(table.kind),
            columns: table.columns.iter().map(ColumnDetail::from).collect(),
            primary_key: table.primary_key.clone(),
            foreign_keys: table
                .foreign_keys
                .iter()
                .map(ForeignKeySummary::from)
                .collect(),
            indexes: table.indexes.iter().map(IndexSummary::from).collect(),
            truncated: table.truncated,
        }
    }
}

impl From<&warden_core::schema::Schema> for SchemaSummary {
    fn from(schema: &warden_core::schema::Schema) -> Self {
        Self {
            name: schema.name.clone(),
            tables: schema.tables.iter().map(TableSummary::from).collect(),
        }
    }
}

impl From<&SchemaDescription> for DescribeOutput {
    fn from(description: &SchemaDescription) -> Self {
        Self {
            schemas: description
                .schemas
                .iter()
                .map(SchemaSummary::from)
                .collect(),
        }
    }
}

impl ToolResponse for DescribeOutput {
    fn summary(&self) -> String {
        let table_count: usize = self.schemas.iter().map(|schema| schema.tables.len()).sum();
        format!(
            "{}, {}",
            count_phrase(self.schemas.len(), "schema", "schemas"),
            count_phrase(table_count, "table", "tables"),
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::time::Duration;

    use warden_core::connection::Environment;
    use warden_core::dialect::Dialect;

    use super::*;

    fn result_set_with_secret() -> ResultSet {
        ResultSet {
            columns: vec![
                ResultColumn {
                    name: "id".to_owned(),
                    database_type: "BIGINT".to_owned(),
                    nullable: Some(false),
                },
                ResultColumn {
                    name: "password".to_owned(),
                    database_type: "TEXT".to_owned(),
                    nullable: Some(false),
                },
            ],
            rows: vec![vec![
                ResultValue::I64(1),
                ResultValue::String("hunter2".to_owned()),
            ]],
            truncated: false,
            stats: QueryStats {
                rows_returned: 1,
                bytes: 41,
                duration: Duration::from_millis(12),
            },
        }
    }

    fn result_set_with(value: ResultValue) -> ResultSet {
        ResultSet {
            columns: vec![ResultColumn {
                name: "value".to_owned(),
                database_type: "BIGINT".to_owned(),
                nullable: Some(false),
            }],
            rows: vec![vec![value]],
            truncated: false,
            stats: QueryStats {
                rows_returned: 1,
                bytes: 8,
                duration: Duration::from_millis(1),
            },
        }
    }

    fn mysql_plan() -> QueryPlan {
        QueryPlan {
            dialect: Dialect::MySql,
            summary: PlanSummary::default(),
            plan: serde_json::json!({ "query_block": { "select_id": 1 } }),
        }
    }

    /// The `summary()` table's other documented example: `"postgresql plan, estimated
    /// rows: 1200"`.
    fn postgres_plan() -> QueryPlan {
        QueryPlan {
            dialect: Dialect::PostgreSql,
            summary: PlanSummary {
                estimated_rows: Some(1200),
            },
            plan: serde_json::json!({ "Node Type": "Seq Scan" }),
        }
    }

    fn description() -> SchemaDescription {
        SchemaDescription {
            schemas: vec![warden_core::schema::Schema {
                name: "app".to_owned(),
                tables: vec![
                    Table {
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
                    },
                    // A second table so `DescribeOutput::summary` exercises the plural
                    // "tables" path, not only "1 table".
                    Table {
                        schema: "app".to_owned(),
                        name: "order_items".to_owned(),
                        kind: TableKind::Table,
                        columns: Vec::new(),
                        primary_key: Vec::new(),
                        foreign_keys: Vec::new(),
                        indexes: Vec::new(),
                        truncated: false,
                    },
                ],
            }],
        }
    }

    fn truncated_search() -> SchemaSearchResult {
        SchemaSearchResult {
            matches: vec![
                SchemaMatch {
                    schema: "app".to_owned(),
                    table: "orders".to_owned(),
                    kind: TableKind::Table,
                    // MatchReason::ExactTable is the ranking-order-first variant; its own
                    // Serialize spells this "exact_table"
                    // (`crates/warden-core/src/schema.rs`), which `WireMatchReason`
                    // mirrors by using the same variant name.
                    reason: MatchReason::ExactTable,
                },
                // A second hit so `SearchOutput::summary` exercises the plural
                // "matches" path, not only "1 match".
                SchemaMatch {
                    schema: "app".to_owned(),
                    table: "order_items".to_owned(),
                    kind: TableKind::Table,
                    reason: MatchReason::TablePrefix,
                },
            ],
            truncated: true,
        }
    }

    fn metadata() -> ConnectionMetadata {
        ConnectionMetadata {
            name: "production-mysql".parse().unwrap(),
            dialect: Dialect::MySql,
            environment: Environment::Production,
            database: "app".to_owned(),
        }
    }

    #[test]
    fn a_result_set_becomes_structured_content_and_a_summary_that_names_no_value() {
        // ADR-0040: the data goes in structured_content; the text block says how much
        // arrived, never what. A summary carrying a cell would put database content back
        // in the free-text channel docs/security.md section 9 exists to drain.
        let output = QueryOutput::from(&result_set_with_secret());
        let summary = output.summary();
        assert!(summary.contains("1 row"), "{summary}");
        assert!(summary.contains("truncated: false"), "{summary}");
        assert!(!summary.contains("hunter2"), "{summary}");

        let result = output.into_result();
        assert_eq!(result.is_error, Some(false));
        assert_eq!(result.content.len(), 1);
        let text = serde_json::to_string(&result.content[0]).unwrap();
        assert!(!text.contains("hunter2"), "{text}");
        let structured = result.structured_content.unwrap();
        assert_eq!(structured["rows"][0][1], serde_json::json!("hunter2"));
        assert_eq!(structured["truncated"], serde_json::json!(false));
    }

    #[test]
    fn an_integer_outside_the_exact_json_range_arrives_as_a_string() {
        // docs/data-model.md section 8.1, rule 6, and the note in warden-core's
        // result.rs that asks this milestone to declare it in the schema.
        let output = QueryOutput::from(&result_set_with(ResultValue::I64(9_007_199_254_740_993)));
        let structured = output.into_result().structured_content.unwrap();
        assert_eq!(
            structured["rows"][0][0],
            serde_json::json!("9007199254740993")
        );
    }

    #[test]
    fn the_cell_schema_declares_both_representations_of_a_large_integer() {
        let schema = serde_json::to_value(rmcp::schemars::schema_for!(CellValue)).unwrap();
        let types = schema["type"].as_array().unwrap();
        for expected in [
            "integer", "string", "number", "boolean", "null", "array", "object",
        ] {
            assert!(
                types.contains(&serde_json::json!(expected)),
                "cell schema omits {expected}: {schema}"
            );
        }
    }

    #[test]
    fn a_plan_summary_omits_what_its_engine_never_stated() {
        // docs/architecture.md section 11: do not invent values. MySQL states no
        // statement-level estimate and the field stays null rather than borrowing a
        // per-step figure.
        let mysql = ExplainOutput::from(&mysql_plan());
        assert_eq!(mysql.summary_estimated_rows(), None);
        let structured = mysql.into_result().structured_content.unwrap();
        assert_eq!(
            structured["summary"]["estimated_rows"],
            serde_json::Value::Null
        );
        assert_eq!(structured["dialect"], serde_json::json!("mysql"));
    }

    #[test]
    fn a_description_carries_every_relation_fact_the_inspector_produced() {
        let output = DescribeOutput::from(&description());
        let structured = output.into_result().structured_content.unwrap();
        let table = &structured["schemas"][0]["tables"][0];
        assert_eq!(table["name"], serde_json::json!("orders"));
        assert_eq!(table["kind"], serde_json::json!("table"));
        assert_eq!(table["primary_key"], serde_json::json!(["id"]));
        assert_eq!(table["truncated"], serde_json::json!(false));
        assert_eq!(table["columns"][0]["nullable"], serde_json::json!(false));
    }

    #[test]
    fn a_truncated_search_says_so_in_the_data_and_in_the_summary() {
        let output = SearchOutput::from(&truncated_search());
        assert!(
            output.summary().contains("truncated: true"),
            "{}",
            output.summary()
        );
        let structured = output.into_result().structured_content.unwrap();
        assert_eq!(structured["truncated"], serde_json::json!(true));
        assert_eq!(
            structured["matches"][0]["reason"],
            serde_json::json!("exact_table")
        );
    }

    #[test]
    fn a_connection_listing_carries_no_field_a_dsn_could_hide_in() {
        // ConnectionMetadata cannot hold a DSN, and neither can its wire form: the test
        // pins the field set so a future addition is a deliberate act.
        let output = ConnectionsOutput::from_metadata(&[metadata()]);
        let structured = output.into_result().structured_content.unwrap();
        let entry = &structured["connections"][0];
        let mut fields: Vec<&str> = entry
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        fields.sort_unstable();
        assert_eq!(fields, ["database", "dialect", "environment", "name"]);
    }

    #[test]
    fn every_output_type_has_an_object_rooted_schema() {
        // rmcp strips a schema's title and description but does not require an object
        // root for output; an agent reading a non-object output schema has no field
        // names to work with, so Warden requires it of itself.
        for schema in [
            serde_json::to_value(rmcp::schemars::schema_for!(ConnectionsOutput)).unwrap(),
            serde_json::to_value(rmcp::schemars::schema_for!(QueryOutput)).unwrap(),
            serde_json::to_value(rmcp::schemars::schema_for!(ExplainOutput)).unwrap(),
            serde_json::to_value(rmcp::schemars::schema_for!(SearchOutput)).unwrap(),
            serde_json::to_value(rmcp::schemars::schema_for!(DescribeOutput)).unwrap(),
        ] {
            assert_eq!(schema["type"], serde_json::json!("object"), "{schema}");
        }
    }

    #[test]
    fn count_phrase_uses_the_singular_only_for_exactly_one() {
        // The mechanism every summary's pluralization shares: zero and two both take
        // the plural form, and only one takes the singular. Exercised once here for
        // every caller instead of per noun, since it is the same code path regardless
        // of which words a call site supplies.
        assert_eq!(count_phrase(0, "row", "rows"), "0 rows");
        assert_eq!(count_phrase(1, "row", "rows"), "1 row");
        assert_eq!(count_phrase(2, "row", "rows"), "2 rows");
    }

    #[test]
    fn cell_value_debug_never_prints_a_value() {
        // Mirrors crate::input::ParameterInput's own test for the same hand-written
        // Debug impl (input.rs's `parameter_input_debug_never_prints_a_value`): the
        // redaction is a deliberate deviation from "every output type derives Debug",
        // and nothing else in this module would fail if someone replaced it with
        // `#[derive(Debug)]`.
        let secret = to_cell(&ResultValue::String("hunter2".to_owned()));
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert_eq!(rendered, "String(<redacted 7 bytes>)");
    }

    #[test]
    fn every_summary_matches_the_documented_format() {
        // The brief's own table (task-4-brief.md, Step 3), pinned exactly. A substring
        // check like `contains("1 row")` still passes if a summary starts naming a
        // column or a connection; only the full string actually constrains "counts and
        // flags, never a value".
        assert_eq!(
            ConnectionsOutput::from_metadata(&[metadata()]).summary(),
            "1 connection"
        );
        assert_eq!(
            ConnectionsOutput::from_metadata(&[metadata(), metadata()]).summary(),
            "2 connections"
        );
        assert_eq!(
            QueryOutput::from(&result_set_with_secret()).summary(),
            "1 row, 2 columns, truncated: false, 41 bytes, 12 ms"
        );
        assert_eq!(
            ExplainOutput::from(&postgres_plan()).summary(),
            "postgresql plan, estimated rows: 1200"
        );
        assert_eq!(ExplainOutput::from(&mysql_plan()).summary(), "mysql plan");
        assert_eq!(
            SearchOutput::from(&truncated_search()).summary(),
            "2 matches, truncated: true"
        );
        assert_eq!(
            DescribeOutput::from(&description()).summary(),
            "1 schema, 2 tables"
        );
    }
}
