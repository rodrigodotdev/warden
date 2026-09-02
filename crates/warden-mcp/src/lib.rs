//! Warden's MCP adapter: the five generic tools, their schemas, and the boundary where
//! an internal failure becomes a public code.
//!
//! This crate depends on `warden-core`, `warden-service`, and `rmcp`, and must not depend
//! on `sqlx`, `sqlparser`, or either adapter (SPEC section 6, invariants 26–28;
//! `docs/architecture.md` section 3). `tests/architecture.rs` enforces the first two
//! mechanically and `tests/mcp_rules.rs` the third.
//!
//! # The tool names are generic on purpose
//!
//! ```text
//! list_connections   search_schema   describe_schema   query   explain
//! ```
//!
//! There is no `mysql_query` and no `postgres_query`. The selected connection chooses the
//! backend while the schema stays identical across adapters (`docs/mcp.md` section 1), and
//! `tests/tool_schema.rs` snapshots the descriptors so any drift shows up in a diff.
//!
//! # What crosses the boundary
//!
//! ```text
//! in :  JSON arguments ─▶ input.rs ─▶ warden-core request types (already size-validated)
//! out:  service result  ─▶ output.rs ─▶ structured_content + a summary line
//! err:  typed error     ─▶ PublicErrorCode ─▶ error.rs ─▶ one of fourteen fixed codes
//! ```
//!
//! Nothing else. A raw `sqlx` message, a DSN, a hostname, or a SQL fragment reaching a
//! model would violate `docs/security.md` section 10, so `error` is the only module that
//! builds a failed [`rmcp::model::CallToolResult`] and it takes a code, not a message.

mod error;
mod identity;
mod input;
mod output;
mod server;
mod stdio;

#[cfg(test)]
mod testing;

pub use input::{
    DEFAULT_SEARCH_LIMIT, DescribeInput, ExplainInput, ParameterInput, QueryInput, SearchInput,
};
pub use output::{
    CellValue, ColumnDetail, ColumnSummary, ConnectionSummary, ConnectionsOutput, DescribeOutput,
    ExplainOutput, ForeignKeySummary, IndexSummary, MatchSummary, PlanDocument, PlanSummaryOutput,
    QueryOutput, SchemaSummary, SearchOutput, StatsSummary, TableSummary, WireDialect,
    WireMatchReason, WireTableKind,
};
pub use server::{SERVER_INSTRUCTIONS, WARDEN_PROTOCOL_VERSIONS, WardenServer};
pub use stdio::{StdioError, serve_stdio};
