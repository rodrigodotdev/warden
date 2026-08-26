//! Warden's PostgreSQL adapter: analysis, connections, and execution now,
//! inspection and explain in Milestones 9 and 10.
//!
//! This crate may depend on `warden-core`, `warden-policy`, `warden-ports`, `sqlx`,
//! and `sqlparser`, but never `rmcp`.
//!
//! # The AST stops here
//!
//! Every module below is private, and the crate exports the analyzer, the
//! connection types, the search path, and their errors. Their signatures name only
//! `warden-core`, `warden-policy`, and `warden-ports` types, so no `sqlparser` type
//! can appear in a public signature (SPEC section 6, invariant 28; ADR-0007).
//! `tests/adapter_rules.rs` enforces that mechanically rather than by review, over
//! the five files allowed to declare a `pub` item.
//!
//! # The driver stops here too
//!
//! [`PostgreSqlConnectionPools`] owns two concrete `PgPool` values (ADR-0005,
//! ADR-0025) and hands out neither: the accessors are `pub(crate)`, so the crate's
//! public surface names no SQLx type at all. `tests/adapter_rules.rs` enforces that
//! the same way it enforces the AST rule.
//! Normalization reads driver values and produces only `warden-core` types, so no
//! SQLx type crosses out of that module either.
//!
//! Every statement destined for `agent_pool` is built by `crate::query::agent_query`,
//! which applies `.persistent(false)`. The executor makes its bound agent statement a
//! narrow exception: SQLx needs a named statement while resolving custom result
//! metadata, then the executor deallocates it on the same pinned connection. If that
//! cleanup is unconfirmed, or the request future drops mid-stream, the connection is
//! retired instead of reused. That keeps `statement_cache_capacity(0)` from retaining a
//! named prepared statement per distinct agent query for the connection's lifetime
//! (ADR-0025).
//!
//! # How analysis fails, and how it does not
//!
//! A statement this crate understands and distrusts is **not** an error. It becomes
//! evidence — an `Unknown` statement kind, a risk flag, an unclassified function —
//! and `warden-policy` denies it with a code an auditor can read (ADR-0011). Only a
//! statement that yielded nothing to evaluate becomes an `AnalyzeError`.
//!
//! # Where the wildcards are
//!
//! A `sqlparser` enum this crate classifies gets a wildcard arm that maps to
//! something denied: an unmapped `Statement` becomes `StatementKind::Unknown`, an
//! unmapped `TableFactor` adds `RiskFlag::UnknownConstruct`, and a function outside
//! the registry is `FunctionClassification::Unknown`. `Expr` gets no such arm,
//! deliberately: it is overwhelmingly arithmetic and comparison, and side effects
//! reach a PostgreSQL expression through three classified shapes — a function call, a
//! user-defined operator invoked as `OPERATOR(schema.name)`, and a nested statement
//! the visitor descends into. A fourth shape is known and deliberately left
//! unclassified: a user-defined cast — `'x'::evil_type` or `CAST('x' AS evil_type)` —
//! reaches `Expr::Cast`, never `Expr::Function`. That is acceptable because creating
//! the cast, or the type it casts to, requires DDL, which this tool denies. A
//! `warden-core` security enum never gets a wildcard at all (ADR-0021).

mod analyzer;
mod bind;
mod connection;
mod error;
mod execute;
mod fingerprint;
mod functions;
mod normalize;
mod options;
mod parse;
mod pool;
mod query;
mod statement;
mod visit;

#[cfg(all(test, feature = "docker"))]
mod container_tests;

pub use analyzer::PostgreSqlAnalyzer;
pub use connection::{
    MAX_SCHEMA_NAME_LEN, PostgreSqlConnectionConfig, PostgreSqlConnectionPools, SearchPath,
    SearchPathError,
};
pub use error::ConnectError;
pub use execute::PostgreSqlQueryExecutor;
