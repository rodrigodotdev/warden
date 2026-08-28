//! Warden's MySQL adapter: analysis, connections, execution, and inspection now;
//! explain in Milestone 10.
//!
//! This crate may depend on `warden-core`, `warden-policy`, `warden-ports`, `sqlx`,
//! and `sqlparser`, but never `rmcp`.
//!
//! # The AST stops here
//!
//! Every module below is private, and the crate exports six names: the analyzer,
//! executor, inspector, two connection types, and their error. Their signatures name
//! only `warden-core`, `warden-policy`, and `warden-ports` types, so no `sqlparser`
//! type can appear in a public signature (SPEC section 6, invariant 28; ADR-0007).
//! `tests/adapter_rules.rs` enforces that mechanically rather than by review, over
//! the six files allowed to declare a `pub` item.
//!
//! # The driver stops here too
//!
//! [`MySqlConnectionPools`] owns two concrete `MySqlPool` values (ADR-0005,
//! ADR-0025) and hands out neither: the accessors are `pub(crate)`, so the crate's
//! public surface names no SQLx type at all. The composition root builds a pools
//! value, passes it to the executor, and never depends on `sqlx` itself.
//! `tests/adapter_rules.rs` enforces that the same way it enforces the AST rule.
//! Normalization reads driver values and produces only `warden-core` types, so no
//! `sqlx` type crosses out of that module either.
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
//! reach a MySQL expression through exactly three shapes — a function call, a nested
//! statement the visitor descends into, and the `:=` assignment operator — all three
//! of which are classified. A `warden-core` security enum never gets a wildcard at
//! all (ADR-0021).

mod analyzer;
mod bind;
mod catalog;
mod connection;
mod error;
mod execute;
mod fingerprint;
mod functions;
mod inspector;
mod normalize;
mod options;
mod parse;
mod pool;
mod statement;
mod tokens;
mod visit;

#[cfg(all(test, feature = "docker"))]
mod container_tests;

pub use analyzer::MySqlAnalyzer;
pub use connection::{MySqlConnectionConfig, MySqlConnectionPools};
pub use error::ConnectError;
pub use execute::MySqlQueryExecutor;
pub use inspector::MySqlSchemaInspector;
