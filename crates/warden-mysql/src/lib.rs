//! Warden's MySQL adapter: analysis and connections now, execution, inspection and
//! explain in Milestones 7, 9 and 10.
//!
//! This crate may depend on `warden-core`, `warden-policy`, `warden-ports`, `sqlx`,
//! and `sqlparser`, but never `rmcp`.
//!
//! # The AST stops here
//!
//! Every module below is private and every item in them is `pub(crate)`. The crate's
//! entire public surface is `MySqlAnalyzer`, whose signatures name only
//! `warden-core`, `warden-policy`, and `warden-ports` types, so no `sqlparser` type
//! can appear in a public signature (SPEC section 6, invariant 28; ADR-0007).
//! `tests/adapter_rules.rs` enforces that mechanically rather than by review.
//!
//! # The driver stops here too
//!
//! [`MySqlConnectionPools`] owns two concrete `MySqlPool` values (ADR-0005,
//! ADR-0025) and hands out neither: the accessors are `pub(crate)`, so the crate's
//! public surface names no SQLx type at all. The composition root builds a pools
//! value, passes it to the executor, and never depends on `sqlx` itself.
//! `tests/adapter_rules.rs` enforces that the same way it enforces the AST rule.
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
mod connection;
mod error;
mod fingerprint;
mod functions;
mod options;
mod parse;
mod pool;
mod statement;
mod tokens;
mod visit;

pub use analyzer::MySqlAnalyzer;
pub use connection::{MySqlConnectionConfig, MySqlConnectionPools};
pub use error::ConnectError;
