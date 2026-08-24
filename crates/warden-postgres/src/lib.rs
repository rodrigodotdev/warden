//! Warden's PostgreSQL adapter: analysis now, execution, inspection, explain,
//! normalization, and connections in Milestones 8, 9 and 10.
//!
//! This crate may depend on `warden-core`, `warden-policy`, `warden-ports`, `sqlx`,
//! and `sqlparser`, but never `rmcp`.
//!
//! # The AST stops here
//!
//! Every module below is private and every item in them is `pub(crate)`. The crate's
//! entire public surface is `PostgreSqlAnalyzer`, whose signatures name only
//! `warden-core`, `warden-policy`, and `warden-ports` types, so no `sqlparser` type
//! can appear in a public signature (SPEC section 6, invariant 28; ADR-0007).
//! `tests/adapter_rules.rs` enforces that mechanically rather than by review.
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
mod fingerprint;
mod functions;
mod parse;
mod statement;
mod visit;

pub use analyzer::PostgreSqlAnalyzer;
