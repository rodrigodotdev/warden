//! Warden's MySQL adapter: analysis now, execution, inspection, explain,
//! normalization, and connections in Milestones 7, 9 and 10.
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
//! # How analysis fails, and how it does not
//!
//! A statement this crate understands and distrusts is **not** an error. It becomes
//! evidence — an `Unknown` statement kind, a risk flag, an unclassified function —
//! and `warden-policy` denies it with a code an auditor can read (ADR-0011). Only a
//! statement that yielded nothing to evaluate becomes an `AnalyzeError`.

mod parse;
mod statement;
