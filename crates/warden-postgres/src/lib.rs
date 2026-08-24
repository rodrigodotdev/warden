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

// Until Task 4 exports `PostgreSqlAnalyzer`, nothing `pub` reaches these modules and
// `dead_code` fires on every `pub(crate)` item in them in a non-test build. `expect`
// rather than `allow` because an unfulfilled expectation is itself a warning: the
// moment the export exists this line starts failing the build, which is how it gets
// removed instead of outliving its reason. Scoped to `not(test)`: the unit tests
// below call into `parse` and `statement` directly, which makes those items reachable
// — and therefore not dead — in the `#[cfg(test)]` build, so an unscoped `expect`
// would be unfulfilled there even though nothing is wrong.
#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the crate exports nothing until Task 4 wires up the analyzer"
    )
)]

mod functions;
mod parse;
mod statement;
