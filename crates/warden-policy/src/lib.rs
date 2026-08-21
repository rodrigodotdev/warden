//! Warden's policy engine, `AllowDecision`, and `AuthorizedQuery`.
//!
//! This crate turns evidence into permission. It depends on `warden-core`, `serde`,
//! and `thiserror`, and must never depend on `sqlx`, `rmcp`, or `sqlparser`
//! (SPEC sections 4 and 6; `docs/architecture.md` section 3), a rule
//! `tests/architecture.rs` enforces mechanically.
//!
//! # The transition this crate owns
//!
//! ```text
//! AnalyzedQuery     request + parser-independent evidence
//!    │ PolicyEngine::authorize   synchronous, deterministic, no I/O
//!    ├─ Err(PolicyRejection)     every denial, ordered by precedence
//!    └─ Ok(AuthorizedQuery)      carries an AllowDecision only this crate builds
//! ```
//!
//! # Rules this crate follows
//!
//! * Every policy is evaluated and every denial is aggregated; evaluation never
//!   stops at the first one (ADR-0012).
//! * Unknown, unsupported, and ambiguous evidence is denied (ADR-0011). Wildcard
//!   arms do not exist here: every match on a `warden-core` security enum is
//!   exhaustive, so adding a variant there breaks this crate's build (ADR-0021).
//! * The agent receives one [`DenyCode`] and fixed-table text. Object names,
//!   function names, and configuration stay in `internal_detail`, which never
//!   crosses the MCP boundary (`docs/security.md` section 6).
//! * A policy cannot read the SQL. [`PolicyInput`] carries evidence, not the
//!   request.
//! * Only [`PolicyEngine`] can build an [`AllowDecision`], and it never hands one
//!   out on its own (ADR-0010).

pub mod decision;
pub mod engine;
pub mod input;
pub mod policy;
pub mod state;

#[cfg(test)]
mod testing;

pub use decision::{DenyCode, DenyReason, PolicyDecision, PolicyRejection};
pub use engine::{PolicyEngine, PolicyEngineError};
pub use input::{PolicyContext, PolicyInput};
pub use policy::{ObjectAccessPolicy, Policy};
pub use state::{AllowDecision, AnalyzedQuery, AuthorizedQuery};
