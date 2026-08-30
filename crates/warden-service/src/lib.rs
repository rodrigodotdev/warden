//! Warden's application services: the orchestration between an MCP tool call and a
//! database adapter.
//!
//! This crate depends on `warden-core`, `warden-policy`, and `warden-ports`, and must
//! not depend on `sqlx`, `sqlparser`, or `rmcp` (SPEC section 6, invariants 26–28;
//! `docs/architecture.md` section 3), a rule `tests/architecture.rs` enforces
//! mechanically.
//!
//! # The order this crate owns
//!
//! ```text
//! QueryRequest        size-validated by its own constructor, before it arrives here
//!    │ registry       resolve the connection            -> ConnectionError
//!    │ analyzer       parse in the target dialect       -> AnalyzedQuery
//!    │ engine         evaluate every policy             -> AuthorizedQuery
//!    │ audit sink     record the attempt, FAIL CLOSED   (ADR-0022)
//!    │ runtime        acquire a permit within max_queue_wait
//!    │ executor       run under a deadline and a token  (ADR-0024)
//!    │ redactor       apply the configured column rules
//!    │ audit sink     record the outcome, fail open with an alarm
//! ResultSet
//! ```
//!
//! # Why the middle four steps are a type
//!
//! ADR-0032 made the concurrency permit a parameter, so execution cannot begin
//! without one — but a `&QueryPermit` carries no connection identity, and nothing
//! ordered it against the audit attempt (`docs/open-questions.md` item 14).
//! [`crate::pipeline`]'s gate closes both gaps: its single constructor records the
//! attempt and then acquires the permit from the same [`ConnectionRuntime`] it will
//! dispatch to, and it is the only place in this crate allowed to name
//! `executor()`, `explainer()`, or `acquire_query_permit()` (ADR-0038).
//! `tests/service_rules.rs` enforces that mechanically.
//!
//! # What this crate does not do
//!
//! It does not normalize rows: bounding and normalization happen inside the adapter,
//! under the limits carried by the `AuthorizedQuery` this crate authorized
//! (`docs/architecture.md` section 8, step 8). It does not sanitize errors for the
//! wire either; it returns typed errors whose [`warden_core::error::PublicError`]
//! code Milestone 12 maps at the MCP boundary.

pub mod redaction;
pub mod registry;

#[cfg(test)]
mod testing;

pub use redaction::{REDACTED, RedactionRuleError, RedactionSettings, RedactionStrategy, Redactor};
pub use registry::{RegistryError, StaticConnectionRegistry};
