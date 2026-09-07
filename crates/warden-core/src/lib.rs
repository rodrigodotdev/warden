//! Warden domain types for dialects, connections, queries, results, schemas, and
//! errors.
//!
//! This crate is the root of the dependency graph and depends only on `serde`,
//! `serde_json`, `thiserror`, `secrecy`, `url`, and `percent-encoding`. The last
//! three are all one decision: both adapters need a typed, redacted DSN and neither
//! may depend on `warden-config` (`docs/architecture.md` section 3; ADR-0019), and
//! that DSN is parsed and validated here rather than by a driver's own URL parser
//! (ADR-0031). It must not depend on `sqlx`,
//! `rmcp`, or `sqlparser` (SPEC sections 4 and 6), a rule `tests/architecture.rs`
//! enforces mechanically.
//!
//! # The pipeline these types describe
//!
//! ```text
//! QueryRequest      size-validated input, never re-serialized to the model
//!    │ analyze      adapter, synchronous, no I/O
//! QueryAnalysis     lossy, parser-independent security evidence
//!    │ authorize    warden-policy, synchronous, no I/O  (Milestone 2)
//! AuthorizedQuery   carries the unforgeable AllowDecision (Milestone 2)
//!    │ execute
//! ResultSet         bounded, normalized, redacted
//! ```
//!
//! # Rules this crate follows
//!
//! * Validated newtypes implement `TryFrom<String>`, `FromStr`, `Display`, and
//!   `AsRef<str>`, deserialize through `#[serde(try_from = "String")]`, and never
//!   implement `Deref`.
//! * Security enums are closed and carry no `#[non_exhaustive]`, so adding a
//!   variant breaks `warden-policy` instead of silently matching a wildcard
//!   (ADR-0021).
//! * Security-sensitive state is private with read-only accessors.
//! * `Debug` never prints SQL text or parameter values (SPEC section 6,
//!   invariants 22–23).
//! * A secret-bearing type implements neither `Display` nor `AsRef<str>` nor
//!   `Serialize`, and redacts `Debug`. This deliberately breaks the newtype rule
//!   above, because those three traits are the leak paths (ADR-0019).

// `Index` panics on a miss and is the one panic shape `clippy::unwrap_used` and
// `expect_used` cannot see, which is why `AGENTS.md` bans the others. This crate runs
// on the startup path, where a panic is a failed boot rather than a contained
// request. Scoped to `not(test)` because test code indexes assertions freely and the
// goal is to catch a panic before serving, not to fight a fixture.
#![cfg_attr(not(test), warn(clippy::indexing_slicing))]

/// The largest integer magnitude a JSON consumer can represent exactly (2^53).
///
/// Shared by the parameter and result models: inbound numbers above this bound are
/// rejected rather than truncated, and outbound integers above it serialize as
/// strings (`docs/data-model.md` sections 3.1 and 8.1).
pub const MAX_EXACT_JSON_INTEGER: u64 = 9_007_199_254_740_992;

/// The SQL parser's explicit recursion bound, shared by every adapter.
///
/// ADR-0006 requires the bound to be set explicitly rather than inherited, and both
/// adapters previously declared their own copy while each doc comment promised it
/// equalled the other's — a promise nothing checked. One constant makes it true by
/// construction. It lives here rather than in an adapter because it carries no
/// dialect semantics: it is a plain depth, and `warden-core` must not depend on
/// `sqlparser` to state one.
///
/// It equals sqlparser 0.62's own default, so pinning it changes nothing today and
/// stops an upstream default change from moving Warden's bound silently. It is the
/// middle of three layers: `QueryRequest` caps the input at 64 KiB before parsing
/// (`docs/data-model.md` section 2), this bound caps nesting, and sqlparser's default
/// `recursive-protection` feature keeps a deep tree from overflowing the stack
/// (`docs/operations.md` section 2.4).
///
/// The bound limits depth, not length: measured against sqlparser 0.62 under both
/// dialects, 2000 chained `OR`s parse well within it because an operator chain is
/// iterative. What it stops is nesting.
pub const SQL_RECURSION_LIMIT: usize = 50;

mod identifier;

pub mod analysis;
pub mod connection;
pub mod context;
pub mod dialect;
pub mod error;
pub mod explain;
pub mod fingerprint;
pub mod limits;
pub mod parameter;
pub mod pool;
pub mod query;
pub mod result;
pub mod schema;
pub mod secret;
pub mod tls;

pub use identifier::{IdentifierError, IdentifierViolation};
