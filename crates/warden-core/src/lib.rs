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

/// The largest integer magnitude a JSON consumer can represent exactly (2^53).
///
/// Shared by the parameter and result models: inbound numbers above this bound are
/// rejected rather than truncated, and outbound integers above it serialize as
/// strings (`docs/data-model.md` sections 3.1 and 8.1).
pub const MAX_EXACT_JSON_INTEGER: u64 = 9_007_199_254_740_992;

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
