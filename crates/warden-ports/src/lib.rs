//! Warden capability traits for analysis, execution, inspection, explain, audit, and
//! registry access.
//!
//! This crate is the seam between what Warden decides and what a database actually
//! does. It depends on `warden-core` and `warden-policy` and must not depend on
//! `sqlx`, `rmcp`, or `sqlparser` (SPEC sections 4 and 6; `docs/architecture.md`
//! section 3), a rule `tests/architecture.rs` enforces mechanically.
//!
//! # The boundary these traits draw
//!
//! ```text
//! QueryRequest      size-validated input                (warden-core)
//!    │ QueryAnalyzer::analyze          synchronous, no I/O
//! AnalyzedQuery                                          (warden-policy)
//!    │ PolicyEngine::authorize         synchronous, no I/O
//! AuthorizedQuery                                        (warden-policy)
//!    │ AuditSink::record_attempt       fail closed       (ADR-0022)
//!    │ ConnectionRuntime::acquire_query_permit           bounded wait
//!    │ QueryExecutor::execute_read_only deadline + token (ADR-0024)
//! ResultSet                                              (warden-core)
//!    │ AuditSink::record_outcome       fail open
//! ```
//!
//! # Rules this crate follows
//!
//! * No port accepts SQL. The only statement a port can run arrives as an
//!   `AuthorizedQuery`, which only `warden-policy` can produce (ADR-0010), so
//!   "MCP calls `execute(raw_sql)`" is not an API that exists
//!   (`docs/security.md` section 12).
//! * Dynamic dispatch uses the explicit [`BoxFuture`] alias below. `async-trait` is
//!   banned in `deny.toml`, and allocation stays visible at a security boundary
//!   (ADR-0013).
//! * Every method that runs SQL takes a deadline and a `CancellationToken`, because
//!   dropping a future does not stop a server-side query
//!   (`docs/operations.md` section 5.4).
//! * Every failure that can reach a model implements `warden_core::error::PublicError`
//!   and prints no driver text (`docs/security.md` section 10).

use std::future::Future;
use std::pin::Pin;

pub mod analyzer;
pub mod audit;
pub mod error;
pub mod executor;
pub mod explainer;
pub mod inspector;

#[cfg(test)]
mod testing;

pub use analyzer::QueryAnalyzer;
pub use audit::{AuditAttempt, AuditEventId, AuditOutcome, AuditOutcomeEvent, AuditSink};
pub use error::{
    AnalyzeError, AuditError, ConnectionError, ExecuteError, ExplainError, SchemaError,
};
pub use executor::QueryExecutor;
pub use explainer::Explainer;
pub use inspector::SchemaInspector;

/// The future a dynamically dispatched port returns.
///
/// `async fn` in a trait is stable but not dyn-compatible, and Warden chooses the
/// connection at runtime, so boxing is unavoidable. Writing it out instead of hiding
/// it behind `async-trait` keeps the allocation and the `Send` bound visible to a
/// reviewer, which is the whole argument of ADR-0013.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
