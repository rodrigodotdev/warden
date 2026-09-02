//! Warden's configuration model, loading, validation, and secret resolution.
//!
//! This crate may depend on `serde`, `toml`, `secrecy`, `thiserror`, and `warden-core`
//! metadata. It must not depend on `sqlx`, `rmcp`, or `sqlparser`, and it deliberately
//! does not depend on `warden-policy` or `warden-service` either
//! (`docs/architecture.md` section 3): it emits core types and plain strings, and
//! `src/startup.rs` maps those into `PolicySettings` and `RedactionSettings`.
//!
//! # Two stages, on purpose
//!
//! ```text
//! TOML text ──parse──▶ Config          every field as written, unknown fields refused
//!                        │ resolve     secrets read, cross-field rules applied
//!                        ▼
//!                     ResolvedConfig   what the composition root can actually build
//! ```
//!
//! [`Config`] is what the operator wrote. `ResolvedConfig` (Task 2) is what survives
//! `docs/operations.md` section 3.2's startup validation. Keeping them apart is what lets
//! `#[serde(deny_unknown_fields)]` sit on the first without leaking serde concerns into the
//! second, and what lets a validation error name the profile or connection it came from.
//!
//! # Errors never carry secret values
//!
//! A DSN is read here and immediately wrapped (`docs/operations.md` section 3.3). No
//! error variant in this crate carries a DSN, a password, or a file's contents — only the
//! name of the variable or the path that failed.

mod duration;
mod error;
mod model;
mod resolve;
mod secrets;

pub use duration::HumanDuration;
pub use error::ConfigError;
pub use model::{
    AuditEntry, AuditMode, Config, ConnectionEntry, PolicyProfile, PoolProfile, RedactionEntry,
    RedactionStrategyEntry, SUPPORTED_VERSION, TlsEntry,
};
