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

// `Index` panics on a miss and is the one panic shape `clippy::unwrap_used` and
// `expect_used` cannot see, which is why `AGENTS.md` bans the others. This crate runs
// on the startup path, where a panic is a failed boot rather than a contained
// request. Scoped to `not(test)` because test code indexes assertions freely and the
// goal is to catch a panic before serving, not to fight a fixture.
#![cfg_attr(not(test), warn(clippy::indexing_slicing))]

mod duration;
mod error;
mod model;
mod resolve;
mod secrets;

pub use duration::HumanDuration;
pub use error::ConfigError;
pub use model::{
    AuditDestinationEntry, AuditEntry, AuditMode, Config, ConnectionEntry, PolicyProfile,
    PoolProfile, RedactionEntry, RedactionStrategyEntry, SUPPORTED_VERSION, TlsEntry,
};
pub use resolve::{
    AuditDestination, ResolvedAudit, ResolvedConfig, ResolvedConnection, ResolvedPolicy,
};
pub use secrets::SecretSource;

use std::path::Path;

/// Reads, parses, and resolves a configuration file.
///
/// The one entry point the composition root needs. Errors name the file, never its
/// contents: a configuration file holds no secret, but the environment and files it
/// points at do, and a reader should not have to reason about which is which.
///
/// # Errors
///
/// Returns [`ConfigError`] when the file cannot be read, does not parse, declares an
/// unsupported version, or fails any rule in `docs/operations.md` section 3.2.
pub fn load_from_path(path: &Path) -> Result<ResolvedConfig, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|error| ConfigError::Unreadable {
        path: path.to_path_buf(),
        message: error.to_string(),
    })?;
    Config::from_toml_str(&text)?.resolve()
}
