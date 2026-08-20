//! Warden configuration model, loading, validation, and secrets.
//!
//! This crate may depend on `serde`, `toml`, `secrecy`, and `warden-core` metadata.
//! It must not depend on `sqlx`, `rmcp`, or `sqlparser` (SPEC sections 4 and 6;
//! `docs/architecture.md` section 3). Implemented from Milestone 0.5 onward.
