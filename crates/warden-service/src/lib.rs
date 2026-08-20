//! Warden application services for queries, schemas, explain, registry, limits, and
//! redaction.
//!
//! This crate may depend on `warden-core`, `warden-policy`, and `warden-ports`. It
//! must not depend on `sqlx` or `sqlparser` (SPEC section 6, invariant 28;
//! `docs/architecture.md` section 3). Implemented in Milestone 11.
