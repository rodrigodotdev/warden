//! Warden's policy engine, `AllowDecision`, and `AuthorizedQuery`.
//!
//! This crate may depend on `warden-core`. It must not depend on `sqlx`, `rmcp`, or
//! `sqlparser` (SPEC sections 4 and 6; `docs/architecture.md` section 3). Implemented
//! in Milestone 2.
