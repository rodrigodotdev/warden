//! Warden capability traits for analysis, execution, inspection, explain, audit, and
//! registry access.
//!
//! This crate may depend on `warden-core` and `warden-policy`. It must not depend on
//! `sqlx`, `rmcp`, or `sqlparser` (SPEC sections 4 and 6; `docs/architecture.md`
//! section 3). Implemented in Milestone 3.
