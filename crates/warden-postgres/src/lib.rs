//! Warden's PostgreSQL adapter: analysis, execution, inspection, explain,
//! normalization, and connections.
//!
//! This crate may depend on `warden-core`, `warden-policy`, `warden-ports`, `sqlx`,
//! and `sqlparser`, but never `rmcp`. Parser ASTs may be used internally and must not
//! appear in public signatures (SPEC section 6, invariant 28). Implemented in
//! Milestones 5 and 8.
