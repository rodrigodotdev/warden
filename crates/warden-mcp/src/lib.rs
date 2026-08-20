//! Warden's MCP adapter: server, tools, mappings, stdio, and HTTP.
//!
//! This crate may depend on `warden-core`, `warden-service`, and `rmcp`. It must not
//! depend on `sqlx` or `sqlparser` (SPEC section 6, invariants 26–28;
//! `docs/architecture.md` section 3). Implemented in Milestone 12.
