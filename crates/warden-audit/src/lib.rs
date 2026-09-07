//! The audit record format, and the two sinks that write it.
//!
//! `AuditSink` is a port declared in `warden-ports`, exactly like `QueryExecutor`,
//! `Explainer` and `SchemaInspector`. This crate is its adapter — the one that used to
//! live in the binary, which made it the only port in the system whose implementations
//! did (ADR-0048).
//!
//! `record` is the single declaration of what an audit record contains: its shape,
//! its key order, and the names no record may ever carry. `tracing_sink` writes it
//! through the process's stderr subscriber; `file` appends it to a JSON Lines trail
//! with the durability protocol ADR-0043 specifies. Both project the same field set
//! from the same declaration, which `tests/audit_rules.rs` asserts from outside.
//!
//! # What this crate must not reach
//!
//! `sqlx`, `rmcp`, `sqlparser`, either adapter, `warden-service`, `warden-policy` and
//! `warden-config`. That list was unenforceable while these files lived in the binary,
//! which legitimately depends on all of them; `FORBIDDEN_EDGES` in
//! `tests/architecture.rs` states it now.

mod file;
mod record;
mod tracing_sink;

pub use file::FileAuditSink;
pub use tracing_sink::TracingAuditSink;
