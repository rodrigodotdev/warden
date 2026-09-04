//! The audit module: one record format, and the sinks that write it.
//!
//! `record` is the single declaration of what an audit record contains — its shape,
//! its key order, and the names no record may ever carry. `tracing_sink` is the
//! stderr sink that has existed since Milestone 12, rebuilt on that declaration so
//! the field list is no longer duplicated between a `tracing` call and a constant
//! beside it. `file` is the append-only sink Milestone 13 adds beside it, on the
//! same declaration.

mod file;
mod record;
mod tracing_sink;

pub(crate) use tracing_sink::TracingAuditSink;
