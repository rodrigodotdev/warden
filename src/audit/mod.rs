//! The audit module: one record format, and the sinks that write it.
//!
//! `record` is the single declaration of what an audit record contains — its shape,
//! its key order, and the names no record may ever carry. `tracing_sink` is the
//! stderr sink that has existed since Milestone 12, rebuilt on that declaration so
//! the field list is no longer duplicated between a `tracing` call and a constant
//! beside it. `file` is the append-only sink Milestone 13 adds beside it, on the
//! same declaration.

use std::sync::Arc;

use anyhow::Context as _;
use warden_config::{AuditDestination, ResolvedAudit};
use warden_ports::AuditSink;

mod file;
mod record;
mod tracing_sink;

use file::FileAuditSink;
use tracing_sink::TracingAuditSink;

/// Builds the sink the configuration selected.
///
/// # Errors
///
/// Returns an operator-facing error naming the path when the file destination
/// cannot be opened. A deployment that cannot write its audit trail does not start
/// serving one: ADR-0022 denies a query whose attempt cannot be written, and a
/// gateway that refuses every query is worse than one that refuses to boot.
pub(crate) async fn build(settings: &ResolvedAudit) -> anyhow::Result<Arc<dyn AuditSink>> {
    match &settings.destination {
        AuditDestination::Stderr => Ok(Arc::new(TracingAuditSink::new(settings.mode))),
        AuditDestination::File(path) => {
            let sink = FileAuditSink::open(path.clone(), settings.mode)
                .await
                .with_context(|| {
                    format!("the audit trail at {} could not be opened", path.display())
                })?;
            Ok(Arc::new(sink))
        }
    }
}
