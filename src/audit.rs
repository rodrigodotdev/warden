//! Choosing the audit sink the configuration named.
//!
//! The sinks themselves are an adapter and live in `warden-audit` (ADR-0048). What is
//! left here is composition: `AuditDestination` is a `warden-config` type naming a
//! deployment choice, and turning one into a port implementation is what a composition
//! root is for — the same shape as `startup.rs`'s `policy_settings` and
//! `redaction_settings`.

use std::sync::Arc;

use anyhow::Context as _;
use warden_audit::{FileAuditSink, TracingAuditSink};
use warden_config::{AuditDestination, ResolvedAudit};
use warden_ports::AuditSink;

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
