//! The append-only audit trail an operator can keep.
//!
//! One JSON object per line, appended, flushed, and — for the attempt phase —
//! `sync_data`'d before the write is reported as successful. That last step is what
//! ADR-0022's argument actually needs: the attempt exists so a process that dies
//! mid-execution still leaves a record, and a record sitting in a page cache does
//! not survive the machine dying with it. The outcome phase is not synced: it fails
//! open, and execution has already happened.
//!
//! Unlike Milestone 12's stderr sink, **this one can fail** — a full volume, a
//! revoked permission, a full quota — which is what turns ADR-0022's fail-closed
//! attempt from a structural claim into a tested behaviour.
use std::fmt;
use std::path::PathBuf;

use tokio::io::AsyncWriteExt;
use warden_config::AuditMode;
use warden_ports::{AuditAttempt, AuditError, AuditOutcomeEvent, AuditSink, BoxFuture};

use super::record::{AttemptRecord, OutcomeRecord};

/// Appends the shared audit record shape to a JSON Lines file.
pub(crate) struct FileAuditSink {
    mode: AuditMode,
    /// The open file, held across write and flush so two concurrent records cannot
    /// interleave halves of a line.
    file: tokio::sync::Mutex<tokio::fs::File>,
    path: PathBuf,
}

impl FileAuditSink {
    /// Opens (or creates) `path` for appending.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`std::io::Error`] if the file could not be created or
    /// opened for appending — a missing parent directory, or a permission a
    /// misconfigured deployment did not grant.
    pub(crate) async fn open(path: PathBuf, mode: AuditMode) -> Result<Self, std::io::Error> {
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await?;
        Ok(Self {
            mode,
            file: tokio::sync::Mutex::new(file),
            path,
        })
    }

    /// Writes `line`, flushes it, and — when `durable` — `sync_data`s before
    /// returning. The lock is held across all three so two concurrent records
    /// cannot interleave halves of a line.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::Unavailable`] if the write, the flush, or the sync
    /// fails. The io error's detail goes in the structured field; `Display` never
    /// repeats a path or an errno.
    async fn write(&self, line: String, durable: bool) -> Result<(), AuditError> {
        let mut file = self.file.lock().await;
        file.write_all(line.as_bytes())
            .await
            .map_err(|error| AuditError::Unavailable {
                detail: error.to_string(),
            })?;
        file.flush()
            .await
            .map_err(|error| AuditError::Unavailable {
                detail: error.to_string(),
            })?;
        if durable {
            file.sync_data()
                .await
                .map_err(|error| AuditError::Unavailable {
                    detail: error.to_string(),
                })?;
        }
        Ok(())
    }
}

impl fmt::Debug for FileAuditSink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileAuditSink")
            .field("path", &self.path)
            .field("mode", &self.mode)
            .finish()
    }
}

impl AuditSink for FileAuditSink {
    fn record_attempt<'a>(
        &'a self,
        event: &'a AuditAttempt,
    ) -> BoxFuture<'a, Result<(), AuditError>> {
        Box::pin(async move {
            let record = AttemptRecord::new(event, self.mode);
            let mut line =
                serde_json::to_string(&record).map_err(|error| AuditError::Unavailable {
                    detail: error.to_string(),
                })?;
            line.push('\n');
            self.write(line, true).await
        })
    }

    fn record_outcome<'a>(
        &'a self,
        event: &'a AuditOutcomeEvent,
    ) -> BoxFuture<'a, Result<(), AuditError>> {
        Box::pin(async move {
            let record = OutcomeRecord::new(event);
            let mut line =
                serde_json::to_string(&record).map_err(|error| AuditError::Unavailable {
                    detail: error.to_string(),
                })?;
            line.push('\n');
            self.write(line, false).await
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use warden_core::analysis::StatementKind;
    use warden_core::connection::Environment;
    use warden_core::dialect::Dialect;
    use warden_ports::{AuditEventId, AuditOperation, AuditOutcome};

    use super::super::record::RECORD_SCHEMA;
    use super::*;

    #[tokio::test]
    async fn both_phases_land_as_one_json_line_each() {
        let file = TempPath::new("records");
        let sink = FileAuditSink::open(file.path().to_owned(), AuditMode::Fingerprint)
            .await
            .unwrap();
        let attempt = attempt();
        sink.record_attempt(&attempt).await.unwrap();
        sink.record_outcome(&outcome(attempt.id)).await.unwrap();

        let lines: Vec<serde_json::Value> = std::fs::read_to_string(file.path())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["event"], serde_json::json!("attempt"));
        assert_eq!(lines[0]["schema"], serde_json::json!(RECORD_SCHEMA));
        assert_eq!(lines[1]["attempt_id"], lines[0]["attempt_id"]);
    }

    #[tokio::test]
    async fn a_sink_appends_rather_than_truncating_what_is_already_recorded() {
        let file = TempPath::new("append");
        for _ in 0..2 {
            let sink = FileAuditSink::open(file.path().to_owned(), AuditMode::Fingerprint)
                .await
                .unwrap();
            sink.record_attempt(&attempt()).await.unwrap();
        }
        assert_eq!(
            std::fs::read_to_string(file.path())
                .unwrap()
                .lines()
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn a_destination_that_cannot_be_opened_is_a_startup_failure_not_a_silent_one() {
        let missing = TempPath::new("missing").path().join("nested/audit.jsonl");
        assert!(
            FileAuditSink::open(missing, AuditMode::Fingerprint)
                .await
                .is_err()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_write_that_fails_is_reported_so_the_caller_can_fail_closed() {
        // `/dev/full` accepts an open and fails every write with ENOSPC, which is the
        // deterministic version of the disk an operator's audit volume will one day
        // become. This is the failure ADR-0022's attempt phase exists to react to, and
        // the Milestone 12 sink could not produce it at all.
        let sink = FileAuditSink::open(PathBuf::from("/dev/full"), AuditMode::Fingerprint)
            .await
            .unwrap();
        let error = sink.record_attempt(&attempt()).await.unwrap_err();
        assert!(matches!(error, AuditError::Unavailable { .. }), "{error:?}");
        // The io error names a path and an errno, and `Display` must not repeat it.
        assert_eq!(error.to_string(), "the audit sink is unavailable");
    }

    /// One representative attempt: production, MySQL, a select, denied for writing.
    fn attempt() -> AuditAttempt {
        AuditAttempt {
            id: AuditEventId::generate(),
            timestamp: time::OffsetDateTime::UNIX_EPOCH,
            request_id: "request-1".parse().unwrap(),
            principal: "local-stdio".parse().unwrap(),
            client: "example-client".parse().unwrap(),
            connection: "production-db".parse().unwrap(),
            dialect: Dialect::MySql,
            environment: Environment::Production,
            operation: AuditOperation::Query,
            fingerprint: None,
            statement_kind: Some(StatementKind::Select),
            deny_reasons: Vec::new(),
        }
    }

    /// One outcome correlated with `attempt_id`.
    fn outcome(attempt_id: AuditEventId) -> AuditOutcomeEvent {
        AuditOutcomeEvent {
            attempt_id,
            outcome: AuditOutcome::Succeeded,
            duration: Some(Duration::from_millis(3)),
            queue_wait: None,
            rows_returned: Some(1),
            result_bytes: Some(64),
            error_code: None,
        }
    }

    /// A unique path under `std::env::temp_dir()`, removed on drop.
    struct TempPath(PathBuf);

    impl TempPath {
        fn new(label: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "warden-audit-{label}-{}-{unique}",
                std::process::id()
            ));
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempPath {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}
