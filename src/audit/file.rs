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
use std::io;
#[cfg(unix)]
use std::io::{Read as _, Seek as _};
use std::path::{Path, PathBuf};

use warden_config::AuditMode;
use warden_ports::{AuditAttempt, AuditError, AuditOutcomeEvent, AuditSink, BoxFuture};

use super::record::{AttemptRecord, OutcomeRecord};

mod writer;
use writer::Writer;

/// Appends the shared audit record shape to a JSON Lines file.
pub(crate) struct FileAuditSink {
    mode: AuditMode,
    /// The open file, held across write and flush so two concurrent records cannot
    /// interleave halves of a line.
    file: tokio::sync::Mutex<Writer<tokio::fs::File>>,
    path: PathBuf,
}

impl FileAuditSink {
    /// Opens (or creates) a regular file at `path` for appending.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`std::io::Error`] if the file could not be read,
    /// opened for appending, or persisted together with its parent directory. Returns
    /// [`std::io::ErrorKind::Unsupported`] outside Unix (ADR-0043), and
    /// [`std::io::ErrorKind::InvalidData`] for an unterminated existing tail. Also returns
    /// [`std::io::ErrorKind::InvalidInput`] when the target is not a regular file or
    /// resolves to the same file target as stdout.
    pub(crate) async fn open(path: PathBuf, mode: AuditMode) -> Result<Self, std::io::Error> {
        let file = open_regular_file(&path).await?;
        Ok(Self {
            mode,
            file: tokio::sync::Mutex::new(Writer::new(file)),
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
        self.file.lock().await.write(&line, durable).await
    }
}

/// Opens one append-only regular file without permitting a special file to block.
async fn open_regular_file(path: &Path) -> io::Result<tokio::fs::File> {
    let path = path.to_owned();
    let file = tokio::task::spawn_blocking(move || open_regular_file_sync(&path))
        .await
        .map_err(io::Error::other)??;
    Ok(tokio::fs::File::from_std(file))
}

/// Unix needs `O_NONBLOCK` during the open itself: checking the path first is subject
/// to replacement, and a FIFO substituted between that check and `open` would
/// otherwise wait forever for a reader. The flag has no effect on the regular files
/// this function allows through.
#[cfg(unix)]
fn open_regular_file_sync(path: &Path) -> io::Result<std::fs::File> {
    open_regular_file_sync_with(path, std::fs::File::sync_all)
}

#[cfg(unix)]
fn open_regular_file_sync_with(
    path: &Path,
    persist_directory: impl FnOnce(&std::fs::File) -> io::Result<()>,
) -> io::Result<std::fs::File> {
    use rustix::fs::{Mode, OFlags};

    reject_existing_non_regular_file(path)?;

    // Resolve an existing final symlink before retaining its containing directory.
    // NOFOLLOW on openat below refuses a replacement rather than syncing the wrong
    // directory. For a new file only its existing parent needs resolution.
    let resolved = match path.canonicalize() {
        Ok(resolved) => resolved,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            parent
                .canonicalize()?
                .join(path.file_name().ok_or_else(invalid_audit_destination)?)
        }
        Err(error) => return Err(error),
    };
    let directory: std::fs::File = rustix::fs::open(
        resolved.parent().ok_or_else(invalid_audit_destination)?,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )?
    .into();
    let descriptor = rustix::fs::openat(
        &directory,
        resolved.file_name().ok_or_else(invalid_audit_destination)?,
        OFlags::RDWR
            | OFlags::APPEND
            | OFlags::CREATE
            | OFlags::CLOEXEC
            | OFlags::NONBLOCK
            | OFlags::NOFOLLOW,
        Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH,
    )?;
    let file = validate_opened_file(descriptor.into())?;
    file.sync_all()?;
    persist_directory(&directory)?;
    Ok(file)
}

/// Do not silently claim directory-entry persistence where no equivalent safe
/// protocol is implemented. Tracing remains available on these platforms (ADR-0043).
#[cfg(not(unix))]
fn open_regular_file_sync(_path: &Path) -> io::Result<std::fs::File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "durable audit file creation is not supported on this platform; use stderr tracing",
    ))
}

/// Validates the object the open actually reached, then compares that object with the
/// process's stdout target. `same-file` performs the safe platform-specific descriptor
/// comparison on both Unix and Windows; comparing paths would miss descriptor aliases,
/// symlinks, and hardlinks.
#[cfg(unix)]
fn validate_opened_file(file: std::fs::File) -> io::Result<std::fs::File> {
    if !file.metadata()?.is_file() {
        return Err(invalid_audit_destination());
    }

    let mut retained = file.try_clone()?;
    let opened = same_file::Handle::from_file(file)?;
    if opened == same_file::Handle::stdout()? {
        return Err(invalid_audit_destination());
    }
    if retained.metadata()?.len() != 0 {
        retained.seek(io::SeekFrom::End(-1))?;
        let mut tail = [0];
        retained.read_exact(&mut tail)?;
        if tail != *b"\n" {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the audit destination has an unterminated record",
            ));
        }
    }
    Ok(retained)
}

/// Refuses a known special target before opening it. A missing target is valid: the
/// sink creates a new regular file there.
#[cfg(unix)]
fn reject_existing_non_regular_file(path: &Path) -> io::Result<()> {
    match std::fs::metadata(path) {
        Ok(metadata) if !metadata.is_file() => Err(invalid_audit_destination()),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn invalid_audit_destination() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "the audit destination must be a regular file distinct from stdout",
    )
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
    #[cfg(unix)]
    use std::time::Duration;

    use warden_core::analysis::StatementKind;
    use warden_core::connection::Environment;
    use warden_core::dialect::Dialect;
    #[cfg(unix)]
    use warden_ports::AuditOutcome;
    use warden_ports::{AuditEventId, AuditOperation};

    #[cfg(unix)]
    use super::super::record::RECORD_SCHEMA;
    use super::*;

    #[cfg(not(unix))]
    #[tokio::test]
    async fn unsupported_directory_persistence_fails_before_creation() {
        let file = TempPath::new("unsupported-persistence");
        let error = FileAuditSink::open(file.path().to_owned(), AuditMode::Fingerprint)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(!file.path().exists());
    }

    #[cfg(unix)]
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

    #[cfg(unix)]
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
    async fn an_interrupted_tail_is_rejected_before_appending() {
        let file = TempPath::new("interrupted-tail");
        let prefix = b"{\"schema\":\"warden.audit.v1\"";
        std::fs::write(file.path(), prefix).unwrap();
        let error = FileAuditSink::open(file.path().to_owned(), AuditMode::Fingerprint)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(std::fs::read(file.path()).unwrap(), prefix);
    }

    #[cfg(unix)]
    #[test]
    fn directory_persistence_failure_refuses_startup() {
        let file = TempPath::new("directory-sync-failure");
        let error = open_regular_file_sync_with(file.path(), |directory| {
            assert!(directory.metadata()?.is_dir());
            Err(io::Error::other("injected directory persistence failure"))
        })
        .unwrap_err();
        assert_eq!(error.to_string(), "injected directory persistence failure");
    }

    #[cfg(unix)]
    #[test]
    fn creation_persists_the_directory_that_contains_the_opened_file() {
        let file = TempPath::new("directory-sync-success");
        let mut persisted = false;
        open_regular_file_sync_with(file.path(), |directory| {
            assert!(directory.metadata()?.is_dir());
            assert_eq!(
                same_file::Handle::from_file(directory.try_clone()?)?,
                same_file::Handle::from_path(file.path().parent().unwrap())?,
            );
            assert!(
                file.path().is_file(),
                "create must precede directory persistence"
            );
            directory.sync_all()?;
            persisted = true;
            Ok(())
        })
        .unwrap();
        assert!(persisted, "startup must persist the directory entry");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_non_regular_special_file_is_rejected_before_use() {
        let error = FileAuditSink::open(PathBuf::from("/dev/full"), AuditMode::Fingerprint)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn a_regular_file_write_failure_is_reported_so_the_caller_can_fail_closed() {
        let file = TempPath::new("write-failure");
        std::fs::write(file.path(), "").unwrap();
        let read_only = std::fs::File::open(file.path()).unwrap();
        let sink = FileAuditSink {
            mode: AuditMode::Fingerprint,
            file: tokio::sync::Mutex::new(Writer::new(tokio::fs::File::from_std(read_only))),
            path: file.path().to_owned(),
        };

        let error = sink.record_attempt(&attempt()).await.unwrap_err();
        assert!(matches!(error, AuditError::Unavailable { .. }), "{error:?}");
        // The io error names a path and an errno, and `Display` must not repeat it.
        assert_eq!(error.to_string(), "the audit sink is unavailable");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_fifo_without_a_reader_is_rejected_without_blocking() {
        let fifo = TempPath::new("fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(fifo.path())
            .status()
            .unwrap();
        assert!(status.success());

        let error = tokio::time::timeout(
            Duration::from_secs(1),
            FileAuditSink::open(fifo.path().to_owned(), AuditMode::Fingerprint),
        )
        .await
        .expect("opening a FIFO must return rather than block")
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn the_stdout_descriptor_target_is_rejected_before_any_record_can_be_written() {
        let error = FileAuditSink::open(PathBuf::from("/dev/stdout"), AuditMode::Fingerprint)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
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
    #[cfg(unix)]
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
