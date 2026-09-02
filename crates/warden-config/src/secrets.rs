//! Reads a DSN from the source a connection names, and wraps it without ever
//! logging or returning its contents.
//!
//! Exactly one source is read per connection. The text is trimmed of ASCII
//! whitespace — a secret mounted by Docker or Kubernetes, or written by `echo`,
//! usually ends in a newline, and a DSN with a trailing newline is not a different
//! DSN — and handed straight to [`warden_core::secret::Dsn`], which is where
//! ADR-0031's rules live. This module never logs, never returns, and never formats
//! the text it read; only the variable name or the path it came from ever reaches an
//! error (`docs/operations.md` section 3.3).

use std::path::PathBuf;

use warden_core::connection::ConnectionName;
use warden_core::secret::Dsn;

use crate::error::ConfigError;

/// Where a connection's DSN comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretSource {
    /// The name of an environment variable holding the DSN.
    Environment(String),
    /// The path to a file holding the DSN.
    File(PathBuf),
}

/// Reads and parses the DSN a connection names.
///
/// # Errors
///
/// [`ConfigError::DsnVariableMissing`] when an environment variable is unset or not
/// UTF-8; [`ConfigError::DsnFileUnreadable`] when a file cannot be read;
/// [`ConfigError::InvalidDsn`] when the text read is not a DSN `warden-core` accepts.
///
/// `pub(crate)`, not `pub`: [`SecretSource`] is the crate's public surface for a DSN
/// source, and `Config::resolve` is the public surface for reading one. Nothing
/// outside this crate calls `secrets::resolve` directly, and the module itself is
/// private (`mod secrets;` in `lib.rs`), so a wider visibility would be unreachable.
pub(crate) fn resolve(
    connection: &ConnectionName,
    source: &SecretSource,
) -> Result<Dsn, ConfigError> {
    let raw = match source {
        SecretSource::Environment(variable) => {
            std::env::var(variable).map_err(|_error| ConfigError::DsnVariableMissing {
                connection: connection.clone(),
                variable: variable.clone(),
            })?
        }
        SecretSource::File(path) => {
            std::fs::read_to_string(path).map_err(|error| ConfigError::DsnFileUnreadable {
                connection: connection.clone(),
                path: path.clone(),
                message: error.to_string(),
            })?
        }
    };

    Dsn::try_from(raw.trim().to_owned()).map_err(|error| ConfigError::InvalidDsn {
        connection: connection.clone(),
        message: error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    const DSN: &str = "mysql://warden_ro:pw@db.internal:3306/app";

    fn name() -> ConnectionName {
        "production-mysql".parse().unwrap()
    }

    /// A uniquely named directory under the OS temp directory. Built from the process
    /// id and an atomic counter rather than a new dependency, so parallel test binaries
    /// and repeated test functions in this one never collide.
    fn tempdir() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "warden-config-secrets-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        directory
    }

    #[test]
    fn a_dsn_file_is_read_and_trimmed() {
        // A file written by `echo` ends in a newline; a DSN with a trailing newline is not
        // a different DSN, and refusing it would be a support ticket, not a control.
        let directory = tempdir();
        let path = directory.join("dsn");
        std::fs::write(&path, format!("{DSN}\n")).unwrap();
        let dsn = resolve(&name(), &SecretSource::File(path)).unwrap();
        assert_eq!(dsn.host(), "db.internal");
        assert_eq!(dsn.database(), "app");
    }

    #[test]
    fn a_missing_file_names_the_path_and_not_its_contents() {
        let error = resolve(&name(), &SecretSource::File("/nonexistent/dsn".into())).unwrap_err();
        let rendered = error.to_string();
        assert!(rendered.contains("/nonexistent/dsn"), "{rendered}");
        assert!(!rendered.contains("pw"), "{rendered}");
    }

    #[test]
    fn an_invalid_dsn_is_refused_without_echoing_itself() {
        let directory = tempdir();
        let path = directory.join("dsn");
        // ADR-0031: a DSN names only the target. A query string is a second, unreviewed
        // source of a decision Warden makes from its own configuration.
        std::fs::write(
            &path,
            "mysql://warden_ro:hunter2@db:3306/app?sslmode=DISABLED",
        )
        .unwrap();
        let error = resolve(&name(), &SecretSource::File(path)).unwrap_err();
        let rendered = error.to_string();
        assert!(
            matches!(error, ConfigError::InvalidDsn { .. }),
            "{rendered}"
        );
        assert!(!rendered.contains("hunter2"), "{rendered}");
    }
}
