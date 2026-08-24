//! Why a MySQL connection could not be built or proved healthy.
//!
//! Deliberately **not** a `warden_core::error::PublicError`. Every failure here is
//! raised by the composition root before a transport is serving, or by a readiness
//! probe an operator reads, so none crosses the MCP boundary and none has a code an
//! agent could observe — the same distinction `warden_ports::error::RuntimeError`
//! draws.
//!
//! Two rules, matching `warden-ports`:
//!
//! * **`Display` never prints a `detail` field.** A `sqlx::Error` can name the host,
//!   the database user, the database, and the statement, and `tracing::warn!(%error)`
//!   would then write all of it into the operator log that SPEC section 6, invariants
//!   21 and 22 keep clean.
//! * **[`ConnectError::InvalidDsn`] carries nothing at all.** The driver's parse
//!   failure is a `sqlx::Error::Configuration` wrapping a URL error whose message can
//!   quote the string it failed on, and that string is the DSN.

use warden_core::dialect::Dialect;
use warden_core::limits::LimitsError;
use warden_core::pool::PoolSettingsError;
use warden_core::tls::TlsError;

/// Why a MySQL connection is unusable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConnectError {
    /// The driver could not parse the DSN.
    ///
    /// Carries no detail on purpose; see the module documentation.
    #[error("the DSN is not a usable MySQL connection string")]
    InvalidDsn,
    /// The DSN's scheme names a different engine than this adapter speaks.
    ///
    /// SQLx does not check this: `MySqlConnectOptions::from_str` parses a
    /// `postgres://` URL without complaint and would then speak the MySQL protocol to
    /// a PostgreSQL port.
    #[error("this adapter is mysql but the DSN names {actual}")]
    DialectMismatch {
        /// The dialect the DSN's scheme named.
        actual: Dialect,
    },
    /// The DSN names no default database.
    ///
    /// MySQL resolves an unqualified table name against the session's default
    /// database, so leaving it unset is bypass 3 of `docs/security.md` section 5.
    #[error("the DSN names no database; MySQL name resolution needs an explicit one")]
    MissingDatabase,
    /// The pool capacity is not usable.
    #[error("the pool settings are not usable: {source}")]
    PoolSettings {
        /// Which bound was rejected.
        #[from]
        source: PoolSettingsError,
    },
    /// The transport security is not usable for this connection's environment.
    #[error("the TLS settings are not usable: {source}")]
    Tls {
        /// Which rule rejected it.
        #[from]
        source: TlsError,
    },
    /// The execution limits are not usable.
    #[error("the execution limits are not usable: {source}")]
    Limits {
        /// Which bound was rejected.
        #[from]
        source: LimitsError,
    },
    /// The driver could not open or use a connection.
    #[error("the database connection could not be established")]
    Driver {
        /// The driver's own message, for a deliberate diagnostic path only.
        detail: String,
    },
    /// A probe did not answer within its deadline.
    #[error("the connection probe exceeded its deadline")]
    Timeout,
    /// A hardened session setting did not survive to the server.
    ///
    /// `docs/operations.md` section 5.1 names the case: a pooler or proxy between
    /// Warden and the server can discard connection-time settings, and the deployment
    /// then believes it has a server-side deadline it does not have. Both fields are
    /// setting values, never secrets, so `Display` prints them.
    #[error("session setting {setting} is {actual:?} at the server; expected {expected:?}")]
    SessionSettingRejected {
        /// The setting that did not survive.
        setting: &'static str,
        /// What Warden configured.
        expected: String,
        /// What the server reports.
        actual: String,
    },
}

impl ConnectError {
    /// Wraps a driver failure without letting its message reach `Display`.
    pub(crate) fn driver(error: &sqlx::Error) -> Self {
        Self::Driver {
            detail: error.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// Stands in for everything a driver message can carry.
    const LEAKY: &str = "postgres://warden:hunter2@db-01.internal/app";

    #[test]
    fn display_never_repeats_an_internal_detail() {
        let rendered = ConnectError::Driver {
            detail: LEAKY.to_owned(),
        }
        .to_string();
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains("db-01.internal"), "{rendered}");
    }

    #[test]
    fn a_session_setting_failure_names_the_setting_and_both_values() {
        assert_eq!(
            ConnectError::SessionSettingRejected {
                setting: "MAX_EXECUTION_TIME",
                expected: "5000".to_owned(),
                actual: "0".to_owned(),
            }
            .to_string(),
            "session setting MAX_EXECUTION_TIME is \"0\" at the server; expected \"5000\""
        );
    }
}
