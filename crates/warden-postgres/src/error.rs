//! Why a PostgreSQL connection could not be built or proved healthy.
//!
//! These errors occur before serving begins or in operator-facing probes. Driver
//! details are retained only for an explicit diagnostic path and never render.

use warden_core::dialect::Dialect;
use warden_core::limits::LimitsError;
use warden_core::pool::PoolSettingsError;
use warden_core::tls::TlsError;

/// Why a PostgreSQL connection is unusable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConnectError {
    /// The DSN's scheme names a different engine than this adapter speaks.
    #[error("this adapter is postgresql but the DSN names {actual}")]
    DialectMismatch {
        /// The dialect the DSN's scheme named.
        actual: Dialect,
    },
    /// The environment would still influence the connection.
    ///
    /// `PgConnectOptions` reads its host, credentials and TLS material from `PG*`
    /// variables and offers no way to clear the certificate fields once a
    /// constructor has filled them in. A connection whose trust anchor or password
    /// came from the environment is one Warden's configuration does not describe, so
    /// startup refuses it and names the variable (ADR-0031). The name is a fixed
    /// string from `options::AMBIENT_VARIABLES`; the value is never read.
    #[error(
        "the environment variable {variable} would influence this connection; \
         Warden's configuration is the only source, so unset it"
    )]
    AmbientConnectionInput {
        /// The variable that must be unset.
        variable: &'static str,
    },
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
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;
    const LEAKY: &str = "postgres://warden:hunter2@db-02.internal/analytics";

    #[test]
    fn display_never_repeats_an_internal_detail() {
        let rendered = ConnectError::Driver {
            detail: LEAKY.to_owned(),
        }
        .to_string();
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains("db-02.internal"), "{rendered}");
    }

    #[test]
    fn a_session_setting_failure_names_the_setting_and_both_values() {
        assert_eq!(
            ConnectError::SessionSettingRejected {
                setting: "default_transaction_read_only",
                expected: "on".to_owned(),
                actual: "off".to_owned(),
            }
            .to_string(),
            "session setting default_transaction_read_only is \"off\" at the server; expected \"on\""
        );
    }
}
