//! Every way a configuration can be refused, and nothing a refusal may carry.
//!
//! Deliberately **not** a [`warden_core::error::PublicError`]: these are raised by the
//! composition root before any transport is serving, so none of them crosses the MCP
//! boundary. They are read by an operator on stderr, so they name the field, profile,
//! connection, variable, or path at fault — and never a DSN, a password, or the contents of
//! a secret file (`docs/operations.md` section 3.2).

use std::path::PathBuf;

use warden_core::connection::ConnectionName;

/// Why a configuration cannot be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read. Carries the path and the OS message, never contents.
    ///
    /// Named `message`, not `source`: thiserror treats a field literally named `source`
    /// as this error's `Error::source()` and requires it to implement `std::error::Error`,
    /// which plain OS-message text never does.
    #[error("configuration file {path} could not be read: {message}")]
    Unreadable {
        /// The file Warden tried to read.
        path: PathBuf,
        /// The operating system's own message.
        message: String,
    },
    /// The file is not valid TOML, or carries a field no struct declares.
    #[error("configuration is not valid: {message}")]
    Malformed {
        /// `toml`'s own message, which names the offending key and line.
        message: String,
    },
    /// The `version` key does not name a format this build understands.
    #[error("configuration declares version {found}; this build supports {supported}")]
    UnsupportedVersion {
        /// The version the file declared.
        found: u32,
        /// The version this build supports.
        supported: u32,
    },
    /// A duration was not `<positive integer><ms|s|m>`.
    #[error("duration {value:?} is not a number followed by ms, s, or m")]
    MalformedDuration {
        /// The rejected text. A duration is never a secret.
        value: String,
    },
    /// No connection was configured.
    #[error("no connections are configured")]
    NoConnections,
    /// Two connection entries claimed the same name.
    #[error("connection {name} is configured more than once")]
    DuplicateConnection {
        /// The repeated name.
        name: ConnectionName,
    },
    /// A connection referenced a profile that does not exist.
    #[error("connection {connection} references undefined policy profile {profile:?}")]
    UnknownProfile {
        /// The connection that referenced it.
        connection: ConnectionName,
        /// The profile name that was not defined.
        profile: String,
    },
    /// Two referenced profiles disagree about a rule the process can only hold once.
    ///
    /// ADR-0039: `Services` holds one `PolicyEngine`, so relaxations and object rules are
    /// process-wide. Applying one profile's policy to a connection that asked for another
    /// would be worse than refusing to start.
    #[error(
        "policy profiles {first:?} and {second:?} disagree about {field}; \
         a build with one policy engine cannot honour both (ADR-0039)"
    )]
    ConflictingPolicy {
        /// The first profile, in configuration order.
        first: String,
        /// The profile that disagreed with it.
        second: String,
        /// Which rule differs.
        field: &'static str,
    },
    /// A connection declared neither `dsn_env` nor `dsn_file`, or both.
    #[error("connection {connection} must set exactly one of dsn_env and dsn_file")]
    DsnSourceAmbiguous {
        /// The offending connection.
        connection: ConnectionName,
    },
    /// The named environment variable is unset or not UTF-8.
    #[error("connection {connection}: environment variable {variable} is unset or not UTF-8")]
    DsnVariableMissing {
        /// The offending connection.
        connection: ConnectionName,
        /// The variable name. A name, never its value.
        variable: String,
    },
    /// The DSN file could not be read.
    #[error("connection {connection}: DSN file {path} could not be read: {message}")]
    DsnFileUnreadable {
        /// The offending connection.
        connection: ConnectionName,
        /// The file that could not be read.
        path: PathBuf,
        /// The operating system's own message.
        message: String,
    },
    /// The resolved DSN is not one a connection may use (ADR-0031).
    ///
    /// Carries `DsnError`'s own message, which `warden-core` already writes without echoing
    /// the connection string.
    #[error("connection {connection}: {message}")]
    InvalidDsn {
        /// The offending connection.
        connection: ConnectionName,
        /// `warden_core::secret::DsnError`'s message.
        message: String,
    },
    /// The DSN's dialect is not the dialect the entry declares.
    #[error("connection {connection} declares {declared} but its DSN names {actual}")]
    DialectMismatch {
        /// The offending connection.
        connection: ConnectionName,
        /// What the entry declared.
        declared: warden_core::dialect::Dialect,
        /// What the DSN's scheme named.
        actual: warden_core::dialect::Dialect,
    },
    /// `search_path` was set on a connection whose dialect has none.
    #[error("connection {connection} sets search_path, which only PostgreSQL has")]
    SearchPathOnMySql {
        /// The offending connection.
        connection: ConnectionName,
    },
    /// A limit, pool, or TLS setting was refused by `warden-core`'s own validation.
    ///
    /// Carries the core error's message, which names the field and the bound.
    #[error("connection {connection}: {message}")]
    InvalidSettings {
        /// The offending connection.
        connection: ConnectionName,
        /// The core validator's message.
        message: String,
    },
}
