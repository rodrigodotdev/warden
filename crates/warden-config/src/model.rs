//! The configuration exactly as an operator writes it.
//!
//! Every struct carries `#[serde(deny_unknown_fields)]`. Without it, a misspelled
//! `allow_locking_read` is silently ignored, the default applies, and the operator believes
//! the deployment is hardened when it is not (`docs/operations.md` section 3.1). The
//! mechanical guard in `tests/config_rules.rs` fails the build if a struct here loses the
//! attribute.
//!
//! Fields that mirror a `warden-core` bound default to that bound's own constant rather than
//! to a number written twice: `ExecutionLimits::default()` and `PoolSettings::agent()` are
//! the documented production values (`docs/data-model.md` section 7,
//! `docs/operations.md` section 4), and a second copy here would drift.
//!
//! The two settings ADR-0025 owns — `statement_cache_capacity` and `persistent_statements` —
//! are deliberately absent. They are invariants the adapters apply, and an invariant has no
//! configuration key (ADR-0026), so `deny_unknown_fields` refuses them.

use std::collections::BTreeMap;
use std::path::PathBuf;

use warden_core::connection::{ConnectionName, Environment};
use warden_core::dialect::Dialect;
use warden_core::limits::ExecutionLimits;
use warden_core::pool::PoolSettings;
use warden_core::tls::TlsMode;

use crate::duration::HumanDuration;
use crate::error::ConfigError;

/// The only configuration format version this build understands.
///
/// The format is versioned from the beginning (SPEC section 10), and the check runs before
/// any other field is interpreted so a future format fails with one clear sentence rather
/// than a pile of unknown-field errors.
pub const SUPPORTED_VERSION: u32 = 1;

/// A whole configuration file.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The configuration format version. Must equal [`SUPPORTED_VERSION`].
    pub version: u32,
    /// Every configured connection, in file order.
    #[serde(default)]
    pub connections: Vec<ConnectionEntry>,
    /// Named policy profiles, referenced by `ConnectionEntry::policy`.
    #[serde(default)]
    pub policies: BTreeMap<String, PolicyProfile>,
    /// Deterministic column redaction.
    #[serde(default)]
    pub redaction: RedactionEntry,
    /// What the audit sink records.
    #[serde(default)]
    pub audit: AuditEntry,
}

impl Config {
    /// Parses TOML text, checking the version before anything else.
    ///
    /// # Errors
    ///
    /// [`ConfigError::UnsupportedVersion`] for a version this build does not implement, and
    /// [`ConfigError::Malformed`] for anything `toml` refuses, including a field no struct
    /// declares.
    pub fn from_toml_str(text: &str) -> Result<Self, ConfigError> {
        #[derive(serde::Deserialize)]
        struct VersionOnly {
            version: u32,
        }

        // Two passes so an old or new format reports its version rather than every field it
        // does not share with this one.
        let probe: VersionOnly = toml::from_str(text).map_err(|error| ConfigError::Malformed {
            message: error.to_string(),
        })?;
        if probe.version != SUPPORTED_VERSION {
            return Err(ConfigError::UnsupportedVersion {
                found: probe.version,
                supported: SUPPORTED_VERSION,
            });
        }
        toml::from_str(text).map_err(|error| ConfigError::Malformed {
            message: error.to_string(),
        })
    }
}

/// One named connection.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionEntry {
    /// The name an agent passes to every tool.
    pub name: ConnectionName,
    /// Which adapter serves it.
    pub dialect: Dialect,
    /// The deployment environment, which decides whether cleartext TLS is legal.
    pub environment: Environment,
    /// The default database or catalog, for the agent's orientation.
    pub database: String,
    /// The environment variable holding the DSN.
    #[serde(default)]
    pub dsn_env: Option<String>,
    /// The file holding the DSN. Docker and Kubernetes mount secrets as files, and
    /// forcing environment variables pushes operators toward the worse pattern
    /// (`docs/operations.md` section 3.1).
    #[serde(default)]
    pub dsn_file: Option<PathBuf>,
    /// Which profile in `policies` this connection uses.
    pub policy: String,
    /// PostgreSQL's `search_path`, in resolution order. Empty on MySQL.
    #[serde(default)]
    pub search_path: Vec<String>,
    /// Transport security.
    #[serde(default)]
    pub tls: TlsEntry,
}

/// One connection's transport security.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsEntry {
    /// What the driver must prove. Defaults to the strictest mode (ADR-0030).
    #[serde(default = "default_tls_mode")]
    pub mode: TlsMode,
    /// A private certificate authority, for a server whose chain reaches no public root.
    #[serde(default)]
    pub root_certificate: Option<PathBuf>,
}

impl Default for TlsEntry {
    fn default() -> Self {
        Self {
            mode: default_tls_mode(),
            root_certificate: None,
        }
    }
}

fn default_tls_mode() -> TlsMode {
    TlsMode::VerifyIdentity
}

/// One named policy profile.
///
/// It carries both halves an operator thinks of together: the per-connection capacity
/// (limits and pools) and the process-wide policy (relaxations and object rules). ADR-0039
/// explains why only the first half may differ between profiles in this build.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyProfile {
    /// The query deadline.
    #[serde(default = "default_query_timeout")]
    pub query_timeout: HumanDuration,
    /// The longest wait for a concurrency permit before `server_busy`.
    #[serde(default = "default_max_queue_wait")]
    pub max_queue_wait: HumanDuration,
    /// The largest number of rows returned.
    #[serde(default = "default_max_rows")]
    pub max_rows: usize,
    /// The largest normalized size of a single value.
    #[serde(default = "default_max_value_bytes")]
    pub max_value_bytes: usize,
    /// The largest normalized size of a whole result.
    #[serde(default = "default_max_result_bytes")]
    pub max_result_bytes: usize,
    /// The largest number of concurrent queries on one connection.
    #[serde(default = "default_max_concurrent_queries")]
    pub max_concurrent_queries: usize,
    /// Allow statements that take row locks (SPEC section 6, invariant 6 relaxation).
    #[serde(default)]
    pub allow_locking_reads: bool,
    /// Allow functions the adapter could not classify (ADR-0011 relaxation).
    #[serde(default)]
    pub allow_unknown_functions: bool,
    /// Schemas the connection may touch. Absent restricts no schema.
    #[serde(default)]
    pub schemas: Option<Vec<String>>,
    /// Tables the connection may touch, as `name` or `schema.name`.
    #[serde(default)]
    pub allow_tables: Option<Vec<String>>,
    /// Tables the connection may never touch. Wins over `allow_tables`.
    #[serde(default)]
    pub deny_tables: Vec<String>,
    /// Capacity for agent queries and `EXPLAIN`.
    #[serde(default)]
    pub agent_pool: PoolProfile,
    /// Capacity for health checks and schema introspection.
    #[serde(default = "default_control_pool")]
    pub control_pool: PoolProfile,
}

/// One pool's capacity.
///
/// `Default` is the **agent** pool's, because that is the pool an operator who writes
/// nothing is most likely thinking about; `PoolProfile::control_defaults` supplies the other
/// set, and `PolicyProfile::control_pool`'s own default uses it.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolProfile {
    /// Largest number of connections the pool opens.
    #[serde(default = "default_agent_max_connections")]
    pub max_connections: u32,
    /// Number of connections the pool keeps open when idle.
    #[serde(default = "default_agent_min_connections")]
    pub min_connections: u32,
    /// Longest wait for a connection before the driver reports a pool timeout.
    #[serde(default = "default_acquire_timeout")]
    pub acquire_timeout: HumanDuration,
    /// How long an idle connection is kept. Absent keeps the core default.
    #[serde(default)]
    pub idle_timeout: Option<HumanDuration>,
    /// How long any connection is reused. Absent keeps the core default.
    #[serde(default)]
    pub max_lifetime: Option<HumanDuration>,
}

impl Default for PoolProfile {
    fn default() -> Self {
        let agent = PoolSettings::agent();
        Self {
            max_connections: agent.max_connections,
            min_connections: agent.min_connections,
            acquire_timeout: HumanDuration::from_duration(agent.acquire_timeout),
            idle_timeout: agent.idle_timeout.map(HumanDuration::from_duration),
            max_lifetime: agent.max_lifetime.map(HumanDuration::from_duration),
        }
    }
}

impl PoolProfile {
    /// The control pool's own defaults, used where an operator writes no `control_pool`.
    #[must_use]
    pub fn control_defaults() -> Self {
        let control = PoolSettings::control();
        Self {
            max_connections: control.max_connections,
            min_connections: control.min_connections,
            acquire_timeout: HumanDuration::from_duration(control.acquire_timeout),
            idle_timeout: control.idle_timeout.map(HumanDuration::from_duration),
            max_lifetime: control.max_lifetime.map(HumanDuration::from_duration),
        }
    }
}

fn default_control_pool() -> PoolProfile {
    PoolProfile::control_defaults()
}

fn default_query_timeout() -> HumanDuration {
    HumanDuration::from_duration(ExecutionLimits::default().timeout)
}

fn default_max_queue_wait() -> HumanDuration {
    HumanDuration::from_duration(ExecutionLimits::default().max_queue_wait)
}

fn default_max_rows() -> usize {
    ExecutionLimits::default().max_rows
}

fn default_max_value_bytes() -> usize {
    ExecutionLimits::default().max_value_bytes
}

fn default_max_result_bytes() -> usize {
    ExecutionLimits::default().max_result_bytes
}

fn default_max_concurrent_queries() -> usize {
    ExecutionLimits::default().max_concurrent_queries
}

fn default_agent_max_connections() -> u32 {
    PoolSettings::agent().max_connections
}

fn default_agent_min_connections() -> u32 {
    PoolSettings::agent().min_connections
}

fn default_acquire_timeout() -> HumanDuration {
    HumanDuration::from_duration(PoolSettings::agent().acquire_timeout)
}

/// Deterministic column redaction, exactly as an operator writes it.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactionEntry {
    /// Rules of the form `table.column` or `*.column`.
    #[serde(default)]
    pub columns: Vec<String>,
    /// What a match does.
    #[serde(default)]
    pub strategy: RedactionStrategyEntry,
}

/// What a redaction match does.
///
/// Mirrors `warden_service::RedactionStrategy` without depending on it (Decision 7): this
/// crate emits plain data, and `src/startup.rs` maps this into the service type.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionStrategyEntry {
    /// Replace the value with a fixed marker, so the agent can see a value existed.
    #[default]
    Replace,
    /// Drop the value, so the response carries no trace of it.
    Null,
}

/// What the audit sink records.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEntry {
    /// The audit mode.
    #[serde(default)]
    pub mode: AuditMode,
}

/// What the audit sink records.
///
/// M12 has only a tracing sink (`src/audit.rs`) that writes structured events to stderr;
/// M13 gives the mode its full meaning against a persistent sink.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditMode {
    /// Record a fingerprint of the statement, never its literal values.
    #[default]
    Fingerprint,
    /// Record nothing beyond that a request happened.
    #[serde(rename = "none")]
    None_,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::time::Duration;

    use super::*;

    const EXAMPLE: &str = include_str!("../tests/fixtures/example.toml");

    #[test]
    fn the_documented_example_parses_into_the_documented_shape() {
        let config = Config::from_toml_str(EXAMPLE).unwrap();
        assert_eq!(config.version, SUPPORTED_VERSION);
        assert_eq!(config.connections.len(), 2);
        assert_eq!(config.connections[0].dialect, Dialect::MySql);
        assert_eq!(
            config.connections[0].dsn_env.as_deref(),
            Some("WARDEN_PRODUCTION_MYSQL_DSN")
        );
        assert_eq!(config.connections[1].search_path, ["app", "public"]);
        let profile = config.policies.get("production").unwrap();
        assert_eq!(profile.query_timeout.get(), Duration::from_secs(5));
        assert_eq!(profile.max_rows, 200);
        assert!(!profile.allow_locking_reads);
        assert_eq!(profile.deny_tables, ["app.audit_log"]);
        assert_eq!(profile.agent_pool.max_connections, 5);
        assert_eq!(config.redaction.columns.len(), 5);
        assert_eq!(config.audit.mode, AuditMode::Fingerprint);
    }

    #[test]
    fn a_misspelled_field_fails_and_names_itself() {
        // docs/operations.md section 3.1: without deny_unknown_fields, a misspelled
        // `allow_locking_read` silently keeps the default and the operator believes
        // the deployment is hardened when it is not.
        let error = Config::from_toml_str(
            "version = 1\n\
             [[connections]]\n\
             name = \"db\"\ndialect = \"mysql\"\nenvironment = \"development\"\n\
             database = \"app\"\ndsn_env = \"D\"\npolicy = \"p\"\n\
             [policies.p]\nallow_locking_read = true\n",
        )
        .unwrap_err();
        assert!(error.to_string().contains("allow_locking_read"), "{error}");
    }

    #[test]
    fn an_adapter_owned_pool_setting_is_not_a_configuration_key() {
        // ADR-0025 fixes both values and ADR-0026 says an invariant has no key.
        for key in [
            "statement_cache_capacity = 0",
            "persistent_statements = false",
        ] {
            let toml = format!(
                "version = 1\n[[connections]]\nname = \"db\"\ndialect = \"mysql\"\n\
                 environment = \"development\"\ndatabase = \"app\"\ndsn_env = \"D\"\n\
                 policy = \"p\"\n[policies.p]\n[policies.p.agent_pool]\n{key}\n"
            );
            assert!(Config::from_toml_str(&toml).is_err(), "{key} was accepted");
        }
    }

    #[test]
    fn an_unsupported_version_is_refused_before_anything_else() {
        let error = Config::from_toml_str("version = 2\n").unwrap_err();
        assert_eq!(
            error,
            ConfigError::UnsupportedVersion {
                found: 2,
                supported: SUPPORTED_VERSION
            }
        );
    }

    #[test]
    fn a_profile_omitting_every_optional_field_takes_the_hardened_defaults() {
        let config = Config::from_toml_str(
            "version = 1\n[[connections]]\nname = \"db\"\ndialect = \"mysql\"\n\
             environment = \"development\"\ndatabase = \"app\"\ndsn_env = \"D\"\n\
             policy = \"p\"\n[policies.p]\n",
        )
        .unwrap();
        let profile = config.policies.get("p").unwrap();
        assert!(!profile.allow_locking_reads);
        assert!(!profile.allow_unknown_functions);
        assert_eq!(profile.max_rows, ExecutionLimits::default().max_rows);
        assert_eq!(
            profile.agent_pool.max_connections,
            PoolSettings::agent().max_connections
        );
        assert_eq!(config.connections[0].tls.mode, TlsMode::VerifyIdentity);
    }
}
