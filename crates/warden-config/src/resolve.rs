//! Cross-field validation and the shape the composition root can actually build.
//!
//! [`Config::resolve`] applies every startup rule in `docs/operations.md` section 3.2, in
//! the order that puts the cheapest and most operator-visible failures first: at least
//! one connection, a valid audit destination, no duplicate names, every profile defined,
//! every referenced profile agreeing about policy (ADR-0039), exactly one DSN source, the DSN itself, its
//! dialect, `search_path`, and finally the limit, pool, and TLS checks `warden-core`
//! already owns — the same four calls `MySqlConnectionPools::connect` makes, run here so
//! a bad number fails before any network I/O.
//!
//! [`ResolvedConfig`] is what survives: metadata and settings the composition root can
//! hand to an adapter. `Capabilities` are **not** built here — they describe an
//! adapter, and this crate names no adapter (`src/startup.rs` supplies them, Task 8).

use std::path::PathBuf;

use warden_core::audit::AuditMode;
use warden_core::connection::{ConnectionMetadata, ConnectionName, Environment};
use warden_core::dialect::Dialect;
use warden_core::limits::ExecutionLimits;
use warden_core::pool::PoolSettings;
use warden_core::secret::Dsn;
use warden_core::tls::TlsSettings;

use crate::error::ConfigError;
use crate::model::{
    AuditDestinationEntry, AuditEntry, Config, ConnectionEntry, PolicyProfile,
    RedactionStrategyEntry,
};
use crate::secrets::{self, SecretSource};

/// One connection, fully resolved: its DSN read and parsed, and every setting
/// `warden-core` validates already checked.
#[derive(Debug)]
pub struct ResolvedConnection {
    /// The public description an agent may see.
    pub metadata: ConnectionMetadata,
    /// The connection target, still secret.
    pub dsn: Dsn,
    /// The per-request bounds this connection runs under.
    pub limits: ExecutionLimits,
    /// Capacity for agent queries and `EXPLAIN`.
    pub agent_pool: PoolSettings,
    /// Capacity for health checks and schema introspection.
    pub control_pool: PoolSettings,
    /// Transport security.
    pub tls: TlsSettings,
    /// PostgreSQL's `search_path`, in resolution order. Empty on MySQL.
    pub search_path: Vec<String>,
}

/// The policy every connection in this build shares (ADR-0039).
///
/// `Services` holds one `Arc<PolicyEngine>`, so relaxations and object rules are
/// process-wide even though several profiles may be configured. `Config::resolve`
/// already proved every referenced profile agrees on these fields; this is that
/// agreed value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPolicy {
    /// Allow statements that take row locks.
    pub allow_locking_reads: bool,
    /// Allow functions the adapter could not classify.
    pub allow_unknown_functions: bool,
    /// Schemas the connection may touch. Absent restricts no schema.
    pub schemas: Option<Vec<String>>,
    /// Tables the connection may touch, as `name` or `schema.name`.
    pub allow_tables: Option<Vec<String>>,
    /// Tables the connection may never touch. Wins over `allow_tables`.
    pub deny_tables: Vec<String>,
}

/// Audit settings after the destination and path have been validated together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedAudit {
    /// Which safe subset of an attempt record the sink writes.
    pub mode: AuditMode,
    /// Where the sink writes each record.
    pub destination: AuditDestination,
}

/// A validated audit destination the composition root can open directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditDestination {
    /// Write structured audit events through the process's stderr subscriber.
    Stderr,
    /// Append JSON Lines records to this path.
    File(PathBuf),
}

/// What survives `docs/operations.md` section 3.2's startup validation: everything the
/// composition root needs, and nothing it has to re-derive.
#[derive(Debug)]
pub struct ResolvedConfig {
    /// Every configured connection, in file order.
    pub connections: Vec<ResolvedConnection>,
    /// The policy every connection shares (ADR-0039).
    pub policy: ResolvedPolicy,
    /// Deterministic column redaction rules, as plain strings (Decision 7:
    /// `warden-config` emits core types and plain strings, never a policy or service
    /// type).
    pub redaction_columns: Vec<String>,
    /// What a redaction match does.
    pub redaction_strategy: RedactionStrategyEntry,
    /// What the audit sink records and where it writes those records.
    pub audit: ResolvedAudit,
}

impl ResolvedConfig {
    /// Whether any connection targets [`Environment::Production`].
    #[must_use]
    pub fn has_production_connection(&self) -> bool {
        self.connections
            .iter()
            .any(|connection| connection.metadata.environment == Environment::Production)
    }
}

impl Config {
    /// Applies every startup rule in `docs/operations.md` section 3.2 and produces what
    /// the composition root can actually build.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for the first rule this configuration breaks; see the
    /// module documentation for the order they are checked in.
    pub fn resolve(self) -> Result<ResolvedConfig, ConfigError> {
        if self.connections.is_empty() {
            return Err(ConfigError::NoConnections);
        }
        let audit = resolve_audit(self.audit)?;

        let mut seen_names: Vec<ConnectionName> = Vec::with_capacity(self.connections.len());
        for connection in &self.connections {
            if seen_names.contains(&connection.name) {
                return Err(ConfigError::DuplicateConnection {
                    name: connection.name.clone(),
                });
            }
            seen_names.push(connection.name.clone());
        }

        // Resolving each connection's profile is also what proves the name is defined,
        // so this replaces both a `contains_key` pass and the four `Index` lookups the
        // rest of this function used to make. `Index` panics on a miss, and it is the
        // one panic shape `clippy::unwrap_used` and `expect_used` cannot see — which is
        // why `AGENTS.md` bans the others. Every key here is provably present; the
        // point is that the proof is not what keeps startup from panicking.
        let mut resolved: Vec<(&ConnectionEntry, &PolicyProfile)> =
            Vec::with_capacity(self.connections.len());
        for connection in &self.connections {
            let profile = self.policies.get(&connection.policy).ok_or_else(|| {
                ConfigError::UnknownProfile {
                    connection: connection.name.clone(),
                    profile: connection.policy.clone(),
                }
            })?;
            resolved.push((connection, profile));
        }

        // The distinct profiles, in first-reference order, each keeping the name a
        // disagreement message has to quote (ADR-0039).
        let mut referenced: Vec<(&str, &PolicyProfile)> = Vec::new();
        for (connection, profile) in &resolved {
            if !referenced
                .iter()
                .any(|(name, _)| *name == connection.policy)
            {
                referenced.push((connection.policy.as_str(), profile));
            }
        }
        // `self.connections` was proved non-empty at the top, so every connection
        // contributed a profile and `referenced` cannot be empty. Saying so with the
        // error that check already produces costs one arm and no panic.
        let Some(((representative_name, representative), rest)) = referenced.split_first() else {
            return Err(ConfigError::NoConnections);
        };
        for (name, other) in rest {
            agree_on_policy(representative_name, representative, name, other)?;
        }

        let mut connections = Vec::with_capacity(self.connections.len());
        for (connection, profile) in &resolved {
            connections.push(resolve_connection(connection, profile)?);
        }

        let policy = ResolvedPolicy {
            allow_locking_reads: representative.allow_locking_reads,
            allow_unknown_functions: representative.allow_unknown_functions,
            schemas: representative.schemas.clone(),
            allow_tables: representative.allow_tables.clone(),
            deny_tables: representative.deny_tables.clone(),
        };
        Ok(ResolvedConfig {
            connections,
            policy,
            redaction_columns: self.redaction.columns,
            redaction_strategy: self.redaction.strategy,
            audit,
        })
    }
}

/// Validates the two audit destination keys as one setting.
fn resolve_audit(entry: AuditEntry) -> Result<ResolvedAudit, ConfigError> {
    let destination = match (entry.destination, entry.path) {
        (AuditDestinationEntry::Stderr, None) => AuditDestination::Stderr,
        (AuditDestinationEntry::File, Some(path)) => AuditDestination::File(path),
        (AuditDestinationEntry::File, None) => return Err(ConfigError::AuditPathMissing),
        (AuditDestinationEntry::Stderr, Some(_)) => return Err(ConfigError::AuditPathUnused),
    };

    Ok(ResolvedAudit {
        mode: entry.mode,
        destination,
    })
}

/// Checks the five fields `Services`' one `PolicyEngine` cannot hold two answers for.
///
/// Compares the object rule lists exactly as written, without sorting or
/// deduplicating: two spellings of one rule set are still two review surfaces
/// (ADR-0039).
fn agree_on_policy(
    first_name: &str,
    first: &PolicyProfile,
    second_name: &str,
    second: &PolicyProfile,
) -> Result<(), ConfigError> {
    let mismatch = |field: &'static str| ConfigError::ConflictingPolicy {
        first: first_name.to_owned(),
        second: second_name.to_owned(),
        field,
    };
    if first.allow_locking_reads != second.allow_locking_reads {
        return Err(mismatch("allow_locking_reads"));
    }
    if first.allow_unknown_functions != second.allow_unknown_functions {
        return Err(mismatch("allow_unknown_functions"));
    }
    if first.schemas != second.schemas {
        return Err(mismatch("schemas"));
    }
    if first.allow_tables != second.allow_tables {
        return Err(mismatch("allow_tables"));
    }
    if first.deny_tables != second.deny_tables {
        return Err(mismatch("deny_tables"));
    }
    Ok(())
}

/// Resolves one connection: its DSN source, the DSN itself, its dialect,
/// `search_path`, and the limit, pool, and TLS checks `warden-core` owns.
fn resolve_connection(
    connection: &ConnectionEntry,
    profile: &PolicyProfile,
) -> Result<ResolvedConnection, ConfigError> {
    let source = match (&connection.dsn_env, &connection.dsn_file) {
        (Some(variable), None) => SecretSource::Environment(variable.clone()),
        (None, Some(path)) => SecretSource::File(path.clone()),
        _ => {
            return Err(ConfigError::DsnSourceAmbiguous {
                connection: connection.name.clone(),
            });
        }
    };
    let dsn = secrets::resolve(&connection.name, &source)?;

    if dsn.dialect() != connection.dialect {
        return Err(ConfigError::DialectMismatch {
            connection: connection.name.clone(),
            declared: connection.dialect,
            actual: dsn.dialect(),
        });
    }

    if !connection.search_path.is_empty() && connection.dialect != Dialect::PostgreSql {
        return Err(ConfigError::SearchPathOnMySql {
            connection: connection.name.clone(),
        });
    }

    let invalid_settings = |message: String| ConfigError::InvalidSettings {
        connection: connection.name.clone(),
        message,
    };

    let limits = ExecutionLimits {
        timeout: profile.query_timeout.get(),
        max_queue_wait: profile.max_queue_wait.get(),
        max_rows: profile.max_rows,
        max_value_bytes: profile.max_value_bytes,
        max_result_bytes: profile.max_result_bytes,
        max_concurrent_queries: profile.max_concurrent_queries,
    };
    limits
        .validate()
        .map_err(|error| invalid_settings(error.to_string()))?;

    let agent_pool = PoolSettings {
        max_connections: profile.agent_pool.max_connections,
        min_connections: profile.agent_pool.min_connections,
        acquire_timeout: profile.agent_pool.acquire_timeout.get(),
        idle_timeout: profile
            .agent_pool
            .idle_timeout
            .map(|duration| duration.get()),
        max_lifetime: profile
            .agent_pool
            .max_lifetime
            .map(|duration| duration.get()),
    };
    agent_pool
        .validate_concurrency(&limits)
        .map_err(|error| invalid_settings(error.to_string()))?;

    let control_pool = PoolSettings {
        max_connections: profile.control_pool.max_connections,
        min_connections: profile.control_pool.min_connections,
        acquire_timeout: profile.control_pool.acquire_timeout.get(),
        idle_timeout: profile
            .control_pool
            .idle_timeout
            .map(|duration| duration.get()),
        max_lifetime: profile
            .control_pool
            .max_lifetime
            .map(|duration| duration.get()),
    };
    control_pool
        .validate()
        .map_err(|error| invalid_settings(error.to_string()))?;

    let tls = TlsSettings {
        mode: connection.tls.mode,
        root_certificate: connection.tls.root_certificate.clone(),
    };
    tls.validate(&connection.environment)
        .map_err(|error| invalid_settings(error.to_string()))?;

    let metadata = ConnectionMetadata {
        name: connection.name.clone(),
        dialect: connection.dialect,
        environment: connection.environment.clone(),
        database: connection.database.clone(),
    };

    Ok(ResolvedConnection {
        metadata,
        dsn,
        limits,
        agent_pool,
        control_pool,
        tls,
        search_path: connection.search_path.clone(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    /// A uniquely named directory under the OS temp directory, removed on drop.
    ///
    /// Built from the process id and an atomic counter rather than a new dependency, so
    /// parallel test binaries and repeated test functions in this one never collide.
    /// The `Drop` is the point: without it every `cargo test -p warden-config` left
    /// directories behind, which the two helpers this replaces both did.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
            let directory = std::env::temp_dir().join(format!(
                "warden-config-{label}-{}-{unique}",
                std::process::id()
            ));
            std::fs::create_dir_all(&directory).unwrap();
            Self(directory)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ignored = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Parses a TOML literal after substituting `{MYSQL_DSN}` and `{POSTGRES_DSN}` for
    /// the paths of two files this helper writes, so no test needs an environment
    /// variable.
    /// A parsed configuration and the directory holding the DSN files it points at.
    ///
    /// The directory is returned rather than dropped here: `Config::resolve` reads
    /// those files, so they have to outlive this call. They used to survive only
    /// because the helper leaked its directory into `/tmp` on every run.
    fn config_with(template: &str) -> (Config, TempDir) {
        let directory = TempDir::new("resolve");
        let mysql_path = directory.join("mysql-dsn");
        let postgres_path = directory.join("postgres-dsn");
        std::fs::write(&mysql_path, "mysql://warden_ro:pw@db.internal:3306/app").unwrap();
        std::fs::write(
            &postgres_path,
            "postgres://warden_ro:pw@db.internal:5432/analytics",
        )
        .unwrap();
        let text = template
            .replace("{MYSQL_DSN}", &mysql_path.display().to_string())
            .replace("{POSTGRES_DSN}", &postgres_path.display().to_string());
        (Config::from_toml_str(&text).unwrap(), directory)
    }

    /// Resolves an audit-focused literal with one otherwise valid connection.
    fn load(template: &str) -> Result<ResolvedConfig, ConfigError> {
        let complete = format!(
            "{template}\n\
             [[connections]]\n\
             name = \"db\"\n\
             dialect = \"mysql\"\n\
             environment = \"development\"\n\
             database = \"app\"\n\
             dsn_file = \"{{MYSQL_DSN}}\"\n\
             policy = \"p\"\n\
             [policies.p]\n"
        );
        config_with(&complete).0.resolve()
    }

    const PROFILES_AGREE: &str = r#"
version = 1

[[connections]]
name = "production-mysql"
dialect = "mysql"
environment = "production"
database = "app"
dsn_file = "{MYSQL_DSN}"
policy = "production"

[[connections]]
name = "production-postgres"
dialect = "postgresql"
environment = "production"
database = "analytics"
dsn_file = "{POSTGRES_DSN}"
policy = "production"
search_path = ["app", "public"]

[policies.production]
query_timeout = "5s"
max_queue_wait = "2s"
max_rows = 200
max_value_bytes = 65536
max_result_bytes = 262144
max_concurrent_queries = 3
allow_locking_reads = false
allow_unknown_functions = false
deny_tables = ["app.audit_log"]

[policies.production.agent_pool]
max_connections = 5
min_connections = 0
acquire_timeout = "3s"

[policies.production.control_pool]
max_connections = 2
min_connections = 1
acquire_timeout = "3s"
"#;

    const PROFILES_DISAGREE: &str = r#"
version = 1

[[connections]]
name = "production-mysql"
dialect = "mysql"
environment = "production"
database = "app"
dsn_file = "{MYSQL_DSN}"
policy = "production"

[[connections]]
name = "production-postgres"
dialect = "postgresql"
environment = "production"
database = "analytics"
dsn_file = "{POSTGRES_DSN}"
policy = "relaxed"

[policies.production]
allow_locking_reads = false
allow_unknown_functions = false

[policies.relaxed]
allow_locking_reads = false
allow_unknown_functions = true
"#;

    const PROFILES_DIFFER_IN_CAPACITY: &str = r#"
version = 1

[[connections]]
name = "production-mysql"
dialect = "mysql"
environment = "production"
database = "app"
dsn_file = "{MYSQL_DSN}"
policy = "small"

[[connections]]
name = "production-postgres"
dialect = "postgresql"
environment = "production"
database = "analytics"
dsn_file = "{POSTGRES_DSN}"
policy = "large"

[policies.small]
max_rows = 50

[policies.large]
max_rows = 500
"#;

    const NO_CONNECTIONS: &str = "version = 1\n";

    const DUPLICATE_NAME: &str = r#"
version = 1

[[connections]]
name = "db"
dialect = "mysql"
environment = "production"
database = "app"
dsn_file = "{MYSQL_DSN}"
policy = "p"

[[connections]]
name = "db"
dialect = "mysql"
environment = "production"
database = "app"
dsn_file = "{MYSQL_DSN}"
policy = "p"

[policies.p]
"#;

    const UNKNOWN_PROFILE: &str = r#"
version = 1

[[connections]]
name = "db"
dialect = "mysql"
environment = "production"
database = "app"
dsn_file = "{MYSQL_DSN}"
policy = "missing"
"#;

    const BOTH_DSN_SOURCES: &str = r#"
version = 1

[[connections]]
name = "db"
dialect = "mysql"
environment = "production"
database = "app"
dsn_env = "SOME_VAR"
dsn_file = "{MYSQL_DSN}"
policy = "p"

[policies.p]
"#;

    const NEITHER_DSN_SOURCE: &str = r#"
version = 1

[[connections]]
name = "db"
dialect = "mysql"
environment = "production"
database = "app"
policy = "p"

[policies.p]
"#;

    const MYSQL_WITH_SEARCH_PATH: &str = r#"
version = 1

[[connections]]
name = "db"
dialect = "mysql"
environment = "production"
database = "app"
dsn_file = "{MYSQL_DSN}"
policy = "p"
search_path = ["app"]

[policies.p]
"#;

    const ZERO_MAX_ROWS: &str = r#"
version = 1

[[connections]]
name = "db"
dialect = "mysql"
environment = "production"
database = "app"
dsn_file = "{MYSQL_DSN}"
policy = "p"

[policies.p]
max_rows = 0
"#;

    const POOL_BELOW_CONCURRENCY: &str = r#"
version = 1

[[connections]]
name = "db"
dialect = "mysql"
environment = "production"
database = "app"
dsn_file = "{MYSQL_DSN}"
policy = "p"

[policies.p]
max_concurrent_queries = 5

[policies.p.agent_pool]
max_connections = 1
"#;

    // The connection name deliberately embeds "tls": `InvalidSettings`'s own message
    // renders as "connections in the production environment must use TLS", uppercase,
    // and this test table asserts on the lowercase substring the rest of this list
    // uses, which the name supplies.
    const CLEARTEXT_IN_PRODUCTION: &str = r#"
version = 1

[[connections]]
name = "cleartext-tls"
dialect = "mysql"
environment = "production"
database = "app"
dsn_file = "{MYSQL_DSN}"
policy = "p"
tls = { mode = "disabled" }

[policies.p]
"#;

    const POSTGRES_DSN_ON_MYSQL_ENTRY: &str = r#"
version = 1

[[connections]]
name = "db"
dialect = "mysql"
environment = "production"
database = "app"
dsn_file = "{POSTGRES_DSN}"
policy = "p"

[policies.p]
"#;

    #[test]
    fn a_valid_deployment_resolves_into_what_the_composition_root_needs() {
        let resolved = config_with(PROFILES_AGREE).0.resolve().unwrap();
        assert_eq!(resolved.connections.len(), 2);
        assert_eq!(resolved.connections[0].metadata.database, "app");
        assert_eq!(resolved.connections[0].limits.max_rows, 200);
        assert_eq!(resolved.connections[1].search_path, ["app", "public"]);
        assert!(!resolved.policy.allow_locking_reads);
        assert!(resolved.has_production_connection());
    }

    #[test]
    fn a_file_destination_needs_a_path_and_a_stderr_one_refuses_it() {
        let missing = load(
            r#"
                version = 1
                [audit]
                destination = "file"
            "#,
        );
        assert!(matches!(
            missing.unwrap_err(),
            ConfigError::AuditPathMissing
        ));

        let extra = load(
            r#"
                version = 1
                [audit]
                destination = "stderr"
                path = "/var/log/warden/audit.jsonl"
            "#,
        );
        assert!(matches!(extra.unwrap_err(), ConfigError::AuditPathUnused));
    }

    #[test]
    fn the_default_destination_is_stderr_in_fingerprint_mode() {
        let resolved = load("version = 1").unwrap();
        assert_eq!(resolved.audit.mode, AuditMode::Fingerprint);
        assert_eq!(resolved.audit.destination, AuditDestination::Stderr);
    }

    #[test]
    fn two_profiles_that_disagree_about_policy_refuse_to_start() {
        // ADR-0039: one PolicyEngine cannot honour two policies, and quietly applying one
        // of them to a connection that asked for the other is the worst option available.
        let error = config_with(PROFILES_DISAGREE).0.resolve().unwrap_err();
        assert_eq!(
            error,
            ConfigError::ConflictingPolicy {
                first: "production".to_owned(),
                second: "relaxed".to_owned(),
                field: "allow_unknown_functions",
            }
        );
    }

    #[test]
    fn two_profiles_may_differ_in_capacity() {
        let resolved = config_with(PROFILES_DIFFER_IN_CAPACITY)
            .0
            .resolve()
            .unwrap();
        assert_ne!(
            resolved.connections[0].limits.max_rows,
            resolved.connections[1].limits.max_rows
        );
    }

    #[test]
    fn every_startup_rule_from_operations_section_3_2_is_enforced() {
        for (toml, expected) in [
            (NO_CONNECTIONS, "no connections"),
            (DUPLICATE_NAME, "more than once"),
            (UNKNOWN_PROFILE, "undefined policy profile"),
            (BOTH_DSN_SOURCES, "exactly one of dsn_env and dsn_file"),
            (NEITHER_DSN_SOURCE, "exactly one of dsn_env and dsn_file"),
            (MYSQL_WITH_SEARCH_PATH, "only PostgreSQL has"),
            (ZERO_MAX_ROWS, "max_rows"),
            (POOL_BELOW_CONCURRENCY, "max_connections"),
            (CLEARTEXT_IN_PRODUCTION, "tls"),
        ] {
            let error = config_with(toml).0.resolve().unwrap_err().to_string();
            assert!(error.contains(expected), "{toml}\n-> {error}");
        }
    }

    #[test]
    fn a_dsn_whose_scheme_contradicts_the_declared_dialect_is_refused() {
        let error = config_with(POSTGRES_DSN_ON_MYSQL_ENTRY)
            .0
            .resolve()
            .unwrap_err();
        assert!(
            matches!(error, ConfigError::DialectMismatch { .. }),
            "{error}"
        );
    }
}
