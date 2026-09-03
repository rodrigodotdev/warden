//! Assembling a resolved configuration into running services.
//!
//! This module walks `docs/architecture.md` section 12 in order, and is the only place in
//! the workspace that names an adapter and the MCP layer at the same time:
//!
//! ```text
//! install tracing subscriber   (main)
//!     ↓ load configuration     (main, warden-config)
//!     ↓ validate configuration (warden-config)
//!     ↓ resolve secrets        (warden-config)
//!     ↓ create audit sink      ← here
//!     ↓ build MySQL connections (agent_pool + control_pool)
//!     ↓ build PostgreSQL connections
//!     ↓ build ConnectionRegistry
//!     ↓ build PolicyEngine
//!     ↓ build application services
//!     ↓ build MCP adapter      (main)
//!     ↓ serve selected transport (main)
//! ```
//!
//! # Why the mapping lives here
//!
//! `warden-config` emits core types and plain strings and depends on neither
//! `warden-policy` nor `warden-service` (`docs/architecture.md` section 3), so something
//! has to turn a resolved profile into [`PolicySettings`] and
//! [`RedactionSettings`]. Doing it in the composition root is what a composition root is
//! for: [`policy_settings`] and [`redaction_settings`] are that translation, and they are
//! the only place a configuration word becomes a policy word.
//!
//! # Errors are operator-facing
//!
//! Failures here use `anyhow`, which `AGENTS.md` permits in `main`, startup composition,
//! and CLI diagnostics and nowhere else. Every context line names the connection and
//! never the DSN: an operator needs to know *which* connection refused to open.
//!
//! The adapter errors underneath never **display** a host, user, or password, and that
//! is the whole of the guarantee. `ConnectError::Driver` retains `sqlx::Error`'s own
//! text — which routinely names a host and a database user — in a private `detail` field
//! that its `Display` deliberately omits and only `Debug` reveals. `anyhow` renders a
//! source chain through `Display`, so the paths here are safe; a startup diagnostic that
//! reached for `tracing::error!(?error, …)` instead would print the detail. Render these
//! errors through `Display`.

use std::sync::Arc;

use anyhow::{Context as _, Result};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use warden_config::{RedactionStrategyEntry, ResolvedConfig, ResolvedConnection, ResolvedPolicy};
use warden_core::connection::{Capabilities, ConnectionName};
use warden_core::dialect::Dialect;
use warden_mcp::WardenServer;
use warden_mysql::{
    MySqlAnalyzer, MySqlConnectionConfig, MySqlConnectionPools, MySqlExplainer, MySqlQueryExecutor,
    MySqlSchemaInspector,
};
use warden_policy::{ObjectRules, PolicyEngine, PolicySettings, Relaxations};
use warden_ports::{AuditSink, ConnectionRegistry, ConnectionRuntime, ConnectionRuntimeParts};
use warden_postgres::{
    PostgreSqlAnalyzer, PostgreSqlConnectionConfig, PostgreSqlConnectionPools, PostgreSqlExplainer,
    PostgreSqlQueryExecutor, PostgreSqlSchemaInspector, SearchPath,
};
use warden_service::{
    MAX_ADAPTER_CLEANUP, RedactionSettings, RedactionStrategy, ServiceParts, Services,
    StaticConnectionRegistry,
};

use crate::audit::TracingAuditSink;

/// One running Warden: its services, the pools behind them, and the token that stops both.
///
/// The pools are kept beside the services rather than only inside the adapters because
/// shutdown has to close them and `warden check` has to probe them
/// (`docs/architecture.md` section 13, `docs/operations.md` section 11), and a
/// `ConnectionRuntime` deliberately exposes neither.
#[derive(Debug)]
pub(crate) struct Deployment {
    services: Arc<Services>,
    pools: Vec<PoolHandle>,
    shutdown: CancellationToken,
}

impl Deployment {
    /// Builds the MCP adapter over these services.
    ///
    /// Takes `&self` and returns a fresh server: the transport owns the
    /// [`WardenServer`], the deployment owns everything under it, and only the latter
    /// knows how to shut down.
    pub(crate) fn server(&self) -> WardenServer {
        WardenServer::new(Arc::clone(&self.services))
    }

    /// Every connection's pools, in configuration order.
    pub(crate) fn pools(&self) -> &[PoolHandle] {
        &self.pools
    }

    /// Signals cancellation and then closes every pool, bounded.
    ///
    /// `docs/architecture.md` section 13 in order: stop in-flight operations by
    /// cancelling the root token every service child descends from, then close the
    /// pools, and never wait indefinitely. The bound is
    /// [`MAX_ADAPTER_CLEANUP`], the same figure `warden-service` budgets for an
    /// adapter's post-query cleanup, because that is what a draining pool is waiting on.
    pub(crate) async fn close(self) {
        self.shutdown.cancel();
        for pool in &self.pools {
            if tokio::time::timeout(MAX_ADAPTER_CLEANUP, pool.close())
                .await
                .is_err()
            {
                tracing::warn!(
                    target: "warden.startup",
                    connection = %pool.name(),
                    "the connection pool did not drain within the cleanup budget"
                );
            }
        }
    }
}

/// One connection's pools, with the dialect resolved once at startup.
///
/// An enum rather than a trait object: the two adapters share no pool trait, and
/// inventing one so the composition root could avoid a two-armed match would put a
/// driver-shaped abstraction into `warden-ports`, where `docs/architecture.md`
/// section 3 does not want one.
#[derive(Debug)]
pub(crate) enum PoolHandle {
    /// A MySQL connection's agent and control pools.
    MySql {
        /// The connection these pools belong to.
        name: ConnectionName,
        /// The pools themselves, shared with the four adapter ports.
        pools: Arc<MySqlConnectionPools>,
    },
    /// A PostgreSQL connection's agent and control pools.
    PostgreSql {
        /// The connection these pools belong to.
        name: ConnectionName,
        /// The pools themselves, shared with the four adapter ports.
        pools: Arc<PostgreSqlConnectionPools>,
    },
}

impl PoolHandle {
    /// The connection these pools belong to.
    pub(crate) fn name(&self) -> &ConnectionName {
        match self {
            Self::MySql { name, .. } | Self::PostgreSql { name, .. } => name,
        }
    }

    /// Confirms the database answers, on the control pool.
    ///
    /// # Errors
    ///
    /// Returns an operator-facing error naming the connection, caused by the adapter's
    /// own connect error — which never *displays* a host, user, or password. See the
    /// module header before rendering one any way but through `Display`.
    pub(crate) async fn health_check(&self, deadline: Instant) -> Result<()> {
        match self {
            Self::MySql { name, pools } => pools
                .health_check(deadline)
                .await
                .with_context(|| format!("connection {name} did not answer a health check")),
            Self::PostgreSql { name, pools } => pools
                .health_check(deadline)
                .await
                .with_context(|| format!("connection {name} did not answer a health check")),
        }
    }

    /// Confirms the server-side deadline survived to the server, on both pools.
    ///
    /// # Errors
    ///
    /// Returns an operator-facing error naming the connection when a pooler or proxy
    /// discarded the connection-time setting (`docs/operations.md` section 5.2).
    pub(crate) async fn verify_session_settings(&self, deadline: Instant) -> Result<()> {
        match self {
            Self::MySql { name, pools } => pools
                .verify_session_settings(deadline)
                .await
                .with_context(|| format!("connection {name} lost its server-side timeout")),
            Self::PostgreSql { name, pools } => pools
                .verify_session_settings(deadline)
                .await
                .with_context(|| format!("connection {name} lost its server-side timeout")),
        }
    }

    /// Closes both pools, waiting for in-flight connections to return.
    async fn close(&self) {
        match self {
            Self::MySql { pools, .. } => pools.close().await,
            Self::PostgreSql { pools, .. } => pools.close().await,
        }
    }
}

/// Builds every connection, the registry, the policy engine, and the services.
///
/// Connects eagerly, because each adapter's `connect` does: a bad DSN, a refused
/// handshake, a missing database, or a missing role becomes a startup failure rather
/// than the first agent query's error.
///
/// # Errors
///
/// Returns an operator-facing error naming the connection, the registry, the policy
/// profile, or the redaction rules — whichever refused to be built. No message carries a
/// DSN.
pub(crate) async fn build(
    config: ResolvedConfig,
    shutdown: CancellationToken,
) -> Result<Deployment> {
    let ResolvedConfig {
        connections,
        policy,
        redaction_columns,
        redaction_strategy,
        // Milestone 12's sink writes one shape of event and cannot fail; the mode is what
        // Milestone 13's persistent sink varies, and honouring it here would mean
        // inventing a meaning for it a milestone early (`crate::audit`).
        audit: _mode,
    } = config;

    // The sink comes first: `docs/architecture.md` section 12 puts it before any pool, so
    // a connection that fails to open is the first thing an audit-capable process sees.
    let audit: Arc<dyn AuditSink> = Arc::new(TracingAuditSink);

    let mut runtimes = Vec::with_capacity(connections.len());
    let mut pools = Vec::with_capacity(connections.len());
    for connection in connections {
        let (runtime, pool) = build_connection(connection).await?;
        runtimes.push(Arc::new(runtime));
        pools.push(pool);
    }

    let registry: Arc<dyn ConnectionRegistry> = Arc::new(
        StaticConnectionRegistry::new(runtimes).context("the connection registry is unusable")?,
    );

    // One engine for the whole process (ADR-0039). `warden-config` already proved every
    // referenced profile agrees about policy, so this is that agreed value and not one
    // profile silently applied to a connection that asked for another.
    let engine = Arc::new(
        PolicyEngine::with_defaults(&policy_settings(&policy))
            .context("the configured policy profile is not a valid policy")?,
    );

    let services = Arc::new(
        Services::new(ServiceParts {
            registry,
            engine,
            audit,
            redaction: redaction_settings(redaction_columns, redaction_strategy),
            shutdown: shutdown.clone(),
        })
        .context("the application services could not be built")?,
    );

    Ok(Deployment {
        services,
        pools,
        shutdown,
    })
}

/// Opens one connection's pools and wires its four ports into a runtime.
async fn build_connection(
    connection: ResolvedConnection,
) -> Result<(ConnectionRuntime, PoolHandle)> {
    let ResolvedConnection {
        metadata,
        dsn,
        limits,
        agent_pool,
        control_pool,
        tls,
        search_path: configured_search_path,
    } = connection;
    let name = metadata.name.clone();

    let (parts, handle) = match metadata.dialect {
        Dialect::MySql => {
            let pools = Arc::new(
                MySqlConnectionPools::connect(MySqlConnectionConfig {
                    dsn,
                    environment: metadata.environment.clone(),
                    limits,
                    agent_pool,
                    control_pool,
                    tls,
                })
                .await
                .with_context(|| format!("connection {name} could not be opened"))?,
            );
            let parts = ConnectionRuntimeParts {
                capabilities: capabilities_for(Dialect::MySql),
                limits,
                analyzer: Arc::new(MySqlAnalyzer::new()),
                executor: Arc::new(MySqlQueryExecutor::new(Arc::clone(&pools))),
                inspector: Arc::new(MySqlSchemaInspector::new(Arc::clone(&pools), name.clone())),
                explainer: Arc::new(MySqlExplainer::new(Arc::clone(&pools))),
                metadata,
            };
            let handle = PoolHandle::MySql {
                name: name.clone(),
                pools,
            };
            (parts, handle)
        }
        Dialect::PostgreSql => {
            let search_path = search_path(&configured_search_path)
                .with_context(|| format!("connection {name} has an unusable `search_path`"))?;
            let pools = Arc::new(
                PostgreSqlConnectionPools::connect(PostgreSqlConnectionConfig {
                    dsn,
                    environment: metadata.environment.clone(),
                    limits,
                    agent_pool,
                    control_pool,
                    tls,
                    search_path,
                })
                .await
                .with_context(|| format!("connection {name} could not be opened"))?,
            );
            let parts = ConnectionRuntimeParts {
                capabilities: capabilities_for(Dialect::PostgreSql),
                limits,
                analyzer: Arc::new(PostgreSqlAnalyzer::new()),
                executor: Arc::new(PostgreSqlQueryExecutor::new(Arc::clone(&pools))),
                inspector: Arc::new(PostgreSqlSchemaInspector::new(
                    Arc::clone(&pools),
                    name.clone(),
                )),
                explainer: Arc::new(PostgreSqlExplainer::new(Arc::clone(&pools))),
                metadata,
            };
            let handle = PoolHandle::PostgreSql {
                name: name.clone(),
                pools,
            };
            (parts, handle)
        }
    };

    // `ConnectionRuntime::new` rejects an analyzer whose dialect differs from the
    // connection's. The match above makes that unreachable today, which is the point:
    // the check costs nothing here and would otherwise surface at the first query.
    let runtime = ConnectionRuntime::new(parts)
        .with_context(|| format!("connection {name} could not be assembled"))?;
    Ok((runtime, handle))
}

/// What each adapter can actually do.
///
/// A function rather than a literal beside each branch, so a future adapter cannot copy
/// a `true` it has not earned. Both dialects answer the same today because both earned
/// every flag: read-only transactions and the server-side statement timeout in
/// Milestones 6 to 8, schema search in Milestone 9, and structured `EXPLAIN` in
/// Milestone 10.
fn capabilities_for(dialect: Dialect) -> Capabilities {
    match dialect {
        Dialect::MySql | Dialect::PostgreSql => Capabilities {
            read_only_transactions: true,
            structured_explain: true,
            server_statement_timeout: true,
            schema_search: true,
        },
    }
}

/// Turns a resolved policy profile into the engine's own settings (Decision 7).
///
/// A field-by-field mapping rather than a `From` impl in either crate: `warden-config`
/// may not name `warden-policy` and `warden-policy` may not name configuration, so this
/// translation belongs to neither and to the composition root instead. Object rules stay
/// raw strings — [`PolicyEngine::with_defaults`] parses them, so a malformed rule fails
/// startup rather than the first query that touches it.
fn policy_settings(policy: &ResolvedPolicy) -> PolicySettings {
    PolicySettings {
        relaxations: Relaxations {
            locking_reads: policy.allow_locking_reads,
            unknown_functions: policy.allow_unknown_functions,
        },
        objects: ObjectRules {
            schemas: policy.schemas.clone(),
            allow_tables: policy.allow_tables.clone(),
            deny_tables: policy.deny_tables.clone(),
        },
    }
}

/// Turns the configured redaction rules into the service layer's own settings
/// (Decision 7).
///
/// Rules stay raw strings for the same reason object rules do: `Services::new` parses
/// them once, so a malformed rule fails startup with a message naming it.
fn redaction_settings(columns: Vec<String>, strategy: RedactionStrategyEntry) -> RedactionSettings {
    RedactionSettings {
        columns,
        strategy: match strategy {
            RedactionStrategyEntry::Replace => RedactionStrategy::Replace,
            RedactionStrategyEntry::Null => RedactionStrategy::Null,
        },
    }
}

/// Validates one PostgreSQL connection's `search_path`.
///
/// `warden-config` accepts an empty list because MySQL has none and it will not invent a
/// PostgreSQL default; `SearchPath::new` refuses an empty one because an unqualified name
/// has to resolve somewhere. This is the single place those two facts meet, so a
/// PostgreSQL connection configured without a `search_path` fails at startup instead of
/// resolving names against whatever the server's default happens to be
/// (`docs/security.md` section 5.2).
///
/// Only this branch calls it: MySQL has no `search_path`, and `warden-config` has already
/// rejected a configuration that gave one to a MySQL connection.
fn search_path<I, S>(schemas: I) -> Result<SearchPath>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    SearchPath::new(schemas)
        .context("`search_path` must be a non-empty list of unquoted schema identifiers")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn both_dialects_declare_the_capabilities_their_milestones_delivered() {
        for dialect in [Dialect::MySql, Dialect::PostgreSql] {
            let capabilities = capabilities_for(dialect);
            assert!(capabilities.read_only_transactions, "{dialect}");
            assert!(capabilities.structured_explain, "{dialect}");
            assert!(capabilities.server_statement_timeout, "{dialect}");
            assert!(capabilities.schema_search, "{dialect}");
        }
    }

    #[test]
    fn the_policy_engine_is_built_from_the_resolved_profile_and_nothing_else() {
        let settings = policy_settings(&ResolvedPolicy {
            allow_locking_reads: false,
            allow_unknown_functions: false,
            schemas: Some(vec!["app".to_owned()]),
            allow_tables: None,
            deny_tables: vec!["app.audit_log".to_owned()],
        });
        assert!(!settings.relaxations.locking_reads);
        assert_eq!(settings.objects.deny_tables, ["app.audit_log"]);
        assert!(PolicyEngine::with_defaults(&settings).is_ok());
    }

    #[test]
    fn a_relaxed_profile_reaches_the_engine_as_a_relaxation() {
        // The inverse of the test above: a mapping that dropped a field would leave a
        // deliberately relaxed deployment silently hardened, or a hardened one relaxed.
        let settings = policy_settings(&ResolvedPolicy {
            allow_locking_reads: true,
            allow_unknown_functions: true,
            schemas: None,
            allow_tables: Some(vec!["app.orders".to_owned()]),
            ..hardened()
        });
        assert!(settings.relaxations.locking_reads);
        assert!(settings.relaxations.unknown_functions);
        assert_eq!(
            settings.objects.allow_tables.as_deref(),
            Some(["app.orders".to_owned()].as_slice())
        );
    }

    #[test]
    fn a_malformed_object_rule_fails_startup_rather_than_the_first_query() {
        let settings = policy_settings(&ResolvedPolicy {
            deny_tables: vec!["a.b.c".to_owned()],
            ..hardened()
        });
        assert!(PolicyEngine::with_defaults(&settings).is_err());
    }

    #[test]
    fn a_search_path_reaches_only_the_adapter_that_has_one() {
        assert!(search_path(["app", "public"]).is_ok());
        assert!(search_path(["not an identifier"]).is_err());
    }

    #[test]
    fn a_postgresql_connection_without_a_search_path_fails_at_startup() {
        // `warden-config` permits the empty list; PostgreSQL cannot use it. The
        // composition root is where that becomes a refusal rather than a default nobody
        // configured.
        let empty: [&str; 0] = [];
        assert!(search_path(empty).is_err());
    }

    fn hardened() -> ResolvedPolicy {
        ResolvedPolicy {
            allow_locking_reads: false,
            allow_unknown_functions: false,
            schemas: None,
            allow_tables: None,
            deny_tables: Vec::new(),
        }
    }
}
