//! One PostgreSQL connection's two pools, and the schemas names resolve against.

use std::fmt;
use std::time::Duration;

use sqlx::postgres::PgPool;
use tokio::time::{Instant, timeout_at};
use warden_core::connection::Environment;
use warden_core::limits::ExecutionLimits;
use warden_core::pool::PoolSettings;
use warden_core::secret::Dsn;
use warden_core::tls::TlsSettings;

use crate::error::ConnectError;
use crate::options::{self, PoolRole};
use crate::pool;
use crate::query::agent_query;

/// PostgreSQL's `NAMEDATALEN - 1`: the longest identifier the server stores.
pub const MAX_SCHEMA_NAME_LEN: usize = 63;

/// Why a list of schemas is not a usable search path.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SearchPathError {
    /// No schema was given.
    #[error("the search path is empty; PostgreSQL name resolution must be fixed")]
    Empty,
    /// A schema name was not an unquoted identifier.
    #[error("schema name {name:?} is not an unquoted PostgreSQL identifier")]
    NotAnIdentifier {
        /// The rejected name.
        name: String,
    },
    /// A schema name was longer than the server would store.
    #[error("a schema name is {actual} bytes; the limit is {limit}")]
    TooLong {
        /// Length of the rejected name.
        actual: usize,
        /// The limit.
        limit: usize,
    },
}

/// The schemas PostgreSQL resolves unqualified names against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchPath(String);

impl SearchPath {
    /// Validates a list of schema names and joins them in order.
    ///
    /// # Errors
    ///
    /// - [`SearchPathError::TooLong`] if a name exceeds [`MAX_SCHEMA_NAME_LEN`].
    /// - [`SearchPathError::NotAnIdentifier`] if a name is not an unquoted
    ///   identifier. The path is interpolated into a startup option, so a name that
    ///   would need quoting is refused rather than quoted — nothing here builds SQL
    ///   from a string it had to escape.
    /// - [`SearchPathError::Empty`] if the list yields no schema.
    pub fn new<I, S>(schemas: I) -> Result<Self, SearchPathError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut joined = String::new();
        for schema in schemas {
            let name = schema.as_ref();
            if name.len() > MAX_SCHEMA_NAME_LEN {
                return Err(SearchPathError::TooLong {
                    actual: name.len(),
                    limit: MAX_SCHEMA_NAME_LEN,
                });
            }
            if !is_unquoted_identifier(name) {
                return Err(SearchPathError::NotAnIdentifier {
                    name: name.to_owned(),
                });
            }
            if !joined.is_empty() {
                joined.push(',');
            }
            joined.push_str(name);
        }
        if joined.is_empty() {
            return Err(SearchPathError::Empty);
        }
        Ok(Self(joined))
    }

    /// The value written into the startup `search_path` option.
    pub(crate) fn as_option_value(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for SearchPath {
    type Error = SearchPathError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Self::new(std::iter::empty::<&str>());
        }
        Self::new(value.split(','))
    }
}

impl std::str::FromStr for SearchPath {
    type Err = SearchPathError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value.to_owned())
    }
}

impl AsRef<str> for SearchPath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SearchPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_ref())
    }
}

/// PostgreSQL's restricted unquoted identifier rule, deliberately ASCII-only.
fn is_unquoted_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && characters
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '$'))
}

/// Everything one PostgreSQL connection needs before it can open a pool.
#[derive(Debug)]
pub struct PostgreSqlConnectionConfig {
    /// The connection string, still secret.
    pub dsn: Dsn,
    /// The deployment environment, which decides whether cleartext is legal.
    pub environment: Environment,
    /// The bounds every request on this connection runs under.
    pub limits: ExecutionLimits,
    /// Capacity for agent queries and `EXPLAIN`.
    pub agent_pool: PoolSettings,
    /// Capacity for health checks and schema introspection.
    pub control_pool: PoolSettings,
    /// Transport security.
    pub tls: TlsSettings,
    /// The schemas unqualified names resolve against.
    pub search_path: SearchPath,
}

/// One PostgreSQL connection's two pools (ADR-0025).
#[derive(Debug)]
pub struct PostgreSqlConnectionPools {
    agent: PgPool,
    control: PgPool,
    statement_timeout: Duration,
    search_path: SearchPath,
}

impl PostgreSqlConnectionPools {
    /// Validates the configuration and opens both pools.
    ///
    /// Connects eagerly, so a bad DSN or an unreachable database is a startup failure
    /// rather than the first agent query's error (`docs/architecture.md` section 12).
    ///
    /// # Errors
    ///
    /// Configuration first, before any socket: [`ConnectError::Limits`],
    /// [`ConnectError::PoolSettings`], [`ConnectError::Tls`],
    /// [`ConnectError::DialectMismatch`] if the DSN's scheme names MySQL, and
    /// [`ConnectError::AmbientConnectionInput`] if a `PG*` variable would still
    /// influence the connection (ADR-0031). Then [`ConnectError::Driver`] if either
    /// pool cannot open a connection; its message is held in a field `Display` does
    /// not print.
    pub async fn connect(config: PostgreSqlConnectionConfig) -> Result<Self, ConnectError> {
        config.limits.validate()?;
        config.agent_pool.validate_concurrency(&config.limits)?;
        config.control_pool.validate()?;
        config.tls.validate(&config.environment)?;
        let statement_timeout = config.limits.server_timeout();
        let agent_options = options::connect_options(
            &config.dsn,
            &config.tls,
            &config.search_path,
            statement_timeout,
            PoolRole::Agent,
        )?;
        let control_options = options::connect_options(
            &config.dsn,
            &config.tls,
            &config.search_path,
            statement_timeout,
            PoolRole::Control,
        )?;
        let agent = pool::build(config.agent_pool, agent_options).await?;
        let control = match pool::build(config.control_pool, control_options).await {
            Ok(control) => control,
            Err(error) => {
                agent.close().await;
                return Err(error);
            }
        };
        Ok(Self {
            agent,
            control,
            statement_timeout,
            search_path: config.search_path,
        })
    }

    /// The pool agent queries and `EXPLAIN` run on.
    pub(crate) fn agent(&self) -> &PgPool {
        &self.agent
    }
    /// The pool health checks and schema introspection run on.
    pub(crate) fn control(&self) -> &PgPool {
        &self.control
    }

    /// The server-side deadline pinned in this connection's startup options.
    ///
    /// `crate::execute` reads it so a request's local deadline can only tighten
    /// the already-pinned server deadline (ADR-0024).
    pub(crate) fn statement_timeout(&self) -> Duration {
        self.statement_timeout
    }

    /// Confirms the database answers, using a fixed adapter query.
    ///
    /// Runs on `control_pool`, never on `agent_pool`: readiness must not execute an
    /// agent query (`docs/operations.md` section 10.4), and keeping it off the agent
    /// pool is what stops saturated agent traffic from making a healthy connection
    /// look unhealthy (ADR-0025).
    ///
    /// # Errors
    ///
    /// [`ConnectError::Timeout`] if the probe does not answer by `deadline`, or
    /// [`ConnectError::Driver`] if the control pool cannot serve it.
    pub async fn health_check(&self, deadline: Instant) -> Result<(), ConnectError> {
        let probe = sqlx::query_scalar::<_, i32>("SELECT 1").fetch_one(self.control());
        match timeout_at(deadline, probe).await {
            Ok(Ok(_value)) => Ok(()),
            Ok(Err(error)) => Err(ConnectError::driver(&error)),
            Err(_elapsed) => Err(ConnectError::Timeout),
        }
    }

    /// Confirms every startup setting survived to the server, on both pools.
    ///
    /// `docs/operations.md` section 5.2 requires this check because a pooler or proxy
    /// between Warden and the server can discard startup options, leaving a deployment
    /// that believes it has a server-side deadline and a fixed `search_path` it does
    /// not have. This is what `warden check` calls; it is not part of readiness, which
    /// must stay cheap.
    ///
    /// # Errors
    ///
    /// [`ConnectError::SessionSettingRejected`] naming the first setting whose value
    /// at the server differs from what was configured. Otherwise
    /// [`ConnectError::Timeout`] or [`ConnectError::Driver`] as for
    /// [`PostgreSqlConnectionPools::health_check`].
    pub async fn verify_session_settings(&self, deadline: Instant) -> Result<(), ConnectError> {
        let expected = options::expected_settings(self.statement_timeout, &self.search_path);
        for pool in [self.agent(), self.control()] {
            for (setting, want) in &expected {
                let setting = *setting;
                let read = agent_query("SELECT setting FROM pg_settings WHERE name = $1")
                    .bind(setting)
                    .fetch_one(pool);
                let row = match timeout_at(deadline, read).await {
                    Ok(Ok(row)) => row,
                    Ok(Err(error)) => return Err(ConnectError::driver(&error)),
                    Err(_elapsed) => return Err(ConnectError::Timeout),
                };
                let actual: String = sqlx::Row::try_get(&row, "setting")
                    .map_err(|error| ConnectError::driver(&error))?;
                let matches = if setting == "search_path" {
                    normalized_path(&actual) == normalized_path(want)
                } else {
                    actual == *want
                };
                if !matches {
                    return Err(ConnectError::SessionSettingRejected {
                        setting,
                        expected: want.clone(),
                        actual,
                    });
                }
            }
        }
        Ok(())
    }

    /// Closes both pools, waiting for in-flight connections to return.
    pub async fn close(&self) {
        self.agent.close().await;
        self.control.close().await;
    }
}

#[cfg(test)]
impl PostgreSqlConnectionPools {
    /// Builds two lazy pools for adapter unit tests without opening a socket.
    pub(crate) fn lazy_for_tests() -> Self {
        let options = sqlx::postgres::PgConnectOptions::new();
        Self {
            agent: sqlx::postgres::PgPoolOptions::new().connect_lazy_with(options.clone()),
            control: sqlx::postgres::PgPoolOptions::new().connect_lazy_with(options),
            statement_timeout: Duration::ZERO,
            search_path: SearchPath("public".to_owned()),
        }
    }
}

/// Splits a search path into schema names, ignoring server-inserted spacing.
fn normalized_path(value: &str) -> Vec<&str> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use std::str::FromStr;

    use super::*;
    use warden_core::tls::{TlsError, TlsMode};

    fn config(environment: Environment, tls: TlsSettings) -> PostgreSqlConnectionConfig {
        PostgreSqlConnectionConfig {
            dsn: "postgres://warden:hunter2@db-02.internal:5432/analytics"
                .parse()
                .unwrap(),
            environment,
            limits: ExecutionLimits::default(),
            agent_pool: PoolSettings::agent(),
            control_pool: PoolSettings::control(),
            tls,
            search_path: SearchPath::new(["app", "public"]).unwrap(),
        }
    }
    #[test]
    fn a_search_path_joins_validated_schemas_in_order() {
        let path = SearchPath::new(["app", "public", "reporting_v2"]).unwrap();
        assert_eq!(path.as_option_value(), "app,public,reporting_v2");
        assert_eq!(path.to_string(), "app,public,reporting_v2");
    }

    #[test]
    fn search_path_string_traits_share_the_constructor_validation() {
        let parsed = SearchPath::from_str("app,public").unwrap();
        let converted = SearchPath::try_from("app,public".to_owned()).unwrap();
        let value: &str = parsed.as_ref();
        assert_eq!(value, "app,public");
        assert_eq!(parsed, converted);
        assert_eq!(
            SearchPath::try_from(String::new()),
            Err(SearchPathError::Empty)
        );
        assert_eq!(
            "app,$user".parse::<SearchPath>(),
            Err(SearchPathError::NotAnIdentifier {
                name: "$user".to_owned(),
            })
        );
    }
    #[test]
    fn the_search_path_rejects_everything_that_would_reintroduce_ambiguity() {
        assert_eq!(
            SearchPath::new(Vec::<String>::new()),
            Err(SearchPathError::Empty)
        );
        assert_eq!(
            SearchPath::new(["$user", "public"]),
            Err(SearchPathError::NotAnIdentifier {
                name: "$user".to_owned()
            })
        );
        for name in ["\"App\"", "app,public", "app public", "", "pg catalog"] {
            assert!(
                matches!(
                    SearchPath::new([name]),
                    Err(SearchPathError::NotAnIdentifier { .. })
                ),
                "{name:?} was accepted"
            );
        }
        assert!(matches!(
            SearchPath::new(["a".repeat(MAX_SCHEMA_NAME_LEN + 1)]),
            Err(SearchPathError::TooLong {
                limit: MAX_SCHEMA_NAME_LEN,
                ..
            })
        ));
        SearchPath::new(["a".repeat(MAX_SCHEMA_NAME_LEN)]).unwrap();
    }
    #[tokio::test]
    async fn cleartext_against_production_fails_before_any_socket_is_opened() {
        let error = PostgreSqlConnectionPools::connect(config(
            Environment::Production,
            TlsSettings {
                mode: TlsMode::Disabled,
                root_certificate: None,
            },
        ))
        .await
        .unwrap_err();
        assert_eq!(
            error,
            ConnectError::Tls {
                source: TlsError::CleartextOutsideDevelopment {
                    environment: Environment::Production
                }
            }
        );
    }
    #[tokio::test]
    async fn a_pool_below_the_concurrency_bound_fails_before_any_socket_is_opened() {
        let mut settings = config(Environment::Production, TlsSettings::default());
        settings.limits = ExecutionLimits {
            max_concurrent_queries: 6,
            ..ExecutionLimits::default()
        };
        assert!(matches!(
            PostgreSqlConnectionPools::connect(settings)
                .await
                .unwrap_err(),
            ConnectError::PoolSettings {
                source: warden_core::pool::PoolSettingsError::BelowConcurrency { .. }
            }
        ));
    }
    #[test]
    fn the_config_debug_prints_no_credential() {
        let rendered = format!(
            "{:?}",
            config(Environment::Production, TlsSettings::default())
        );
        assert!(rendered.contains("Production"), "{rendered}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains("db-02.internal"), "{rendered}");
    }
    #[test]
    fn a_normalized_path_ignores_the_servers_spacing() {
        assert_eq!(
            normalized_path("app, public"),
            normalized_path("app,public")
        );
        assert_ne!(normalized_path("app,public"), normalized_path("public,app"));
    }
}
