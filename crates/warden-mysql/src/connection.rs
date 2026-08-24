//! One MySQL connection's two pools.
//!
//! `agent_pool` carries agent queries and `EXPLAIN`; `control_pool` carries health
//! checks and schema introspection. They are separate because a client timeout during
//! row streaming forces SQLx to discard the connection, so under repeated slow queries
//! a single pool drains and takes readiness and schema discovery down with it
//! (ADR-0025).
//!
//! The pool handles are `pub(crate)`. Nothing outside this crate needs a `MySqlPool`:
//! the composition root builds a [`MySqlConnectionPools`], hands it to Milestone 7's
//! executor, and never names a SQLx type. Keeping them internal is what makes "no
//! driver type escapes an adapter" a property `tests/adapter_rules.rs` can check.

use std::time::Duration;

use sqlx::mysql::MySqlPool;
use tokio::time::{Instant, timeout_at};
use warden_core::connection::Environment;
use warden_core::limits::ExecutionLimits;
use warden_core::pool::PoolSettings;
use warden_core::secret::Dsn;
use warden_core::tls::TlsSettings;

use crate::error::ConnectError;
use crate::options::{self, PoolRole};
use crate::pool::{self, statement_timeout_millis};

/// Everything one MySQL connection needs before it can open a pool.
///
/// A parts struct rather than a six-argument constructor: a struct literal must name
/// every field, and two `PoolSettings` values cannot be transposed by accident — the
/// same reasoning as `ConnectionRuntimeParts` in `warden-ports`.
///
/// `Debug` is derived and safe: every field's own `Debug` is either non-secret or
/// already redacted, and a test pins that.
#[derive(Debug)]
pub struct MySqlConnectionConfig {
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
}

/// One MySQL connection's two pools (ADR-0025).
///
/// `Debug` is derived and safe: `Pool<DB>`'s own `Debug` prints size, idle count,
/// closed state and capacity, and never the connect options that hold the password.
#[derive(Debug)]
pub struct MySqlConnectionPools {
    agent: MySqlPool,
    control: MySqlPool,
    statement_timeout: Duration,
}

impl MySqlConnectionPools {
    /// Validates the configuration and opens both pools.
    ///
    /// Connects eagerly: `connect_with` opens a connection before returning, so a bad
    /// DSN, a refused TLS handshake, a missing database or a missing role becomes a
    /// startup failure rather than the first agent query's error
    /// (`docs/architecture.md` section 12). Warden therefore does not start while the
    /// database is unreachable, which is the intended trade for a security gateway.
    pub async fn connect(config: MySqlConnectionConfig) -> Result<Self, ConnectError> {
        config.limits.validate()?;
        config.agent_pool.validate_concurrency(&config.limits)?;
        config.control_pool.validate()?;
        config.tls.validate(&config.environment)?;

        let statement_timeout = config.limits.server_timeout();
        let agent_options = options::connect_options(&config.dsn, &config.tls, PoolRole::Agent)?;
        let control_options =
            options::connect_options(&config.dsn, &config.tls, PoolRole::Control)?;

        let agent = pool::build(config.agent_pool, agent_options, statement_timeout).await?;
        let control =
            match pool::build(config.control_pool, control_options, statement_timeout).await {
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
        })
    }

    /// The pool agent queries and `EXPLAIN` run on.
    pub(crate) fn agent(&self) -> &MySqlPool {
        &self.agent
    }

    /// The pool health checks and schema introspection run on.
    pub(crate) fn control(&self) -> &MySqlPool {
        &self.control
    }

    /// Confirms the database answers, using a fixed adapter query.
    ///
    /// Runs on `control_pool`, never on `agent_pool`: readiness must not execute an
    /// agent query (`docs/operations.md` section 10.4), and routing it through the
    /// control pool is also what keeps saturated agent traffic from making a healthy
    /// connection look unhealthy — the whole argument of ADR-0025.
    pub async fn health_check(&self, deadline: Instant) -> Result<(), ConnectError> {
        let probe = sqlx::query_scalar::<_, i64>("SELECT 1").fetch_one(self.control());
        match timeout_at(deadline, probe).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(error)) => Err(ConnectError::driver(&error)),
            Err(_elapsed) => Err(ConnectError::Timeout),
        }
    }

    /// Confirms the server-side deadline survived to the server, on both pools.
    ///
    /// `docs/operations.md` section 5.2 requires this check because a pooler or proxy
    /// between Warden and the server can discard connection-time settings, leaving a
    /// deployment that believes it has a server-side deadline it does not have. This
    /// is what `warden check` calls; it is not part of readiness, which must stay
    /// cheap.
    pub async fn verify_session_settings(&self, deadline: Instant) -> Result<(), ConnectError> {
        let expected = statement_timeout_millis(self.statement_timeout);

        for pool in [self.agent(), self.control()] {
            let read =
                sqlx::query_scalar::<_, i64>("SELECT CAST(@@SESSION.MAX_EXECUTION_TIME AS SIGNED)")
                    .fetch_one(pool);

            let actual = match timeout_at(deadline, read).await {
                Ok(Ok(value)) => value,
                Ok(Err(error)) => return Err(ConnectError::driver(&error)),
                Err(_elapsed) => return Err(ConnectError::Timeout),
            };

            if u64::try_from(actual).ok() != Some(expected) {
                return Err(ConnectError::SessionSettingRejected {
                    setting: "MAX_EXECUTION_TIME",
                    expected: expected.to_string(),
                    actual: actual.to_string(),
                });
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
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use warden_core::connection::Environment;
    use warden_core::limits::ExecutionLimits;
    use warden_core::pool::PoolSettings;
    use warden_core::tls::{TlsError, TlsMode, TlsSettings};

    use super::*;
    use crate::error::ConnectError;

    fn config(environment: Environment, tls: TlsSettings) -> MySqlConnectionConfig {
        MySqlConnectionConfig {
            dsn: "mysql://warden:hunter2@db-01.internal:3306/app"
                .parse()
                .unwrap(),
            environment,
            limits: ExecutionLimits::default(),
            agent_pool: PoolSettings::agent(),
            control_pool: PoolSettings::control(),
            tls,
        }
    }

    #[tokio::test]
    async fn cleartext_against_production_fails_before_any_socket_is_opened() {
        let error = MySqlConnectionPools::connect(config(
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
                    environment: Environment::Production,
                },
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
        let error = MySqlConnectionPools::connect(settings).await.unwrap_err();
        assert!(
            matches!(
                error,
                ConnectError::PoolSettings {
                    source: warden_core::pool::PoolSettingsError::BelowConcurrency { .. }
                }
            ),
            "{error:?}"
        );
    }

    #[test]
    fn the_config_debug_prints_no_credential() {
        let rendered = format!(
            "{:?}",
            config(Environment::Production, TlsSettings::default())
        );
        assert!(rendered.contains("Production"), "{rendered}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains("db-01.internal"), "{rendered}");
    }
}
