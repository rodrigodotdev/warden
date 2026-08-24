//! Pool construction and the session hardening applied to every new connection.

use std::time::Duration;

use sqlx::mysql::{MySqlConnectOptions, MySqlPool, MySqlPoolOptions};
use warden_core::pool::PoolSettings;

use crate::error::ConnectError;

/// Converts a deadline to the milliseconds MySQL expects, never to zero.
///
/// `MAX_EXECUTION_TIME = 0` means **no limit**, so a sub-millisecond timeout that
/// rounded down would silently remove the server-side deadline instead of
/// tightening it (ADR-0024). `ExecutionLimits::validate` already rejects a zero
/// timeout; this handles the rounding.
pub(crate) fn statement_timeout_millis(timeout: Duration) -> u64 {
    u64::try_from(timeout.as_millis())
        .unwrap_or(u64::MAX)
        .max(1)
}

/// The pool options for one pool, with no connection opened.
///
/// Separate from [`build`] so the exact capacity numbers are testable without a
/// database, which is what `docs/milestones.md` asks M6 to pin.
pub(crate) fn pool_options(
    settings: PoolSettings,
    statement_timeout: Duration,
) -> MySqlPoolOptions {
    let millis = statement_timeout_millis(statement_timeout);
    MySqlPoolOptions::new()
        .max_connections(settings.max_connections)
        .min_connections(settings.min_connections)
        .acquire_timeout(settings.acquire_timeout)
        .idle_timeout(settings.idle_timeout)
        .max_lifetime(settings.max_lifetime)
        .after_connect(move |connection, _metadata| {
            Box::pin(async move {
                sqlx::query("SET SESSION MAX_EXECUTION_TIME = ?")
                    .bind(millis)
                    .execute(connection)
                    .await?;
                Ok(())
            })
        })
}

/// Opens one pool, connecting eagerly so a misconfiguration fails at startup.
pub(crate) async fn build(
    settings: PoolSettings,
    options: MySqlConnectOptions,
    statement_timeout: Duration,
) -> Result<MySqlPool, ConnectError> {
    pool_options(settings, statement_timeout)
        .connect_with(options)
        .await
        .map_err(|error| ConnectError::driver(&error))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::time::Duration;

    use super::*;
    use warden_core::pool::PoolSettings;

    #[test]
    fn the_pool_options_are_the_documented_numbers() {
        let agent = pool_options(PoolSettings::agent(), Duration::from_secs(5));
        assert_eq!(agent.get_max_connections(), 5);
        assert_eq!(agent.get_min_connections(), 0);
        assert_eq!(agent.get_acquire_timeout(), Duration::from_secs(3));
        assert_eq!(agent.get_idle_timeout(), Some(Duration::from_secs(600)));
        assert_eq!(agent.get_max_lifetime(), Some(Duration::from_secs(1800)));

        let control = pool_options(PoolSettings::control(), Duration::from_secs(5));
        assert_eq!(control.get_max_connections(), 2);
        assert_eq!(control.get_min_connections(), 1);
        assert_eq!(control.get_acquire_timeout(), Duration::from_secs(3));
    }

    #[test]
    fn a_sub_millisecond_deadline_never_becomes_no_deadline() {
        assert_eq!(statement_timeout_millis(Duration::from_secs(5)), 5_000);
        assert_eq!(statement_timeout_millis(Duration::from_nanos(1)), 1);
        assert_eq!(statement_timeout_millis(Duration::MAX), u64::MAX);
    }
}
