//! Pool construction for PostgreSQL.
//!
//! PostgreSQL startup options travel in the connection packet, before the first
//! statement, rather than through an `after_connect` hook.

use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use warden_core::pool::PoolSettings;

use crate::error::ConnectError;

/// The pool options for one pool, with no connection opened.
pub(crate) fn pool_options(settings: PoolSettings) -> PgPoolOptions {
    PgPoolOptions::new()
        .max_connections(settings.max_connections)
        .min_connections(settings.min_connections)
        .acquire_timeout(settings.acquire_timeout)
        .idle_timeout(settings.idle_timeout)
        .max_lifetime(settings.max_lifetime)
}

/// Opens one pool, connecting eagerly so a misconfiguration fails at startup.
pub(crate) async fn build(
    settings: PoolSettings,
    options: PgConnectOptions,
) -> Result<PgPool, ConnectError> {
    pool_options(settings)
        .connect_with(options)
        .await
        .map_err(|error| ConnectError::driver(&error))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use super::*;
    use std::time::Duration;

    #[test]
    fn the_pool_options_are_the_documented_numbers() {
        let agent = pool_options(PoolSettings::agent());
        assert_eq!(agent.get_max_connections(), 5);
        assert_eq!(agent.get_min_connections(), 0);
        assert_eq!(agent.get_acquire_timeout(), Duration::from_secs(3));
        assert_eq!(agent.get_idle_timeout(), Some(Duration::from_secs(600)));
        assert_eq!(agent.get_max_lifetime(), Some(Duration::from_secs(1800)));
        let control = pool_options(PoolSettings::control());
        assert_eq!(control.get_max_connections(), 2);
        assert_eq!(control.get_min_connections(), 1);
        assert_eq!(control.get_acquire_timeout(), Duration::from_secs(3));
    }
}
