//! The capacity each of a connection's two pools runs under.
//!
//! Every field is set explicitly, including the ones whose driver default would be
//! acceptable. `PoolOptions::new()` in SQLx 0.9 defaults to `max_connections: 10` and
//! `acquire_timeout: 30s`; inheriting those would double the connection budget of
//! `docs/operations.md` section 4 and turn a bounded queue wait into a thirty-second
//! one, and nothing in a code review would show it.

use std::time::Duration;

use crate::limits::ExecutionLimits;

/// Agent-pool connection ceiling from `docs/operations.md` section 4.
pub const AGENT_POOL_MAX_CONNECTIONS: u32 = 5;
/// Agent-pool floor: idle connections cost a server-side session for no benefit,
/// because agent traffic is bursty.
pub const AGENT_POOL_MIN_CONNECTIONS: u32 = 0;
/// Control-pool connection ceiling: health checks and introspection are small and
/// serial.
pub const CONTROL_POOL_MAX_CONNECTIONS: u32 = 2;
/// Control-pool floor: readiness must not pay for a connect on its first probe.
pub const CONTROL_POOL_MIN_CONNECTIONS: u32 = 1;
/// Longest wait for a pooled connection on either pool.
pub const POOL_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(3);
/// How long an idle connection is kept, mirroring SQLx's own default explicitly.
pub const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);
/// How long any connection is reused before it is replaced, mirroring SQLx's own
/// default explicitly. A bounded lifetime is also what lets a rotated credential or a
/// renewed server certificate take effect without a restart.
pub const POOL_MAX_LIFETIME: Duration = Duration::from_secs(30 * 60);

/// A pool configuration that would remove a bound or contradict another one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PoolSettingsError {
    /// A setting was zero, which would remove the bound entirely.
    #[error("pool setting `{field}` must be greater than zero")]
    Zero {
        /// Name of the offending field.
        field: &'static str,
    },
    /// The floor was above the ceiling, which no pool can satisfy.
    #[error("min_connections ({min}) exceeds max_connections ({max})")]
    MinAboveMax {
        /// Configured floor.
        min: u32,
        /// Configured ceiling.
        max: u32,
    },
    /// The pool cannot serve the concurrency the connection permits.
    ///
    /// `docs/operations.md` section 3.2 requires startup to fail on "pool maxima
    /// below required concurrency": otherwise `max_concurrent_queries` permits more
    /// simultaneous queries than the pool can hand out connections for, and the
    /// surplus waits on the pool's `acquire_timeout` instead of on the connection's
    /// `max_queue_wait`, which is the bound SPEC section 6, invariant 16 names.
    #[error("max_connections ({max}) is below max_concurrent_queries ({concurrency})")]
    BelowConcurrency {
        /// Configured pool ceiling.
        max: u32,
        /// Configured per-connection concurrency.
        concurrency: usize,
    },
    /// An idle connection would outlive the lifetime bound, which cannot happen.
    #[error("idle_timeout ({idle:?}) exceeds max_lifetime ({lifetime:?})")]
    IdleAboveLifetime {
        /// Configured idle bound.
        idle: Duration,
        /// Configured lifetime bound.
        lifetime: Duration,
    },
}

/// The capacity of one pool.
///
/// Fields are public because these are operator-chosen capacity settings, not
/// security state — the same reasoning as [`ExecutionLimits`] — but startup calls
/// [`PoolSettings::validate`] before anything uses them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolSettings {
    /// Largest number of connections the pool opens.
    pub max_connections: u32,
    /// Number of connections the pool keeps open when idle.
    pub min_connections: u32,
    /// Longest wait for a connection before the driver reports a pool timeout.
    pub acquire_timeout: Duration,
    /// How long an idle connection is kept before it is closed.
    pub idle_timeout: Option<Duration>,
    /// How long any connection is reused before it is replaced.
    pub max_lifetime: Option<Duration>,
}

impl PoolSettings {
    /// The pool agent queries and `EXPLAIN` run on (ADR-0025).
    #[must_use]
    pub const fn agent() -> Self {
        Self {
            max_connections: AGENT_POOL_MAX_CONNECTIONS,
            min_connections: AGENT_POOL_MIN_CONNECTIONS,
            acquire_timeout: POOL_ACQUIRE_TIMEOUT,
            idle_timeout: Some(POOL_IDLE_TIMEOUT),
            max_lifetime: Some(POOL_MAX_LIFETIME),
        }
    }

    /// The pool health checks and schema introspection run on (ADR-0025).
    ///
    /// Separate from the agent pool because a client timeout during row streaming
    /// forces SQLx to discard the connection; under repeated slow queries a single
    /// pool drains and takes readiness down with it.
    #[must_use]
    pub const fn control() -> Self {
        Self {
            max_connections: CONTROL_POOL_MAX_CONNECTIONS,
            min_connections: CONTROL_POOL_MIN_CONNECTIONS,
            acquire_timeout: POOL_ACQUIRE_TIMEOUT,
            idle_timeout: Some(POOL_IDLE_TIMEOUT),
            max_lifetime: Some(POOL_MAX_LIFETIME),
        }
    }

    /// Rejects settings that remove a bound or contradict another one.
    pub fn validate(&self) -> Result<(), PoolSettingsError> {
        for (field, is_zero) in [
            ("max_connections", self.max_connections == 0),
            ("acquire_timeout", self.acquire_timeout.is_zero()),
            (
                "idle_timeout",
                self.idle_timeout.is_some_and(|duration| duration.is_zero()),
            ),
            (
                "max_lifetime",
                self.max_lifetime.is_some_and(|duration| duration.is_zero()),
            ),
        ] {
            if is_zero {
                return Err(PoolSettingsError::Zero { field });
            }
        }

        if self.min_connections > self.max_connections {
            return Err(PoolSettingsError::MinAboveMax {
                min: self.min_connections,
                max: self.max_connections,
            });
        }

        if let (Some(idle), Some(lifetime)) = (self.idle_timeout, self.max_lifetime)
            && idle > lifetime
        {
            return Err(PoolSettingsError::IdleAboveLifetime { idle, lifetime });
        }

        Ok(())
    }

    /// Validates the settings and checks that the pool can serve the connection's
    /// concurrency bound. Use this for the agent pool.
    pub fn validate_concurrency(&self, limits: &ExecutionLimits) -> Result<(), PoolSettingsError> {
        self.validate()?;

        // `u64::try_from` rather than `as`: a lossy cast here would silently satisfy
        // the check it exists to perform. `unwrap_or(u64::MAX)` cannot be reached on
        // any supported target and fails closed if it ever is.
        let concurrency = u64::try_from(limits.max_concurrent_queries).unwrap_or(u64::MAX);
        if u64::from(self.max_connections) < concurrency {
            return Err(PoolSettingsError::BelowConcurrency {
                max: self.max_connections,
                concurrency: limits.max_concurrent_queries,
            });
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn the_defaults_are_the_documented_numbers() {
        // `docs/operations.md` section 4, verbatim. SQLx's own defaults are
        // `max_connections: 10` and `acquire_timeout: 30s`, so this test is what
        // separates "configured" from "inherited".
        let agent = PoolSettings::agent();
        assert_eq!(agent.max_connections, 5);
        assert_eq!(agent.min_connections, 0);
        assert_eq!(agent.acquire_timeout, Duration::from_secs(3));

        let control = PoolSettings::control();
        assert_eq!(control.max_connections, 2);
        assert_eq!(control.min_connections, 1);
        assert_eq!(control.acquire_timeout, Duration::from_secs(3));

        agent.validate().unwrap();
        control.validate().unwrap();
        agent
            .validate_concurrency(&ExecutionLimits::default())
            .unwrap();
    }

    #[test]
    fn every_removed_bound_is_rejected_by_name() {
        let cases: [(&str, PoolSettings); 4] = [
            (
                "max_connections",
                PoolSettings {
                    max_connections: 0,
                    ..PoolSettings::agent()
                },
            ),
            (
                "acquire_timeout",
                PoolSettings {
                    acquire_timeout: Duration::ZERO,
                    ..PoolSettings::agent()
                },
            ),
            (
                "idle_timeout",
                PoolSettings {
                    idle_timeout: Some(Duration::ZERO),
                    ..PoolSettings::agent()
                },
            ),
            (
                "max_lifetime",
                PoolSettings {
                    max_lifetime: Some(Duration::ZERO),
                    ..PoolSettings::agent()
                },
            ),
        ];
        for (field, settings) in cases {
            assert_eq!(settings.validate(), Err(PoolSettingsError::Zero { field }));
        }
    }

    #[test]
    fn contradictory_settings_are_rejected() {
        let inverted = PoolSettings {
            min_connections: 6,
            ..PoolSettings::agent()
        };
        assert_eq!(
            inverted.validate(),
            Err(PoolSettingsError::MinAboveMax { min: 6, max: 5 })
        );

        let outlives = PoolSettings {
            idle_timeout: Some(Duration::from_secs(60)),
            max_lifetime: Some(Duration::from_secs(30)),
            ..PoolSettings::agent()
        };
        assert!(matches!(
            outlives.validate(),
            Err(PoolSettingsError::IdleAboveLifetime { .. })
        ));

        // Absent bounds are legal; only a present zero or an inversion is not.
        let unbounded = PoolSettings {
            idle_timeout: None,
            max_lifetime: None,
            ..PoolSettings::agent()
        };
        unbounded.validate().unwrap();
    }

    #[test]
    fn a_pool_smaller_than_the_concurrency_bound_fails_at_startup() {
        let limits = ExecutionLimits {
            max_concurrent_queries: 6,
            ..ExecutionLimits::default()
        };
        assert_eq!(
            PoolSettings::agent().validate_concurrency(&limits),
            Err(PoolSettingsError::BelowConcurrency {
                max: 5,
                concurrency: 6,
            })
        );

        // Equality is allowed: five permits and five connections is exactly enough.
        let exact = ExecutionLimits {
            max_concurrent_queries: 5,
            ..ExecutionLimits::default()
        };
        PoolSettings::agent().validate_concurrency(&exact).unwrap();
    }
}
