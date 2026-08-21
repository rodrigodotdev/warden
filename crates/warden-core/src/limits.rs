//! Per-request resource bounds.

use std::time::Duration;

/// The highest configurable total result size.
///
/// `docs/data-model.md` section 7: the consumer is model context, and 1 MiB of JSON
/// is roughly 250,000 tokens, so a client exhausts its context long before Warden
/// truncates. The default is a quarter of this.
pub const MAX_RESULT_BYTES_CEILING: usize = 1024 * 1024;

/// A limit that would disable a bound or exceed its ceiling.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LimitsError {
    /// A limit was zero, which would remove the bound entirely.
    #[error("execution limit `{field}` must be greater than zero")]
    Zero {
        /// Name of the offending field.
        field: &'static str,
    },
    /// `max_result_bytes` exceeded [`MAX_RESULT_BYTES_CEILING`].
    #[error("max_result_bytes is {actual} bytes; the ceiling is {ceiling}")]
    AboveCeiling {
        /// Configured value.
        actual: usize,
        /// Hard ceiling.
        ceiling: usize,
    },
    /// A per-value budget larger than the total budget cannot bind anything.
    #[error("max_value_bytes ({value}) exceeds max_result_bytes ({total})")]
    ValueAboveTotal {
        /// Configured per-value budget.
        value: usize,
        /// Configured total budget.
        total: usize,
    },
}

/// The bounds one request runs under.
///
/// Fields are public because these are operator-chosen capacity settings, not
/// security state — but startup calls [`ExecutionLimits::validate`] before anything
/// uses them (`docs/operations.md` section 3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionLimits {
    /// The query deadline.
    ///
    /// Adapters apply this server-side and set the client-side safety net slightly
    /// later, so the normal path receives a clean server error and returns an
    /// intact connection to the pool (`docs/operations.md` section 5.3). Deriving
    /// the two values belongs to Milestone 6.
    pub timeout: Duration,
    /// The longest wait for a concurrency permit before `server_busy`.
    ///
    /// Necessary because `timeout` measures execution, not waiting: without it,
    /// queued callers wait unboundedly.
    pub max_queue_wait: Duration,
    /// The largest number of rows returned.
    pub max_rows: usize,
    /// The largest normalized size of a single value.
    ///
    /// Necessary because one row holding a 500 MB `TEXT` is bounded by neither
    /// `max_rows` nor incremental byte accounting. This bounds what leaves Warden;
    /// the driver still materializes the incoming value.
    pub max_value_bytes: usize,
    /// The largest normalized size of a whole result.
    pub max_result_bytes: usize,
    /// The largest number of concurrent queries on one connection.
    pub max_concurrent_queries: usize,
}

impl Default for ExecutionLimits {
    /// The initial production defaults from `docs/data-model.md` section 7.
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            max_queue_wait: Duration::from_secs(2),
            max_rows: 200,
            max_value_bytes: 64 * 1024,
            max_result_bytes: 256 * 1024,
            max_concurrent_queries: 3,
        }
    }
}

impl ExecutionLimits {
    /// Rejects limits that disable a bound, exceed the ceiling, or contradict.
    pub fn validate(&self) -> Result<(), LimitsError> {
        for (field, is_zero) in [
            ("timeout", self.timeout.is_zero()),
            ("max_queue_wait", self.max_queue_wait.is_zero()),
            ("max_rows", self.max_rows == 0),
            ("max_value_bytes", self.max_value_bytes == 0),
            ("max_result_bytes", self.max_result_bytes == 0),
            ("max_concurrent_queries", self.max_concurrent_queries == 0),
        ] {
            if is_zero {
                return Err(LimitsError::Zero { field });
            }
        }
        if self.max_result_bytes > MAX_RESULT_BYTES_CEILING {
            return Err(LimitsError::AboveCeiling {
                actual: self.max_result_bytes,
                ceiling: MAX_RESULT_BYTES_CEILING,
            });
        }
        if self.max_value_bytes > self.max_result_bytes {
            return Err(LimitsError::ValueAboveTotal {
                value: self.max_value_bytes,
                total: self.max_result_bytes,
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
    fn defaults_match_the_data_model() {
        let limits = ExecutionLimits::default();
        assert_eq!(limits.timeout, Duration::from_secs(5));
        assert_eq!(limits.max_queue_wait, Duration::from_secs(2));
        assert_eq!(limits.max_rows, 200);
        assert_eq!(limits.max_value_bytes, 65_536);
        assert_eq!(limits.max_result_bytes, 262_144);
        assert_eq!(limits.max_concurrent_queries, 3);
    }

    #[test]
    fn the_defaults_are_valid() {
        ExecutionLimits::default().validate().unwrap();
    }

    #[test]
    fn every_zero_limit_is_rejected_by_name() {
        let cases: [(&str, ExecutionLimits); 6] = [
            (
                "timeout",
                ExecutionLimits {
                    timeout: Duration::ZERO,
                    ..Default::default()
                },
            ),
            (
                "max_queue_wait",
                ExecutionLimits {
                    max_queue_wait: Duration::ZERO,
                    ..Default::default()
                },
            ),
            (
                "max_rows",
                ExecutionLimits {
                    max_rows: 0,
                    ..Default::default()
                },
            ),
            (
                "max_value_bytes",
                ExecutionLimits {
                    max_value_bytes: 0,
                    ..Default::default()
                },
            ),
            (
                "max_result_bytes",
                ExecutionLimits {
                    max_result_bytes: 0,
                    ..Default::default()
                },
            ),
            (
                "max_concurrent_queries",
                ExecutionLimits {
                    max_concurrent_queries: 0,
                    ..Default::default()
                },
            ),
        ];
        for (field, limits) in cases {
            assert_eq!(limits.validate(), Err(LimitsError::Zero { field }));
        }
    }

    #[test]
    fn the_ceiling_and_the_value_budget_are_enforced() {
        let above = ExecutionLimits {
            max_result_bytes: MAX_RESULT_BYTES_CEILING + 1,
            ..Default::default()
        };
        assert_eq!(
            above.validate(),
            Err(LimitsError::AboveCeiling {
                actual: MAX_RESULT_BYTES_CEILING + 1,
                ceiling: MAX_RESULT_BYTES_CEILING,
            })
        );

        let at_ceiling = ExecutionLimits {
            max_result_bytes: MAX_RESULT_BYTES_CEILING,
            ..Default::default()
        };
        at_ceiling.validate().unwrap();

        let inverted = ExecutionLimits {
            max_value_bytes: 512 * 1024,
            max_result_bytes: 256 * 1024,
            ..Default::default()
        };
        assert!(matches!(
            inverted.validate(),
            Err(LimitsError::ValueAboveTotal { .. })
        ));
    }
}
