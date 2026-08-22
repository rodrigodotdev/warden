//! One connection's ports, capabilities, and concurrency bound.
//!
//! A `ConnectionRuntime` is what "the connection is chosen at runtime" actually
//! means: the composition root builds one per configured connection, wires the four
//! adapter objects into it, and the services then work through the ports without
//! knowing which engine answered (`docs/architecture.md` section 6).
//!
//! # Why the semaphore is private
//!
//! `docs/architecture.md` section 6 sketches `query_semaphore: Arc<Semaphore>` as a
//! field. Handing that out, even read-only, hands out
//! `Semaphore::add_permits(&self, n)`, which raises the connection's concurrency
//! limit at runtime and defeats SPEC section 6, invariant 17 in one safe line.
//!
//! So the runtime builds the semaphore from validated limits, keeps it private, and
//! offers exactly one way in: [`ConnectionRuntime::acquire_query_permit`], which
//! waits at most `limits.max_queue_wait` and then reports
//! `ConnectionError::Busy` — the `server_busy` of SPEC section 6, invariant 16.
//! Both bounds are therefore structural rather than a caller's responsibility.

use std::fmt;
use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use warden_core::connection::{Capabilities, ConnectionMetadata};
use warden_core::limits::ExecutionLimits;

use crate::analyzer::QueryAnalyzer;
use crate::error::{ConnectionError, RuntimeError};
use crate::executor::QueryExecutor;
use crate::explainer::Explainer;
use crate::inspector::SchemaInspector;

/// Everything one connection needs before it can serve a request.
///
/// A parts struct rather than a seven-argument constructor: a struct literal must
/// name every field, and two `Arc<dyn _>` values of different traits cannot be
/// transposed by accident — the same reasoning behind `QueryAnalysisParts` in
/// `warden-core`.
pub struct ConnectionRuntimeParts {
    /// The connection's public description.
    pub metadata: ConnectionMetadata,
    /// What this adapter can actually do.
    pub capabilities: Capabilities,
    /// The bounds every request on this connection runs under.
    pub limits: ExecutionLimits,
    /// The dialect analyzer.
    pub analyzer: Arc<dyn QueryAnalyzer>,
    /// The read-only executor.
    pub executor: Arc<dyn QueryExecutor>,
    /// The schema inspector.
    pub inspector: Arc<dyn SchemaInspector>,
    /// The non-executing explainer.
    pub explainer: Arc<dyn Explainer>,
}

/// Prints the describable half only.
///
/// Adding `Debug` as a supertrait to the ports would be the easy fix and the wrong
/// one: an adapter would derive it over a driver pool, and a pool's `Debug` can
/// print connect options (SPEC section 6, invariants 20 and 21).
impl fmt::Debug for ConnectionRuntimeParts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionRuntimeParts")
            .field("metadata", &self.metadata)
            .field("capabilities", &self.capabilities)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

/// One configured connection, ready to serve.
///
/// Fields are private with read-only accessors. The unit of sharing is
/// `Arc<ConnectionRuntime>`, which the registry hands out.
pub struct ConnectionRuntime {
    metadata: ConnectionMetadata,
    capabilities: Capabilities,
    limits: ExecutionLimits,
    analyzer: Arc<dyn QueryAnalyzer>,
    executor: Arc<dyn QueryExecutor>,
    inspector: Arc<dyn SchemaInspector>,
    explainer: Arc<dyn Explainer>,
    query_semaphore: Arc<Semaphore>,
}

impl ConnectionRuntime {
    /// Validates the parts and builds the connection's concurrency bound.
    ///
    /// Validation order matters: the limits are checked first, which is what rules
    /// out `Semaphore::new(max_concurrent_queries)` receiving zero — `ExecutionLimits`
    /// rejects a zero bound, and a semaphore with zero permits would deadlock every
    /// request instead of failing at startup. (`Semaphore::new` also panics above
    /// `Semaphore::MAX_PERMITS`, but that ceiling is far beyond any value validation
    /// needs to guard against.)
    pub fn new(parts: ConnectionRuntimeParts) -> Result<Self, RuntimeError> {
        parts
            .limits
            .validate()
            .map_err(|source| RuntimeError::Limits {
                name: parts.metadata.name.clone(),
                source,
            })?;

        let analyzer_dialect = parts.analyzer.dialect();
        if analyzer_dialect != parts.metadata.dialect {
            return Err(RuntimeError::DialectMismatch {
                name: parts.metadata.name.clone(),
                expected: parts.metadata.dialect,
                actual: analyzer_dialect,
            });
        }

        let query_semaphore = Arc::new(Semaphore::new(parts.limits.max_concurrent_queries));
        Ok(Self {
            metadata: parts.metadata,
            capabilities: parts.capabilities,
            limits: parts.limits,
            analyzer: parts.analyzer,
            executor: parts.executor,
            inspector: parts.inspector,
            explainer: parts.explainer,
            query_semaphore,
        })
    }

    /// The connection's public description.
    #[must_use]
    pub fn metadata(&self) -> &ConnectionMetadata {
        &self.metadata
    }

    /// What this adapter can actually do.
    ///
    /// Services inspect capabilities instead of matching on `Dialect`, except where
    /// the user-visible behavior is inherently dialect-specific, such as placeholder
    /// syntax (`docs/architecture.md` section 7).
    #[must_use]
    pub fn capabilities(&self) -> Capabilities {
        self.capabilities
    }

    /// The bounds every request on this connection runs under.
    ///
    /// This is the connection's own configured bound. `AuthorizedQuery::limits()` is
    /// whatever value the caller passed into `PolicyEngine::authorize`, and nothing
    /// checks the two agree — so Milestone 11 must pass this value into `authorize`
    /// rather than any other source, or a query could run under a different budget
    /// than the connection it targets actually has.
    #[must_use]
    pub fn limits(&self) -> ExecutionLimits {
        self.limits
    }

    /// The dialect analyzer.
    #[must_use]
    pub fn analyzer(&self) -> &dyn QueryAnalyzer {
        self.analyzer.as_ref()
    }

    /// The read-only executor.
    #[must_use]
    pub fn executor(&self) -> &dyn QueryExecutor {
        self.executor.as_ref()
    }

    /// The schema inspector.
    #[must_use]
    pub fn inspector(&self) -> &dyn SchemaInspector {
        self.inspector.as_ref()
    }

    /// The non-executing explainer.
    #[must_use]
    pub fn explainer(&self) -> &dyn Explainer {
        self.explainer.as_ref()
    }

    /// Waits for a concurrency slot, at most `limits.max_queue_wait`.
    ///
    /// An inherent `async fn` rather than a port method: there is no dynamic dispatch
    /// here, so ADR-0013's boxing requirement does not apply and the caller keeps a
    /// concrete, inspectable future.
    ///
    /// The wait is bounded because the query deadline measures execution, not
    /// queueing: without this bound, callers beyond `max_concurrent_queries` would
    /// wait indefinitely and client-perceived latency would include an unbounded
    /// queue (`docs/data-model.md` section 7).
    pub async fn acquire_query_permit(&self) -> Result<QueryPermit, ConnectionError> {
        let semaphore = Arc::clone(&self.query_semaphore);
        match timeout(self.limits.max_queue_wait, semaphore.acquire_owned()).await {
            Ok(Ok(permit)) => Ok(QueryPermit { _permit: permit }),
            // The semaphore is closed only during shutdown.
            Ok(Err(_closed)) => Err(ConnectionError::Unavailable {
                name: self.metadata.name.clone(),
            }),
            Err(_elapsed) => Err(ConnectionError::Busy {
                name: self.metadata.name.clone(),
            }),
        }
    }

    /// How many slots are free right now. Diagnostics and tests only.
    #[must_use]
    pub fn available_permits(&self) -> usize {
        self.query_semaphore.available_permits()
    }
}

/// See [`ConnectionRuntimeParts`]'s `Debug` for why this is hand-written.
impl fmt::Debug for ConnectionRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionRuntime")
            .field("metadata", &self.metadata)
            .field("capabilities", &self.capabilities)
            .field("limits", &self.limits)
            .field("available_permits", &self.available_permits())
            .finish_non_exhaustive()
    }
}

/// Proof that one request holds a concurrency slot on its connection.
///
/// The slot is released when this value is dropped, so it must be held for as long
/// as the query runs. There is no way to construct one except through
/// [`ConnectionRuntime::acquire_query_permit`], and no way to create extra slots at
/// all.
#[must_use = "dropping the permit releases the connection's concurrency slot"]
pub struct QueryPermit {
    /// Held for its `Drop` effect only; nothing ever reads it back.
    _permit: OwnedSemaphorePermit,
}

/// See [`ConnectionRuntimeParts`]'s `Debug` for why this is hand-written rather than
/// derived: a derived impl would render the permit's inner `Arc<Semaphore>` state.
impl fmt::Debug for QueryPermit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueryPermit").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::time::Duration;

    use warden_core::dialect::Dialect;
    use warden_core::error::PublicError;

    use super::*;
    use crate::testing;

    #[test]
    fn a_runtime_exposes_its_ports_and_hides_its_semaphore() {
        let runtime = testing::runtime(Dialect::MySql, ExecutionLimits::default());
        assert_eq!(runtime.metadata().name.as_str(), "production-db");
        assert_eq!(runtime.analyzer().dialect(), Dialect::MySql);
        assert!(runtime.capabilities().read_only_transactions);
        assert_eq!(runtime.limits(), ExecutionLimits::default());
        assert_eq!(
            runtime.available_permits(),
            ExecutionLimits::default().max_concurrent_queries
        );
    }

    #[test]
    fn debug_prints_no_port_and_no_secret() {
        let runtime = testing::runtime(Dialect::MySql, ExecutionLimits::default());
        let rendered = format!("{runtime:?}");
        assert!(rendered.contains("production-db"), "{rendered}");
        assert!(rendered.contains(".."), "{rendered}");
        assert!(!rendered.contains("FakeExecutor"), "{rendered}");
    }

    #[test]
    fn parts_debug_also_prints_no_port_and_no_secret() {
        let parts = ConnectionRuntimeParts {
            metadata: testing::connection(Dialect::MySql),
            capabilities: testing::capabilities(),
            limits: ExecutionLimits::default(),
            analyzer: Arc::new(testing::FakeAnalyzer::new(Dialect::MySql)),
            executor: Arc::new(testing::FakeExecutor::default()),
            inspector: Arc::new(testing::FakeInspector::default()),
            explainer: Arc::new(testing::FakeExplainer::default()),
        };
        let rendered = format!("{parts:?}");
        assert!(rendered.contains("production-db"), "{rendered}");
        assert!(rendered.contains(".."), "{rendered}");
        for field in ["analyzer", "executor", "inspector", "explainer"] {
            assert!(!rendered.contains(field), "{rendered}");
        }
        assert!(!rendered.contains("FakeExecutor"), "{rendered}");
        // The milestone checklist requires that `Debug` print metadata, capabilities,
        // and limits — the previous assertions prove the ports are absent, these
        // prove the required fields are actually present.
        assert!(rendered.contains("capabilities"), "{rendered}");
        assert!(rendered.contains("limits"), "{rendered}");
    }

    #[test]
    fn invalid_limits_fail_at_startup_instead_of_at_the_first_query() {
        let limits = ExecutionLimits {
            max_concurrent_queries: 0,
            ..ExecutionLimits::default()
        };
        let error = testing::try_runtime(Dialect::MySql, limits, Dialect::MySql).unwrap_err();
        assert!(matches!(error, RuntimeError::Limits { .. }), "{error:?}");
    }

    #[test]
    fn an_analyzer_for_the_wrong_dialect_fails_at_startup() {
        let error = testing::try_runtime(
            Dialect::PostgreSql,
            ExecutionLimits::default(),
            Dialect::MySql,
        )
        .unwrap_err();
        assert_eq!(
            error,
            RuntimeError::DialectMismatch {
                name: "production-db".parse().unwrap(),
                expected: Dialect::PostgreSql,
                actual: Dialect::MySql,
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn concurrency_is_bounded_and_the_queue_wait_is_too() {
        let limits = ExecutionLimits {
            max_concurrent_queries: 1,
            max_queue_wait: Duration::from_secs(2),
            ..ExecutionLimits::default()
        };
        let runtime = testing::runtime(Dialect::MySql, limits);

        let held = runtime.acquire_query_permit().await.unwrap();
        assert_eq!(runtime.available_permits(), 0);

        // The second caller waits exactly `max_queue_wait` and is then told the
        // connection is busy, rather than waiting for a query it cannot see. Asserting
        // the elapsed time, not merely that the call eventually returns, is what
        // distinguishes this connection's own configured bound from any other
        // hardcoded duration a future refactor might substitute for it.
        let started = tokio::time::Instant::now();
        let error = runtime.acquire_query_permit().await.unwrap_err();
        assert_eq!(started.elapsed(), limits.max_queue_wait);
        assert_eq!(
            error,
            ConnectionError::Busy {
                name: "production-db".parse().unwrap(),
            }
        );
        assert_eq!(
            error.public_code(),
            warden_core::error::PublicErrorCode::ServerBusy
        );

        drop(held);
        assert_eq!(runtime.available_permits(), 1);
        let reacquired = runtime.acquire_query_permit().await.unwrap();
        drop(reacquired);
    }
}
