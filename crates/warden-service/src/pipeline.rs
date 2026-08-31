//! The one place in this crate that may reach a database.
//!
//! ADR-0032 made the concurrency permit a parameter of `execute_read_only` and
//! `explain`, so execution cannot begin without a slot. It deliberately did not
//! resolve two remaining gaps, both recorded in `docs/open-questions.md` item 14:
//!
//! * a `&QueryPermit` carries no connection identity, so a permit taken on one
//!   connection type-checks against another's executor;
//! * nothing ordered the permit against `AuditSink::record_attempt`, which ADR-0022
//!   requires to happen first.
//!
//! [`ExecutionGate`] closes both by construction. Its only constructor records the
//! attempt, and *then* acquires the permit from the same [`ConnectionRuntime`] it
//! stores and later dispatches to. There is no other constructor, no accessor that
//! hands the permit out, and no way to build one from a runtime it will not use
//! (ADR-0038).
//!
//! The guarantee is scoped honestly: it holds because this gate is the only caller of
//! `acquire_query_permit`, `executor()`, and `explainer()` in `warden-service`, which
//! `tests/service_rules.rs` asserts mechanically. It does not constrain a future crate
//! that calls the ports directly, and it does not replace database privileges
//! (ADR-0016).

#![cfg_attr(
    not(test),
    expect(dead_code, reason = "Task 6 consumes the gate's explain path")
)]

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use warden_core::explain::QueryPlan;
use warden_core::result::ResultSet;
use warden_policy::AuthorizedQuery;
use warden_ports::{
    AuditAttempt, AuditError, AuditSink, ConnectionError, ConnectionRuntime, ExecuteError,
    ExplainError, QueryPermit,
};

use crate::audit;
use crate::limits::RequestBudget;

/// Why a request never reached the database.
///
/// The two variants have different consequences for the caller, which is why they are
/// distinct: an audit failure means no attempt was recorded, so there is no outcome to
/// complete, while a connection failure means the attempt is already on record and the
/// caller owes it an outcome (`AuditOutcome::NotStarted`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum GateError {
    /// The attempt could not be recorded, so nothing may run.
    #[error(transparent)]
    Audit(AuditError),
    /// The connection could not give this request a slot.
    #[error(transparent)]
    Connection(ConnectionError),
}

/// An authorized statement, its connection, a recorded attempt, and that connection's
/// permit — in that order, held together.
#[derive(Debug)]
pub(crate) struct ExecutionGate<'a> {
    runtime: &'a ConnectionRuntime,
    query: AuthorizedQuery,
    /// Both the witness `execute_read_only` and `explain` require (ADR-0032) and the
    /// slot itself: dropping the gate releases it.
    permit: QueryPermit,
    deadline: Instant,
    cancel: CancellationToken,
}

impl<'a> ExecutionGate<'a> {
    /// Records the attempt, then takes a permit from the same runtime.
    ///
    /// The order is the contract. A caller cannot reverse it, skip the attempt, or
    /// pair the permit with a different connection, because this is the only
    /// constructor and it does all three itself.
    pub(crate) async fn enter(
        runtime: &'a ConnectionRuntime,
        sink: &dyn AuditSink,
        attempt: &AuditAttempt,
        query: AuthorizedQuery,
        cancel: CancellationToken,
    ) -> Result<Self, GateError> {
        audit::record_attempt(sink, attempt)
            .await
            .map_err(GateError::Audit)?;
        let permit = runtime
            .acquire_query_permit()
            .await
            .map_err(GateError::Connection)?;
        Ok(Self {
            runtime,
            query,
            permit,
            deadline: RequestBudget::new(runtime.limits()).deadline(Instant::now()),
            cancel,
        })
    }

    /// Runs the statement, releasing the slot when the call returns.
    ///
    /// Takes `self` by value so the permit is dropped at the end of the call rather
    /// than whenever the caller happens to drop the gate.
    pub(crate) async fn execute(self) -> Result<ResultSet, ExecuteError> {
        self.runtime
            .executor()
            .execute_read_only(
                &self.query,
                &self.permit,
                self.deadline,
                self.cancel.clone(),
            )
            .await
    }

    /// Plans the statement without running it, releasing the slot when the call
    /// returns.
    pub(crate) async fn explain(self) -> Result<QueryPlan, ExplainError> {
        self.runtime
            .explainer()
            .explain(
                &self.query,
                &self.permit,
                self.deadline,
                self.cancel.clone(),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::Arc;
    use std::time::Duration;

    use tokio_util::sync::CancellationToken;
    use warden_core::dialect::Dialect;
    use warden_core::limits::ExecutionLimits;
    use warden_ports::{ConnectionError, ExecuteError, ExplainError};

    use super::*;
    use crate::testing;

    #[tokio::test]
    async fn entering_records_the_attempt_before_taking_a_permit() {
        let sink = testing::FakeAuditSink::new();
        let runtime = testing::runtime(Dialect::MySql);
        let attempt = testing::attempt();
        let gate = ExecutionGate::enter(
            &runtime,
            &sink,
            &attempt,
            testing::authorized(&runtime),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(sink.attempts().len(), 1);
        assert_eq!(
            runtime.available_permits(),
            ExecutionLimits::default().max_concurrent_queries - 1
        );
        drop(gate);
        assert_eq!(
            runtime.available_permits(),
            ExecutionLimits::default().max_concurrent_queries
        );
    }

    #[tokio::test]
    async fn a_broken_attempt_write_takes_no_permit_and_reaches_no_executor() {
        let sink = testing::FakeAuditSink::broken_attempts();
        let executor = Arc::new(testing::FakeExecutor::new());
        let runtime = testing::runtime_with_executor(Dialect::MySql, Arc::clone(&executor));
        let error = ExecutionGate::enter(
            &runtime,
            &sink,
            &testing::attempt(),
            testing::authorized(&runtime),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, GateError::Audit(_)));
        assert!(
            sink.attempts().is_empty(),
            "a failed write must not look recorded"
        );
        assert_eq!(executor.calls(), 0, "the database must not be reached");
        assert_eq!(
            runtime.available_permits(),
            ExecutionLimits::default().max_concurrent_queries
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_saturated_connection_reports_busy_after_max_queue_wait() {
        let limits = ExecutionLimits {
            max_concurrent_queries: 1,
            ..ExecutionLimits::default()
        };
        let runtime = testing::runtime_with_limits(Dialect::MySql, limits);
        let sink = testing::FakeAuditSink::new();
        let held = ExecutionGate::enter(
            &runtime,
            &sink,
            &testing::attempt(),
            testing::authorized(&runtime),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let error = ExecutionGate::enter(
            &runtime,
            &sink,
            &testing::attempt(),
            testing::authorized(&runtime),
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            error,
            GateError::Connection(ConnectionError::Busy { .. })
        ));
        // The second attempt was still recorded: the ordering is attempt first.
        assert_eq!(sink.attempts().len(), 2);
        drop(held);
    }

    #[tokio::test]
    async fn the_gate_passes_the_client_deadline_and_the_token_through() {
        let runtime = testing::runtime(Dialect::MySql);
        let cancel = CancellationToken::new();
        cancel.cancel();
        let gate = ExecutionGate::enter(
            &runtime,
            &testing::FakeAuditSink::new(),
            &testing::attempt(),
            testing::authorized(&runtime),
            cancel,
        )
        .await
        .unwrap();
        assert_eq!(gate.execute().await.unwrap_err(), ExecuteError::Cancelled);
        assert_eq!(
            runtime.available_permits(),
            ExecutionLimits::default().max_concurrent_queries
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_adapter_meets_the_deadline_rather_than_running_forever() {
        let runtime = testing::runtime_with_executor(
            Dialect::MySql,
            Arc::new(testing::FakeExecutor::taking(Duration::from_secs(600))),
        );
        let gate = ExecutionGate::enter(
            &runtime,
            &testing::FakeAuditSink::new(),
            &testing::attempt(),
            testing::authorized(&runtime),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(gate.execute().await.unwrap_err(), ExecuteError::Timeout);
        assert_eq!(
            runtime.available_permits(),
            ExecutionLimits::default().max_concurrent_queries
        );
    }

    #[tokio::test]
    async fn a_successful_execution_releases_its_permit() {
        let runtime = testing::runtime(Dialect::MySql);
        let gate = ExecutionGate::enter(
            &runtime,
            &testing::FakeAuditSink::new(),
            &testing::attempt(),
            testing::authorized(&runtime),
            CancellationToken::new(),
        )
        .await
        .unwrap();

        gate.execute().await.unwrap();

        assert_eq!(
            runtime.available_permits(),
            ExecutionLimits::default().max_concurrent_queries
        );
    }

    #[tokio::test]
    async fn an_adapter_execution_error_releases_its_permit() {
        let runtime = testing::runtime_with_executor(
            Dialect::MySql,
            Arc::new(testing::FakeExecutor::failing(ExecuteError::Database {
                detail: "fixture failure".to_owned(),
            })),
        );
        let gate = ExecutionGate::enter(
            &runtime,
            &testing::FakeAuditSink::new(),
            &testing::attempt(),
            testing::authorized(&runtime),
            CancellationToken::new(),
        )
        .await
        .unwrap();

        assert!(matches!(
            gate.execute().await,
            Err(ExecuteError::Database { .. })
        ));
        assert_eq!(
            runtime.available_permits(),
            ExecutionLimits::default().max_concurrent_queries
        );
    }

    #[tokio::test]
    async fn a_successful_explain_releases_its_permit() {
        let runtime = testing::runtime(Dialect::MySql);
        let gate = ExecutionGate::enter(
            &runtime,
            &testing::FakeAuditSink::new(),
            &testing::attempt(),
            testing::authorized(&runtime),
            CancellationToken::new(),
        )
        .await
        .unwrap();

        gate.explain().await.unwrap();

        assert_eq!(
            runtime.available_permits(),
            ExecutionLimits::default().max_concurrent_queries
        );
    }

    #[tokio::test]
    async fn an_adapter_explain_error_releases_its_permit() {
        let runtime = testing::runtime_with_explainer(
            Dialect::MySql,
            Arc::new(testing::FakeExplainer::failing(ExplainError::Database {
                detail: "fixture failure".to_owned(),
            })),
        );
        let gate = ExecutionGate::enter(
            &runtime,
            &testing::FakeAuditSink::new(),
            &testing::attempt(),
            testing::authorized(&runtime),
            CancellationToken::new(),
        )
        .await
        .unwrap();

        assert!(matches!(
            gate.explain().await,
            Err(ExplainError::Database { .. })
        ));
        assert_eq!(
            runtime.available_permits(),
            ExecutionLimits::default().max_concurrent_queries
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cancelling_an_explain_releases_its_permit() {
        let cancel = CancellationToken::new();
        cancel.cancel();
        let runtime = testing::runtime_with_explainer(
            Dialect::MySql,
            Arc::new(testing::FakeExplainer::taking(Duration::from_secs(600))),
        );
        let gate = ExecutionGate::enter(
            &runtime,
            &testing::FakeAuditSink::new(),
            &testing::attempt(),
            testing::authorized(&runtime),
            cancel,
        )
        .await
        .unwrap();

        assert_eq!(gate.explain().await.unwrap_err(), ExplainError::Cancelled);
        assert_eq!(
            runtime.available_permits(),
            ExecutionLimits::default().max_concurrent_queries
        );
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_an_in_flight_execution_releases_its_permit() {
        let limits = ExecutionLimits {
            max_concurrent_queries: 1,
            ..ExecutionLimits::default()
        };
        let executor = Arc::new(testing::FakeExecutor::taking(Duration::from_secs(600)));
        let mut parts = testing::FakeParts::new(Dialect::MySql);
        parts.limits = limits;
        parts.executor = executor;
        let runtime = testing::runtime_from(parts);
        let gate = ExecutionGate::enter(
            &runtime,
            &testing::FakeAuditSink::new(),
            &testing::attempt(),
            testing::authorized(&runtime),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let mut execution = Box::pin(gate.execute());
        tokio::select! {
            result = &mut execution => panic!("execution unexpectedly finished: {result:?}"),
            () = tokio::time::sleep(Duration::from_millis(1)) => {}
        }
        assert_eq!(runtime.available_permits(), 0);

        drop(execution);

        assert_eq!(runtime.available_permits(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_an_in_flight_explain_releases_its_permit() {
        let limits = ExecutionLimits {
            max_concurrent_queries: 1,
            ..ExecutionLimits::default()
        };
        let explainer = Arc::new(testing::FakeExplainer::taking(Duration::from_secs(600)));
        let mut parts = testing::FakeParts::new(Dialect::MySql);
        parts.limits = limits;
        parts.explainer = explainer;
        let runtime = testing::runtime_from(parts);
        let gate = ExecutionGate::enter(
            &runtime,
            &testing::FakeAuditSink::new(),
            &testing::attempt(),
            testing::authorized(&runtime),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let mut explanation = Box::pin(gate.explain());
        tokio::select! {
            result = &mut explanation => panic!("explain unexpectedly finished: {result:?}"),
            () = tokio::time::sleep(Duration::from_millis(1)) => {}
        }
        assert_eq!(runtime.available_permits(), 0);

        drop(explanation);

        assert_eq!(runtime.available_permits(), 1);
    }

    #[tokio::test]
    async fn execute_receives_the_same_cancellation_domain_not_a_child() {
        let executor = Arc::new(testing::FakeExecutor::new());
        let runtime = testing::runtime_with_executor(Dialect::MySql, Arc::clone(&executor));
        let cancel = CancellationToken::new();
        let gate = ExecutionGate::enter(
            &runtime,
            &testing::FakeAuditSink::new(),
            &testing::attempt(),
            testing::authorized(&runtime),
            cancel.clone(),
        )
        .await
        .unwrap();

        gate.execute().await.unwrap();

        let (_, observed_cancel) = executor.latest_observation();
        observed_cancel.cancel();
        assert!(cancel.is_cancelled());
    }

    #[tokio::test]
    async fn explain_receives_the_same_cancellation_domain_not_a_child() {
        let explainer = Arc::new(testing::FakeExplainer::new());
        let runtime = testing::runtime_with_explainer(Dialect::MySql, Arc::clone(&explainer));
        let cancel = CancellationToken::new();
        let gate = ExecutionGate::enter(
            &runtime,
            &testing::FakeAuditSink::new(),
            &testing::attempt(),
            testing::authorized(&runtime),
            cancel.clone(),
        )
        .await
        .unwrap();

        gate.explain().await.unwrap();

        let (_, observed_cancel) = explainer.latest_observation();
        observed_cancel.cancel();
        assert!(cancel.is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn execute_receives_the_original_token_and_a_post_queue_deadline() {
        let queue_wait = Duration::from_millis(500);
        let limits = ExecutionLimits {
            max_concurrent_queries: 1,
            ..ExecutionLimits::default()
        };
        let executor = Arc::new(testing::FakeExecutor::new());
        let mut parts = testing::FakeParts::new(Dialect::MySql);
        parts.limits = limits;
        parts.executor = Arc::clone(&executor) as Arc<dyn warden_ports::QueryExecutor>;
        let runtime = testing::runtime_from(parts);
        let held = ExecutionGate::enter(
            &runtime,
            &testing::FakeAuditSink::new(),
            &testing::attempt(),
            testing::authorized(&runtime),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let cancel = CancellationToken::new();
        let waiting_sink = testing::FakeAuditSink::new();
        let waiting_attempt = testing::attempt();
        let mut waiting = Box::pin(ExecutionGate::enter(
            &runtime,
            &waiting_sink,
            &waiting_attempt,
            testing::authorized(&runtime),
            cancel.clone(),
        ));
        tokio::select! {
            result = &mut waiting => panic!("permit acquired while held: {result:?}"),
            () = tokio::time::sleep(queue_wait) => {}
        }
        drop(held);
        let gate = waiting.await.unwrap();
        let permit_acquired_at = Instant::now();

        gate.execute().await.unwrap();

        let (deadline, observed_cancel) = executor.latest_observation();
        assert_eq!(deadline, permit_acquired_at + limits.client_timeout());
        assert!(!observed_cancel.is_cancelled());
        cancel.cancel();
        assert!(observed_cancel.is_cancelled());
        assert_eq!(runtime.available_permits(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn explain_receives_the_original_token_and_a_post_queue_deadline() {
        let queue_wait = Duration::from_millis(500);
        let limits = ExecutionLimits {
            max_concurrent_queries: 1,
            ..ExecutionLimits::default()
        };
        let explainer = Arc::new(testing::FakeExplainer::new());
        let mut parts = testing::FakeParts::new(Dialect::MySql);
        parts.limits = limits;
        parts.explainer = Arc::clone(&explainer) as Arc<dyn warden_ports::Explainer>;
        let runtime = testing::runtime_from(parts);
        let held = ExecutionGate::enter(
            &runtime,
            &testing::FakeAuditSink::new(),
            &testing::attempt(),
            testing::authorized(&runtime),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let cancel = CancellationToken::new();
        let waiting_sink = testing::FakeAuditSink::new();
        let waiting_attempt = testing::attempt();
        let mut waiting = Box::pin(ExecutionGate::enter(
            &runtime,
            &waiting_sink,
            &waiting_attempt,
            testing::authorized(&runtime),
            cancel.clone(),
        ));
        tokio::select! {
            result = &mut waiting => panic!("permit acquired while held: {result:?}"),
            () = tokio::time::sleep(queue_wait) => {}
        }
        drop(held);
        let gate = waiting.await.unwrap();
        let permit_acquired_at = Instant::now();

        gate.explain().await.unwrap();

        let (deadline, observed_cancel) = explainer.latest_observation();
        assert_eq!(deadline, permit_acquired_at + limits.client_timeout());
        assert!(!observed_cancel.is_cancelled());
        cancel.cancel();
        assert!(observed_cancel.is_cancelled());
        assert_eq!(runtime.available_permits(), 1);
    }
}
