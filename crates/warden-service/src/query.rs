//! `resolve -> analyze -> authorize -> attempt -> acquire -> execute -> redact ->
//! outcome`.
//!
//! The order is `docs/architecture.md` section 8's, and the two steps that are not
//! visible in this file are the point:
//!
//! * **Input size validation** happened in `QueryRequest::new`, before this service
//!   could be called: there is no way to hand it an unvalidated statement, because
//!   the type does not exist without the check (`docs/data-model.md` section 2).
//! * **Normalization** happens inside the adapter, under the row, value, and byte
//!   budgets carried by the `AuthorizedQuery` — which is why this service passes
//!   `runtime.limits()` into `PolicyEngine::authorize` and no other value
//!   (`crates/warden-ports/src/runtime.rs` says so explicitly).
//!
//! Every exit records an outcome for the attempt it recorded, including the paths
//! where nothing ran. A failed attempt write on an authorized statement is the one
//! exception: no attempt was recorded, so there is nothing to complete and nothing
//! may run. A statement already refused by analysis or policy keeps that refusal even
//! if either audit write fails.

use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;
use warden_core::context::RequestContext;
use warden_core::error::PublicError;
use warden_core::query::QueryRequest;
use warden_core::result::ResultSet;
use warden_policy::PolicyEngine;
use warden_ports::{
    AuditOperation, AuditOutcome, AuditOutcomeEvent, AuditSink, ConnectionRegistry, ExecuteError,
};

use crate::error::QueryServiceError;
use crate::pipeline::{GateError, ServiceCore};
use crate::redaction::Redactor;

/// Runs one agent statement, end to end.
///
/// A thin wrapper over `ServiceCore`, which holds the collaborators and runs the
/// preflight this service shares with [`crate::ExplainService`]. What is left here is
/// what genuinely differs: the operation constant, the root span, the gated call, the
/// error-to-outcome map, and the redaction step.
#[derive(Debug)]
pub struct QueryService {
    core: ServiceCore,
}

impl QueryService {
    /// Wires the collaborators one query needs.
    #[must_use]
    pub fn new(
        registry: Arc<dyn ConnectionRegistry>,
        engine: Arc<PolicyEngine>,
        audit: Arc<dyn AuditSink>,
        redactor: Arc<Redactor>,
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            core: ServiceCore::new(registry, engine, audit, redactor, shutdown),
        }
    }

    /// Executes one validated statement and returns a bounded, redacted result.
    ///
    /// # Errors
    ///
    /// In pipeline order, which is also the order the audit records them:
    /// - [`QueryServiceError::Connection`] if the name resolves to no connection, or
    ///   if no concurrency slot came free within `max_queue_wait`.
    /// - [`QueryServiceError::Analyze`] if the statement does not parse.
    /// - [`QueryServiceError::Rejected`] if policy denied it, carrying every reason.
    /// - [`QueryServiceError::Audit`] if the *attempt* record could not be written.
    ///   This denies the query: an unauditable execution does not happen (ADR-0022).
    /// - [`QueryServiceError::Execute`] if the database refused or the deadline
    ///   elapsed.
    ///
    /// A failed *outcome* record is not an error here — execution already happened,
    /// so it raises an alarm and the result is still returned.
    pub async fn execute(
        &self,
        context: &RequestContext,
        request: QueryRequest,
    ) -> Result<ResultSet, QueryServiceError> {
        let span = tracing::info_span!(
            "warden.query",
            request_id = %context.request_id(),
            connection = %request.connection(),
        );
        let outcome_parent = span.clone();
        async move {
            let preflight = self
                .core
                .preflight(context, request, AuditOperation::Query)
                .await?;
            let (runtime, attempt, authorized) = preflight.into_parts();

            let (gate, guard) = match self
                .core
                .gate(&runtime, &attempt, authorized, outcome_parent)
                .await
            {
                Ok(gate) => gate,
                // No attempt was recorded, so there is no outcome to complete.
                Err(GateError::Audit(error)) => return Err(error.into()),
                // The gate completed the recorded attempt as not_started.
                Err(GateError::Connection { error, .. }) => return Err(error.into()),
            };

            let queue_wait = gate.queue_wait();
            match gate.execute().await {
                Ok(mut result) => {
                    {
                        let _entered = tracing::debug_span!("result.redact").entered();
                        self.core.redactor().redact_result(&mut result);
                    }
                    guard
                        .complete(AuditOutcomeEvent {
                            attempt_id: attempt.id,
                            outcome: AuditOutcome::Succeeded,
                            // The adapter's own clock over the whole database call, not a
                            // measurement of the statement alone: it starts before the
                            // pool checkout and `BEGIN READ ONLY` and their setup round
                            // trips, and stops once the rows are collected and normalized,
                            // before rollback and cleanup
                            // (`crates/warden-mysql/src/execute.rs`; PostgreSQL has the
                            // same shape). `explain.rs` records a service-side elapsed
                            // time instead, because a `QueryPlan` carries no stats; the
                            // two are not the same quantity and an auditor should not
                            // compare them directly.
                            duration: Some(result.stats.duration),
                            queue_wait: Some(queue_wait),
                            rows_returned: Some(result.stats.rows_returned),
                            // After redaction, so the figure describes what the agent
                            // actually receives.
                            result_bytes: Some(result.stats.bytes),
                            error_code: None,
                        })
                        .await;
                    Ok(result)
                }
                Err(error) => {
                    let outcome = match &error {
                        ExecuteError::Timeout => AuditOutcome::TimedOut,
                        ExecuteError::Cancelled => AuditOutcome::Cancelled,
                        ExecuteError::ResultTooLarge { .. }
                        | ExecuteError::Normalization(_)
                        | ExecuteError::Database { .. } => AuditOutcome::Failed,
                    };
                    let code = error.public_code();
                    guard
                        .complete(AuditOutcomeEvent {
                            attempt_id: attempt.id,
                            outcome,
                            duration: None,
                            queue_wait: Some(queue_wait),
                            rows_returned: None,
                            result_bytes: None,
                            error_code: Some(code),
                        })
                        .await;
                    Err(error.into())
                }
            }
        }
        .instrument(span)
        .await
    }
}

#[cfg(test)]
pub(crate) fn redactor_arc(service: &QueryService) -> &Redactor {
    service.core.redactor()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::time::Duration;

    use std::sync::Arc;

    use warden_core::dialect::Dialect;
    use warden_core::error::{PublicError, PublicErrorCode};
    use warden_core::result::NormalizationError;
    use warden_ports::{AnalyzeError, AuditOutcome, ExecuteError};

    use crate::testing;

    #[tokio::test]
    async fn a_safe_select_runs_and_is_audited_twice() {
        let sink = Arc::new(testing::FakeAuditSink::new());
        let service = testing::query_service(testing::ServiceFakes {
            audit: sink.clone(),
            ..testing::ServiceFakes::default()
        });
        let result = service
            .execute(&testing::request_context(), testing::request())
            .await
            .unwrap();
        assert_eq!(result.rows.len(), 1);
        let attempts = sink.attempts();
        let outcomes = sink.outcomes();
        assert_eq!(attempts.len(), 1);
        assert_eq!(outcomes.len(), 1);
        let outcome = &outcomes[0];
        assert_eq!(outcome.outcome, AuditOutcome::Succeeded);
        assert_eq!(outcome.attempt_id, attempts[0].id);
        assert_eq!(outcome.rows_returned, Some(1));
        assert_eq!(outcome.result_bytes, Some(result.stats.bytes));
        assert_eq!(outcome.error_code, None);
    }

    #[tokio::test]
    async fn an_unknown_connection_never_reaches_an_analyzer() {
        let service = testing::query_service(testing::ServiceFakes::default());
        let error = service
            .execute(
                &testing::request_context(),
                testing::request_for("staging-db"),
            )
            .await
            .unwrap_err();
        assert_eq!(error.public_code(), PublicErrorCode::ConnectionNotFound);
    }

    #[tokio::test]
    async fn a_denied_statement_is_audited_with_every_reason_and_never_runs() {
        let executor = Arc::new(testing::FakeExecutor::new());
        let sink = Arc::new(testing::FakeAuditSink::new());
        let service = testing::query_service(testing::ServiceFakes {
            analyzer: Arc::new(testing::FakeAnalyzer::writing(Dialect::MySql)),
            executor: executor.clone(),
            audit: sink.clone(),
            ..testing::ServiceFakes::default()
        });
        let error = service
            .execute(&testing::request_context(), testing::request())
            .await
            .unwrap_err();
        assert_eq!(error.public_code(), PublicErrorCode::QueryRejected);
        assert_eq!(executor.calls(), 0);
        let attempts = sink.attempts();
        let outcomes = sink.outcomes();
        assert_eq!(attempts.len(), 1);
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].attempt_id, attempts[0].id);
        assert_eq!(
            attempts[0]
                .deny_reasons
                .iter()
                .map(warden_policy::DenyReason::code)
                .collect::<Vec<_>>(),
            [
                warden_policy::DenyCode::WriteStatement,
                warden_policy::DenyCode::NestedWrite,
            ]
        );
        assert_eq!(outcomes[0].outcome, AuditOutcome::Denied);
        assert_eq!(outcomes[0].error_code, Some(PublicErrorCode::QueryRejected));
    }

    #[tokio::test]
    async fn every_analysis_failure_is_audited_with_its_exact_denial() {
        for (failure, expected_deny_code) in [
            (
                AnalyzeError::Parse {
                    detail: "parser.internal".to_owned(),
                },
                warden_policy::DenyCode::UnknownConstruct,
            ),
            (
                AnalyzeError::RecursionLimit,
                warden_policy::DenyCode::ParserRecursionLimit,
            ),
        ] {
            let sink = Arc::new(testing::FakeAuditSink::new());
            let service = testing::query_service(testing::ServiceFakes {
                analyzer: Arc::new(testing::FakeAnalyzer::failing(failure)),
                audit: sink.clone(),
                ..testing::ServiceFakes::default()
            });
            let error = service
                .execute(&testing::request_context(), testing::request())
                .await
                .unwrap_err();
            assert_eq!(error.public_code(), PublicErrorCode::QueryParseError);
            let attempts = sink.attempts();
            let outcomes = sink.outcomes();
            assert_eq!(attempts.len(), 1);
            assert_eq!(outcomes.len(), 1);
            assert_eq!(outcomes[0].attempt_id, attempts[0].id);
            assert_eq!(attempts[0].deny_reasons.len(), 1);
            assert_eq!(attempts[0].deny_reasons[0].code(), expected_deny_code);
            assert_eq!(outcomes[0].outcome, AuditOutcome::Denied);
            assert_eq!(
                outcomes[0].error_code,
                Some(PublicErrorCode::QueryParseError)
            );
        }
    }

    #[tokio::test]
    async fn every_analysis_failure_keeps_its_code_when_attempt_audit_fails() {
        for failure in [
            AnalyzeError::Parse {
                detail: "parser.internal".to_owned(),
            },
            AnalyzeError::RecursionLimit,
        ] {
            let sink = Arc::new(testing::FakeAuditSink::broken_attempts());
            let service = testing::query_service(testing::ServiceFakes {
                analyzer: Arc::new(testing::FakeAnalyzer::failing(failure)),
                audit: sink.clone(),
                ..testing::ServiceFakes::default()
            });
            let error = service
                .execute(&testing::request_context(), testing::request())
                .await
                .unwrap_err();
            assert_eq!(error.public_code(), PublicErrorCode::QueryParseError);
            assert!(sink.attempts().is_empty());
            let outcomes = sink.outcomes();
            assert_eq!(outcomes.len(), 1);
            assert_eq!(outcomes[0].outcome, AuditOutcome::Denied);
            assert_eq!(
                outcomes[0].error_code,
                Some(PublicErrorCode::QueryParseError)
            );
        }
    }

    #[tokio::test]
    async fn a_broken_attempt_write_denies_the_query_as_an_internal_error() {
        let executor = Arc::new(testing::FakeExecutor::new());
        let sink = Arc::new(testing::FakeAuditSink::broken_attempts());
        let service = testing::query_service(testing::ServiceFakes {
            audit: sink.clone(),
            executor: executor.clone(),
            ..testing::ServiceFakes::default()
        });
        let error = service
            .execute(&testing::request_context(), testing::request())
            .await
            .unwrap_err();
        assert_eq!(error.public_code(), PublicErrorCode::InternalError);
        assert_eq!(executor.calls(), 0);
        assert!(sink.attempts().is_empty());
        assert!(sink.outcomes().is_empty());
    }

    #[tokio::test]
    async fn a_broken_outcome_write_still_returns_the_result() {
        let sink = Arc::new(testing::FakeAuditSink::broken_outcomes());
        let service = testing::query_service(testing::ServiceFakes {
            audit: sink.clone(),
            ..testing::ServiceFakes::default()
        });
        assert!(
            service
                .execute(&testing::request_context(), testing::request())
                .await
                .is_ok()
        );
        let attempts = sink.attempts();
        let outcomes = sink.outcomes();
        assert_eq!(attempts.len(), 1);
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].attempt_id, attempts[0].id);
    }

    #[tokio::test]
    async fn a_failed_execution_records_the_outcome_the_failure_actually_was() {
        for (failure, expected_outcome, expected_code) in [
            (
                ExecuteError::Timeout,
                AuditOutcome::TimedOut,
                PublicErrorCode::QueryTimeout,
            ),
            (
                ExecuteError::Cancelled,
                AuditOutcome::Cancelled,
                PublicErrorCode::QueryCancelled,
            ),
            (
                ExecuteError::ResultTooLarge { limit: 4096 },
                AuditOutcome::Failed,
                PublicErrorCode::QueryResultTooLarge,
            ),
            (
                ExecuteError::Normalization(NormalizationError::NonFiniteFloat {
                    column: "amount".to_owned(),
                }),
                AuditOutcome::Failed,
                PublicErrorCode::QueryNormalizationError,
            ),
            (
                ExecuteError::Database {
                    detail: "boom".to_owned(),
                },
                AuditOutcome::Failed,
                PublicErrorCode::QueryExecutionError,
            ),
        ] {
            let sink = Arc::new(testing::FakeAuditSink::new());
            let service = testing::query_service(testing::ServiceFakes {
                executor: Arc::new(testing::FakeExecutor::failing(failure.clone())),
                audit: sink.clone(),
                ..testing::ServiceFakes::default()
            });
            let error = service
                .execute(&testing::request_context(), testing::request())
                .await
                .unwrap_err();
            let attempts = sink.attempts();
            let outcomes = sink.outcomes();
            assert_eq!(attempts.len(), 1);
            assert_eq!(outcomes.len(), 1);
            assert_eq!(outcomes[0].attempt_id, attempts[0].id);
            assert_eq!(error.public_code(), expected_code);
            assert_eq!(outcomes[0].outcome, expected_outcome);
            assert_eq!(outcomes[0].error_code, Some(expected_code));
        }
    }

    #[tokio::test]
    async fn the_response_is_redacted_and_its_byte_count_matches() {
        let sink = Arc::new(testing::FakeAuditSink::new());
        let service = testing::query_service(testing::ServiceFakes {
            redactor: testing::redactor(&["*.password"]),
            executor: Arc::new(testing::FakeExecutor::returning(testing::secret_result())),
            audit: sink.clone(),
            ..testing::ServiceFakes::default()
        });
        let result = service
            .execute(&testing::request_context(), testing::request())
            .await
            .unwrap();
        assert_eq!(
            result.rows[0][1],
            warden_core::result::ResultValue::String(crate::redaction::REDACTED.to_owned())
        );
        let expected: usize = result
            .rows
            .iter()
            .map(|row| warden_core::result::row_json_bytes(row))
            .sum();
        assert_eq!(result.stats.bytes, expected);
        assert_eq!(sink.outcomes()[0].result_bytes, Some(expected));
    }

    #[tokio::test(start_paused = true)]
    async fn a_saturated_connection_records_an_outcome_that_does_not_claim_it_ran() {
        let (service, sink, _held) = testing::saturated_query_service().await;
        let error = service
            .execute(&testing::request_context(), testing::request())
            .await
            .unwrap_err();
        assert_eq!(error.public_code(), PublicErrorCode::ServerBusy);
        let attempts = sink.attempts();
        let outcomes = sink.outcomes();
        assert_eq!(attempts.len(), 1);
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].attempt_id, attempts[0].id);
        assert_eq!(outcomes[0].outcome, AuditOutcome::NotStarted);
        assert_eq!(outcomes[0].error_code, Some(PublicErrorCode::ServerBusy));
    }

    #[tokio::test(start_paused = true)]
    async fn a_saturated_connection_records_the_wait_that_produced_server_busy() {
        let (service, sink, _held) = testing::saturated_query_service().await;
        let error = service
            .execute(&testing::request_context(), testing::request())
            .await
            .unwrap_err();
        assert_eq!(error.public_code(), PublicErrorCode::ServerBusy);
        let outcomes = sink.outcomes();
        assert_eq!(outcomes[0].outcome, AuditOutcome::NotStarted);
        assert_eq!(
            outcomes[0].queue_wait,
            Some(warden_core::limits::ExecutionLimits::default().max_queue_wait)
        );
        assert_eq!(
            sink.attempts()[0].operation,
            warden_ports::AuditOperation::Query
        );
    }

    #[tokio::test]
    async fn authorization_uses_the_connection_s_own_limits() {
        let limits = warden_core::limits::ExecutionLimits {
            timeout: Duration::from_secs(11),
            max_queue_wait: Duration::from_secs(3),
            max_rows: 7,
            max_value_bytes: 1_234,
            max_result_bytes: 4_321,
            max_concurrent_queries: 2,
        };
        let executor = Arc::new(testing::FakeExecutor::new());
        let service = testing::query_service(testing::ServiceFakes {
            limits,
            executor: executor.clone(),
            ..testing::ServiceFakes::default()
        });
        service
            .execute(&testing::request_context(), testing::request())
            .await
            .unwrap();
        assert_eq!(executor.observed_limits().unwrap(), limits);
    }

    #[tokio::test(start_paused = true)]
    async fn root_shutdown_cancels_an_in_flight_query_through_its_child() {
        let shutdown = tokio_util::sync::CancellationToken::new();
        let executor = Arc::new(testing::FakeExecutor::taking(Duration::from_secs(60)));
        let service = testing::query_service(testing::ServiceFakes {
            executor: executor.clone(),
            shutdown: shutdown.clone(),
            ..testing::ServiceFakes::default()
        });
        let context = testing::request_context();
        let mut execution = Box::pin(service.execute(&context, testing::request()));
        tokio::select! {
            result = &mut execution => panic!("query completed before shutdown: {result:?}"),
            () = tokio::time::sleep(Duration::from_millis(1)) => {}
        }
        assert_eq!(executor.calls(), 1);

        let (_, observed) = executor.latest_observation();
        shutdown.cancel();
        let error = execution.await.unwrap_err();
        assert_eq!(error.public_code(), PublicErrorCode::QueryCancelled);
        assert!(observed.is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn cancelling_an_in_flight_request_does_not_cancel_root_shutdown() {
        let shutdown = tokio_util::sync::CancellationToken::new();
        let executor = Arc::new(testing::FakeExecutor::taking(Duration::from_secs(60)));
        let service = testing::query_service(testing::ServiceFakes {
            executor: executor.clone(),
            shutdown: shutdown.clone(),
            ..testing::ServiceFakes::default()
        });
        let context = testing::request_context();
        let mut execution = Box::pin(service.execute(&context, testing::request()));
        tokio::select! {
            result = &mut execution => panic!("query completed before cancellation: {result:?}"),
            () = tokio::time::sleep(Duration::from_millis(1)) => {}
        }
        assert_eq!(executor.calls(), 1);

        let (_, observed) = executor.latest_observation();
        observed.cancel();
        assert!(!shutdown.is_cancelled());
        let error = execution.await.unwrap_err();
        assert_eq!(error.public_code(), PublicErrorCode::QueryCancelled);
    }

    #[tokio::test]
    async fn a_refused_statement_keeps_its_denial_when_the_attempt_write_fails() {
        let executor = Arc::new(testing::FakeExecutor::new());
        let sink = Arc::new(testing::FakeAuditSink::broken_attempts());
        let service = testing::query_service(testing::ServiceFakes {
            analyzer: Arc::new(testing::FakeAnalyzer::writing(Dialect::MySql)),
            executor: executor.clone(),
            audit: sink.clone(),
            ..testing::ServiceFakes::default()
        });
        let error = service
            .execute(&testing::request_context(), testing::request())
            .await
            .unwrap_err();
        assert_eq!(error.public_code(), PublicErrorCode::QueryRejected);
        assert_eq!(executor.calls(), 0);
        assert!(sink.attempts().is_empty());
        let outcomes = sink.outcomes();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].outcome, AuditOutcome::Denied);
        assert_eq!(outcomes[0].error_code, Some(PublicErrorCode::QueryRejected));
    }

    #[tokio::test]
    async fn a_panicking_adapter_still_completes_the_audit_record_it_opened() {
        // ADR-0038's remaining gap: containment kept the process alive, but the
        // attempt it recorded never received an outcome, so the audit trail's most
        // interesting record was its most incomplete one.
        let sink = Arc::new(testing::FakeAuditSink::new());
        let service = Arc::new(testing::query_service(testing::ServiceFakes {
            executor: Arc::new(testing::FakeExecutor::panicking()),
            audit: sink.clone(),
            ..testing::ServiceFakes::default()
        }));
        let task = tokio::spawn({
            let service = Arc::clone(&service);
            async move {
                let context = testing::request_context();
                service.execute(&context, testing::request()).await
            }
        });
        assert!(task.await.unwrap_err().is_panic());

        let outcome = testing::await_outcome(&sink).await;
        assert_eq!(outcome.attempt_id, sink.attempts()[0].id);
        assert_eq!(outcome.outcome, AuditOutcome::Abandoned);
        assert_eq!(outcome.error_code, Some(PublicErrorCode::InternalError));
    }

    #[tokio::test(start_paused = true)]
    async fn a_dropped_request_completes_its_audit_record_too() {
        let sink = Arc::new(testing::FakeAuditSink::new());
        let service = testing::query_service(testing::ServiceFakes {
            executor: Arc::new(testing::FakeExecutor::taking(Duration::from_secs(600))),
            audit: sink.clone(),
            ..testing::ServiceFakes::default()
        });
        let context = testing::request_context();
        let mut execution = Box::pin(service.execute(&context, testing::request()));
        tokio::select! {
            result = &mut execution => panic!("query completed early: {result:?}"),
            () = tokio::time::sleep(Duration::from_millis(1)) => {}
        }
        drop(execution);

        let outcome = testing::await_outcome(&sink).await;
        assert_eq!(outcome.outcome, AuditOutcome::Abandoned);
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_a_queued_query_records_abandoned() {
        let (service, sink, _held) = testing::saturated_query_service().await;
        let context = testing::request_context();
        let mut execution = Box::pin(service.execute(&context, testing::request()));
        tokio::select! {
            result = &mut execution => panic!("queued query completed: {result:?}"),
            () = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
        assert_eq!(sink.attempts().len(), 1);
        assert!(sink.outcomes().is_empty());
        drop(execution);
        let outcome = testing::await_outcome(&sink).await;
        assert_eq!(outcome.attempt_id, sink.attempts()[0].id);
        assert_eq!(outcome.outcome, AuditOutcome::Abandoned);
    }

    #[tokio::test]
    async fn an_ordinary_request_records_exactly_one_outcome() {
        // The guard must disarm on the normal path, or every successful query would
        // be followed by a contradictory `abandoned` record.
        let sink = Arc::new(testing::FakeAuditSink::new());
        let service = testing::query_service(testing::ServiceFakes {
            audit: sink.clone(),
            ..testing::ServiceFakes::default()
        });
        service
            .execute(&testing::request_context(), testing::request())
            .await
            .unwrap();
        assert_eq!(sink.outcomes().len(), 1);
        assert_eq!(sink.outcomes()[0].outcome, AuditOutcome::Succeeded);
        assert_eq!(
            Arc::strong_count(&sink),
            2,
            "no detached duplicate writer may remain"
        );
    }

    #[test]
    fn debug_discloses_no_trait_object_or_shutdown_state() {
        let service = testing::query_service(testing::ServiceFakes::default());
        let rendered = format!("{service:?}");
        assert!(rendered.contains("QueryService"), "{rendered}");
        assert!(rendered.contains("redactor_is_empty"), "{rendered}");
        assert!(rendered.contains(".."), "{rendered}");
        for hidden in ["registry", "engine", "audit", "shutdown", "FakeExecutor"] {
            assert!(!rendered.contains(hidden), "{rendered}");
        }
    }
}
