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

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use warden_core::analysis::StatementKind;
use warden_core::context::RequestContext;
use warden_core::error::PublicError;
use warden_core::query::QueryRequest;
use warden_core::result::ResultSet;
use warden_policy::PolicyEngine;
use warden_ports::{
    AuditAttempt, AuditOutcome, AuditOutcomeEvent, AuditSink, ConnectionRegistry, ExecuteError,
};

use crate::audit;
use crate::error::QueryServiceError;
use crate::pipeline::{ExecutionGate, GateError};
use crate::redaction::Redactor;

/// Runs one agent statement, end to end.
pub struct QueryService {
    registry: Arc<dyn ConnectionRegistry>,
    engine: Arc<PolicyEngine>,
    audit: Arc<dyn AuditSink>,
    redactor: Arc<Redactor>,
    shutdown: CancellationToken,
}

/// Prints only non-secret configuration state.
///
/// Port implementations are deliberately omitted: an adapter may hold a driver
/// pool whose debug output includes connection options.
impl fmt::Debug for QueryService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueryService")
            .field("redactor_is_empty", &self.redactor.is_empty())
            .finish_non_exhaustive()
    }
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
            registry,
            engine,
            audit,
            redactor,
            shutdown,
        }
    }

    /// Executes one validated statement and returns a bounded, redacted result.
    pub async fn execute(
        &self,
        context: &RequestContext,
        request: QueryRequest,
    ) -> Result<ResultSet, QueryServiceError> {
        let runtime = self.registry.get(request.connection())?;

        let analyzed = match runtime.analyzer().analyze(request) {
            Ok(analyzed) => analyzed,
            Err(error) => {
                // SPEC section 6, invariant 24: an attempt that never reached policy
                // is still an attempt. `AnalyzeError::deny_reason` is the only
                // producer of `DenyCode::ParserRecursionLimit`, and it copies no
                // parser text into the record.
                let attempt = audit::attempt(
                    context,
                    runtime.metadata(),
                    StatementKind::Unknown,
                    None,
                    vec![error.deny_reason()],
                );
                self.refuse(&attempt, AuditOutcome::Denied, error.public_code())
                    .await;
                return Err(error.into());
            }
        };

        let statement_kind = analyzed.analysis().root_kind();
        let fingerprint = analyzed.analysis().fingerprint().cloned();
        // `runtime.limits()` and nothing else: `AuthorizedQuery::limits()` is whatever
        // the caller passed here, and the adapter treats it as authoritative for the
        // row and byte bounds (crates/warden-ports/src/runtime.rs).
        let authorized =
            match self
                .engine
                .authorize(context, runtime.metadata(), analyzed, runtime.limits())
            {
                Ok(authorized) => authorized,
                Err(rejection) => {
                    let attempt = audit::attempt(
                        context,
                        runtime.metadata(),
                        statement_kind,
                        fingerprint,
                        rejection.reasons().to_vec(),
                    );
                    self.refuse(&attempt, AuditOutcome::Denied, rejection.public_code())
                        .await;
                    return Err(rejection.into());
                }
            };

        let attempt = audit::attempt(
            context,
            runtime.metadata(),
            statement_kind,
            fingerprint,
            Vec::new(),
        );
        let gate = match ExecutionGate::enter(
            &runtime,
            self.audit.as_ref(),
            &attempt,
            authorized,
            self.shutdown.child_token(),
        )
        .await
        {
            Ok(gate) => gate,
            // No attempt was recorded, so there is no outcome to complete.
            Err(GateError::Audit(error)) => return Err(error.into()),
            Err(GateError::Connection(error)) => {
                let code = error.public_code();
                self.complete(&attempt, AuditOutcome::NotStarted, None, code)
                    .await;
                return Err(error.into());
            }
        };

        match gate.execute().await {
            Ok(mut result) => {
                self.redactor.redact_result(&mut result);
                audit::record_outcome(
                    self.audit.as_ref(),
                    AuditOutcomeEvent {
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
                        rows_returned: Some(result.stats.rows_returned),
                        // After redaction, so the figure describes what the agent
                        // actually receives.
                        result_bytes: Some(result.stats.bytes),
                        error_code: None,
                    },
                )
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
                self.complete(&attempt, outcome, None, code).await;
                Err(error.into())
            }
        }
    }

    /// Records a refused attempt and its terminal outcome together.
    ///
    /// Analysis and policy refusals happen before [`ExecutionGate`] records an
    /// attempt. The attempt write's failure is logged rather than returned: the
    /// statement was already refused, so there is no execution window for a
    /// fail-closed rule to protect (ADR-0022).
    async fn refuse(
        &self,
        attempt: &AuditAttempt,
        outcome: AuditOutcome,
        error_code: warden_core::error::PublicErrorCode,
    ) {
        if let Err(error) = audit::record_attempt(self.audit.as_ref(), attempt).await {
            tracing::error!(
                target: "warden.audit",
                attempt_id = %attempt.id,
                %error,
                "the audit attempt could not be recorded for a refused statement"
            );
        }
        self.complete(attempt, outcome, None, error_code).await;
    }

    /// Records the terminal state of an attempt without writing the attempt again.
    async fn complete(
        &self,
        attempt: &AuditAttempt,
        outcome: AuditOutcome,
        duration: Option<Duration>,
        error_code: warden_core::error::PublicErrorCode,
    ) {
        audit::record_outcome(
            self.audit.as_ref(),
            AuditOutcomeEvent {
                attempt_id: attempt.id,
                outcome,
                duration,
                rows_returned: None,
                result_bytes: None,
                error_code: Some(error_code),
            },
        )
        .await;
    }
}

#[cfg(test)]
pub(crate) fn redactor_arc(service: &QueryService) -> &Arc<Redactor> {
    &service.redactor
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::Arc;
    use std::time::Duration;

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
