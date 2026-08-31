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
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::Arc;

    use warden_core::dialect::Dialect;
    use warden_core::error::{PublicError, PublicErrorCode};
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
        assert_eq!(sink.attempts().len(), 1);
        let outcome = &sink.outcomes()[0];
        assert_eq!(outcome.outcome, AuditOutcome::Succeeded);
        assert_eq!(outcome.attempt_id, sink.attempts()[0].id);
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
        assert!(!sink.attempts()[0].deny_reasons.is_empty());
        assert_eq!(sink.outcomes()[0].outcome, AuditOutcome::Denied);
        assert_eq!(
            sink.outcomes()[0].error_code,
            Some(PublicErrorCode::QueryRejected)
        );
    }

    #[tokio::test]
    async fn an_unparseable_statement_is_audited_before_it_is_refused() {
        let sink = Arc::new(testing::FakeAuditSink::new());
        let service = testing::query_service(testing::ServiceFakes {
            analyzer: Arc::new(testing::FakeAnalyzer::failing(AnalyzeError::RecursionLimit)),
            audit: sink.clone(),
            ..testing::ServiceFakes::default()
        });
        let error = service
            .execute(&testing::request_context(), testing::request())
            .await
            .unwrap_err();
        assert_eq!(error.public_code(), PublicErrorCode::QueryParseError);
        assert_eq!(
            sink.attempts()[0].deny_reasons[0].code(),
            warden_policy::DenyCode::ParserRecursionLimit
        );
        assert_eq!(sink.outcomes()[0].outcome, AuditOutcome::Denied);
    }

    #[tokio::test]
    async fn a_broken_attempt_write_denies_the_query_as_an_internal_error() {
        let executor = Arc::new(testing::FakeExecutor::new());
        let service = testing::query_service(testing::ServiceFakes {
            audit: Arc::new(testing::FakeAuditSink::broken_attempts()),
            executor: executor.clone(),
            ..testing::ServiceFakes::default()
        });
        let error = service
            .execute(&testing::request_context(), testing::request())
            .await
            .unwrap_err();
        assert_eq!(error.public_code(), PublicErrorCode::InternalError);
        assert_eq!(executor.calls(), 0);
    }

    #[tokio::test]
    async fn a_broken_outcome_write_still_returns_the_result() {
        let service = testing::query_service(testing::ServiceFakes {
            audit: Arc::new(testing::FakeAuditSink::broken_outcomes()),
            ..testing::ServiceFakes::default()
        });
        assert!(
            service
                .execute(&testing::request_context(), testing::request())
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn a_failed_execution_records_the_outcome_the_failure_actually_was() {
        for (failure, expected) in [
            (ExecuteError::Timeout, AuditOutcome::TimedOut),
            (ExecuteError::Cancelled, AuditOutcome::Cancelled),
            (
                ExecuteError::Database {
                    detail: "boom".to_owned(),
                },
                AuditOutcome::Failed,
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
            assert_eq!(sink.attempts().len(), 1);
            assert_eq!(sink.outcomes()[0].outcome, expected);
            assert_eq!(sink.outcomes()[0].error_code, Some(error.public_code()));
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
        assert_eq!(sink.attempts().len(), 1);
        assert_eq!(
            sink.outcomes().last().unwrap().outcome,
            AuditOutcome::NotStarted
        );
    }

    #[tokio::test]
    async fn authorization_uses_the_connection_s_own_limits() {
        let limits = warden_core::limits::ExecutionLimits {
            max_rows: 7,
            ..warden_core::limits::ExecutionLimits::default()
        };
        let executor = Arc::new(testing::FakeExecutor::recording_limits());
        let service = testing::query_service(testing::ServiceFakes {
            limits,
            executor: executor.clone(),
            ..testing::ServiceFakes::default()
        });
        service
            .execute(&testing::request_context(), testing::request())
            .await
            .unwrap();
        assert_eq!(executor.observed_limits().unwrap().max_rows, 7);
    }

    #[tokio::test]
    async fn execution_receives_a_child_of_the_shutdown_token() {
        let shutdown = tokio_util::sync::CancellationToken::new();
        let executor = Arc::new(testing::FakeExecutor::new());
        let service = testing::query_service(testing::ServiceFakes {
            executor: executor.clone(),
            shutdown: shutdown.clone(),
            ..testing::ServiceFakes::default()
        });
        service
            .execute(&testing::request_context(), testing::request())
            .await
            .unwrap();

        let (_, observed) = executor.latest_observation();
        observed.cancel();
        assert!(!shutdown.is_cancelled());
    }

    #[tokio::test]
    async fn a_refused_statement_keeps_its_denial_when_the_attempt_write_fails() {
        let executor = Arc::new(testing::FakeExecutor::new());
        let service = testing::query_service(testing::ServiceFakes {
            analyzer: Arc::new(testing::FakeAnalyzer::writing(Dialect::MySql)),
            executor: executor.clone(),
            audit: Arc::new(testing::FakeAuditSink::broken_attempts()),
            ..testing::ServiceFakes::default()
        });
        let error = service
            .execute(&testing::request_context(), testing::request())
            .await
            .unwrap_err();
        assert_eq!(error.public_code(), PublicErrorCode::QueryRejected);
        assert_eq!(executor.calls(), 0);
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
