//! `resolve -> analyze -> authorize -> attempt -> acquire -> explain -> redact ->
//! outcome`.
//!
//! Planning deliberately follows the query flow step for step. PostgreSQL can execute
//! `IMMUTABLE` functions while constant-folding a plan, and planning shares the
//! connection's `agent_pool` with read-only execution (`docs/mcp.md` section 3.1;
//! ADR-0032). For that reason [`warden_ports::Explainer::explain`] accepts an
//! [`warden_policy::AuthorizedQuery`], not an [`ExplainRequest`]: the request's
//! validated [`warden_core::query::QueryRequest`] passes through the same analysis,
//! policy, audit, and concurrency boundaries as an executed query.
//!
//! [`ExplainRequest::query`] exposes the wrapped request by reference only, so this
//! service clones that `QueryRequest` before analysis. It does not reconstruct one or
//! introduce a second authorization input.
//!
//! Every exit records an outcome for the attempt it recorded. A failed attempt write
//! on an authorized statement is the exception: no attempt exists to complete and
//! planning must not begin. Analysis and policy refusals retain their refusal even if
//! either audit write fails.

use std::sync::Arc;

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;
use warden_core::context::RequestContext;
use warden_core::error::PublicError;
use warden_core::explain::{ExplainRequest, QueryPlan};
use warden_policy::PolicyEngine;
use warden_ports::{
    AuditOperation, AuditOutcome, AuditOutcomeEvent, AuditSink, ConnectionRegistry, ExplainError,
};

use crate::error::ExplainServiceError;
use crate::pipeline::{GateError, ServiceCore};
use crate::redaction::Redactor;

/// Plans one agent statement through the same safety boundaries as execution.
///
/// A thin wrapper over [`ServiceCore`], which holds the collaborators and runs the
/// preflight this service shares with [`crate::QueryService`]. What is left here is
/// what genuinely differs: the operation constant, the root span, the gated call, the
/// error-to-outcome map, and the redaction step.
#[derive(Debug)]
pub struct ExplainService {
    core: ServiceCore,
}

impl ExplainService {
    /// Wires the collaborators one explain request needs.
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

    /// Plans one validated statement and returns a bounded, redacted plan.
    ///
    /// # Errors
    ///
    /// The same pipeline as [`crate::QueryService::execute`], with
    /// [`ExplainServiceError::Explain`] in place of the execution variant:
    /// [`ExplainServiceError::Connection`], [`ExplainServiceError::Analyze`],
    /// [`ExplainServiceError::Rejected`], then [`ExplainServiceError::Audit`] if the
    /// attempt record could not be written — which denies the plan, since planning is
    /// an attempt too.
    ///
    /// The statement is planned, never run: `EXPLAIN ANALYZE` is not reachable from
    /// here (SPEC section 6, invariant 11), and the prefixed statement is reparsed and
    /// verified before it goes to the database (ADR-0037).
    pub async fn explain(
        &self,
        context: &RequestContext,
        request: ExplainRequest,
    ) -> Result<QueryPlan, ExplainServiceError> {
        let span = tracing::info_span!(
            "warden.explain",
            request_id = %context.request_id(),
            connection = %request.query().connection(),
        );
        let outcome_parent = span.clone();
        async move {
            // `ExplainRequest` is a `QueryRequest` in a wrapper: the same statement
            // goes through the same analysis and the same policy, which is the point of
            // ADR-0017 — planning is real work on the server, not a dry run.
            let preflight = self
                .core
                .preflight(context, request.query().clone(), AuditOperation::Explain)
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

            // different quantities.
            let queue_wait = gate.queue_wait();
            let started = Instant::now();
            let planned = gate.explain().await;
            let elapsed = started.elapsed();
            match planned {
                Ok(mut plan) => {
                    {
                        let _entered = tracing::debug_span!("result.redact").entered();
                        self.core.redactor().redact_plan(&mut plan);
                    }
                    let plan_bytes = plan.plan_bytes();
                    guard
                        .complete(AuditOutcomeEvent {
                            attempt_id: attempt.id,
                            outcome: AuditOutcome::Succeeded,
                            duration: Some(elapsed),
                            queue_wait: Some(queue_wait),
                            rows_returned: None,
                            result_bytes: Some(plan_bytes),
                            error_code: None,
                        })
                        .await;
                    Ok(plan)
                }
                Err(error) => {
                    let outcome = match &error {
                        ExplainError::Timeout => AuditOutcome::TimedOut,
                        ExplainError::Cancelled => AuditOutcome::Cancelled,
                        ExplainError::PrefixVerificationFailed
                        | ExplainError::MalformedPlan { .. }
                        | ExplainError::PlanTooLarge { .. }
                        | ExplainError::Database { .. } => AuditOutcome::Failed,
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
pub(crate) fn redactor_arc(service: &ExplainService) -> &Redactor {
    service.core.redactor()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::time::Duration;

    #[tokio::test(start_paused = true)]
    async fn dropping_a_queued_explain_records_abandoned() {
        let (service, sink, _held) = testing::saturated_explain_service().await;
        let context = testing::request_context();
        let mut explanation =
            Box::pin(service.explain(&context, ExplainRequest::new(testing::request())));
        tokio::select! {
            result = &mut explanation => panic!("queued explain completed: {result:?}"),
            () = tokio::time::sleep(Duration::from_millis(10)) => {}
        }
        assert_eq!(sink.attempts().len(), 1);
        assert!(sink.outcomes().is_empty());
        drop(explanation);
        let outcome = testing::await_outcome(&sink).await;
        assert_eq!(outcome.attempt_id, sink.attempts()[0].id);
        assert_eq!(outcome.outcome, AuditOutcome::Abandoned);
    }

    use std::sync::Arc;

    use warden_core::dialect::Dialect;
    use warden_core::error::{PublicError, PublicErrorCode};
    use warden_core::explain::ExplainRequest;
    use warden_ports::{AnalyzeError, AuditOperation, AuditOutcome, ExplainError};

    use crate::testing;

    #[tokio::test(start_paused = true)]
    async fn a_plan_is_produced_audited_redacted_and_timed() {
        let sink = Arc::new(testing::FakeAuditSink::taking(Duration::from_millis(5)));
        let explainer = Arc::new(testing::FakeExplainer::taking(Duration::from_millis(7)));
        let service = testing::explain_service(testing::ServiceFakes {
            audit: sink.clone(),
            explainer,
            redactor: testing::redactor(&["*.password"]),
            ..testing::ServiceFakes::default()
        });
        let plan = service
            .explain(
                &testing::request_context(),
                ExplainRequest::new(testing::request()),
            )
            .await
            .unwrap();
        assert_eq!(
            plan.plan["password"],
            serde_json::json!(crate::redaction::REDACTED)
        );
        let attempts = sink.attempts();
        let outcomes = sink.outcomes();
        assert_eq!(attempts.len(), 1);
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].attempt_id, attempts[0].id);
        assert_eq!(outcomes[0].outcome, AuditOutcome::Succeeded);
        assert_eq!(outcomes[0].duration, Some(Duration::from_millis(7)));
        assert_eq!(outcomes[0].rows_returned, None);
        assert_eq!(outcomes[0].result_bytes, Some(plan.plan_bytes()));
        assert_eq!(outcomes[0].error_code, None);
        assert_eq!(attempts[0].operation, AuditOperation::Explain);
        assert_eq!(
            Arc::strong_count(&sink),
            2,
            "no detached duplicate writer may remain"
        );
    }

    #[tokio::test]
    async fn an_unknown_connection_never_reaches_the_explainer() {
        let explainer = Arc::new(testing::FakeExplainer::new());
        let service = testing::explain_service(testing::ServiceFakes {
            explainer: explainer.clone(),
            ..testing::ServiceFakes::default()
        });
        let error = service
            .explain(
                &testing::request_context(),
                ExplainRequest::new(testing::request_for("staging-db")),
            )
            .await
            .unwrap_err();
        assert_eq!(error.public_code(), PublicErrorCode::ConnectionNotFound);
        assert_eq!(explainer.calls(), 0);
    }

    #[tokio::test]
    async fn a_denied_statement_is_audited_with_every_reason_and_never_planned() {
        let explainer = Arc::new(testing::FakeExplainer::new());
        let sink = Arc::new(testing::FakeAuditSink::new());
        let service = testing::explain_service(testing::ServiceFakes {
            analyzer: Arc::new(testing::FakeAnalyzer::writing(Dialect::MySql)),
            explainer: explainer.clone(),
            audit: sink.clone(),
            ..testing::ServiceFakes::default()
        });
        let error = service
            .explain(
                &testing::request_context(),
                ExplainRequest::new(testing::request()),
            )
            .await
            .unwrap_err();
        assert_eq!(error.public_code(), PublicErrorCode::QueryRejected);
        assert_eq!(explainer.calls(), 0);
        let attempts = sink.attempts();
        let outcomes = sink.outcomes();
        assert_eq!(attempts.len(), 1);
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].attempt_id, attempts[0].id);
        assert_eq!(
            sink.history(),
            vec![
                testing::FakeAuditEvent::Attempt(attempts[0].clone()),
                testing::FakeAuditEvent::Outcome(outcomes[0]),
            ]
        );
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
    async fn every_analysis_failure_is_audited_with_its_exact_denial_and_never_planned() {
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
            let explainer = Arc::new(testing::FakeExplainer::new());
            let sink = Arc::new(testing::FakeAuditSink::new());
            let service = testing::explain_service(testing::ServiceFakes {
                analyzer: Arc::new(testing::FakeAnalyzer::failing(failure)),
                explainer: explainer.clone(),
                audit: sink.clone(),
                ..testing::ServiceFakes::default()
            });
            let error = service
                .explain(
                    &testing::request_context(),
                    ExplainRequest::new(testing::request()),
                )
                .await
                .unwrap_err();
            assert_eq!(error.public_code(), PublicErrorCode::QueryParseError);
            assert_eq!(explainer.calls(), 0);
            let attempts = sink.attempts();
            let outcomes = sink.outcomes();
            assert_eq!(attempts.len(), 1);
            assert_eq!(outcomes.len(), 1);
            assert_eq!(outcomes[0].attempt_id, attempts[0].id);
            assert_eq!(
                sink.history(),
                vec![
                    testing::FakeAuditEvent::Attempt(attempts[0].clone()),
                    testing::FakeAuditEvent::Outcome(outcomes[0]),
                ]
            );
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
            let explainer = Arc::new(testing::FakeExplainer::new());
            let sink = Arc::new(testing::FakeAuditSink::broken_attempts());
            let service = testing::explain_service(testing::ServiceFakes {
                analyzer: Arc::new(testing::FakeAnalyzer::failing(failure)),
                explainer: explainer.clone(),
                audit: sink.clone(),
                ..testing::ServiceFakes::default()
            });
            let error = service
                .explain(
                    &testing::request_context(),
                    ExplainRequest::new(testing::request()),
                )
                .await
                .unwrap_err();
            assert_eq!(error.public_code(), PublicErrorCode::QueryParseError);
            assert_eq!(explainer.calls(), 0);
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
    async fn a_broken_authorized_attempt_write_reaches_no_explainer_or_outcome() {
        let explainer = Arc::new(testing::FakeExplainer::new());
        let sink = Arc::new(testing::FakeAuditSink::broken_attempts());
        let service = testing::explain_service(testing::ServiceFakes {
            audit: sink.clone(),
            explainer: explainer.clone(),
            ..testing::ServiceFakes::default()
        });
        let error = service
            .explain(
                &testing::request_context(),
                ExplainRequest::new(testing::request()),
            )
            .await
            .unwrap_err();
        assert_eq!(error.public_code(), PublicErrorCode::InternalError);
        assert_eq!(explainer.calls(), 0);
        assert!(sink.attempts().is_empty());
        assert!(sink.outcomes().is_empty());
    }

    #[tokio::test]
    async fn a_broken_outcome_write_still_returns_the_plan() {
        let sink = Arc::new(testing::FakeAuditSink::broken_outcomes());
        let service = testing::explain_service(testing::ServiceFakes {
            audit: sink.clone(),
            ..testing::ServiceFakes::default()
        });
        assert!(
            service
                .explain(
                    &testing::request_context(),
                    ExplainRequest::new(testing::request())
                )
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
    async fn every_explain_failure_records_its_exact_outcome_and_public_code() {
        let cases = [
            (
                ExplainError::PrefixVerificationFailed,
                AuditOutcome::Failed,
                PublicErrorCode::ExplainError,
            ),
            (
                ExplainError::MalformedPlan {
                    detail: "plan.internal".to_owned(),
                },
                AuditOutcome::Failed,
                PublicErrorCode::ExplainError,
            ),
            (
                ExplainError::PlanTooLarge { limit: 4096 },
                AuditOutcome::Failed,
                PublicErrorCode::ExplainError,
            ),
            (
                ExplainError::Timeout,
                AuditOutcome::TimedOut,
                PublicErrorCode::QueryTimeout,
            ),
            (
                ExplainError::Cancelled,
                AuditOutcome::Cancelled,
                PublicErrorCode::QueryCancelled,
            ),
            (
                ExplainError::Database {
                    detail: "db.internal".to_owned(),
                },
                AuditOutcome::Failed,
                PublicErrorCode::ExplainError,
            ),
        ];
        for (failure, expected_outcome, expected_code) in cases {
            let sink = Arc::new(testing::FakeAuditSink::new());
            let service = testing::explain_service(testing::ServiceFakes {
                explainer: Arc::new(testing::FakeExplainer::failing(failure)),
                audit: sink.clone(),
                ..testing::ServiceFakes::default()
            });
            let error = service
                .explain(
                    &testing::request_context(),
                    ExplainRequest::new(testing::request()),
                )
                .await
                .unwrap_err();
            let attempts = sink.attempts();
            let outcomes = sink.outcomes();
            assert_eq!(attempts.len(), 1);
            assert_eq!(outcomes.len(), 1);
            assert_eq!(outcomes[0].attempt_id, attempts[0].id);
            assert_eq!(error.public_code(), expected_code);
            assert_eq!(outcomes[0].outcome, expected_outcome);
            assert_eq!(outcomes[0].duration, None);
            assert_eq!(outcomes[0].rows_returned, None);
            assert_eq!(outcomes[0].result_bytes, None);
            assert_eq!(outcomes[0].error_code, Some(expected_code));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_saturated_connection_records_an_outcome_that_does_not_claim_it_ran() {
        let (service, sink, _held) = testing::saturated_explain_service().await;
        let error = service
            .explain(
                &testing::request_context(),
                ExplainRequest::new(testing::request()),
            )
            .await
            .unwrap_err();
        assert_eq!(error.public_code(), PublicErrorCode::ServerBusy);
        let attempts = sink.attempts();
        let outcomes = sink.outcomes();
        assert_eq!(attempts.len(), 1);
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].attempt_id, attempts[0].id);
        assert_eq!(outcomes[0].outcome, AuditOutcome::NotStarted);
        assert_eq!(outcomes[0].duration, None);
        assert_eq!(outcomes[0].rows_returned, None);
        assert_eq!(outcomes[0].result_bytes, None);
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
        let explainer = Arc::new(testing::FakeExplainer::new());
        let service = testing::explain_service(testing::ServiceFakes {
            limits,
            explainer: explainer.clone(),
            ..testing::ServiceFakes::default()
        });
        service
            .explain(
                &testing::request_context(),
                ExplainRequest::new(testing::request()),
            )
            .await
            .unwrap();
        assert_eq!(explainer.observed_limits().unwrap(), limits);
    }

    #[tokio::test(start_paused = true)]
    async fn root_shutdown_cancels_an_in_flight_explain_through_its_child() {
        let shutdown = tokio_util::sync::CancellationToken::new();
        let explainer = Arc::new(testing::FakeExplainer::taking(Duration::from_secs(60)));
        let service = testing::explain_service(testing::ServiceFakes {
            explainer: explainer.clone(),
            shutdown: shutdown.clone(),
            ..testing::ServiceFakes::default()
        });
        let context = testing::request_context();
        let mut planning =
            Box::pin(service.explain(&context, ExplainRequest::new(testing::request())));
        tokio::select! {
            result = &mut planning => panic!("explain completed before shutdown: {result:?}"),
            () = tokio::time::sleep(Duration::from_millis(1)) => {}
        }
        assert_eq!(explainer.calls(), 1);

        let (_, observed) = explainer.latest_observation();
        shutdown.cancel();
        let error = planning.await.unwrap_err();
        assert_eq!(error.public_code(), PublicErrorCode::QueryCancelled);
        assert!(observed.is_cancelled());
    }

    #[tokio::test(start_paused = true)]
    async fn cancelling_an_in_flight_explain_does_not_cancel_root_shutdown() {
        let shutdown = tokio_util::sync::CancellationToken::new();
        let explainer = Arc::new(testing::FakeExplainer::taking(Duration::from_secs(60)));
        let service = testing::explain_service(testing::ServiceFakes {
            explainer: explainer.clone(),
            shutdown: shutdown.clone(),
            ..testing::ServiceFakes::default()
        });
        let context = testing::request_context();
        let mut planning =
            Box::pin(service.explain(&context, ExplainRequest::new(testing::request())));
        tokio::select! {
            result = &mut planning => panic!("explain completed before cancellation: {result:?}"),
            () = tokio::time::sleep(Duration::from_millis(1)) => {}
        }
        assert_eq!(explainer.calls(), 1);

        let (_, observed) = explainer.latest_observation();
        observed.cancel();
        assert!(!shutdown.is_cancelled());
        let error = planning.await.unwrap_err();
        assert_eq!(error.public_code(), PublicErrorCode::QueryCancelled);
    }

    #[tokio::test]
    async fn a_refused_statement_keeps_its_denial_when_the_attempt_write_fails() {
        let explainer = Arc::new(testing::FakeExplainer::new());
        let sink = Arc::new(testing::FakeAuditSink::broken_attempts());
        let service = testing::explain_service(testing::ServiceFakes {
            analyzer: Arc::new(testing::FakeAnalyzer::writing(Dialect::MySql)),
            explainer: explainer.clone(),
            audit: sink.clone(),
            ..testing::ServiceFakes::default()
        });
        let error = service
            .explain(
                &testing::request_context(),
                ExplainRequest::new(testing::request()),
            )
            .await
            .unwrap_err();
        assert_eq!(error.public_code(), PublicErrorCode::QueryRejected);
        assert_eq!(explainer.calls(), 0);
        assert!(sink.attempts().is_empty());
        let outcomes = sink.outcomes();
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].outcome, AuditOutcome::Denied);
        assert_eq!(outcomes[0].error_code, Some(PublicErrorCode::QueryRejected));
    }

    #[test]
    fn debug_discloses_no_trait_object_or_shutdown_state() {
        let service = testing::explain_service(testing::ServiceFakes::default());
        let rendered = format!("{service:?}");
        assert!(rendered.contains("ExplainService"), "{rendered}");
        assert!(rendered.contains("redactor_is_empty"), "{rendered}");
        assert!(rendered.contains(".."), "{rendered}");
        for hidden in ["registry", "engine", "audit", "shutdown", "FakeExplainer"] {
            assert!(!rendered.contains(hidden), "{rendered}");
        }
    }
}
