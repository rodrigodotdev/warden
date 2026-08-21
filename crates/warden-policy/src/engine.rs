//! Deterministic authorization.

use std::fmt;

use warden_core::analysis::{ObjectRef, QueryAnalysis};
use warden_core::connection::ConnectionMetadata;
use warden_core::context::RequestContext;
use warden_core::limits::ExecutionLimits;

use crate::decision::{DenyReason, PolicyDecision, PolicyRejection};
use crate::input::{PolicyContext, PolicyInput};
use crate::policy::{ObjectAccessPolicy, Policy};
use crate::state::{AllowDecision, AnalyzedQuery, AuthorizedQuery};

/// An engine that could not be built.
///
/// Operator-facing, so it deliberately does not implement
/// `warden_core::error::PublicError`: a misconfigured engine fails startup and never
/// reaches a model.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyEngineError {
    /// No statement policies were supplied.
    #[error("a policy engine needs at least one policy; an empty engine authorizes everything")]
    NoPolicies,
    /// More policies than a decision can record.
    #[error("a policy engine cannot hold more than {max} policies")]
    TooManyPolicies {
        /// The maximum an `AllowDecision` can record.
        max: u16,
    },
}

/// Evaluates every policy and aggregates every denial.
///
/// Evaluating all of them costs nothing measurable on an in-memory struct and buys
/// two things (ADR-0012): the audit record shows the complete picture, and the agent
/// cannot use the error as an oracle that reveals one rule at a time.
pub struct PolicyEngine {
    policies: Vec<Box<dyn Policy>>,
    object_policies: Vec<Box<dyn ObjectAccessPolicy>>,
    evaluated_policies: u16,
}

impl PolicyEngine {
    /// Builds an engine from an explicit policy list.
    ///
    /// Rejects an empty statement-policy list: an engine with no policies authorizes
    /// every query while looking perfectly healthy, and a security control that
    /// fails open silently is worse than one that fails to start.
    ///
    /// Object policies may legitimately be empty, which means the deployment
    /// configured no object rules.
    pub fn new(
        policies: Vec<Box<dyn Policy>>,
        object_policies: Vec<Box<dyn ObjectAccessPolicy>>,
    ) -> Result<Self, PolicyEngineError> {
        if policies.is_empty() {
            return Err(PolicyEngineError::NoPolicies);
        }
        let total = policies.len().saturating_add(object_policies.len());
        let evaluated_policies = u16::try_from(total)
            .map_err(|_| PolicyEngineError::TooManyPolicies { max: u16::MAX })?;
        Ok(Self {
            policies,
            object_policies,
            evaluated_policies,
        })
    }

    /// The names of the statement policies, in evaluation order.
    #[must_use]
    pub fn policy_names(&self) -> Vec<&'static str> {
        self.policies.iter().map(|policy| policy.name()).collect()
    }

    /// The names of the object policies, in evaluation order.
    #[must_use]
    pub fn object_policy_names(&self) -> Vec<&'static str> {
        self.object_policies
            .iter()
            .map(|policy| policy.name())
            .collect()
    }

    /// Turns evidence into an executable state, or into every reason it cannot be.
    ///
    /// The caller needs the statement kind and the fingerprint for the audit attempt
    /// on both paths, so read them from the `AnalyzedQuery` before calling: this
    /// method takes ownership.
    pub fn authorize(
        &self,
        context: &RequestContext,
        connection: &ConnectionMetadata,
        query: AnalyzedQuery,
        limits: ExecutionLimits,
    ) -> Result<AuthorizedQuery, PolicyRejection> {
        let reasons = self.evaluate(context, connection, query.analysis(), limits);
        if let Some(rejection) = PolicyRejection::new(reasons) {
            return Err(rejection);
        }

        let decision = AllowDecision::new(
            self.evaluated_policies,
            query.analysis().fingerprint().cloned(),
        );
        Ok(AuthorizedQuery::new(query, decision, limits))
    }

    /// Applies the object rules to one object, outside any statement.
    ///
    /// This is how `search_schema` and `describe_schema` reach the same rules
    /// `query` does, so a denied table is not merely unreadable but also
    /// undescribable (`docs/security.md` section 5.2).
    pub fn check_object(
        &self,
        object: &ObjectRef,
        context: &PolicyContext<'_>,
    ) -> Result<(), PolicyRejection> {
        match PolicyRejection::new(self.object_reasons(object, context)) {
            Some(rejection) => Err(rejection),
            None => Ok(()),
        }
    }

    /// Runs every policy and returns every denial, unsorted.
    ///
    /// Separated from `authorize` so the borrow of the analysis ends before the
    /// `AnalyzedQuery` is moved into the authorized state.
    fn evaluate(
        &self,
        context: &RequestContext,
        connection: &ConnectionMetadata,
        analysis: &QueryAnalysis,
        limits: ExecutionLimits,
    ) -> Vec<DenyReason> {
        let policy_context = PolicyContext::new(context, connection);
        let input = PolicyInput::new(policy_context, analysis, limits);

        let mut reasons = Vec::new();
        for policy in &self.policies {
            if let PolicyDecision::Deny(mut reason) = policy.evaluate(&input) {
                reason.attribute(policy.name());
                reasons.push(reason);
            }
        }
        for object in analysis.objects() {
            reasons.extend(self.object_reasons(object, &policy_context));
        }
        reasons
    }

    fn object_reasons(&self, object: &ObjectRef, context: &PolicyContext<'_>) -> Vec<DenyReason> {
        let mut reasons = Vec::new();
        for policy in &self.object_policies {
            if let PolicyDecision::Deny(mut reason) = policy.check(object, context) {
                reason.attribute(policy.name());
                reasons.push(reason);
            }
        }
        reasons
    }
}

/// Prints the rules, not the trait objects.
///
/// Hand-written so `Policy` does not need a `Debug` supertrait, and because the
/// useful thing to see in a startup log is which rules are active.
impl fmt::Debug for PolicyEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyEngine")
            .field("policies", &self.policy_names())
            .field("object_policies", &self.object_policy_names())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use warden_core::dialect::Dialect;

    use super::*;
    use crate::decision::DenyCode;
    use crate::testing::{self, AlwaysAllow, AlwaysDeny, DenyEveryObject};

    fn engine(policies: Vec<Box<dyn Policy>>) -> PolicyEngine {
        PolicyEngine::new(policies, Vec::new()).unwrap()
    }

    fn authorize(engine: &PolicyEngine) -> Result<AuthorizedQuery, PolicyRejection> {
        let context = testing::request_context();
        let connection = testing::connection(Dialect::MySql);
        let analyzed = testing::analyzed(testing::analysis(Dialect::MySql));
        engine.authorize(&context, &connection, analyzed, ExecutionLimits::default())
    }

    #[test]
    fn an_engine_without_policies_cannot_be_built() {
        assert_eq!(
            PolicyEngine::new(Vec::new(), Vec::new()).unwrap_err(),
            PolicyEngineError::NoPolicies
        );
    }

    #[test]
    fn a_statement_no_policy_objects_to_is_authorized() {
        let engine = engine(vec![
            Box::new(AlwaysAllow("first")),
            Box::new(AlwaysAllow("second")),
        ]);
        let authorized = authorize(&engine).unwrap();

        assert_eq!(authorized.sql(), "SELECT id FROM orders");
        assert_eq!(authorized.evaluated_policies(), 2);
    }

    #[test]
    fn every_denial_is_collected_and_attributed() {
        let engine = engine(vec![
            Box::new(AlwaysDeny("locking_read", DenyCode::LockingRead)),
            Box::new(AlwaysAllow("harmless")),
            Box::new(AlwaysDeny("root_statement", DenyCode::WriteStatement)),
            Box::new(AlwaysDeny("function_safety", DenyCode::UnknownFunction)),
        ]);
        let rejection = authorize(&engine).unwrap_err();

        // Not "the first denial wins": all three, in precedence order.
        assert_eq!(rejection.reasons().len(), 3);
        assert_eq!(rejection.primary_code(), DenyCode::WriteStatement);
        assert_eq!(
            rejection
                .reasons()
                .iter()
                .map(|reason| (reason.code(), reason.policy()))
                .collect::<Vec<_>>(),
            [
                (DenyCode::WriteStatement, Some("root_statement")),
                (DenyCode::UnknownFunction, Some("function_safety")),
                (DenyCode::LockingRead, Some("locking_read")),
            ]
        );
    }

    #[test]
    fn evaluation_does_not_stop_at_the_first_denial() {
        // A denying policy placed first must not shadow the ones behind it: the
        // agent would otherwise learn one rule per attempt (ADR-0012).
        let engine = engine(vec![
            Box::new(AlwaysDeny("first", DenyCode::MultipleStatements)),
            Box::new(AlwaysDeny("second", DenyCode::Ddl)),
        ]);
        let rejection = authorize(&engine).unwrap_err();
        assert_eq!(rejection.reasons().len(), 2);
    }

    #[test]
    fn the_same_input_always_produces_the_same_output() {
        let engine = engine(vec![
            Box::new(AlwaysDeny("a", DenyCode::LockingRead)),
            Box::new(AlwaysDeny("b", DenyCode::LockingRead)),
            Box::new(AlwaysDeny("c", DenyCode::WriteStatement)),
        ]);
        let first = authorize(&engine).unwrap_err();
        let second = authorize(&engine).unwrap_err();
        assert_eq!(first, second);
    }

    #[test]
    fn object_policies_run_once_for_every_object() {
        let mut parts = testing::parts(Dialect::MySql);
        parts.objects = vec![
            testing::table(Some("app"), "orders"),
            testing::table(Some("app"), "customers"),
        ];
        let analysis = QueryAnalysis::new(parts);

        let engine = PolicyEngine::new(
            vec![Box::new(AlwaysAllow("harmless"))],
            vec![Box::new(DenyEveryObject)],
        )
        .unwrap();

        let context = testing::request_context();
        let connection = testing::connection(Dialect::MySql);
        let rejection = engine
            .authorize(
                &context,
                &connection,
                testing::analyzed(analysis),
                ExecutionLimits::default(),
            )
            .unwrap_err();

        assert_eq!(rejection.reasons().len(), 2);
        assert_eq!(rejection.primary_code(), DenyCode::ObjectNotAllowed);
        assert_eq!(rejection.reasons()[0].internal_detail(), Some("app.orders"));
        assert_eq!(rejection.reasons()[0].policy(), Some("deny_every_object"));
    }

    #[test]
    fn objects_can_be_checked_without_a_statement() {
        let engine = PolicyEngine::new(
            vec![Box::new(AlwaysAllow("harmless"))],
            vec![Box::new(DenyEveryObject)],
        )
        .unwrap();
        let context = testing::request_context();
        let connection = testing::connection(Dialect::PostgreSql);
        let policy_context = PolicyContext::new(&context, &connection);

        let rejection = engine
            .check_object(&testing::table(Some("app"), "secrets"), &policy_context)
            .unwrap_err();
        assert_eq!(rejection.primary_code(), DenyCode::ObjectNotAllowed);

        let permissive =
            PolicyEngine::new(vec![Box::new(AlwaysAllow("harmless"))], Vec::new()).unwrap();
        assert!(
            permissive
                .check_object(&testing::table(Some("app"), "secrets"), &policy_context)
                .is_ok()
        );
    }

    #[test]
    fn the_decision_records_every_configured_policy() {
        let engine = PolicyEngine::new(
            vec![Box::new(AlwaysAllow("a")), Box::new(AlwaysAllow("b"))],
            vec![Box::new(DenyEveryObject)],
        )
        .unwrap();
        // No objects in the analysis, so the object policy denies nothing, but it is
        // still part of the engine that authorized the statement.
        assert_eq!(authorize(&engine).unwrap().evaluated_policies(), 3);
    }

    #[test]
    fn debug_lists_the_active_rules() {
        let engine = engine(vec![Box::new(AlwaysAllow("single_statement"))]);
        assert!(format!("{engine:?}").contains("single_statement"));
    }

    #[test]
    fn the_engine_can_be_shared_across_tasks() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PolicyEngine>();
        assert_send_sync::<AuthorizedQuery>();
        assert_send_sync::<AnalyzedQuery>();
        assert_send_sync::<PolicyRejection>();
    }
}
