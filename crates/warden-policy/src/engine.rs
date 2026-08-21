//! Deterministic authorization.

use std::fmt;

use warden_core::analysis::{ObjectRef, QueryAnalysis};
use warden_core::connection::ConnectionMetadata;
use warden_core::context::RequestContext;
use warden_core::limits::ExecutionLimits;

use crate::decision::{DenyCode, DenyReason, PolicyDecision, PolicyRejection};
use crate::input::{PolicyContext, PolicyInput};
use crate::policy::{ObjectAccessPolicy, Policy};
use crate::settings::PolicySettings;
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
    /// A configured object rule could not be parsed.
    #[error(transparent)]
    ObjectRule(#[from] crate::policies::ObjectRuleError),
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

    /// Builds the engine every deployment uses.
    ///
    /// This is the only place the default rule set is named. A composition root
    /// that assembled its own list could quietly omit one, so it calls this instead
    /// and `PolicyEngine::new` stays available for tests and for a future profile
    /// that genuinely needs a different set.
    pub fn with_defaults(settings: &PolicySettings) -> Result<Self, PolicyEngineError> {
        let policies = crate::policies::default_policies(settings.relaxations);
        let object_policies = crate::policies::default_object_policies(&settings.objects)?;
        Self::new(policies, object_policies)
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
    ///
    /// This is also the only place that can compare the request's own
    /// `warden_core::connection::ConnectionName` against `connection.name`: a
    /// `Policy` never sees the request (`crate::input`), so only `authorize` holds
    /// both halves of "this evidence describes the connection it is about to run
    /// against" (`crate::policies::analysis_integrity`). A mismatch is appended to
    /// the same aggregate `evaluate` produced rather than returned early, so it
    /// joins other denials instead of pre-empting them (ADR-0012).
    pub fn authorize(
        &self,
        context: &RequestContext,
        connection: &ConnectionMetadata,
        query: AnalyzedQuery,
        limits: ExecutionLimits,
    ) -> Result<AuthorizedQuery, PolicyRejection> {
        let mut reasons = self.evaluate(context, connection, query.analysis(), limits);
        if query.connection() != &connection.name {
            let mut reason = DenyReason::with_detail(
                // The residual code: a connection mismatch means nothing the
                // policies concluded can be trusted, since they evaluated the wrong
                // connection's rules against this evidence.
                DenyCode::UnknownConstruct,
                format!(
                    "analysis targets connection {} but authorization is against \
                     connection {}",
                    query.connection(),
                    connection.name
                ),
            );
            reason.attribute("connection_identity");
            reasons.push(reason);
        }
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
    use warden_core::query::{InputLimits, QueryRequest};

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

    /// An `AnalyzedQuery` built for `staging-db`, paired with a `connection`
    /// resolved for `production-db` (`testing::connection`'s fixed name). Same
    /// dialect on both sides, so `AnalysisIntegrityPolicy` sees nothing wrong: only
    /// the connection-name comparison in `authorize` can catch this.
    fn mismatched_connection_query(
        dialect: Dialect,
    ) -> (RequestContext, ConnectionMetadata, AnalyzedQuery) {
        let context = testing::request_context();
        let connection = testing::connection(dialect);
        let request = QueryRequest::new(
            "staging-db".parse().unwrap(),
            "SELECT id FROM orders".to_owned(),
            Vec::new(),
            &InputLimits::default(),
        )
        .unwrap();
        let query = AnalyzedQuery::new(request, testing::analysis(dialect));
        (context, connection, query)
    }

    #[test]
    fn a_same_dialect_different_connection_query_is_denied() {
        let engine = engine(vec![Box::new(AlwaysAllow("harmless"))]);
        let (context, connection, query) = mismatched_connection_query(Dialect::MySql);

        let rejection = engine
            .authorize(&context, &connection, query, ExecutionLimits::default())
            .unwrap_err();

        assert_eq!(rejection.primary_code(), DenyCode::UnknownConstruct);
    }

    #[test]
    fn the_mismatch_detail_names_both_connections_and_the_message_names_neither() {
        let engine = engine(vec![Box::new(AlwaysAllow("harmless"))]);
        let (context, connection, query) = mismatched_connection_query(Dialect::MySql);

        let rejection = engine
            .authorize(&context, &connection, query, ExecutionLimits::default())
            .unwrap_err();

        let detail = rejection.reasons()[0]
            .internal_detail()
            .expect("a connection mismatch must carry detail");
        assert!(detail.contains("staging-db"), "{detail}");
        assert!(detail.contains("production-db"), "{detail}");

        for text in [rejection.public_message(), &rejection.to_string()] {
            assert!(!text.contains("staging-db"), "{text}");
            assert!(!text.contains("production-db"), "{text}");
        }
    }

    #[test]
    fn a_matching_connection_still_authorizes() {
        // Guards against over-denying: the comparison must not fire when the
        // request's connection genuinely is the one the caller resolved.
        let engine = engine(vec![Box::new(AlwaysAllow("harmless"))]);
        assert!(authorize(&engine).is_ok());
    }

    #[test]
    fn the_mismatch_is_aggregated_with_other_denials_not_short_circuited() {
        let engine = engine(vec![Box::new(AlwaysDeny(
            "locking_read",
            DenyCode::LockingRead,
        ))]);
        let (context, connection, query) = mismatched_connection_query(Dialect::MySql);

        let rejection = engine
            .authorize(&context, &connection, query, ExecutionLimits::default())
            .unwrap_err();

        assert_eq!(rejection.reasons().len(), 2);
        assert!(
            rejection
                .reasons()
                .iter()
                .any(|reason| reason.code() == DenyCode::LockingRead)
        );
        assert!(
            rejection
                .reasons()
                .iter()
                .any(|reason| reason.code() == DenyCode::UnknownConstruct)
        );
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

#[cfg(test)]
mod default_engine_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use warden_core::analysis::{
        FunctionClassification, QueryAnalysis, QueryAnalysisParts, RiskFlag, StatementKind,
    };
    use warden_core::dialect::Dialect;

    use super::*;
    use crate::decision::DenyCode;
    use crate::settings::{ObjectRules, Relaxations};
    use crate::testing;

    fn engine(settings: &PolicySettings) -> PolicyEngine {
        PolicyEngine::with_defaults(settings).unwrap()
    }

    fn judge(
        engine: &PolicyEngine,
        parts: QueryAnalysisParts,
    ) -> Result<AuthorizedQuery, PolicyRejection> {
        let context = testing::request_context();
        let connection = testing::connection(parts.dialect);
        let analyzed = testing::analyzed(QueryAnalysis::new(parts));
        engine.authorize(&context, &connection, analyzed, ExecutionLimits::default())
    }

    #[test]
    fn the_default_set_is_the_documented_one() {
        let engine = engine(&PolicySettings::default());
        assert_eq!(
            engine.policy_names(),
            [
                "analysis_integrity",
                "single_statement",
                "read_only_root_statement",
                "nested_write",
                "session_mutation",
                "locking_read",
                "function_safety",
                "risk_evidence",
            ]
        );
        // No object rules configured, so no object policy exists at all.
        assert!(engine.object_policy_names().is_empty());
    }

    #[test]
    fn a_plain_select_is_authorized() {
        let engine = engine(&PolicySettings::default());
        let authorized = judge(&engine, testing::parts(Dialect::MySql)).unwrap();
        assert_eq!(authorized.sql(), "SELECT id FROM orders");
        assert_eq!(authorized.evaluated_policies(), 8);
    }

    #[test]
    fn a_delete_hidden_in_a_cte_is_denied_by_two_independent_policies() {
        // WITH changed AS (DELETE FROM orders RETURNING *) SELECT * FROM changed
        let mut parts = testing::parts(Dialect::PostgreSql);
        parts.nested_kinds = vec![StatementKind::Delete];
        parts.risks = vec![RiskFlag::DataModifyingCte];
        parts.has_side_effects = true;

        let engine = engine(&PolicySettings::default());
        let rejection = judge(&engine, parts).unwrap_err();

        assert_eq!(rejection.primary_code(), DenyCode::NestedWrite);
        assert_eq!(
            rejection
                .reasons()
                .iter()
                .map(|reason| reason.policy())
                .collect::<Vec<_>>(),
            [Some("nested_write"), Some("risk_evidence")]
        );
    }

    #[test]
    fn a_query_that_breaks_four_rules_reports_all_of_them_in_precedence_order() {
        let mut parts = testing::parts(Dialect::PostgreSql);
        parts.statement_count = std::num::NonZeroUsize::new(2).unwrap();
        parts.root_kind = StatementKind::Delete;
        parts.has_locking_clause = true;
        parts.risks = vec![RiskFlag::LockingRead, RiskFlag::UnknownConstruct];
        parts.functions = vec![testing::function(
            "pg_sleep",
            FunctionClassification::KnownDangerous,
        )];

        let engine = engine(&PolicySettings::default());
        let rejection = judge(&engine, parts).unwrap_err();

        assert_eq!(rejection.primary_code(), DenyCode::MultipleStatements);
        assert_eq!(
            rejection
                .reasons()
                .iter()
                .map(|reason| (reason.code(), reason.policy()))
                .collect::<Vec<_>>(),
            [
                (DenyCode::MultipleStatements, Some("single_statement")),
                (DenyCode::WriteStatement, Some("read_only_root_statement")),
                (DenyCode::DangerousFunction, Some("function_safety")),
                (DenyCode::LockingRead, Some("locking_read")),
                (DenyCode::LockingRead, Some("risk_evidence")),
            ]
        );
    }

    #[test]
    fn only_select_survives_the_composed_engine() {
        let engine = engine(&PolicySettings::default());
        for kind in StatementKind::ALL {
            let mut parts = testing::parts(Dialect::MySql);
            parts.root_kind = kind;
            let outcome = judge(&engine, parts);
            assert_eq!(
                outcome.is_ok(),
                kind == StatementKind::Select,
                "unexpected outcome for root {}",
                kind.as_str()
            );
        }
    }

    #[test]
    fn every_risk_flag_stops_the_composed_engine() {
        let engine = engine(&PolicySettings::default());
        for flag in RiskFlag::ALL {
            let mut parts = testing::parts(Dialect::MySql);
            parts.risks = vec![flag];
            assert!(
                judge(&engine, parts).is_err(),
                "{} was authorized",
                flag.as_str()
            );
        }
    }

    #[test]
    fn every_unsafe_function_classification_stops_the_composed_engine() {
        let engine = engine(&PolicySettings::default());
        for classification in FunctionClassification::ALL {
            let mut parts = testing::parts(Dialect::MySql);
            parts.functions = vec![testing::function("f", classification)];
            assert_eq!(
                judge(&engine, parts).is_ok(),
                classification == FunctionClassification::KnownSafe,
                "unexpected outcome for {classification:?}"
            );
        }
    }

    #[test]
    fn configured_object_rules_reach_the_engine() {
        let settings = PolicySettings {
            relaxations: Relaxations::default(),
            objects: ObjectRules {
                schemas: Some(vec!["app".to_owned()]),
                allow_tables: None,
                deny_tables: vec!["app.secrets".to_owned()],
            },
        };
        let engine = engine(&settings);
        assert_eq!(
            engine.object_policy_names(),
            ["schema_allow_list", "table_allow_deny"]
        );

        let mut allowed = testing::parts(Dialect::MySql);
        allowed.objects = vec![testing::table(Some("app"), "orders")];
        assert!(judge(&engine, allowed).is_ok());

        let mut denied = testing::parts(Dialect::MySql);
        denied.objects = vec![testing::table(Some("app"), "secrets")];
        assert_eq!(
            judge(&engine, denied).unwrap_err().primary_code(),
            DenyCode::ObjectNotAllowed
        );

        let mut other_schema = testing::parts(Dialect::MySql);
        other_schema.objects = vec![testing::table(Some("internal"), "orders")];
        assert_eq!(
            judge(&engine, other_schema).unwrap_err().primary_code(),
            DenyCode::ObjectNotAllowed
        );
    }

    #[test]
    fn a_malformed_object_rule_stops_the_engine_from_being_built() {
        let settings = PolicySettings {
            relaxations: Relaxations::default(),
            objects: ObjectRules {
                schemas: None,
                allow_tables: None,
                deny_tables: vec!["a.b.c".to_owned()],
            },
        };
        let error = PolicyEngine::with_defaults(&settings).unwrap_err();
        assert!(error.to_string().contains("a.b.c"), "{error}");
    }

    #[test]
    fn nothing_the_agent_receives_names_an_object_a_function_or_a_rule() {
        let mut parts = testing::parts(Dialect::PostgreSql);
        parts.root_kind = StatementKind::Delete;
        parts.objects = vec![testing::table(Some("app"), "customer_secrets")];
        parts.functions = vec![testing::function(
            "pg_advisory_lock",
            FunctionClassification::KnownDangerous,
        )];

        let settings = PolicySettings {
            relaxations: Relaxations::default(),
            objects: ObjectRules {
                schemas: None,
                allow_tables: None,
                deny_tables: vec!["app.customer_secrets".to_owned()],
            },
        };
        let rejection = judge(&engine(&settings), parts).unwrap_err();

        for text in [rejection.public_message(), &rejection.to_string()] {
            assert!(!text.contains("customer_secrets"), "{text}");
            assert!(!text.contains("pg_advisory_lock"), "{text}");
            assert!(!text.contains("app"), "{text}");
        }
        // The auditor sees everything the agent does not.
        let details: Vec<&str> = rejection
            .reasons()
            .iter()
            .filter_map(DenyReason::internal_detail)
            .collect();
        assert!(
            details.iter().any(|d| d.contains("customer_secrets")),
            "{details:?}"
        );
        assert!(
            details.iter().any(|d| d.contains("pg_advisory_lock")),
            "{details:?}"
        );
    }

    #[test]
    fn relaxations_reach_the_policies_that_honor_them() {
        let permissive = engine(&PolicySettings {
            relaxations: Relaxations {
                locking_reads: true,
                unknown_functions: true,
            },
            objects: ObjectRules::default(),
        });

        let mut locking = testing::parts(Dialect::PostgreSql);
        locking.has_locking_clause = true;
        locking.risks = vec![RiskFlag::LockingRead];
        assert!(judge(&permissive, locking).is_ok());

        let mut unknown = testing::parts(Dialect::PostgreSql);
        unknown.functions = vec![testing::function(
            "mystery",
            FunctionClassification::Unknown,
        )];
        unknown.risks = vec![RiskFlag::UserDefinedFunction];
        assert!(judge(&permissive, unknown).is_ok());

        // And nothing else moved.
        let mut write = testing::parts(Dialect::PostgreSql);
        write.root_kind = StatementKind::Update;
        assert!(judge(&permissive, write).is_err());
    }
}
