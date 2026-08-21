//! Only functions the adapter classified as safe may appear.

use warden_core::analysis::{FunctionClassification, FunctionRef};

use crate::decision::{DenyCode, DenyReason, PolicyDecision};
use crate::input::PolicyInput;
use crate::policy::Policy;
use crate::settings::Relaxations;

/// Denies dangerous and unclassified functions.
///
/// SPEC section 6, invariant 7. Functions are security-relevant because a `SELECT`
/// can still have side effects: `SLEEP`, `BENCHMARK`, `GET_LOCK`, `LOAD_FILE`,
/// `pg_sleep`, `pg_advisory_lock`, `nextval`, and every unverified user-defined
/// function live behind a perfectly ordinary-looking projection.
///
/// Classification itself belongs to the adapters; this policy only decides what a
/// classification means, and the mapping is the one `docs/data-model.md` section 5
/// states: `KnownSafe` is eligible, everything else is denied.
#[derive(Debug, Clone, Copy)]
pub struct FunctionSafetyPolicy {
    relaxations: Relaxations,
}

impl FunctionSafetyPolicy {
    /// Builds the policy with the operator's chosen relaxations.
    #[must_use]
    pub fn new(relaxations: Relaxations) -> Self {
        Self { relaxations }
    }

    /// `schema.name` when the statement qualified the call, `name` otherwise.
    fn qualified(function: &FunctionRef) -> String {
        match &function.schema {
            Some(schema) => format!("{schema}.{}", function.name),
            None => function.name.clone(),
        }
    }
}

impl Policy for FunctionSafetyPolicy {
    fn name(&self) -> &'static str {
        "function_safety"
    }

    fn evaluate(&self, input: &PolicyInput<'_>) -> PolicyDecision {
        let mut dangerous = Vec::new();
        let mut unknown = Vec::new();

        for function in input.analysis().functions() {
            // Exhaustive: a new classification must not default to "eligible".
            match function.classification {
                FunctionClassification::KnownSafe => {}
                FunctionClassification::KnownDangerous => {
                    dangerous.push(Self::qualified(function));
                }
                FunctionClassification::Unknown => unknown.push(Self::qualified(function)),
            }
        }

        // Dangerous outranks unknown: naming the certain problem is more useful to
        // an auditor than naming the uncertain one.
        if !dangerous.is_empty() {
            return PolicyDecision::Deny(DenyReason::with_detail(
                DenyCode::DangerousFunction,
                format!("dangerous functions: {}", dangerous.join(", ")),
            ));
        }
        if !unknown.is_empty() && !self.relaxations.unknown_functions {
            return PolicyDecision::Deny(DenyReason::with_detail(
                DenyCode::UnknownFunction,
                format!("unclassified functions: {}", unknown.join(", ")),
            ));
        }
        PolicyDecision::Allow
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use warden_core::analysis::QueryAnalysis;
    use warden_core::dialect::Dialect;

    use super::*;
    use crate::testing;

    fn with_functions(functions: Vec<FunctionRef>) -> QueryAnalysis {
        let mut parts = testing::parts(Dialect::PostgreSql);
        parts.functions = functions;
        QueryAnalysis::new(parts)
    }

    fn denying() -> FunctionSafetyPolicy {
        FunctionSafetyPolicy::new(Relaxations::default())
    }

    #[test]
    fn every_classification_has_a_decided_outcome() {
        let expected = [
            (FunctionClassification::KnownSafe, None),
            (
                FunctionClassification::KnownDangerous,
                Some(DenyCode::DangerousFunction),
            ),
            (
                FunctionClassification::Unknown,
                Some(DenyCode::UnknownFunction),
            ),
        ];
        assert_eq!(
            expected.len(),
            FunctionClassification::ALL.len(),
            "a classification is missing from this table"
        );

        for (classification, code) in expected {
            let analysis = with_functions(vec![testing::function("f", classification)]);
            assert_eq!(testing::denied_code(&denying(), &analysis), code);
        }
    }

    #[test]
    fn the_audit_names_every_offending_function() {
        let analysis = with_functions(vec![
            testing::function("lower", FunctionClassification::KnownSafe),
            testing::function("pg_sleep", FunctionClassification::KnownDangerous),
            testing::function("pg_advisory_lock", FunctionClassification::KnownDangerous),
        ]);
        assert_eq!(
            testing::denied_detail(&denying(), &analysis).as_deref(),
            Some("dangerous functions: pg_sleep, pg_advisory_lock")
        );
    }

    #[test]
    fn dangerous_outranks_unknown() {
        let analysis = with_functions(vec![
            testing::function("mystery", FunctionClassification::Unknown),
            testing::function("pg_sleep", FunctionClassification::KnownDangerous),
        ]);
        assert_eq!(
            testing::denied_code(&denying(), &analysis),
            Some(DenyCode::DangerousFunction)
        );
    }

    #[test]
    fn a_qualified_call_is_reported_with_its_schema() {
        let analysis = with_functions(vec![FunctionRef {
            name: "do_something".to_owned(),
            schema: Some("public".to_owned()),
            classification: FunctionClassification::Unknown,
        }]);
        assert_eq!(
            testing::denied_detail(&denying(), &analysis).as_deref(),
            Some("unclassified functions: public.do_something")
        );
    }

    #[test]
    fn relaxing_unknown_functions_never_relaxes_dangerous_ones() {
        let permissive = FunctionSafetyPolicy::new(Relaxations {
            locking_reads: false,
            unknown_functions: true,
        });

        let unknown = with_functions(vec![testing::function(
            "mystery",
            FunctionClassification::Unknown,
        )]);
        assert_eq!(testing::denied_code(&permissive, &unknown), None);

        let dangerous = with_functions(vec![testing::function(
            "pg_sleep",
            FunctionClassification::KnownDangerous,
        )]);
        assert_eq!(
            testing::denied_code(&permissive, &dangerous),
            Some(DenyCode::DangerousFunction)
        );
    }

    #[test]
    fn the_agent_never_learns_which_function_it_was() {
        let analysis = with_functions(vec![testing::function(
            "internal_secret_lookup",
            FunctionClassification::Unknown,
        )]);
        let code = testing::denied_code(&denying(), &analysis).unwrap();
        assert!(!code.public_message().contains("internal_secret_lookup"));
        assert_eq!(
            code.public_message(),
            "the query uses a function not classified as safe"
        );
    }
}
