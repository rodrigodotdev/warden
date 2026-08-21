//! The evidence must describe the connection it is evaluated against.
//!
//! That property has two halves. This file is the dialect half. The connection-name
//! half — the evidence must also target the same *named* connection, not merely one
//! with the same dialect — lives in `PolicyEngine::authorize`, because a `Policy`
//! never sees the request that carries the connection name
//! (`crate::input::PolicyInput` deliberately withholds it) and the engine is the one
//! place holding both.

use crate::decision::{DenyCode, DenyReason, PolicyDecision};
use crate::input::PolicyInput;
use crate::policy::Policy;

/// Denies a statement whose analysis came from a different dialect than the
/// connection's.
///
/// In correct wiring this can never fire: the service resolves the connection and
/// then calls that connection's own analyzer. That is exactly why it exists.
/// "Unreachable in correct code" is the assumption defense in depth refuses to make,
/// and the cost of checking is one comparison. A mismatch means the evidence
/// describes some other engine's grammar, so nothing else the policies concluded can
/// be trusted.
///
/// This is only the dialect half of connection-identity checking. Two distinct
/// connections that share a dialect — the common case, two PostgreSQL databases with
/// different allowlists — cannot be told apart from here, because `PolicyInput`
/// carries no connection name. `PolicyEngine::authorize` closes that gap directly.
#[derive(Debug, Clone, Copy)]
pub struct AnalysisIntegrityPolicy;

impl Policy for AnalysisIntegrityPolicy {
    fn name(&self) -> &'static str {
        "analysis_integrity"
    }

    fn evaluate(&self, input: &PolicyInput<'_>) -> PolicyDecision {
        let analyzed = input.analysis().dialect();
        let configured = input.dialect();
        if analyzed == configured {
            return PolicyDecision::Allow;
        }
        PolicyDecision::Deny(DenyReason::with_detail(
            // The residual code: Warden cannot classify this statement, because the
            // classification it holds belongs to a different engine.
            DenyCode::UnknownConstruct,
            format!(
                "analysis dialect {} does not match connection dialect {}",
                analyzed.as_str(),
                configured.as_str()
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use warden_core::dialect::Dialect;

    use super::*;
    use crate::testing;

    #[test]
    fn matching_dialects_pass() {
        let analysis = testing::analysis(Dialect::MySql);
        assert_eq!(
            testing::decide_against(&AnalysisIntegrityPolicy, &analysis, Dialect::MySql),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn a_mismatch_is_denied_and_named_in_the_audit() {
        let analysis = testing::analysis(Dialect::PostgreSql);
        let PolicyDecision::Deny(reason) =
            testing::decide_against(&AnalysisIntegrityPolicy, &analysis, Dialect::MySql)
        else {
            panic!("a dialect mismatch must be denied");
        };
        assert_eq!(reason.code(), DenyCode::UnknownConstruct);
        assert_eq!(
            reason.internal_detail(),
            Some("analysis dialect postgresql does not match connection dialect mysql")
        );
    }
}
