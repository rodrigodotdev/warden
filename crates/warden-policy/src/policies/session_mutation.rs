//! Session state and user variables belong to Warden, not to the agent.

use warden_core::analysis::{RiskFlag, StatementKind};

use crate::decision::{DenyCode, DenyReason, PolicyDecision};
use crate::input::PolicyInput;
use crate::policy::Policy;

/// Denies session and user-variable mutation anywhere in the query.
///
/// SPEC section 6, invariant 8. This is a pooling problem as much as a SQL problem:
/// MySQL session and user variables survive on a pooled connection, so a mutation
/// one request performs is a mutation the next request inherits
/// (`docs/operations.md` section 7).
///
/// Deliberately overlaps [`super::ReadOnlyRootStatementPolicy`] and
/// [`super::NestedWritePolicy`], which also reject `SessionControl`. Two independent
/// controls catching the same statement is defense in depth, and the engine records
/// both denials.
#[derive(Debug, Clone, Copy)]
pub struct SessionMutationPolicy;

impl Policy for SessionMutationPolicy {
    fn name(&self) -> &'static str {
        "session_mutation"
    }

    fn evaluate(&self, input: &PolicyInput<'_>) -> PolicyDecision {
        let analysis = input.analysis();

        if analysis.has_risk(RiskFlag::SessionMutation) {
            return PolicyDecision::Deny(DenyReason::with_detail(
                DenyCode::SessionMutation,
                "analysis flagged session or variable mutation",
            ));
        }
        if analysis.root_kind() == StatementKind::SessionControl {
            return PolicyDecision::Deny(DenyReason::with_detail(
                DenyCode::SessionMutation,
                "root statement kind: session_control",
            ));
        }
        if analysis
            .nested_kinds()
            .contains(&StatementKind::SessionControl)
        {
            return PolicyDecision::Deny(DenyReason::with_detail(
                DenyCode::SessionMutation,
                "nested: session_control",
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

    #[test]
    fn a_plain_select_passes() {
        let analysis = testing::analysis(Dialect::MySql);
        assert_eq!(
            testing::denied_code(&SessionMutationPolicy, &analysis),
            None
        );
    }

    #[test]
    fn the_flag_the_root_and_a_nested_statement_are_all_denied() {
        let mut flagged = testing::parts(Dialect::MySql);
        flagged.risks = vec![RiskFlag::SessionMutation];

        let mut root = testing::parts(Dialect::MySql);
        root.root_kind = StatementKind::SessionControl;

        let mut nested = testing::parts(Dialect::MySql);
        nested.nested_kinds = vec![StatementKind::SessionControl];

        for parts in [flagged, root, nested] {
            assert_eq!(
                testing::denied_code(&SessionMutationPolicy, &QueryAnalysis::new(parts)),
                Some(DenyCode::SessionMutation)
            );
        }
    }
}
