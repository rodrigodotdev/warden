//! Row-locking reads are denied by default.

use warden_core::analysis::RiskFlag;

use crate::decision::{DenyCode, DenyReason, PolicyDecision};
use crate::input::PolicyInput;
use crate::policy::Policy;
use crate::settings::Relaxations;

/// Denies `FOR UPDATE`, `FOR SHARE`, `LOCK IN SHARE MODE`, and their relatives.
///
/// SPEC section 6, invariant 6. A locking read is not a write, but it blocks
/// writers, and an agent investigating a production replica has no reason to take
/// row locks.
#[derive(Debug, Clone, Copy)]
pub struct LockingReadPolicy {
    relaxations: Relaxations,
}

impl LockingReadPolicy {
    /// Builds the policy with the operator's chosen relaxations.
    #[must_use]
    pub fn new(relaxations: Relaxations) -> Self {
        Self { relaxations }
    }
}

impl Policy for LockingReadPolicy {
    fn name(&self) -> &'static str {
        "locking_read"
    }

    fn evaluate(&self, input: &PolicyInput<'_>) -> PolicyDecision {
        if self.relaxations.locking_reads {
            return PolicyDecision::Allow;
        }
        let analysis = input.analysis();
        if analysis.has_locking_clause() {
            return PolicyDecision::Deny(DenyReason::with_detail(
                DenyCode::LockingRead,
                "analysis reported a locking clause",
            ));
        }
        if analysis.has_risk(RiskFlag::LockingRead) {
            return PolicyDecision::Deny(DenyReason::with_detail(
                DenyCode::LockingRead,
                "analysis flagged a locking read",
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

    fn locking() -> QueryAnalysis {
        let mut parts = testing::parts(Dialect::PostgreSql);
        parts.has_locking_clause = true;
        QueryAnalysis::new(parts)
    }

    fn denying() -> LockingReadPolicy {
        LockingReadPolicy::new(Relaxations::default())
    }

    #[test]
    fn a_plain_select_passes() {
        let analysis = testing::analysis(Dialect::PostgreSql);
        assert_eq!(testing::denied_code(&denying(), &analysis), None);
    }

    #[test]
    fn a_locking_clause_is_denied() {
        assert_eq!(
            testing::denied_code(&denying(), &locking()),
            Some(DenyCode::LockingRead)
        );
    }

    #[test]
    fn the_risk_flag_alone_is_enough() {
        let mut parts = testing::parts(Dialect::MySql);
        parts.risks = vec![RiskFlag::LockingRead];
        let analysis = QueryAnalysis::new(parts);
        assert_eq!(
            testing::denied_code(&denying(), &analysis),
            Some(DenyCode::LockingRead)
        );
    }

    #[test]
    fn an_operator_can_allow_them_deliberately() {
        let permissive = LockingReadPolicy::new(Relaxations {
            locking_reads: true,
            unknown_functions: false,
        });
        assert_eq!(testing::denied_code(&permissive, &locking()), None);
    }
}
