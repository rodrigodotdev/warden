//! Exactly one agent statement per call.

use warden_core::analysis::RiskFlag;

use crate::decision::{DenyCode, DenyReason, PolicyDecision};
use crate::input::PolicyInput;
use crate::policy::Policy;

/// Denies anything that is not a single statement.
///
/// SPEC section 6, invariant 2. There is no `allow_multiple_statements`
/// configuration key and there never will be: a boolean that can become `true` is
/// the bypass flag SPEC section 9 prohibits, only hidden in a file that attracts
/// less scrutiny than a command-line option (ADR-0026).
///
/// Two independent signals are checked, because an analyzer may report the count, a
/// flag, or both.
#[derive(Debug, Clone, Copy)]
pub struct SingleStatementPolicy;

impl Policy for SingleStatementPolicy {
    fn name(&self) -> &'static str {
        "single_statement"
    }

    fn evaluate(&self, input: &PolicyInput<'_>) -> PolicyDecision {
        let analysis = input.analysis();
        let count = analysis.statement_count().get();
        if count > 1 {
            return PolicyDecision::Deny(DenyReason::with_detail(
                DenyCode::MultipleStatements,
                format!("analysis reported {count} statements"),
            ));
        }
        if analysis.has_risk(RiskFlag::MultipleStatements) {
            return PolicyDecision::Deny(DenyReason::with_detail(
                DenyCode::MultipleStatements,
                "analysis flagged multiple statements",
            ));
        }
        PolicyDecision::Allow
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::num::NonZeroUsize;

    use warden_core::analysis::QueryAnalysis;
    use warden_core::dialect::Dialect;

    use super::*;
    use crate::testing;

    #[test]
    fn one_statement_passes() {
        let analysis = testing::analysis(Dialect::MySql);
        assert_eq!(
            testing::denied_code(&SingleStatementPolicy, &analysis),
            None
        );
    }

    #[test]
    fn a_second_statement_is_denied_with_the_count() {
        let mut parts = testing::parts(Dialect::MySql);
        parts.statement_count = NonZeroUsize::new(2).unwrap();
        let analysis = QueryAnalysis::new(parts);

        assert_eq!(
            testing::denied_code(&SingleStatementPolicy, &analysis),
            Some(DenyCode::MultipleStatements)
        );
        assert_eq!(
            testing::denied_detail(&SingleStatementPolicy, &analysis).as_deref(),
            Some("analysis reported 2 statements")
        );
    }

    #[test]
    fn the_risk_flag_alone_is_enough() {
        // An analyzer that collapsed the input to one statement but noticed a
        // second one must still be believed.
        let mut parts = testing::parts(Dialect::PostgreSql);
        parts.risks = vec![RiskFlag::MultipleStatements];
        let analysis = QueryAnalysis::new(parts);

        assert_eq!(
            testing::denied_code(&SingleStatementPolicy, &analysis),
            Some(DenyCode::MultipleStatements)
        );
    }
}
