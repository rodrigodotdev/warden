//! Every risk the analyzer reported is a denial by default.

use warden_core::analysis::RiskFlag;

use crate::decision::{DenyCode, DenyReason, PolicyDecision};
use crate::input::PolicyInput;
use crate::policy::Policy;
use crate::settings::Relaxations;

/// Denies a statement that carries any [`RiskFlag`], or an unexplained side effect.
///
/// `docs/security.md` section 6.1 lists an `UnknownConstructPolicy` covering one
/// flag. This is that policy widened to all sixteen, because the match is where the
/// value is: every flag is mapped explicitly, none maps to "ignore", and adding a
/// flag to `warden-core` breaks this file (ADR-0021). Risk flags are evidence, and
/// the default answer to evidence is denial (ADR-0011).
///
/// Two flags respect the operator's relaxations, because they correspond to the two
/// configurable tradeoffs of ADR-0026; the other fourteen are unconditional.
///
/// This overlaps [`super::LockingReadPolicy`], [`super::SessionMutationPolicy`],
/// [`super::FunctionSafetyPolicy`], and the two statement-shape policies on purpose.
#[derive(Debug, Clone, Copy)]
pub struct RiskEvidencePolicy {
    relaxations: Relaxations,
}

impl RiskEvidencePolicy {
    /// Builds the policy with the operator's chosen relaxations.
    #[must_use]
    pub fn new(relaxations: Relaxations) -> Self {
        Self { relaxations }
    }

    /// The code a flag is denied with, or `None` when the operator relaxed it.
    fn code_for(&self, flag: RiskFlag) -> Option<DenyCode> {
        match flag {
            RiskFlag::MultipleStatements => Some(DenyCode::MultipleStatements),
            RiskFlag::WriteStatement => Some(DenyCode::WriteStatement),
            RiskFlag::Ddl => Some(DenyCode::Ddl),
            RiskFlag::DataModifyingCte => Some(DenyCode::NestedWrite),
            // `SELECT ... INTO OUTFILE` and `nextval` write. They are not `SELECT`
            // statements that happen to be risky; they modify state outside the
            // result set, and the audit record should say so.
            RiskFlag::FileOutput | RiskFlag::SequenceMutation => Some(DenyCode::WriteStatement),
            // `SELECT INTO` creates a relation.
            RiskFlag::SelectInto => Some(DenyCode::Ddl),
            RiskFlag::SessionMutation => Some(DenyCode::SessionMutation),
            // Function-shaped risks, whatever the adapter's classification said.
            RiskFlag::FileAccess | RiskFlag::DelayFunction | RiskFlag::AdvisoryLock => {
                Some(DenyCode::DangerousFunction)
            }
            // Recognized constructs this tool does not offer.
            RiskFlag::StoredRoutine | RiskFlag::ExplainAnalyze => {
                Some(DenyCode::StatementNotAllowed)
            }
            RiskFlag::UnknownConstruct => Some(DenyCode::UnknownConstruct),
            // The two configurable tradeoffs (ADR-0026).
            RiskFlag::LockingRead => {
                (!self.relaxations.locking_reads).then_some(DenyCode::LockingRead)
            }
            RiskFlag::UserDefinedFunction => {
                (!self.relaxations.unknown_functions).then_some(DenyCode::UnknownFunction)
            }
        }
    }
}

impl Policy for RiskEvidencePolicy {
    fn name(&self) -> &'static str {
        "risk_evidence"
    }

    fn evaluate(&self, input: &PolicyInput<'_>) -> PolicyDecision {
        let analysis = input.analysis();

        let mut violations: Vec<(DenyCode, &'static str)> = analysis
            .risks()
            .iter()
            .filter_map(|flag| self.code_for(*flag).map(|code| (code, flag.as_str())))
            .collect();

        // An adapter that reports a side effect it could not name has told us the
        // most important thing it knows: something happens that Warden cannot
        // describe. The condition is narrow on purpose — if any flag exists, the
        // side effect is explained, and relaxing a flag must not resurface here as
        // an unexplained one.
        if violations.is_empty() && analysis.risks().is_empty() && analysis.has_side_effects() {
            violations.push((DenyCode::UnknownConstruct, "unnamed side effect"));
        }

        let Some(&(code, _)) = violations.iter().min_by_key(|(code, _)| *code) else {
            return PolicyDecision::Allow;
        };
        let named: Vec<&str> = violations.iter().map(|(_, name)| *name).collect();
        PolicyDecision::Deny(DenyReason::with_detail(
            code,
            format!("risk evidence: {}", named.join(", ")),
        ))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use warden_core::analysis::QueryAnalysis;
    use warden_core::dialect::Dialect;

    use super::*;
    use crate::testing;

    fn with_risks(risks: Vec<RiskFlag>) -> QueryAnalysis {
        let mut parts = testing::parts(Dialect::MySql);
        parts.risks = risks;
        QueryAnalysis::new(parts)
    }

    fn denying() -> RiskEvidencePolicy {
        RiskEvidencePolicy::new(Relaxations::default())
    }

    #[test]
    fn evidence_free_analysis_passes() {
        let analysis = testing::analysis(Dialect::MySql);
        assert_eq!(testing::denied_code(&denying(), &analysis), None);
    }

    #[test]
    fn every_risk_flag_is_denied_by_default() {
        let expected = [
            (RiskFlag::MultipleStatements, DenyCode::MultipleStatements),
            (RiskFlag::WriteStatement, DenyCode::WriteStatement),
            (RiskFlag::Ddl, DenyCode::Ddl),
            (RiskFlag::LockingRead, DenyCode::LockingRead),
            (RiskFlag::DataModifyingCte, DenyCode::NestedWrite),
            (RiskFlag::FileAccess, DenyCode::DangerousFunction),
            (RiskFlag::FileOutput, DenyCode::WriteStatement),
            (RiskFlag::DelayFunction, DenyCode::DangerousFunction),
            (RiskFlag::AdvisoryLock, DenyCode::DangerousFunction),
            (RiskFlag::SessionMutation, DenyCode::SessionMutation),
            (RiskFlag::SequenceMutation, DenyCode::WriteStatement),
            (RiskFlag::StoredRoutine, DenyCode::StatementNotAllowed),
            (RiskFlag::UserDefinedFunction, DenyCode::UnknownFunction),
            (RiskFlag::ExplainAnalyze, DenyCode::StatementNotAllowed),
            (RiskFlag::SelectInto, DenyCode::Ddl),
            (RiskFlag::UnknownConstruct, DenyCode::UnknownConstruct),
        ];
        assert_eq!(
            expected.len(),
            RiskFlag::ALL.len(),
            "a risk flag is missing from this table"
        );

        for (flag, code) in expected {
            assert_eq!(
                testing::denied_code(&denying(), &with_risks(vec![flag])),
                Some(code),
                "unexpected outcome for {}",
                flag.as_str()
            );
        }
    }

    #[test]
    fn the_two_relaxable_flags_are_the_only_relaxable_ones() {
        let permissive = RiskEvidencePolicy::new(Relaxations {
            locking_reads: true,
            unknown_functions: true,
        });

        for flag in RiskFlag::ALL {
            let relaxable = matches!(flag, RiskFlag::LockingRead | RiskFlag::UserDefinedFunction);
            let outcome = testing::denied_code(&permissive, &with_risks(vec![flag]));
            assert_eq!(
                outcome.is_none(),
                relaxable,
                "{} was{} relaxed",
                flag.as_str(),
                if outcome.is_none() { "" } else { " not" }
            );
        }
    }

    #[test]
    fn the_highest_precedence_flag_becomes_the_code_and_all_are_audited() {
        let analysis = with_risks(vec![RiskFlag::LockingRead, RiskFlag::Ddl]);
        assert_eq!(
            testing::denied_code(&denying(), &analysis),
            Some(DenyCode::Ddl)
        );
        assert_eq!(
            testing::denied_detail(&denying(), &analysis).as_deref(),
            Some("risk evidence: locking_read, ddl")
        );
    }

    #[test]
    fn an_unexplained_side_effect_is_denied() {
        let mut parts = testing::parts(Dialect::PostgreSql);
        parts.has_side_effects = true;
        let analysis = QueryAnalysis::new(parts);

        assert_eq!(
            testing::denied_code(&denying(), &analysis),
            Some(DenyCode::UnknownConstruct)
        );
        assert_eq!(
            testing::denied_detail(&denying(), &analysis).as_deref(),
            Some("risk evidence: unnamed side effect")
        );
    }

    #[test]
    fn a_relaxed_flag_does_not_reappear_as_an_unexplained_side_effect() {
        // A locking read has a side effect: it takes locks. If the operator allowed
        // locking reads, the fallback must not deny the query anyway, or the
        // configuration knob would be a lie.
        let mut parts = testing::parts(Dialect::PostgreSql);
        parts.risks = vec![RiskFlag::LockingRead];
        parts.has_side_effects = true;
        let analysis = QueryAnalysis::new(parts);

        let permissive = RiskEvidencePolicy::new(Relaxations {
            locking_reads: true,
            unknown_functions: false,
        });
        assert_eq!(testing::denied_code(&permissive, &analysis), None);
    }
}
