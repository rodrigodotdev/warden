//! No write, schema change, or session change nested anywhere in the query.

use warden_core::analysis::{RiskFlag, StatementKind};

use crate::decision::{DenyCode, DenyReason, PolicyDecision};
use crate::input::PolicyInput;
use crate::policy::Policy;

/// Denies a query whose nested statements are not all read-only.
///
/// Classifying only the root is insufficient (`docs/security.md` section 6.3):
///
/// ```sql
/// WITH changed AS (DELETE FROM orders RETURNING *)
/// SELECT * FROM changed;
/// ```
///
/// The root is a `SELECT` and the query deletes rows. Every nested kind is judged
/// with the same table as the root, and the `DataModifyingCte` flag is honored on
/// its own so an analyzer that noticed the shape without enumerating the nested kind
/// is still believed.
#[derive(Debug, Clone, Copy)]
pub struct NestedWritePolicy;

impl NestedWritePolicy {
    /// The code a nested kind is denied with, or `None` when it is read-only.
    ///
    /// Exhaustive for the same reason as the root table (ADR-0021). Writes get
    /// `NestedWrite` rather than `WriteStatement`, so an audit record distinguishes
    /// "the agent asked to delete" from "the agent hid a delete inside a select".
    fn code_for(kind: StatementKind) -> Option<DenyCode> {
        match kind {
            StatementKind::Select => None,
            StatementKind::Insert
            | StatementKind::Update
            | StatementKind::Delete
            | StatementKind::Merge
            | StatementKind::Copy => Some(DenyCode::NestedWrite),
            StatementKind::Ddl => Some(DenyCode::Ddl),
            StatementKind::SessionControl => Some(DenyCode::SessionMutation),
            StatementKind::Call
            | StatementKind::Show
            | StatementKind::Explain
            | StatementKind::TransactionControl
            | StatementKind::Utility => Some(DenyCode::StatementNotAllowed),
            StatementKind::Unknown => Some(DenyCode::UnknownConstruct),
        }
    }
}

impl Policy for NestedWritePolicy {
    fn name(&self) -> &'static str {
        "nested_write"
    }

    fn evaluate(&self, input: &PolicyInput<'_>) -> PolicyDecision {
        let analysis = input.analysis();

        let mut violations: Vec<(DenyCode, &'static str)> = analysis
            .nested_kinds()
            .iter()
            .filter_map(|kind| Self::code_for(*kind).map(|code| (code, kind.as_str())))
            .collect();

        if analysis.has_risk(RiskFlag::DataModifyingCte) {
            violations.push((DenyCode::NestedWrite, RiskFlag::DataModifyingCte.as_str()));
        }

        // One policy produces one reason, so the highest-precedence violation
        // becomes the code and every violation is named in the audit detail.
        let Some(&(code, _)) = violations.iter().min_by_key(|(code, _)| *code) else {
            return PolicyDecision::Allow;
        };
        let named: Vec<&str> = violations.iter().map(|(_, name)| *name).collect();
        PolicyDecision::Deny(DenyReason::with_detail(
            code,
            format!("nested: {}", named.join(", ")),
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

    fn with_nested(kinds: Vec<StatementKind>) -> QueryAnalysis {
        let mut parts = testing::parts(Dialect::PostgreSql);
        parts.nested_kinds = kinds;
        QueryAnalysis::new(parts)
    }

    #[test]
    fn a_read_only_cte_passes() {
        let analysis = with_nested(vec![StatementKind::Select, StatementKind::Select]);
        assert_eq!(testing::denied_code(&NestedWritePolicy, &analysis), None);
    }

    #[test]
    fn every_nested_kind_has_a_decided_outcome() {
        let expected = [
            (StatementKind::Select, None),
            (StatementKind::Explain, Some(DenyCode::StatementNotAllowed)),
            (StatementKind::Show, Some(DenyCode::StatementNotAllowed)),
            (StatementKind::Insert, Some(DenyCode::NestedWrite)),
            (StatementKind::Update, Some(DenyCode::NestedWrite)),
            (StatementKind::Delete, Some(DenyCode::NestedWrite)),
            (StatementKind::Merge, Some(DenyCode::NestedWrite)),
            (StatementKind::Call, Some(DenyCode::StatementNotAllowed)),
            (StatementKind::Copy, Some(DenyCode::NestedWrite)),
            (StatementKind::Ddl, Some(DenyCode::Ddl)),
            (
                StatementKind::TransactionControl,
                Some(DenyCode::StatementNotAllowed),
            ),
            (
                StatementKind::SessionControl,
                Some(DenyCode::SessionMutation),
            ),
            (StatementKind::Utility, Some(DenyCode::StatementNotAllowed)),
            (StatementKind::Unknown, Some(DenyCode::UnknownConstruct)),
        ];
        assert_eq!(
            expected.len(),
            StatementKind::ALL.len(),
            "a statement kind is missing from this table"
        );

        for (kind, code) in expected {
            assert_eq!(
                testing::denied_code(&NestedWritePolicy, &with_nested(vec![kind])),
                code,
                "unexpected outcome for nested {}",
                kind.as_str()
            );
        }
    }

    #[test]
    fn the_data_modifying_cte_flag_alone_is_enough() {
        let mut parts = testing::parts(Dialect::PostgreSql);
        parts.risks = vec![RiskFlag::DataModifyingCte];
        let analysis = QueryAnalysis::new(parts);

        assert_eq!(
            testing::denied_code(&NestedWritePolicy, &analysis),
            Some(DenyCode::NestedWrite)
        );
        assert_eq!(
            testing::denied_detail(&NestedWritePolicy, &analysis).as_deref(),
            Some("nested: data_modifying_cte")
        );
    }

    #[test]
    fn the_highest_precedence_violation_becomes_the_code_and_all_are_audited() {
        let analysis = with_nested(vec![
            StatementKind::Show,
            StatementKind::Delete,
            StatementKind::Select,
        ]);
        assert_eq!(
            testing::denied_code(&NestedWritePolicy, &analysis),
            Some(DenyCode::NestedWrite)
        );
        assert_eq!(
            testing::denied_detail(&NestedWritePolicy, &analysis).as_deref(),
            Some("nested: show, delete")
        );
    }
}
