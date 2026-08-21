//! The root statement must be a `SELECT`.

use warden_core::analysis::StatementKind;

use crate::decision::{DenyCode, DenyReason, PolicyDecision};
use crate::input::PolicyInput;
use crate::policy::Policy;

/// Denies every root statement except `SELECT`.
///
/// ADR-0020: "read-only" is broader than `SELECT`, and accepting the rest through
/// the generic tool would widen the analysis surface without a proportional benefit.
/// `SHOW`, `EXPLAIN`, `SET`, `BEGIN`, `COMMIT`, and `ROLLBACK` are denied here;
/// metadata and plans have dedicated tools with their own contracts.
///
/// A CTE-based `SELECT` reaches this policy as `StatementKind::Select`; whether its
/// nested statements are read-only is [`super::NestedWritePolicy`]'s question.
#[derive(Debug, Clone, Copy)]
pub struct ReadOnlyRootStatementPolicy;

impl ReadOnlyRootStatementPolicy {
    /// The code each root kind is denied with, or `None` for the one kind allowed.
    ///
    /// Exhaustive on purpose. Adding a `StatementKind` variant must fail to compile
    /// here, because the alternative — a wildcard that maps the new kind to
    /// "allowed" or to a vague code — is how a category gets waved through
    /// (ADR-0021).
    fn code_for(kind: StatementKind) -> Option<DenyCode> {
        match kind {
            StatementKind::Select => None,
            // Statements that modify data.
            StatementKind::Insert
            | StatementKind::Update
            | StatementKind::Delete
            | StatementKind::Merge
            | StatementKind::Copy => Some(DenyCode::WriteStatement),
            StatementKind::Ddl => Some(DenyCode::Ddl),
            StatementKind::SessionControl => Some(DenyCode::SessionMutation),
            // Recognized, and deliberately not offered through this tool. Reporting
            // a `SHOW` as a write statement would make the audit record wrong.
            StatementKind::Call
            | StatementKind::Show
            | StatementKind::Explain
            | StatementKind::TransactionControl
            | StatementKind::Utility => Some(DenyCode::StatementNotAllowed),
            StatementKind::Unknown => Some(DenyCode::UnknownConstruct),
        }
    }
}

impl Policy for ReadOnlyRootStatementPolicy {
    fn name(&self) -> &'static str {
        "read_only_root_statement"
    }

    fn evaluate(&self, input: &PolicyInput<'_>) -> PolicyDecision {
        let kind = input.analysis().root_kind();
        match Self::code_for(kind) {
            None => PolicyDecision::Allow,
            Some(code) => PolicyDecision::Deny(DenyReason::with_detail(
                code,
                format!("root statement kind: {}", kind.as_str()),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use warden_core::analysis::QueryAnalysis;
    use warden_core::dialect::Dialect;

    use super::*;
    use crate::testing;

    fn with_root(kind: StatementKind) -> QueryAnalysis {
        let mut parts = testing::parts(Dialect::MySql);
        parts.root_kind = kind;
        QueryAnalysis::new(parts)
    }

    #[test]
    fn every_statement_kind_has_a_decided_outcome() {
        // `docs/testing.md` section 2 requires every variant to be covered
        // explicitly, including `Unknown`. The length assertion makes adding a
        // variant fail here even if `code_for` were given a wildcard by accident.
        let expected = [
            (StatementKind::Select, None),
            (StatementKind::Explain, Some(DenyCode::StatementNotAllowed)),
            (StatementKind::Show, Some(DenyCode::StatementNotAllowed)),
            (StatementKind::Insert, Some(DenyCode::WriteStatement)),
            (StatementKind::Update, Some(DenyCode::WriteStatement)),
            (StatementKind::Delete, Some(DenyCode::WriteStatement)),
            (StatementKind::Merge, Some(DenyCode::WriteStatement)),
            (StatementKind::Call, Some(DenyCode::StatementNotAllowed)),
            (StatementKind::Copy, Some(DenyCode::WriteStatement)),
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
                testing::denied_code(&ReadOnlyRootStatementPolicy, &with_root(kind)),
                code,
                "unexpected outcome for {}",
                kind.as_str()
            );
        }
    }

    #[test]
    fn the_audit_detail_names_the_kind_and_nothing_else() {
        let analysis = with_root(StatementKind::Delete);
        assert_eq!(
            testing::denied_detail(&ReadOnlyRootStatementPolicy, &analysis).as_deref(),
            Some("root statement kind: delete")
        );
    }

    #[test]
    fn the_agent_is_never_told_which_kind_it_used() {
        let analysis = with_root(StatementKind::Show);
        let code = testing::denied_code(&ReadOnlyRootStatementPolicy, &analysis).unwrap();
        assert!(!code.public_message().contains("show"));
    }
}
