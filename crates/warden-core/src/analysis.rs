//! The evidence an authorization decision is made from.

pub mod reference;
pub mod risk;
pub mod statement;

use std::num::NonZeroUsize;

use crate::dialect::Dialect;
use crate::fingerprint::QueryFingerprint;

pub use reference::{
    FunctionClassification, FunctionRef, IdentifierQuoting, ObjectKind, ObjectRef, SqlIdentifier,
};
pub use risk::RiskFlag;
pub use statement::StatementKind;

/// Everything an adapter must state about a statement.
///
/// This is the only way to build a [`QueryAnalysis`], and it exists as a struct
/// rather than a builder so the compiler enforces completeness: a struct literal
/// must name every field, named fields cannot be transposed the way two positional
/// `bool` arguments can, and adding a field here later breaks every adapter until
/// it is considered — the same property ADR-0021 wants from enums.
///
/// Honest scope (`docs/architecture.md` section 4.2): this prevents an *accidental*
/// half-built analysis. It does not make `QueryAnalysis` unforgeable. The
/// unforgeable capability is `AllowDecision` in `warden-policy`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryAnalysisParts {
    /// The dialect the statement was parsed with.
    pub dialect: Dialect,
    /// How many statements the input contained. At least one, or analysis failed.
    pub statement_count: NonZeroUsize,
    /// The category of the root statement.
    pub root_kind: StatementKind,
    /// Categories of every nested statement, such as a CTE body.
    pub nested_kinds: Vec<StatementKind>,
    /// Objects the statement refers to, excluding CTE names and aliases.
    pub objects: Vec<ObjectRef>,
    /// Functions the statement invokes.
    pub functions: Vec<FunctionRef>,
    /// Everything security-relevant the analyzer noticed.
    pub risks: Vec<RiskFlag>,
    /// Whether the statement carries a row-locking clause.
    pub has_locking_clause: bool,
    /// Whether the statement can have effects beyond reading rows.
    pub has_side_effects: bool,
    /// The fingerprint, when the adapter computed one.
    pub fingerprint: Option<QueryFingerprint>,
}

/// A lossy, parser-independent description of one statement.
///
/// Fields are private with read-only accessors because this is the evidence
/// authorization is based on: public fields would let any crate write
/// `analysis.risks = Vec::new()` and defeat the pipeline
/// (`docs/data-model.md` section 5).
///
/// No `sqlparser` type appears here or in any adapter's public signature
/// (ADR-0007), which is what keeps the parser replaceable.
///
/// `Debug` is derived: this type holds object and function names, never SQL text or
/// parameter values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryAnalysis {
    dialect: Dialect,
    statement_count: NonZeroUsize,
    root_kind: StatementKind,
    nested_kinds: Vec<StatementKind>,
    objects: Vec<ObjectRef>,
    functions: Vec<FunctionRef>,
    risks: Vec<RiskFlag>,
    has_locking_clause: bool,
    has_side_effects: bool,
    fingerprint: Option<QueryFingerprint>,
}

impl QueryAnalysis {
    /// Freezes a complete set of parts into read-only evidence.
    #[must_use]
    pub fn new(parts: QueryAnalysisParts) -> Self {
        Self {
            dialect: parts.dialect,
            statement_count: parts.statement_count,
            root_kind: parts.root_kind,
            nested_kinds: parts.nested_kinds,
            objects: parts.objects,
            functions: parts.functions,
            risks: parts.risks,
            has_locking_clause: parts.has_locking_clause,
            has_side_effects: parts.has_side_effects,
            fingerprint: parts.fingerprint,
        }
    }

    /// The dialect the statement was parsed with.
    #[must_use]
    pub fn dialect(&self) -> Dialect {
        self.dialect
    }

    /// How many statements the input contained.
    #[must_use]
    pub fn statement_count(&self) -> NonZeroUsize {
        self.statement_count
    }

    /// The category of the root statement.
    #[must_use]
    pub fn root_kind(&self) -> StatementKind {
        self.root_kind
    }

    /// Categories of every nested statement.
    #[must_use]
    pub fn nested_kinds(&self) -> &[StatementKind] {
        &self.nested_kinds
    }

    /// Objects the statement refers to.
    #[must_use]
    pub fn objects(&self) -> &[ObjectRef] {
        &self.objects
    }

    /// Functions the statement invokes.
    #[must_use]
    pub fn functions(&self) -> &[FunctionRef] {
        &self.functions
    }

    /// Everything security-relevant the analyzer noticed.
    #[must_use]
    pub fn risks(&self) -> &[RiskFlag] {
        &self.risks
    }

    /// Whether a specific flag is present.
    #[must_use]
    pub fn has_risk(&self, flag: RiskFlag) -> bool {
        self.risks.contains(&flag)
    }

    /// Whether the statement carries a row-locking clause.
    #[must_use]
    pub fn has_locking_clause(&self) -> bool {
        self.has_locking_clause
    }

    /// Whether the statement can have effects beyond reading rows.
    #[must_use]
    pub fn has_side_effects(&self) -> bool {
        self.has_side_effects
    }

    /// The fingerprint, when the adapter computed one.
    #[must_use]
    pub fn fingerprint(&self) -> Option<&QueryFingerprint> {
        self.fingerprint.as_ref()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn parts() -> QueryAnalysisParts {
        QueryAnalysisParts {
            dialect: Dialect::PostgreSql,
            statement_count: NonZeroUsize::MIN,
            root_kind: StatementKind::Select,
            nested_kinds: vec![StatementKind::Delete],
            objects: vec![ObjectRef {
                catalog: None,
                schema: Some(SqlIdentifier::unquoted("app")),
                name: SqlIdentifier::unquoted("orders"),
                kind: ObjectKind::Table,
            }],
            functions: vec![FunctionRef {
                name: SqlIdentifier::unquoted("pg_sleep"),
                schema: None,
                classification: FunctionClassification::KnownDangerous,
            }],
            risks: vec![RiskFlag::DataModifyingCte, RiskFlag::WriteStatement],
            has_locking_clause: false,
            has_side_effects: true,
            fingerprint: Some(crate::fingerprint::QueryFingerprint::v1(&"b".repeat(64)).unwrap()),
        }
    }

    #[test]
    fn accessors_return_exactly_what_the_adapter_stated() {
        let analysis = QueryAnalysis::new(parts());
        assert_eq!(analysis.dialect(), Dialect::PostgreSql);
        assert_eq!(analysis.statement_count().get(), 1);
        assert_eq!(analysis.root_kind(), StatementKind::Select);
        assert_eq!(analysis.nested_kinds(), [StatementKind::Delete]);
        assert_eq!(analysis.objects()[0].qualified_name(), "app.orders");
        assert_eq!(analysis.functions()[0].name.value(), "pg_sleep");
        assert!(analysis.has_side_effects());
        assert!(!analysis.has_locking_clause());
        assert_eq!(
            analysis.fingerprint().map(QueryFingerprint::as_str),
            Some(&*format!("v1:{}", "b".repeat(64)))
        );
    }

    #[test]
    fn has_risk_reports_presence_without_deciding_anything() {
        let analysis = QueryAnalysis::new(parts());
        assert!(analysis.has_risk(RiskFlag::DataModifyingCte));
        assert!(!analysis.has_risk(RiskFlag::LockingRead));
        assert_eq!(analysis.risks().len(), 2);
    }

    #[test]
    fn an_analysis_can_never_describe_zero_statements() {
        // NonZeroUsize removes the "statement_count: 0" state that would otherwise
        // need a runtime check on every policy path.
        let analysis = QueryAnalysis::new(parts());
        assert!(analysis.statement_count().get() >= 1);
    }
}
