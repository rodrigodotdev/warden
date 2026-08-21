//! Security-relevant facts about a statement.

/// Evidence, not a decision.
///
/// A policy decides what a flag means; no isolated boolean authorizes anything
/// (`docs/data-model.md` section 5). Same `#[non_exhaustive]` reasoning as
/// [`super::statement::StatementKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskFlag {
    /// More than one statement was submitted.
    MultipleStatements,
    /// A write statement appears at the root or nested inside the query.
    WriteStatement,
    /// A data-definition statement appears anywhere in the query.
    Ddl,
    /// A row-locking read clause such as `FOR UPDATE` or `LOCK IN SHARE MODE`.
    LockingRead,
    /// A CTE that modifies data, such as `WITH x AS (DELETE ... RETURNING *)`.
    DataModifyingCte,
    /// A construct that reads a file, such as `LOAD_FILE`.
    FileAccess,
    /// A construct that writes a file, such as `INTO OUTFILE` or `INTO DUMPFILE`.
    FileOutput,
    /// A delay or benchmark function, such as `SLEEP`, `BENCHMARK`, or `pg_sleep`.
    DelayFunction,
    /// An advisory-lock function.
    AdvisoryLock,
    /// Session or user-variable mutation.
    SessionMutation,
    /// Sequence mutation, such as `nextval` or `setval`.
    SequenceMutation,
    /// A stored-routine invocation.
    StoredRoutine,
    /// A user-defined function Warden cannot classify.
    UserDefinedFunction,
    /// `EXPLAIN ANALYZE`, which executes the underlying query.
    ExplainAnalyze,
    /// A `SELECT INTO` that creates a relation.
    SelectInto,
    /// A construct the analyzer could not classify. Always denied.
    UnknownConstruct,
}

impl RiskFlag {
    /// Every flag. Policy tests iterate this to prove each one is handled.
    pub const ALL: [Self; 16] = [
        Self::MultipleStatements,
        Self::WriteStatement,
        Self::Ddl,
        Self::LockingRead,
        Self::DataModifyingCte,
        Self::FileAccess,
        Self::FileOutput,
        Self::DelayFunction,
        Self::AdvisoryLock,
        Self::SessionMutation,
        Self::SequenceMutation,
        Self::StoredRoutine,
        Self::UserDefinedFunction,
        Self::ExplainAnalyze,
        Self::SelectInto,
        Self::UnknownConstruct,
    ];

    /// The stable name used in audit records and trace fields.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MultipleStatements => "multiple_statements",
            Self::WriteStatement => "write_statement",
            Self::Ddl => "ddl",
            Self::LockingRead => "locking_read",
            Self::DataModifyingCte => "data_modifying_cte",
            Self::FileAccess => "file_access",
            Self::FileOutput => "file_output",
            Self::DelayFunction => "delay_function",
            Self::AdvisoryLock => "advisory_lock",
            Self::SessionMutation => "session_mutation",
            Self::SequenceMutation => "sequence_mutation",
            Self::StoredRoutine => "stored_routine",
            Self::UserDefinedFunction => "user_defined_function",
            Self::ExplainAnalyze => "explain_analyze",
            Self::SelectInto => "select_into",
            Self::UnknownConstruct => "unknown_construct",
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn all_lists_every_flag_exactly_once() {
        let names: BTreeSet<&str> = RiskFlag::ALL.iter().map(|f| f.as_str()).collect();
        assert_eq!(names.len(), RiskFlag::ALL.len());
    }

    #[test]
    fn covers_every_threat_named_in_the_security_document() {
        // `docs/security.md` section 3 lists these by name; losing one would remove
        // a row from the threat-to-control matrix silently.
        for expected in [
            "multiple_statements",
            "write_statement",
            "ddl",
            "locking_read",
            "data_modifying_cte",
            "file_access",
            "file_output",
            "delay_function",
            "advisory_lock",
            "session_mutation",
            "sequence_mutation",
            "explain_analyze",
            "select_into",
            "unknown_construct",
        ] {
            assert!(
                RiskFlag::ALL.iter().any(|f| f.as_str() == expected),
                "missing risk flag: {expected}"
            );
        }
    }
}
