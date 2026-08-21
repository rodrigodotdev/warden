//! Statement categories.

/// What kind of statement the adapter recognized.
///
/// No `#[non_exhaustive]`, deliberately: `warden-policy` is downstream of this
/// crate, so the attribute would force a `_ =>` arm there and let a new variant
/// compile silently through the wildcard — the opposite of the required property
/// (ADR-0021).
///
/// This crate classifies nothing. There is no `is_write` helper here; deciding what
/// a kind means is `warden-policy`'s job, and it must match exhaustively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StatementKind {
    /// A `SELECT`, including a read-only CTE.
    Select,
    /// An `EXPLAIN` in any of its forms.
    Explain,
    /// A `SHOW` or equivalent metadata statement.
    Show,
    /// An `INSERT`.
    Insert,
    /// An `UPDATE`.
    Update,
    /// A `DELETE`.
    Delete,
    /// A `MERGE`.
    Merge,
    /// A stored-routine `CALL`.
    Call,
    /// A `COPY` or equivalent bulk transfer.
    Copy,
    /// Any data-definition statement.
    Ddl,
    /// `BEGIN`, `COMMIT`, `ROLLBACK`, and similar.
    TransactionControl,
    /// `SET` and other session mutation.
    SessionControl,
    /// A recognized utility statement that fits no other category.
    Utility,
    /// Anything the adapter could not classify. Always denied.
    Unknown,
}

impl StatementKind {
    /// Every kind. Policy tests iterate this to prove each one is handled
    /// (`docs/testing.md` section 2).
    pub const ALL: [Self; 14] = [
        Self::Select,
        Self::Explain,
        Self::Show,
        Self::Insert,
        Self::Update,
        Self::Delete,
        Self::Merge,
        Self::Call,
        Self::Copy,
        Self::Ddl,
        Self::TransactionControl,
        Self::SessionControl,
        Self::Utility,
        Self::Unknown,
    ];

    /// The stable name used in audit records and trace fields.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Select => "select",
            Self::Explain => "explain",
            Self::Show => "show",
            Self::Insert => "insert",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Merge => "merge",
            Self::Call => "call",
            Self::Copy => "copy",
            Self::Ddl => "ddl",
            Self::TransactionControl => "transaction_control",
            Self::SessionControl => "session_control",
            Self::Utility => "utility",
            Self::Unknown => "unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn all_lists_every_kind_exactly_once() {
        let names: BTreeSet<&str> = StatementKind::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(names.len(), StatementKind::ALL.len());
    }

    #[test]
    fn serialization_matches_as_str() {
        for kind in StatementKind::ALL {
            assert_eq!(
                serde_json::to_string(&kind).unwrap(),
                format!("\"{}\"", kind.as_str())
            );
        }
    }
}
