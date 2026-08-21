//! Identifier folding for policy comparison.
//!
//! `docs/security.md` section 5.1 requires dialect-specific folding, because
//! comparing raw names has silent false negatives: PostgreSQL folds an unquoted
//! identifier to lowercase, so a rule spelled `Users` would never match a query
//! that says `users`, and MySQL's behavior depends on `lower_case_table_names` and
//! the file system.
//!
//! **Known limitation.** The rule PostgreSQL actually applies distinguishes quoted
//! from unquoted identifiers, and `warden_core::analysis::ObjectRef` does not record
//! which one the statement wrote. Both dialects therefore compare case-insensitively
//! here, which can match a quoted `"Users"` against a rule spelled `users`. That is
//! acceptable and deliberate: the allowlist is not the read-scope boundary, the
//! dedicated role's `GRANT SELECT` is (ADR-0023, SPEC section 7). Whether the
//! analyzers should start carrying quoting is a Milestone 4/5 question.
//!
//! The `match` on [`Dialect`] is exhaustive rather than collapsed into one call, so
//! that a dialect with a different rule has exactly one place to be added and cannot
//! be forgotten.

use warden_core::dialect::Dialect;

/// Compares two identifier parts under the dialect's folding rule.
///
/// ASCII-only case folding on purpose: Unicode case folding is locale-dependent and
/// would make a security comparison depend on the host's locale data.
#[must_use]
pub fn folded_eq(dialect: Dialect, left: &str, right: &str) -> bool {
    match dialect {
        Dialect::MySql | Dialect::PostgreSql => left.eq_ignore_ascii_case(right),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn comparison_ignores_ascii_case_on_both_dialects() {
        for dialect in [Dialect::MySql, Dialect::PostgreSql] {
            assert!(folded_eq(dialect, "Orders", "orders"));
            assert!(folded_eq(dialect, "ORDERS", "orders"));
            assert!(!folded_eq(dialect, "orders", "order"));
        }
    }

    #[test]
    fn non_ascii_case_is_not_folded() {
        // `Ä` and `ä` stay distinct: locale-dependent folding has no place in a
        // security comparison.
        assert!(!folded_eq(Dialect::PostgreSql, "Ärger", "ärger"));
    }
}
