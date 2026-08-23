//! Identifier folding for policy comparison.
//!
//! `docs/security.md` section 5.1 requires dialect-specific folding, because
//! comparing raw names has silent false negatives: PostgreSQL folds an unquoted
//! identifier to lowercase, so a rule spelled `Users` would never match a query that
//! says `users`, and MySQL's behavior depends on `lower_case_table_names` and the
//! file system.
//!
//! The comparison is deliberately **asymmetric**. The rule is operator-written
//! configuration and has no quoting — an operator writes `users` in TOML, never
//! `"users"`. The identifier is what the statement actually wrote, quoting included.
//! Encoding that in the signature is the point: the symmetric `&str`/`&str`
//! comparison this replaced is the shape that lost the distinction.
//!
//! The `match` on [`Dialect`] is exhaustive rather than collapsed into one call, so
//! that a dialect with a different rule has exactly one place to be added and cannot
//! be forgotten.

use warden_core::analysis::{IdentifierQuoting, SqlIdentifier};
use warden_core::dialect::Dialect;

/// Whether a configured rule names the identifier a statement wrote.
///
/// ASCII-only case folding on purpose: Unicode case folding is locale-dependent and
/// would make a security comparison depend on the host's locale data.
///
/// **MySQL.** Compared case-insensitively, and quoting is ignored: backticks escape
/// a name, they do not change how the server folds it. Whether the server itself
/// folds depends on `lower_case_table_names`, which is 1 on Windows and macOS images
/// and frequently 1 on Linux ones, so case-insensitive is the fail-closed choice —
/// it matches more, and every match is a denial or an allowlist hit against a rule
/// the operator wrote on purpose.
///
/// **PostgreSQL.** An unquoted identifier is folded to lowercase by the server, so
/// it is compared case-insensitively. A quoted identifier is the literal characters
/// between the quotes, so it is compared exactly: a rule spelled `users` must not
/// match the distinct relation `"Users"`.
#[must_use]
pub fn rule_matches(dialect: Dialect, rule: &str, identifier: &SqlIdentifier) -> bool {
    match dialect {
        Dialect::MySql => rule.eq_ignore_ascii_case(identifier.value()),
        Dialect::PostgreSql => match identifier.quoting() {
            IdentifierQuoting::Unquoted => rule.eq_ignore_ascii_case(identifier.value()),
            IdentifierQuoting::Quoted => rule == identifier.value(),
        },
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn mysql_ignores_ascii_case_whatever_the_quoting() {
        for identifier in [
            SqlIdentifier::unquoted("Orders"),
            SqlIdentifier::quoted("Orders"),
        ] {
            assert!(rule_matches(Dialect::MySql, "orders", &identifier));
            assert!(rule_matches(Dialect::MySql, "ORDERS", &identifier));
            assert!(!rule_matches(Dialect::MySql, "order", &identifier));
        }
    }

    #[test]
    fn postgres_folds_an_unquoted_name_and_respects_a_quoted_one() {
        let unquoted = SqlIdentifier::unquoted("Orders");
        assert!(rule_matches(Dialect::PostgreSql, "orders", &unquoted));
        assert!(rule_matches(Dialect::PostgreSql, "ORDERS", &unquoted));

        // `"Orders"` is a different relation from `orders`, and a rule spelled for
        // one must not silently cover the other.
        let quoted = SqlIdentifier::quoted("Orders");
        assert!(rule_matches(Dialect::PostgreSql, "Orders", &quoted));
        assert!(!rule_matches(Dialect::PostgreSql, "orders", &quoted));
    }

    #[test]
    fn non_ascii_case_is_not_folded() {
        // `Ä` and `ä` stay distinct: locale-dependent folding has no place in a
        // security comparison.
        let identifier = SqlIdentifier::unquoted("Ärger");
        assert!(!rule_matches(Dialect::PostgreSql, "ärger", &identifier));
        assert!(!rule_matches(Dialect::MySql, "ärger", &identifier));
    }

    #[test]
    fn every_quoting_is_decided_on_both_dialects() {
        // Iterating `ALL` makes a new variant fail here instead of falling into an
        // arm that happens to compile.
        for quoting in IdentifierQuoting::ALL {
            let identifier = match quoting {
                IdentifierQuoting::Unquoted => SqlIdentifier::unquoted("t"),
                IdentifierQuoting::Quoted => SqlIdentifier::quoted("t"),
            };
            for dialect in [Dialect::MySql, Dialect::PostgreSql] {
                assert!(rule_matches(dialect, "t", &identifier));
            }
        }
    }
}
