//! The versioned, literal-free query fingerprint.
//!
//! `docs/security.md` section 11.4 asks each adapter to fingerprint a normalized AST
//! with literals replaced, so audits stay comparable without ever storing SQL. The
//! normalization here is sqlparser's own `Display`, applied after every literal has
//! been replaced with `?`, which also erases whitespace, comments, and keyword case.
//!
//! Identifier quoting is **not** erased: `` `Orders` `` and `Orders` fingerprint
//! differently, because on some MySQL configurations they are different relations and
//! a fingerprint that merged them would merge two different questions.

use core::ops::ControlFlow;
use std::fmt::Write as _;

use sha2::{Digest, Sha256};
use sqlparser::ast::{Statement, Value, ValueWithSpan, VisitMut, VisitorMut};
use warden_core::fingerprint::QueryFingerprint;

/// Replaces every literal with a placeholder.
struct StripLiterals;

impl VisitorMut for StripLiterals {
    type Break = ();

    fn pre_visit_value(&mut self, value: &mut ValueWithSpan) -> ControlFlow<()> {
        // One placeholder for every literal kind, so `WHERE id = 42`,
        // `WHERE id = 'x'` and `WHERE id = ?` share a fingerprint: they are the same
        // question asked about different data.
        value.value = Value::Placeholder("?".to_owned());
        ControlFlow::Continue(())
    }
}

/// Fingerprints a statement list, consuming it.
///
/// Takes ownership because the normalization mutates the tree. The analyzer calls
/// this **after** collecting evidence, so the mutation cannot influence what was
/// observed and no clone of the tree is needed.
///
/// Returns `None` only if the digest is somehow not 64 lowercase hexadecimal
/// characters, which `Sha256` and `{:02x}` make unreachable; the `Option` exists so
/// that an impossible case is a missing fingerprint rather than a panic on the
/// request path (AGENTS.md, "Request path").
pub(crate) fn of(mut statements: Vec<Statement>) -> Option<QueryFingerprint> {
    let _ = statements.visit(&mut StripLiterals);

    let normalized = statements
        .iter()
        .map(Statement::to_string)
        .collect::<Vec<_>>()
        .join("; ");

    let digest = Sha256::digest(normalized.as_bytes());
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    QueryFingerprint::v1(&hex).ok()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::parse;

    fn fingerprint(sql: &str) -> String {
        let statements = parse::statements(sql).expect("fixture must parse");
        of(statements)
            .expect("a parsed statement always fingerprints")
            .as_str()
            .to_owned()
    }

    #[test]
    fn the_same_shape_with_different_data_shares_a_fingerprint() {
        let baseline = fingerprint("SELECT id FROM orders WHERE customer_id = 42");
        for sql in [
            "SELECT id FROM orders WHERE customer_id = 99",
            "select  id  from orders where customer_id = 'abc'",
            "SELECT id FROM orders WHERE customer_id = ?",
            "SELECT id FROM orders WHERE customer_id = 1 -- a comment",
        ] {
            assert_eq!(fingerprint(sql), baseline, "{sql}");
        }
    }

    #[test]
    fn a_different_shape_gets_a_different_fingerprint() {
        assert_ne!(
            fingerprint("SELECT id FROM orders"),
            fingerprint("SELECT id FROM customers")
        );
        assert_ne!(
            fingerprint("SELECT * FROM t WHERE a IN (1)"),
            fingerprint("SELECT * FROM t WHERE a IN (1, 2)")
        );
    }

    #[test]
    fn quoting_is_part_of_the_shape() {
        assert_ne!(
            fingerprint("SELECT 1 FROM `Orders`"),
            fingerprint("SELECT 1 FROM Orders")
        );
    }

    #[test]
    fn the_value_is_a_versioned_sha256() {
        let value = fingerprint("SELECT 1");
        let digest = value.strip_prefix("v1:").expect("a v1 prefix");
        assert_eq!(digest.len(), 64);
        assert!(
            digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
    }

    #[test]
    fn the_fingerprint_contains_no_literal_from_the_statement() {
        // The point of the whole module: an audit record must not become a second
        // store of the data an agent searched for.
        let value = fingerprint("SELECT * FROM users WHERE email = 'alice@example.com'");
        assert!(!value.contains("alice"), "{value}");
    }
}
