//! Turning MySQL text into a statement list, or into the one reason it could not be.

use sqlparser::ast::Statement;
use sqlparser::dialect::MySqlDialect;
use sqlparser::parser::{Parser, ParserError};

/// The parser's explicit recursion bound.
///
/// ADR-0006 requires this to be set explicitly rather than inherited. It equals
/// sqlparser 0.62's own default, so pinning it changes nothing today and prevents an
/// upstream default change from silently moving Warden's bound. It is the middle of
/// three layers: `QueryRequest` caps the input at 64 KiB before parsing
/// (`docs/data-model.md` section 2), this bound caps nesting, and sqlparser's default
/// `recursive-protection` feature keeps a deep tree from overflowing the stack
/// (`docs/operations.md` section 2.4).
///
/// Measured against sqlparser 0.62: 2000 chained `OR`s parse well within it, because
/// an operator chain is iterative, not recursive. What it stops is depth — roughly 50
/// nested parentheses or subqueries.
pub(crate) const RECURSION_LIMIT: usize = 50;

/// Why the MySQL grammar produced no statement list.
///
/// Kept separate from `warden_ports::error::AnalyzeError` because [`Self::Empty`]
/// has no counterpart there and the mapping is the analyzer's decision, not this
/// module's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParseFailure {
    /// The grammar rejected the statement. Carries the parser's own message, which
    /// quotes the offending token and therefore never leaves a diagnostic path.
    Syntax(String),
    /// The statement nests deeper than [`RECURSION_LIMIT`].
    Recursion,
    /// The input contained no statement at all, such as a lone `;`.
    Empty,
}

/// Parses one MySQL input into its statements.
///
/// Returns [`ParseFailure::Empty`] rather than an empty vector: `QueryAnalysis`
/// stores a `NonZeroUsize` statement count, so "zero statements" is a state the
/// evidence model cannot represent and must not be invented downstream.
pub(crate) fn statements(sql: &str) -> Result<Vec<Statement>, ParseFailure> {
    let parsed = Parser::new(&MySqlDialect {})
        .with_recursion_limit(RECURSION_LIMIT)
        .try_with_sql(sql)
        .and_then(|mut parser| parser.parse_statements());

    match parsed {
        Ok(statements) if statements.is_empty() => Err(ParseFailure::Empty),
        Ok(statements) => Ok(statements),
        // Exhaustive: `ParserError` has exactly these three variants in sqlparser
        // 0.62 and is not `#[non_exhaustive]`, so a new one breaks this build.
        Err(ParserError::RecursionLimitExceeded) => Err(ParseFailure::Recursion),
        Err(error @ (ParserError::ParserError(_) | ParserError::TokenizerError(_))) => {
            Err(ParseFailure::Syntax(error.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn a_single_statement_parses_with_or_without_its_semicolon() {
        for sql in ["SELECT 1", "SELECT 1;", "SELECT 1;;", "SELECT 1; "] {
            assert_eq!(statements(sql).unwrap().len(), 1, "{sql}");
        }
    }

    #[test]
    fn a_semicolon_inside_a_literal_or_a_comment_is_not_a_separator() {
        for sql in ["SELECT ';'", "SELECT 1 /* ; */", "SELECT 1 -- ;"] {
            assert_eq!(statements(sql).unwrap().len(), 1, "{sql}");
        }
    }

    #[test]
    fn two_statements_are_reported_as_two() {
        assert_eq!(statements("SELECT 1; SELECT 2").unwrap().len(), 2);
    }

    #[test]
    fn an_input_with_no_statement_is_not_an_empty_success() {
        assert_eq!(statements(";").unwrap_err(), ParseFailure::Empty);
    }

    #[test]
    fn a_syntax_error_carries_the_parser_message_for_diagnostics_only() {
        let ParseFailure::Syntax(detail) = statements("SELECT FROM").unwrap_err() else {
            panic!("expected a syntax failure");
        };
        assert!(detail.contains("sql parser error"), "{detail}");
    }

    #[test]
    fn nesting_past_the_bound_is_a_recursion_failure_not_a_stack_overflow() {
        let sql = format!("SELECT {}1{}", "(".repeat(200), ")".repeat(200));
        assert_eq!(statements(&sql).unwrap_err(), ParseFailure::Recursion);
    }

    #[test]
    fn long_flat_statements_stay_within_the_bound() {
        // The bound limits depth, not length: a 2000-term OR chain is iterative.
        let sql = format!("SELECT 1 WHERE {}", vec!["a = 1"; 2000].join(" OR "));
        assert_eq!(statements(&sql).unwrap().len(), 1);
    }
}
