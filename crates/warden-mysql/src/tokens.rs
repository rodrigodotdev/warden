//! A token-level guard for constructs the MySQL grammar cannot parse.
//!
//! sqlparser 0.62 rejects `SELECT ... INTO OUTFILE '/tmp/x'` outright, so the
//! statement is already denied — but for the wrong reason. The audit record would
//! read `unknown_construct` instead of `file_output`, losing the one fact SPEC
//! section 6, invariant 9 exists to record, and a future sqlparser that learns the
//! syntax would move the statement from "parse error" to "an ordinary `SELECT`" that
//! the AST rules say nothing about. See ADR-0028.
//!
//! The scan runs on the **token stream**, never on the raw string. That is what makes
//! it sound: `SELECT 'into outfile' FROM t` tokenizes to a single string literal with
//! no word tokens, and a comment produces none either, so neither can trip the guard.

// This module's `pub(crate)` item gains its first caller in Task 5's analyzer.
// Until then only this file's own `#[cfg(test)]` block reaches it, which the
// non-test build cannot see, so `dead_code` would otherwise fire here.
#![allow(dead_code)]

use sqlparser::dialect::MySqlDialect;
use sqlparser::tokenizer::{Token, Tokenizer, Word};
use warden_core::analysis::RiskFlag;

/// Risks visible in the token stream alone.
///
/// Returns nothing when tokenizing fails: a statement the tokenizer cannot read is a
/// statement the parser cannot read either, and the analyzer's parse stage reports
/// that failure with the parser's own message.
///
/// The guard covers exactly `INTO OUTFILE` and `INTO DUMPFILE`, because they are the
/// only constructs on `docs/security.md` section 7.2's list with **no** AST path at
/// all. `LOCK IN SHARE MODE` also fails to parse today, but `FOR UPDATE` and
/// `FOR SHARE` do parse into `Query::locks`, so `RiskFlag::LockingRead` already has a
/// real path, a test, and a corpus row that would fail loudly on an upgrade.
pub(crate) fn scan(sql: &str) -> Vec<RiskFlag> {
    let Ok(tokens) = Tokenizer::new(&MySqlDialect {}, sql).tokenize() else {
        return Vec::new();
    };

    let words: Vec<&Word> = tokens
        .iter()
        .filter_map(|token| match token {
            Token::Word(word) => Some(word),
            _ => None,
        })
        .collect();

    let mut risks = Vec::new();
    if words
        .windows(2)
        .any(|pair| is_file_output(pair[0], pair[1]))
    {
        risks.push(RiskFlag::FileOutput);
    }
    risks
}

/// `INTO OUTFILE` or `INTO DUMPFILE`, written as two bare words.
///
/// Both words must be unquoted; a backticked `` `into` `` is an identifier, never
/// the keyword. That does not make the guard exact: `OUTFILE` is reserved in
/// MySQL, but `DUMPFILE` is not, so `INSERT INTO dumpfile VALUES (1)` against a
/// table literally named `dumpfile` does trip it. That false positive costs
/// nothing, because every shape that puts a bare word directly after `INTO` — an
/// `INSERT`, a `REPLACE`, or a table-form `SELECT ... INTO` — is already a write
/// this analyzer denies on its own terms.
fn is_file_output(left: &Word, right: &Word) -> bool {
    left.quote_style.is_none()
        && right.quote_style.is_none()
        && left.value.eq_ignore_ascii_case("into")
        && (right.value.eq_ignore_ascii_case("outfile")
            || right.value.eq_ignore_ascii_case("dumpfile"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn both_file_output_forms_are_reported() {
        for sql in [
            "SELECT * FROM users INTO OUTFILE '/tmp/x'",
            "SELECT * FROM users INTO DUMPFILE '/tmp/x'",
            "select * from users into outfile '/tmp/x'",
            // Whitespace and comments between the words do not hide it: the scan
            // runs on the filtered word sequence.
            "SELECT * FROM users INTO  /* hidden */ OUTFILE '/tmp/x'",
        ] {
            assert_eq!(scan(sql), vec![RiskFlag::FileOutput], "{sql}");
        }
    }

    #[test]
    fn a_string_literal_or_a_comment_never_trips_the_guard() {
        for sql in [
            "SELECT 'into outfile' FROM t",
            "SELECT * FROM t /* INTO OUTFILE */",
            "SELECT * FROM t -- INTO DUMPFILE",
            "SELECT into_col, outfile_col FROM t",
            "SELECT id FROM orders",
        ] {
            assert!(scan(sql).is_empty(), "{sql}");
        }
    }

    #[test]
    fn a_quoted_identifier_is_not_the_keyword() {
        assert!(scan("SELECT * FROM `into`, `outfile`").is_empty());
    }

    #[test]
    fn unreadable_input_yields_no_risk_and_no_panic() {
        // The parse stage reports the failure; this guard stays silent rather than
        // guessing.
        assert!(scan("SELECT 'unterminated").is_empty());
    }
}
