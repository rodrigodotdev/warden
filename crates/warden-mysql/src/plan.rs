//! The one string this crate sends that is not the analyzed statement.
//!
//! SPEC section 6, invariant 19 makes `explain` the single exception to "executed
//! SQL is byte-for-byte analyzed SQL", and `docs/mcp.md` section 3.2 names the
//! compensating control: reparse the prefixed string and verify that it is an
//! `EXPLAIN` of the statement that was analyzed. [`VerifiedExplain`] is that control
//! expressed as a type — its only constructor performs the verification, so no path
//! in this crate can obtain the string without it (ADR-0037).
//!
//! The check asserts the shape it requires rather than enumerating the shapes it
//! forbids. Warden builds the prefix itself, so the expected parse is fully known:
//! exactly one statement, an `EXPLAIN` with every executing and decorating flag
//! false, MySQL's `FORMAT=JSON` spelling, and an inner statement equal to a
//! standalone parse of the analyzed SQL. A list of forbidden spellings would be a
//! list to keep in step with a parser; a required shape is not.

use sqlparser::ast::{AnalyzeFormat, AnalyzeFormatKind, DescribeAlias, Statement};
use warden_ports::error::ExplainError;

use crate::parse;

/// The non-executing prefix, with its trailing space.
///
/// `EXPLAIN FORMAT=JSON`, never `EXPLAIN ANALYZE`, which runs the statement
/// (SPEC section 6, invariant 11; ADR-0017). `tests/adapter_rules.rs` pins this
/// file's only `format!` to this constant.
const EXPLAIN_PREFIX: &str = "EXPLAIN FORMAT=JSON ";

/// A prefixed statement that has been reparsed and matched against its origin.
///
/// Not `Clone` and holding a private `String`: the only way to obtain one is
/// [`VerifiedExplain::build`], which cannot return without having verified.
#[derive(Debug)]
pub(crate) struct VerifiedExplain(String);

impl VerifiedExplain {
    /// Prefixes `analyzed_sql` and proves the result still means the same thing.
    pub(crate) fn build(analyzed_sql: &str) -> Result<Self, ExplainError> {
        let prefixed = format!("{EXPLAIN_PREFIX}{analyzed_sql}");
        verify(&prefixed, analyzed_sql)?;
        Ok(Self(prefixed))
    }

    /// The exact text to send to the server.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Whether `prefixed` is an `EXPLAIN` of exactly the statement in `analyzed_sql`.
///
/// A parse failure on either side is a refusal rather than a diagnostic: the
/// analyzed statement reached this module only because it already parsed, so a
/// failure here means the two parses disagree, and a disagreement about what a
/// string means is the thing this check exists to catch.
fn verify(prefixed: &str, analyzed_sql: &str) -> Result<(), ExplainError> {
    let prefixed = parse::statements(prefixed).map_err(|_failed| refused())?;
    let analyzed = parse::statements(analyzed_sql).map_err(|_failed| refused())?;

    // Slice patterns, so "exactly one statement" is part of the shape rather than a
    // separate check somebody can forget: `EXPLAIN FORMAT=JSON SELECT 1; DROP TABLE
    // t` parses to two statements and fails right here.
    let (
        [
            Statement::Explain {
                describe_alias: DescribeAlias::Explain,
                analyze: false,
                verbose: false,
                query_plan: false,
                estimate: false,
                statement,
                format: Some(AnalyzeFormatKind::Assignment(AnalyzeFormat::JSON)),
                options: None,
            },
        ],
        [expected],
    ) = (prefixed.as_slice(), analyzed.as_slice())
    else {
        return Err(refused());
    };

    // `sqlparser` compares identifiers without their source spans, so an inner
    // statement offset by the prefix compares equal to a standalone parse.
    if statement.as_ref() == expected {
        Ok(())
    } else {
        Err(refused())
    }
}

/// The one failure this module produces.
///
/// A function rather than a repeated literal so every refusal is the same refusal:
/// the caller learns that the prefixed string did not match, and nothing about which
/// part of the shape differed, which would describe the agent's own statement back
/// to it (`docs/security.md` section 10).
fn refused() -> ExplainError {
    ExplainError::PrefixVerificationFailed
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use warden_ports::error::ExplainError;

    use super::{EXPLAIN_PREFIX, VerifiedExplain, verify};

    #[test]
    fn the_prefix_is_the_non_executing_form() {
        // Pinned as an exact string. `EXPLAIN ANALYZE` runs the statement
        // (SPEC section 6, invariant 11; ADR-0017), so widening this constant must
        // be a test failure rather than a review oversight.
        assert_eq!(EXPLAIN_PREFIX, "EXPLAIN FORMAT=JSON ");
        assert!(!EXPLAIN_PREFIX.contains("ANALYZE"));
    }

    #[test]
    fn a_verified_string_is_the_prefix_followed_by_the_analyzed_statement() {
        let sql = "SELECT id FROM orders WHERE customer_id = ? LIMIT 5";
        let verified = VerifiedExplain::build(sql).expect("a plain select verifies");
        assert_eq!(verified.as_str(), format!("EXPLAIN FORMAT=JSON {sql}"));
    }

    #[test]
    fn a_read_only_cte_verifies() {
        let sql = "WITH recent AS (SELECT id FROM orders) SELECT * FROM recent";
        assert!(VerifiedExplain::build(sql).is_ok());
    }

    #[test]
    fn an_analyzing_prefix_is_refused() {
        assert_eq!(
            verify("EXPLAIN ANALYZE SELECT 1", "SELECT 1"),
            Err(ExplainError::PrefixVerificationFailed)
        );
    }

    #[test]
    fn a_decorated_prefix_is_refused() {
        // Only the exact expected shape passes; VERBOSE is not "harmless extra".
        for prefixed in [
            "EXPLAIN VERBOSE SELECT 1",
            "EXPLAIN SELECT 1",
            "EXPLAIN FORMAT=TREE SELECT 1",
            "DESCRIBE FORMAT=JSON SELECT 1",
        ] {
            assert_eq!(
                verify(prefixed, "SELECT 1"),
                Err(ExplainError::PrefixVerificationFailed),
                "{prefixed}"
            );
        }
    }

    #[test]
    fn a_second_statement_after_the_prefix_is_refused() {
        // The whole class of context breaks `docs/mcp.md` section 3.2 closes: the
        // string parses cleanly and means something else entirely.
        assert_eq!(
            verify(
                "EXPLAIN FORMAT=JSON SELECT 1; DROP TABLE orders",
                "SELECT 1"
            ),
            Err(ExplainError::PrefixVerificationFailed)
        );
    }

    #[test]
    fn a_different_inner_statement_is_refused() {
        assert_eq!(
            verify("EXPLAIN FORMAT=JSON SELECT 2", "SELECT 1"),
            Err(ExplainError::PrefixVerificationFailed)
        );
    }

    #[test]
    fn an_unparseable_string_is_refused_rather_than_sent() {
        assert_eq!(
            verify("EXPLAIN FORMAT=JSON SELECT 1 /*", "SELECT 1"),
            Err(ExplainError::PrefixVerificationFailed)
        );
    }

    #[test]
    fn the_verified_string_survives_a_comment_at_the_end_of_the_statement() {
        // A trailing line comment is legal SQL and must not be treated as tampering:
        // the reparse compares meaning, not bytes after the prefix.
        let sql = "SELECT 1 -- the agent's own note";
        assert!(VerifiedExplain::build(sql).is_ok());
    }

    #[test]
    fn an_explain_statement_never_reaches_this_module_from_the_agent() {
        // Defence in depth for ADR-0020: `EXPLAIN ANALYZE SELECT 1` as agent SQL is
        // denied by the policy engine long before an explainer sees it, because its
        // root kind is `Explain` and only `Select` is authorized. This pins that the
        // real analyzer plus the real engine, not this module, is what stops it.
        use warden_core::connection::{ConnectionMetadata, Environment};
        use warden_core::context::RequestContext;
        use warden_core::dialect::Dialect;
        use warden_core::limits::ExecutionLimits;
        use warden_core::query::{InputLimits, QueryRequest};
        use warden_policy::{PolicyEngine, PolicySettings};
        use warden_ports::QueryAnalyzer;

        let request = QueryRequest::new(
            "production-db".parse().unwrap(),
            "EXPLAIN ANALYZE SELECT 1".to_owned(),
            Vec::new(),
            &InputLimits::default(),
        )
        .unwrap();
        let analyzed = crate::analyzer::MySqlAnalyzer::new()
            .analyze(request)
            .expect("the statement parses");
        let context = RequestContext::new(
            "req-1".parse().unwrap(),
            "alice@example.com".parse().unwrap(),
            "Claude Code".parse().unwrap(),
        );
        let connection = ConnectionMetadata {
            name: "production-db".parse().unwrap(),
            dialect: Dialect::MySql,
            environment: Environment::Production,
            database: "app".to_owned(),
        };
        let engine = PolicyEngine::with_defaults(&PolicySettings::default()).unwrap();
        assert!(
            engine
                .authorize(&context, &connection, analyzed, ExecutionLimits::default())
                .is_err(),
            "an EXPLAIN submitted as agent SQL must be denied (ADR-0020)"
        );
    }
}
