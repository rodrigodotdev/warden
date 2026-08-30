//! The one string this crate sends that is not the analyzed statement.
//!
//! SPEC section 6, invariant 19 makes `explain` the single exception to "executed
//! SQL is byte-for-byte analyzed SQL", and `docs/mcp.md` section 3.2 names the
//! compensating control: reparse the prefixed string and verify that it is an
//! `EXPLAIN` of the statement that was analyzed. [`VerifiedExplain`] is that control
//! expressed as a type — its only constructor performs the verification, so no path
//! in this crate can obtain the string without it (ADR-0037).
//!
//! PostgreSQL spells the format as a utility option rather than an assignment, and
//! `EXPLAIN ANALYZE` has two spellings: the bare form sets `Statement::Explain`'s
//! `analyze` flag, while `EXPLAIN (ANALYZE, ...)` leaves it false and records the
//! keyword among the options (ADR-0017). Requiring exactly one option, `FORMAT
//! JSON`, refuses both without enumerating either.

use sqlparser::ast::{DescribeAlias, Expr, Statement, UtilityOption};
use warden_ports::error::ExplainError;

use crate::parse;

/// The non-executing prefix, with its trailing space.
///
/// `EXPLAIN (FORMAT JSON)`, never `ANALYZE TRUE`, which runs the statement
/// (SPEC section 6, invariant 11; ADR-0017). `tests/adapter_rules.rs` pins this
/// file's only `format!` to this constant.
const EXPLAIN_PREFIX: &str = "EXPLAIN (FORMAT JSON) ";

/// A prefixed statement that has been reparsed and matched against its origin.
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

/// Whether `prefixed` is an `EXPLAIN (FORMAT JSON)` of exactly `analyzed_sql`.
fn verify(prefixed: &str, analyzed_sql: &str) -> Result<(), ExplainError> {
    let prefixed = parse::statements(prefixed).map_err(|_failed| refused())?;
    let analyzed = parse::statements(analyzed_sql).map_err(|_failed| refused())?;

    // Slice patterns, so "exactly one statement" is part of the shape: `EXPLAIN
    // (FORMAT JSON) SELECT 1; DROP TABLE t` parses to two and fails right here.
    let (
        [
            Statement::Explain {
                describe_alias: DescribeAlias::Explain,
                analyze: false,
                verbose: false,
                query_plan: false,
                estimate: false,
                statement,
                format: None,
                options: Some(options),
            },
        ],
        [expected],
    ) = (prefixed.as_slice(), analyzed.as_slice())
    else {
        return Err(refused());
    };

    // Exactly one option, and it is the format. An extra option is not "harmless
    // extra": `ANALYZE` and `BUFFERS` both arrive through this list.
    let [
        UtilityOption {
            name,
            arg: Some(argument),
        },
    ] = options.as_slice()
    else {
        return Err(refused());
    };
    if !name.value.eq_ignore_ascii_case("FORMAT") {
        return Err(refused());
    }
    let Expr::Identifier(format) = argument else {
        return Err(refused());
    };
    if !format.value.eq_ignore_ascii_case("JSON") {
        return Err(refused());
    }

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
        assert_eq!(EXPLAIN_PREFIX, "EXPLAIN (FORMAT JSON) ");
        assert!(!EXPLAIN_PREFIX.contains("ANALYZE"));
    }

    #[test]
    fn a_verified_string_is_the_prefix_followed_by_the_analyzed_statement() {
        let sql = "SELECT id FROM orders WHERE customer_id = $1 LIMIT 5";
        let verified = VerifiedExplain::build(sql).expect("a plain select verifies");
        assert_eq!(verified.as_str(), format!("EXPLAIN (FORMAT JSON) {sql}"));
    }

    #[test]
    fn a_read_only_cte_verifies() {
        let sql = "WITH recent AS (SELECT id FROM orders) SELECT * FROM recent";
        assert!(VerifiedExplain::build(sql).is_ok());
    }

    #[test]
    fn an_analyzing_prefix_is_refused_in_both_of_its_spellings() {
        // ADR-0017: the bare form sets `analyze`, while the option-list form leaves
        // that flag false and records `ANALYZE` among the options. The shape check
        // refuses both, because it accepts exactly one option and that option is
        // `FORMAT JSON`.
        for prefixed in [
            "EXPLAIN ANALYZE SELECT 1",
            "EXPLAIN (ANALYZE) SELECT 1",
            "EXPLAIN (ANALYZE, FORMAT JSON) SELECT 1",
            "EXPLAIN (FORMAT JSON, ANALYZE) SELECT 1",
            "EXPLAIN (FORMAT JSON, BUFFERS) SELECT 1",
        ] {
            assert_eq!(
                verify(prefixed, "SELECT 1"),
                Err(ExplainError::PrefixVerificationFailed),
                "{prefixed}"
            );
        }
    }

    #[test]
    fn a_decorated_or_differently_formatted_prefix_is_refused() {
        for prefixed in [
            "EXPLAIN VERBOSE SELECT 1",
            "EXPLAIN SELECT 1",
            "EXPLAIN (FORMAT TEXT) SELECT 1",
            "EXPLAIN (FORMAT YAML) SELECT 1",
            "EXPLAIN FORMAT=JSON SELECT 1",
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
        assert_eq!(
            verify(
                "EXPLAIN (FORMAT JSON) SELECT 1; DROP TABLE orders",
                "SELECT 1"
            ),
            Err(ExplainError::PrefixVerificationFailed)
        );
    }

    #[test]
    fn a_different_inner_statement_is_refused() {
        assert_eq!(
            verify("EXPLAIN (FORMAT JSON) SELECT 2", "SELECT 1"),
            Err(ExplainError::PrefixVerificationFailed)
        );
    }

    #[test]
    fn an_unparseable_string_is_refused_rather_than_sent() {
        assert_eq!(
            verify("EXPLAIN (FORMAT JSON) SELECT 1 /*", "SELECT 1"),
            Err(ExplainError::PrefixVerificationFailed)
        );
    }

    #[test]
    fn the_verified_string_survives_a_comment_at_the_end_of_the_statement() {
        let sql = "SELECT 1 -- the agent's own note";
        assert!(VerifiedExplain::build(sql).is_ok());
    }

    #[test]
    fn an_explain_statement_never_reaches_this_module_from_the_agent() {
        use warden_core::connection::{ConnectionMetadata, Environment};
        use warden_core::context::RequestContext;
        use warden_core::dialect::Dialect;
        use warden_core::limits::ExecutionLimits;
        use warden_core::query::{InputLimits, QueryRequest};
        use warden_policy::{PolicyEngine, PolicySettings};
        use warden_ports::QueryAnalyzer;

        let request = QueryRequest::new(
            "production-db".parse().unwrap(),
            "EXPLAIN (ANALYZE, BUFFERS) SELECT 1".to_owned(),
            Vec::new(),
            &InputLimits::default(),
        )
        .unwrap();
        let analyzed = crate::analyzer::PostgreSqlAnalyzer::new()
            .analyze(request)
            .expect("the statement parses");
        let context = RequestContext::new(
            "req-1".parse().unwrap(),
            "alice@example.com".parse().unwrap(),
            "Claude Code".parse().unwrap(),
        );
        let connection = ConnectionMetadata {
            name: "production-db".parse().unwrap(),
            dialect: Dialect::PostgreSql,
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
