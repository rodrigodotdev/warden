//! The PostgreSQL implementation of the analysis port.

use std::num::NonZeroUsize;

use warden_core::analysis::{QueryAnalysis, QueryAnalysisParts, StatementKind};
use warden_core::dialect::Dialect;
use warden_core::query::QueryRequest;
use warden_policy::AnalyzedQuery;
use warden_ports::analyzer::QueryAnalyzer;
use warden_ports::error::AnalyzeError;

use crate::parse::{self, ParseFailure};
use crate::statement::kind_of;
use crate::{fingerprint, visit};

/// Analyzes PostgreSQL statements in the PostgreSQL grammar.
///
/// Stateless, so one instance serves every connection on this dialect. It holds no
/// pool and touches no network: analysis is local CPU work, which is why the port is
/// synchronous (`docs/architecture.md` section 5).
#[derive(Debug, Clone, Copy, Default)]
pub struct PostgreSqlAnalyzer;

impl PostgreSqlAnalyzer {
    /// Builds the analyzer.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl QueryAnalyzer for PostgreSqlAnalyzer {
    fn dialect(&self) -> Dialect {
        Dialect::PostgreSql
    }

    fn analyze(&self, request: QueryRequest) -> Result<AnalyzedQuery, AnalyzeError> {
        // Unlike `warden-mysql`, there is no token-level guard and therefore no
        // path that returns evidence for a statement the grammar rejected: every
        // PostgreSQL construct `docs/security.md` section 7.3 names has an AST
        // path, so a parse failure really is a statement this analyzer knows
        // nothing about (ADR-0028's bar).
        let statements = parse::statements(request.sql()).map_err(analyze_error)?;

        let evidence = visit::collect(&statements);
        // Derived from the parsed statement list, not from `evidence.kinds`:
        // `Evidence.kinds` interleaves nested statement kinds with top-level ones in
        // visit order, so neither its length nor its first element is the batch
        // shape. `statements` is the one source that is.
        let root_kind = statements.first().map_or(StatementKind::Unknown, kind_of);
        let statement_count = NonZeroUsize::new(statements.len()).unwrap_or(NonZeroUsize::MIN);

        let analysis = QueryAnalysis::new(QueryAnalysisParts {
            dialect: Dialect::PostgreSql,
            statement_count,
            root_kind,
            // The first visited kind is the root; the rest are what the walk found
            // inside it. With more than one statement the tail also holds the other
            // roots, which over-reports rather than under-reports and is denied by
            // `MultipleStatements` either way.
            nested_kinds: evidence.kinds.into_iter().skip(1).collect(),
            objects: evidence.objects,
            functions: evidence.functions,
            // This analyzer never reports a side effect it cannot name, so
            // `RiskEvidencePolicy`'s "unexplained side effect" case is unreachable
            // from here by construction.
            has_side_effects: !evidence.risks.is_empty(),
            has_locking_clause: evidence.has_locking_clause,
            risks: evidence.risks,
            fingerprint: fingerprint::of(statements),
        });

        Ok(AnalyzedQuery::new(request, analysis))
    }
}

/// Maps a parse failure to the port's error.
///
/// `ParseFailure::Empty` is a parse error rather than a category of its own: the
/// agent sent something that contained no statement, and `query_parse_error` is
/// exactly what it needs to hear.
fn analyze_error(failure: ParseFailure) -> AnalyzeError {
    match failure {
        ParseFailure::Recursion => AnalyzeError::RecursionLimit,
        ParseFailure::Syntax(detail) => AnalyzeError::Parse { detail },
        ParseFailure::Empty => AnalyzeError::Parse {
            detail: "the input contained no statement".to_owned(),
        },
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use warden_core::analysis::RiskFlag;
    use warden_core::query::InputLimits;
    use warden_policy::DenyCode;

    use super::*;

    fn request(sql: &str) -> QueryRequest {
        QueryRequest::new(
            "production-postgres".parse().unwrap(),
            sql.to_owned(),
            Vec::new(),
            &InputLimits::default(),
        )
        .unwrap()
    }

    fn analyze(sql: &str) -> Result<AnalyzedQuery, AnalyzeError> {
        PostgreSqlAnalyzer::new().analyze(request(sql))
    }

    #[test]
    fn the_analyzer_reports_the_dialect_it_parses() {
        assert_eq!(PostgreSqlAnalyzer::new().dialect(), Dialect::PostgreSql);
    }

    #[test]
    fn the_analyzed_statement_is_the_submitted_statement() {
        // SPEC section 6, invariant 19: nothing between analysis and execution may
        // replace the bytes.
        let sql = "SELECT id FROM orders WHERE customer_id = $1";
        let analyzed = analyze(sql).unwrap();
        assert_eq!(analyzed.sql(), sql);
        assert_eq!(analyzed.dialect(), Dialect::PostgreSql);
    }

    #[test]
    fn an_ordinary_select_carries_no_risk_and_a_fingerprint() {
        let analyzed = analyze("SELECT id FROM orders").unwrap();
        let analysis = analyzed.analysis();
        assert_eq!(analysis.root_kind(), StatementKind::Select);
        assert_eq!(analysis.statement_count().get(), 1);
        assert!(analysis.risks().is_empty());
        assert!(!analysis.has_side_effects());
        assert!(analysis.fingerprint().is_some());
    }

    #[test]
    fn a_side_effect_is_never_reported_without_a_flag_that_names_it() {
        for sql in [
            "SELECT pg_sleep(5)",
            "DELETE FROM t",
            "SELECT * FROM t FOR UPDATE",
            "SELECT 1; SELECT 2",
            "WITH c AS (DELETE FROM t RETURNING *) SELECT * FROM c",
        ] {
            let analyzed = analyze(sql).unwrap();
            let analysis = analyzed.analysis();
            assert!(analysis.has_side_effects(), "{sql}");
            assert!(!analysis.risks().is_empty(), "{sql}");
        }
    }

    #[test]
    fn a_distrusted_statement_is_evidence_rather_than_an_error() {
        // ADR-0011: only a statement that yielded nothing to evaluate is an error.
        let analyzed = analyze("DELETE FROM orders").unwrap();
        assert_eq!(analyzed.analysis().root_kind(), StatementKind::Delete);
        assert!(analyzed.analysis().has_risk(RiskFlag::WriteStatement));
    }

    #[test]
    fn a_syntax_error_never_echoes_the_statement_through_display() {
        // A lone string literal is not a statement under `PostgreSqlDialect`, so the
        // parser's own message quotes the secret verbatim ("Expected: an SQL
        // statement, found: 'sup3r-s3cret'"). That is exactly the fixture this test
        // needs: `detail` genuinely carries the secret, so the assertion below can
        // actually fail if `AnalyzeError::Parse`'s `Display` ever printed it.
        let error = analyze("'sup3r-s3cret'").unwrap_err();
        assert!(!error.to_string().contains("sup3r-s3cret"), "{error}");
        assert_eq!(error.deny_reason().code(), DenyCode::UnknownConstruct);
    }

    #[test]
    fn an_input_with_no_statement_is_a_parse_error() {
        assert!(matches!(
            analyze(";").unwrap_err(),
            AnalyzeError::Parse { .. }
        ));
    }

    #[test]
    fn a_statement_nested_past_the_bound_is_a_recursion_error() {
        let sql = format!("SELECT {}1{}", "(".repeat(200), ")".repeat(200));
        assert_eq!(analyze(&sql).unwrap_err(), AnalyzeError::RecursionLimit);
    }

    #[test]
    fn nested_kinds_hold_what_the_walk_found_inside_the_root() {
        let analyzed = analyze("WITH c AS (DELETE FROM t RETURNING *) SELECT * FROM c").unwrap();
        let analysis = analyzed.analysis();
        assert_eq!(analysis.root_kind(), StatementKind::Select);
        assert_eq!(analysis.nested_kinds(), [StatementKind::Delete]);
        assert!(analysis.has_risk(RiskFlag::DataModifyingCte));
    }

    #[test]
    fn a_batch_reports_the_first_statement_as_the_root() {
        // `statements.first()` and `statements.len()` are the source of truth for
        // `root_kind` and `statement_count`, not `Evidence.kinds`. This fixture is
        // chosen so the two disagree in length: `EXPLAIN` pushes its own kind and
        // then descends into the query it explains, so `Evidence.kinds` is
        // `[Explain, Select, Delete]` (length 3) while `statements.len()` is 2. A
        // regression that read `root_kind` from `kinds[0]` would still pass by
        // coincidence here (`Explain` is at both position 0 and is the real root),
        // but a regression that read `statement_count` from `kinds.len()` would
        // report 3 statements instead of 2, which this test catches.
        let analyzed = analyze("EXPLAIN SELECT 1; DELETE FROM t").unwrap();
        let analysis = analyzed.analysis();
        assert_eq!(analysis.root_kind(), StatementKind::Explain);
        assert_eq!(analysis.statement_count().get(), 2);
        assert!(analysis.has_risk(RiskFlag::MultipleStatements));
        assert!(analysis.has_risk(RiskFlag::WriteStatement));
    }

    #[test]
    fn the_analyzer_works_behind_a_trait_object() {
        // The connection is chosen at runtime, so the port has to survive this.
        let analyzer: &dyn QueryAnalyzer = &PostgreSqlAnalyzer::new();
        assert_eq!(analyzer.dialect(), Dialect::PostgreSql);
        assert!(analyzer.analyze(request("SELECT 1")).is_ok());
    }
}
