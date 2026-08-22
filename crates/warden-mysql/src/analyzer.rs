//! The MySQL implementation of the analysis port.

use std::num::NonZeroUsize;

use warden_core::analysis::{QueryAnalysis, QueryAnalysisParts, RiskFlag, StatementKind};
use warden_core::dialect::Dialect;
use warden_core::query::QueryRequest;
use warden_policy::AnalyzedQuery;
use warden_ports::analyzer::QueryAnalyzer;
use warden_ports::error::AnalyzeError;

use crate::parse::{self, ParseFailure};
use crate::statement::kind_of;
use crate::{fingerprint, tokens, visit};

/// Analyzes MySQL statements in the MySQL grammar.
///
/// Stateless, so one instance serves every connection on this dialect. It holds no
/// pool and touches no network: analysis is local CPU work, which is why the port is
/// synchronous (`docs/architecture.md` section 5).
#[derive(Debug, Clone, Copy, Default)]
pub struct MySqlAnalyzer;

impl MySqlAnalyzer {
    /// Builds the analyzer.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl QueryAnalyzer for MySqlAnalyzer {
    fn dialect(&self) -> Dialect {
        Dialect::MySql
    }

    fn analyze(&self, request: QueryRequest) -> Result<AnalyzedQuery, AnalyzeError> {
        // The guard runs on every input, parseable or not: the constructs it looks
        // for do not parse today, and the analysis must still name them (ADR-0028).
        let guard_risks = tokens::scan(request.sql());

        let statements = match parse::statements(request.sql()) {
            Ok(statements) => statements,
            Err(failure) => {
                return match unparsed_analysis(&failure, &guard_risks) {
                    Some(analysis) => Ok(AnalyzedQuery::new(request, analysis)),
                    None => Err(analyze_error(failure)),
                };
            }
        };

        let evidence = visit::collect(&statements);
        let root_kind = statements.first().map_or(StatementKind::Unknown, kind_of);

        let mut risks = evidence.risks;
        for risk in guard_risks {
            if !risks.contains(&risk) {
                risks.push(risk);
            }
        }

        let statement_count = NonZeroUsize::new(statements.len()).unwrap_or(NonZeroUsize::MIN);
        let analysis = QueryAnalysis::new(QueryAnalysisParts {
            dialect: Dialect::MySql,
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
            has_side_effects: !risks.is_empty(),
            has_locking_clause: evidence.has_locking_clause,
            risks,
            fingerprint: fingerprint::of(statements),
        });

        Ok(AnalyzedQuery::new(request, analysis))
    }
}

/// The analysis for a statement the grammar rejected but the token guard recognized.
///
/// Returning evidence rather than an error is what keeps the audit record honest: an
/// attempted `INTO OUTFILE` is recorded as `file_output`, which `RiskEvidencePolicy`
/// denies as a write, instead of as an unclassifiable statement (ADR-0028).
/// `UnknownConstruct` rides along because the statement genuinely could not be
/// understood, so nothing here should be read as a complete description.
///
/// A recursion failure never takes this path: a statement too deep to parse is too
/// deep to describe, and `DenyCode::ParserRecursionLimit` already says exactly that.
fn unparsed_analysis(failure: &ParseFailure, guard_risks: &[RiskFlag]) -> Option<QueryAnalysis> {
    if guard_risks.is_empty() || matches!(failure, ParseFailure::Recursion) {
        return None;
    }

    let mut risks = guard_risks.to_vec();
    risks.push(RiskFlag::UnknownConstruct);

    Some(QueryAnalysis::new(QueryAnalysisParts {
        dialect: Dialect::MySql,
        // The minimum truthful count: the parser produced none, and zero is not a
        // state `QueryAnalysis` can hold. `UnknownConstruct` denies the statement
        // regardless of what this says.
        statement_count: NonZeroUsize::MIN,
        root_kind: StatementKind::Unknown,
        nested_kinds: Vec::new(),
        objects: Vec::new(),
        functions: Vec::new(),
        has_locking_clause: false,
        has_side_effects: true,
        risks,
        // No AST, so no normalization to fingerprint.
        fingerprint: None,
    }))
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

    use warden_core::query::InputLimits;
    use warden_policy::DenyCode;

    use super::*;

    fn request(sql: &str) -> QueryRequest {
        QueryRequest::new(
            "production-mysql".parse().unwrap(),
            sql.to_owned(),
            Vec::new(),
            &InputLimits::default(),
        )
        .unwrap()
    }

    fn analyze(sql: &str) -> Result<AnalyzedQuery, AnalyzeError> {
        MySqlAnalyzer::new().analyze(request(sql))
    }

    #[test]
    fn the_analyzer_reports_the_dialect_it_parses() {
        assert_eq!(MySqlAnalyzer::new().dialect(), Dialect::MySql);
    }

    #[test]
    fn the_analyzed_statement_is_the_submitted_statement() {
        // SPEC section 6, invariant 19: nothing between analysis and execution may
        // replace the bytes.
        let sql = "SELECT id FROM orders WHERE customer_id = ?";
        let analyzed = analyze(sql).unwrap();
        assert_eq!(analyzed.sql(), sql);
        assert_eq!(analyzed.dialect(), Dialect::MySql);
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
            "SELECT SLEEP(5)",
            "DELETE FROM t",
            "SELECT * FROM t FOR UPDATE",
            "SELECT 1; SELECT 2",
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
    }

    #[test]
    fn a_syntax_error_never_echoes_the_statement_through_display() {
        let error = analyze("SELECT FROM 'sup3r-s3cret'").unwrap_err();
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
    fn an_unparseable_file_write_is_still_audited_as_a_file_write() {
        // ADR-0028: the parser rejects this, and the record must still say why it
        // mattered.
        let analyzed = analyze("SELECT * FROM users INTO OUTFILE '/tmp/x'").unwrap();
        let analysis = analyzed.analysis();
        assert_eq!(analysis.root_kind(), StatementKind::Unknown);
        assert!(analysis.has_risk(RiskFlag::FileOutput));
        assert!(analysis.has_risk(RiskFlag::UnknownConstruct));
        assert!(analysis.fingerprint().is_none());
    }

    #[test]
    fn a_deeply_nested_file_write_is_a_recursion_error_not_a_guessed_analysis() {
        // The guard fires, but a statement too deep to parse is too deep to
        // describe, so the recursion code wins.
        let sql = format!(
            "SELECT {}1{} INTO OUTFILE '/tmp/x'",
            "(".repeat(200),
            ")".repeat(200)
        );
        assert_eq!(analyze(&sql).unwrap_err(), AnalyzeError::RecursionLimit);
    }

    #[test]
    fn the_analyzer_works_behind_a_trait_object() {
        // The connection is chosen at runtime, so the port has to survive this.
        let analyzer: &dyn QueryAnalyzer = &MySqlAnalyzer::new();
        assert_eq!(analyzer.dialect(), Dialect::MySql);
        assert!(analyzer.analyze(request("SELECT 1")).is_ok());
    }
}
