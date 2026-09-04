//! The synchronous analysis port.
//!
//! Parsing is local CPU work with no I/O, so this port returns a value rather than a
//! future (`docs/architecture.md` section 5). Staying synchronous also keeps a
//! useful property: analysis and authorization both complete before anything can
//! await, so there is no suspension point at which a task holds a half-authorized
//! statement.

use warden_core::dialect::Dialect;
use warden_core::query::QueryRequest;
use warden_policy::AnalyzedQuery;

use crate::error::AnalyzeError;

/// Turns one size-validated request into parser-independent evidence.
///
/// The port takes the whole [`QueryRequest`] and returns an [`AnalyzedQuery`], so the
/// analyzed statement and the statement that will run are the same bytes by
/// construction (SPEC section 6, invariant 19). No method here accepts a `&str`, and
/// no `sqlparser` type appears in the signature, which is what keeps the parser
/// replaceable (ADR-0007).
pub trait QueryAnalyzer: Send + Sync {
    /// The dialect this analyzer parses.
    ///
    /// `ConnectionRuntime::new` compares it with the connection's own dialect, so a
    /// MySQL analyzer wired to a PostgreSQL connection fails at startup instead of
    /// quietly analyzing PostgreSQL syntax with the wrong grammar.
    fn dialect(&self) -> Dialect;

    /// Parses and analyzes exactly one statement.
    ///
    /// A statement the analyzer understands but distrusts is **not** an error. It
    /// becomes evidence — an `Unknown` statement kind, a risk flag, an unclassified
    /// function — and `warden-policy` denies it with a code the audit can explain
    /// (ADR-0011). Only a statement that produced no evidence at all fails here.
    ///
    /// # Errors
    ///
    /// [`AnalyzeError`] when the statement cannot be turned into evidence: it does
    /// not parse, or it is not exactly one statement. No variant carries the SQL
    /// (SPEC section 6, invariant 22).
    fn analyze(&self, request: QueryRequest) -> Result<AnalyzedQuery, AnalyzeError>;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::sync::Arc;

    use warden_policy::DenyCode;

    use super::*;
    use crate::testing;

    #[test]
    fn an_analyzer_works_behind_a_trait_object() {
        // The connection is chosen at runtime, so every port has to survive this.
        let analyzer: Arc<dyn QueryAnalyzer> = Arc::new(testing::FakeAnalyzer::new(Dialect::MySql));
        assert_eq!(analyzer.dialect(), Dialect::MySql);

        let analyzed = analyzer.analyze(testing::request()).unwrap();
        assert_eq!(analyzed.sql(), testing::SQL);
        assert_eq!(analyzed.dialect(), Dialect::MySql);
    }

    #[test]
    fn a_failed_analysis_is_still_auditable() {
        let analyzer = testing::FakeAnalyzer::failing(AnalyzeError::RecursionLimit);
        let error = analyzer.analyze(testing::request()).unwrap_err();
        assert_eq!(error, AnalyzeError::RecursionLimit);
        assert_eq!(error.deny_reason().code(), DenyCode::ParserRecursionLimit);
    }
}
