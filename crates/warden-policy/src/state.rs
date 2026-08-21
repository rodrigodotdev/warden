//! The three security states, and the capability token between the last two.
//!
//! ```text
//! QueryRequest      size-validated input                (warden-core)
//!    │ analyze      adapter, synchronous, no I/O
//! AnalyzedQuery     input plus parser-independent evidence
//!    │ authorize    warden-policy, synchronous, no I/O
//! AuthorizedQuery   carries an AllowDecision only this crate can produce
//!    │ execute_read_only
//! ResultSet         bounded, normalized, redacted        (warden-core)
//! ```
//!
//! Honest scope (`docs/architecture.md` section 4.2): this prevents *accidental*
//! bypasses inside Warden. It does not protect against a malicious adapter crate,
//! and it does not replace database privileges (ADR-0016).

use warden_core::analysis::QueryAnalysis;
use warden_core::connection::ConnectionName;
use warden_core::dialect::Dialect;
use warden_core::fingerprint::QueryFingerprint;
use warden_core::limits::ExecutionLimits;
use warden_core::parameter::ParameterValue;
use warden_core::query::QueryRequest;

/// A validated statement together with the evidence an adapter extracted from it.
///
/// `Debug` is derived and still prints no SQL: `QueryRequest`'s own `Debug` reports
/// shape only (SPEC section 6, invariant 22).
#[derive(Debug, Clone, PartialEq)]
pub struct AnalyzedQuery {
    request: QueryRequest,
    analysis: QueryAnalysis,
}

impl AnalyzedQuery {
    /// Pairs a request with its analysis.
    ///
    /// Public because adapters produce this state (`docs/architecture.md`
    /// section 5). It grants nothing: an `AnalyzedQuery` cannot be executed.
    #[must_use]
    pub fn new(request: QueryRequest, analysis: QueryAnalysis) -> Self {
        Self { request, analysis }
    }

    /// The validated input.
    #[must_use]
    pub fn request(&self) -> &QueryRequest {
        &self.request
    }

    /// The evidence authorization is based on.
    #[must_use]
    pub fn analysis(&self) -> &QueryAnalysis {
        &self.analysis
    }

    /// The exact SQL that was analyzed.
    #[must_use]
    pub fn sql(&self) -> &str {
        self.request.sql()
    }

    /// The bound parameters, in placeholder order.
    #[must_use]
    pub fn parameters(&self) -> &[ParameterValue] {
        self.request.parameters()
    }

    /// The connection this statement targets.
    #[must_use]
    pub fn connection(&self) -> &ConnectionName {
        self.request.connection()
    }

    /// The dialect the statement was parsed with.
    #[must_use]
    pub fn dialect(&self) -> Dialect {
        self.analysis.dialect()
    }
}

/// Proof that every policy in an engine evaluated this statement and none denied it.
///
/// The capability token of `docs/architecture.md` section 4.1. Three properties make
/// it unforgeable outside this crate, and all three are load-bearing:
///
/// * the fields are private and the constructor is `pub(crate)`, so no other crate
///   can build one;
/// * it is **not** `Clone`, and [`AuthorizedQuery`] does not expose it, so an
///   existing authorization cannot be transplanted onto different SQL;
/// * it is **not** `Default` and **not** `Deserialize`, so it cannot be conjured
///   from an empty value or a JSON document.
///
/// `tests/policy_rules.rs` enforces all three mechanically.
#[derive(Debug, PartialEq, Eq)]
pub struct AllowDecision {
    evaluated_policies: u16,
    fingerprint: Option<QueryFingerprint>,
}

impl AllowDecision {
    /// Only [`crate::engine::PolicyEngine`] calls this.
    pub(crate) fn new(evaluated_policies: u16, fingerprint: Option<QueryFingerprint>) -> Self {
        Self {
            evaluated_policies,
            fingerprint,
        }
    }

    /// How many policies the engine that produced this decision was configured with.
    ///
    /// Recorded so an audit can tell a decision made by the full engine from one
    /// made by an engine someone had stripped down.
    #[must_use]
    pub fn evaluated_policies(&self) -> u16 {
        self.evaluated_policies
    }

    /// The statement's fingerprint, when the adapter computed one.
    #[must_use]
    pub fn fingerprint(&self) -> Option<&QueryFingerprint> {
        self.fingerprint.as_ref()
    }
}

/// The only state a query executor accepts.
///
/// Not `Clone`, because [`AllowDecision`] is not.
#[derive(Debug, PartialEq)]
pub struct AuthorizedQuery {
    analyzed: AnalyzedQuery,
    decision: AllowDecision,
    limits: ExecutionLimits,
}

impl AuthorizedQuery {
    /// Wraps an authorized statement with the bounds it runs under.
    ///
    /// Public exactly as ADR-0010 specifies, because it requires an
    /// [`AllowDecision`]. In practice no crate outside `warden-policy` can call it:
    /// `PolicyEngine::authorize` is the only source of the token and it returns a
    /// finished `AuthorizedQuery` rather than the token. There is no
    /// `new_unchecked`.
    #[must_use]
    pub fn new(analyzed: AnalyzedQuery, decision: AllowDecision, limits: ExecutionLimits) -> Self {
        Self {
            analyzed,
            decision,
            limits,
        }
    }

    /// The analyzed statement.
    #[must_use]
    pub fn analyzed(&self) -> &AnalyzedQuery {
        &self.analyzed
    }

    /// The evidence the decision was based on.
    #[must_use]
    pub fn analysis(&self) -> &QueryAnalysis {
        self.analyzed.analysis()
    }

    /// The exact SQL to execute.
    ///
    /// Byte-for-byte the analyzed statement (SPEC section 6, invariant 19): nothing
    /// between analysis and execution can replace it, because every field on the way
    /// is private.
    #[must_use]
    pub fn sql(&self) -> &str {
        self.analyzed.sql()
    }

    /// The bound parameters, in placeholder order.
    #[must_use]
    pub fn parameters(&self) -> &[ParameterValue] {
        self.analyzed.parameters()
    }

    /// The connection this statement targets.
    #[must_use]
    pub fn connection(&self) -> &ConnectionName {
        self.analyzed.connection()
    }

    /// The dialect the statement was parsed with.
    #[must_use]
    pub fn dialect(&self) -> Dialect {
        self.analyzed.dialect()
    }

    /// The bounds this execution runs under.
    #[must_use]
    pub fn limits(&self) -> ExecutionLimits {
        self.limits
    }

    /// How many policies authorized this statement.
    #[must_use]
    pub fn evaluated_policies(&self) -> u16 {
        self.decision.evaluated_policies()
    }

    /// The statement's fingerprint, when the adapter computed one.
    #[must_use]
    pub fn fingerprint(&self) -> Option<&QueryFingerprint> {
        self.decision.fingerprint()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::testing;

    fn authorized() -> AuthorizedQuery {
        let analyzed = testing::analyzed(testing::analysis(Dialect::MySql));
        AuthorizedQuery::new(
            analyzed,
            AllowDecision::new(9, None),
            ExecutionLimits::default(),
        )
    }

    #[test]
    fn the_authorized_statement_is_the_analyzed_statement() {
        let query = authorized();
        assert_eq!(query.sql(), "SELECT id FROM orders");
        assert_eq!(query.connection().as_str(), "production-db");
        assert_eq!(query.dialect(), Dialect::MySql);
        assert_eq!(query.limits(), ExecutionLimits::default());
        assert_eq!(query.evaluated_policies(), 9);
        assert_eq!(query.fingerprint(), None);
    }

    #[test]
    fn debug_still_hides_the_statement() {
        let rendered = format!("{:?}", authorized());
        assert!(!rendered.contains("SELECT id FROM orders"), "{rendered}");
        assert!(rendered.contains("sql_bytes"), "{rendered}");
    }

    #[test]
    fn a_decision_carries_the_fingerprint_it_was_made_from() {
        let fingerprint = QueryFingerprint::v1(&"c".repeat(64)).unwrap();
        let decision = AllowDecision::new(1, Some(fingerprint.clone()));
        assert_eq!(decision.fingerprint(), Some(&fingerprint));
        assert_eq!(decision.evaluated_policies(), 1);
    }
}
