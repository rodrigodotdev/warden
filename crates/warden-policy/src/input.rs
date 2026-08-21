//! What a policy is allowed to see.
//!
//! Deliberately **not** the SQL. A policy that could read the statement text would
//! eventually match on it, and pattern-matching agent SQL is the mechanism SPEC
//! section 5.3 rules out. Excluding the request also makes SPEC section 6
//! invariants 22 and 23 structural: no denial detail can contain SQL or a parameter
//! value, because no policy ever holds one.

use warden_core::analysis::QueryAnalysis;
use warden_core::connection::{ConnectionMetadata, Environment};
use warden_core::context::RequestContext;
use warden_core::dialect::Dialect;
use warden_core::limits::ExecutionLimits;

/// Who is asking, and against which connection.
///
/// Object policies receive this without an analysis, because `search_schema` and
/// `describe_schema` check objects that no statement mentioned
/// (`docs/security.md` section 5.2).
#[derive(Debug, Clone, Copy)]
pub struct PolicyContext<'a> {
    context: &'a RequestContext,
    connection: &'a ConnectionMetadata,
}

impl<'a> PolicyContext<'a> {
    /// Borrows the identity and the connection for one evaluation.
    #[must_use]
    pub fn new(context: &'a RequestContext, connection: &'a ConnectionMetadata) -> Self {
        Self {
            context,
            connection,
        }
    }

    /// The request identity.
    #[must_use]
    pub fn context(&self) -> &'a RequestContext {
        self.context
    }

    /// The connection's public metadata.
    #[must_use]
    pub fn connection(&self) -> &'a ConnectionMetadata {
        self.connection
    }

    /// The connection's dialect, which decides identifier folding.
    #[must_use]
    pub fn dialect(&self) -> Dialect {
        self.connection.dialect
    }

    /// The connection's environment. Policy input, not authorization by itself.
    #[must_use]
    pub fn environment(&self) -> &'a Environment {
        &self.connection.environment
    }
}

/// Everything a statement policy evaluates.
#[derive(Debug, Clone, Copy)]
pub struct PolicyInput<'a> {
    context: PolicyContext<'a>,
    analysis: &'a QueryAnalysis,
    limits: ExecutionLimits,
}

impl<'a> PolicyInput<'a> {
    /// Assembles the input for one evaluation.
    #[must_use]
    pub fn new(
        context: PolicyContext<'a>,
        analysis: &'a QueryAnalysis,
        limits: ExecutionLimits,
    ) -> Self {
        Self {
            context,
            analysis,
            limits,
        }
    }

    /// The identity and connection part, for delegating to an object policy.
    #[must_use]
    pub fn policy_context(&self) -> PolicyContext<'a> {
        self.context
    }

    /// The evidence the adapter produced.
    #[must_use]
    pub fn analysis(&self) -> &'a QueryAnalysis {
        self.analysis
    }

    /// The connection's public metadata.
    #[must_use]
    pub fn connection(&self) -> &'a ConnectionMetadata {
        self.context.connection()
    }

    /// The connection's dialect.
    #[must_use]
    pub fn dialect(&self) -> Dialect {
        self.context.dialect()
    }

    /// The bounds the statement would run under.
    #[must_use]
    pub fn limits(&self) -> ExecutionLimits {
        self.limits
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use crate::testing;

    #[test]
    fn input_exposes_the_evidence_and_the_connection() {
        let context = testing::request_context();
        let connection = testing::connection(Dialect::PostgreSql);
        let analysis = testing::analysis(Dialect::PostgreSql);
        let input = PolicyInput::new(
            PolicyContext::new(&context, &connection),
            &analysis,
            ExecutionLimits::default(),
        );

        assert_eq!(input.dialect(), Dialect::PostgreSql);
        assert_eq!(input.connection().name.as_str(), "production-db");
        assert_eq!(
            input.policy_context().environment(),
            &Environment::Production
        );
        assert_eq!(input.analysis().statement_count().get(), 1);
        assert_eq!(input.limits().max_rows, 200);
    }

    #[test]
    fn a_policy_cannot_reach_the_statement() {
        // Not an assertion but a compile-time fact worth stating where it is
        // relied on: `PolicyInput` has no accessor that returns a `QueryRequest`,
        // a `&str` of SQL, or a `ParameterValue`. `tests/policy_rules.rs` scans
        // this file to keep it that way.
        let context = testing::request_context();
        let connection = testing::connection(Dialect::MySql);
        let analysis = testing::analysis(Dialect::MySql);
        let input = PolicyInput::new(
            PolicyContext::new(&context, &connection),
            &analysis,
            ExecutionLimits::default(),
        );
        assert!(input.analysis().objects().is_empty());
    }
}
