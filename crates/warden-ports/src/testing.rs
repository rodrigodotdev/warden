//! Fakes and fixtures for this crate's tests.
//!
//! `warden-ports` has no parser, no driver, and no database — that is the point of
//! the milestone — so every test here runs against a fake.
//!
//! They live in a `#[cfg(test)]` module rather than behind a `testing` feature
//! because Cargo unifies features across a workspace build
//! (`docs/architecture.md` section 4.3): a feature that exposed these to this
//! crate's tests would expose them to `warden-mcp` too. `warden-service` writes its
//! own fakes in Milestone 11 for the same reason.

#![allow(clippy::unwrap_used, clippy::expect_used)]
// Helpers are shared by tests in several modules. One that the module you are
// editing happens not to use is not dead code.
#![allow(dead_code)]

use std::num::NonZeroUsize;

use warden_core::analysis::{QueryAnalysis, QueryAnalysisParts, StatementKind};
use warden_core::connection::{Capabilities, ConnectionMetadata, Environment};
use warden_core::context::RequestContext;
use warden_core::dialect::Dialect;
use warden_core::limits::ExecutionLimits;
use warden_core::query::{InputLimits, QueryRequest};
use warden_policy::{
    AnalyzedQuery, AuthorizedQuery, PolicyEngine, PolicyRejection, PolicySettings,
};

use crate::analyzer::QueryAnalyzer;
use crate::error::AnalyzeError;

/// The statement every fixture uses.
pub(crate) const SQL: &str = "SELECT id FROM orders";

/// A valid request against the fixture connection.
pub(crate) fn request() -> QueryRequest {
    QueryRequest::new(
        "production-db".parse().unwrap(),
        SQL.to_owned(),
        Vec::new(),
        &InputLimits::default(),
    )
    .unwrap()
}

/// A fixed request identity.
pub(crate) fn request_context() -> RequestContext {
    RequestContext::new(
        "req-1".parse().unwrap(),
        "alice@example.com".parse().unwrap(),
        "Claude Code".parse().unwrap(),
    )
}

/// A production connection on the given dialect.
pub(crate) fn connection(dialect: Dialect) -> ConnectionMetadata {
    ConnectionMetadata {
        name: "production-db".parse().unwrap(),
        dialect,
        environment: Environment::Production,
        database: "app".to_owned(),
    }
}

/// An adapter that can do everything.
pub(crate) fn capabilities() -> Capabilities {
    Capabilities {
        read_only_transactions: true,
        structured_explain: true,
        server_statement_timeout: true,
        schema_search: true,
    }
}

/// The baseline evidence: one safe `SELECT`, no risks, no objects.
pub(crate) fn parts(dialect: Dialect) -> QueryAnalysisParts {
    QueryAnalysisParts {
        dialect,
        statement_count: NonZeroUsize::MIN,
        root_kind: StatementKind::Select,
        nested_kinds: Vec::new(),
        objects: Vec::new(),
        functions: Vec::new(),
        risks: Vec::new(),
        has_locking_clause: false,
        has_side_effects: false,
        fingerprint: None,
    }
}

/// The baseline, frozen.
pub(crate) fn analysis(dialect: Dialect) -> QueryAnalysis {
    QueryAnalysis::new(parts(dialect))
}

/// The baseline paired with the fixture request.
pub(crate) fn analyzed(dialect: Dialect) -> AnalyzedQuery {
    AnalyzedQuery::new(request(), analysis(dialect))
}

/// The real engine with the hardened default settings.
pub(crate) fn engine() -> PolicyEngine {
    PolicyEngine::with_defaults(&PolicySettings::default()).unwrap()
}

/// A real authorization, produced by the real engine.
///
/// There is no shortcut and there must never be one: `AllowDecision` is unforgeable
/// outside `warden-policy` (ADR-0010), so even a test in a downstream crate has to
/// go through `PolicyEngine::authorize`. That this fixture is the only way to build
/// the executor's argument is the capability token working as designed.
pub(crate) fn authorized(dialect: Dialect) -> AuthorizedQuery {
    engine()
        .authorize(
            &request_context(),
            &connection(dialect),
            analyzed(dialect),
            ExecutionLimits::default(),
        )
        .unwrap()
}

/// A real rejection, produced by asking the engine to authorize a write.
pub(crate) fn rejection() -> PolicyRejection {
    let analysis = QueryAnalysis::new(QueryAnalysisParts {
        root_kind: StatementKind::Insert,
        ..parts(Dialect::MySql)
    });
    engine()
        .authorize(
            &request_context(),
            &connection(Dialect::MySql),
            AnalyzedQuery::new(request(), analysis),
            ExecutionLimits::default(),
        )
        .unwrap_err()
}

/// An analyzer with a fixed outcome.
#[derive(Debug)]
pub(crate) struct FakeAnalyzer {
    dialect: Dialect,
    outcome: Result<(), AnalyzeError>,
}

impl FakeAnalyzer {
    /// An analyzer that always produces the baseline evidence.
    pub(crate) fn new(dialect: Dialect) -> Self {
        Self {
            dialect,
            outcome: Ok(()),
        }
    }

    /// An analyzer that always fails the same way.
    pub(crate) fn failing(error: AnalyzeError) -> Self {
        Self {
            dialect: Dialect::MySql,
            outcome: Err(error),
        }
    }
}

impl QueryAnalyzer for FakeAnalyzer {
    fn dialect(&self) -> Dialect {
        self.dialect
    }

    fn analyze(&self, request: QueryRequest) -> Result<AnalyzedQuery, AnalyzeError> {
        match &self.outcome {
            Ok(()) => Ok(AnalyzedQuery::new(request, analysis(self.dialect))),
            Err(error) => Err(error.clone()),
        }
    }
}
