//! Synthetic evidence and fake policies for this crate's tests.
//!
//! `docs/testing.md` section 2 requires policy tests to run on synthetic
//! `QueryAnalysis` values. Milestone 2 has no parser and no database on purpose:
//! every rule here must be provable from evidence alone, and a test that needed
//! real SQL would be testing the analyzer instead.

#![allow(clippy::unwrap_used, clippy::expect_used)]
// Helpers are shared by tests in several modules. One that the module you are
// editing happens not to use is not dead code.
#![allow(dead_code)]

use std::num::NonZeroUsize;

use warden_core::analysis::{
    FunctionClassification, FunctionRef, ObjectKind, ObjectRef, QueryAnalysis, QueryAnalysisParts,
    SqlIdentifier, StatementKind,
};
use warden_core::connection::{ConnectionMetadata, Environment};
use warden_core::context::RequestContext;
use warden_core::dialect::Dialect;
use warden_core::limits::ExecutionLimits;
use warden_core::query::{InputLimits, QueryRequest};

use crate::decision::{DenyCode, DenyReason, PolicyDecision};
use crate::input::{PolicyContext, PolicyInput};
use crate::policy::{ObjectAccessPolicy, Policy};
use crate::state::AnalyzedQuery;

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

/// The baseline every test mutates: one safe `SELECT`, no risks, no objects.
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

/// Pairs an analysis with a fixed, valid request.
pub(crate) fn analyzed(analysis: QueryAnalysis) -> AnalyzedQuery {
    let request = QueryRequest::new(
        "production-db".parse().unwrap(),
        "SELECT id FROM orders".to_owned(),
        Vec::new(),
        &InputLimits::default(),
    )
    .unwrap();
    AnalyzedQuery::new(request, analysis)
}

/// A table reference, optionally schema-qualified. Unquoted, like ordinary SQL.
pub(crate) fn table(schema: Option<&str>, name: &str) -> ObjectRef {
    ObjectRef {
        catalog: None,
        schema: schema.map(SqlIdentifier::unquoted),
        name: SqlIdentifier::unquoted(name),
        kind: ObjectKind::Table,
    }
}

/// A quoted table reference, for the folding cases where quoting decides.
pub(crate) fn quoted_table(schema: Option<&str>, name: &str) -> ObjectRef {
    ObjectRef {
        catalog: None,
        schema: schema.map(SqlIdentifier::unquoted),
        name: SqlIdentifier::quoted(name),
        kind: ObjectKind::Table,
    }
}

/// A function reference with an explicit classification.
pub(crate) fn function(name: &str, classification: FunctionClassification) -> FunctionRef {
    FunctionRef {
        name: SqlIdentifier::unquoted(name),
        schema: None,
        classification,
    }
}

/// Evaluates one object policy against a connection of a chosen dialect.
pub(crate) fn check_object_against(
    policy: &dyn ObjectAccessPolicy,
    object: &ObjectRef,
    dialect: Dialect,
) -> PolicyDecision {
    let context = request_context();
    let connection = connection(dialect);
    policy.check(object, &PolicyContext::new(&context, &connection))
}

/// Evaluates one policy against evidence, using a connection of a chosen dialect.
pub(crate) fn decide_against(
    policy: &dyn Policy,
    analysis: &QueryAnalysis,
    dialect: Dialect,
) -> PolicyDecision {
    let context = request_context();
    let connection = connection(dialect);
    let input = PolicyInput::new(
        PolicyContext::new(&context, &connection),
        analysis,
        ExecutionLimits::default(),
    );
    policy.evaluate(&input)
}

/// Evaluates one policy against a connection that matches the analysis dialect.
pub(crate) fn decide(policy: &dyn Policy, analysis: &QueryAnalysis) -> PolicyDecision {
    decide_against(policy, analysis, analysis.dialect())
}

/// The code a policy denied with, or `None` when it had no objection.
pub(crate) fn denied_code(policy: &dyn Policy, analysis: &QueryAnalysis) -> Option<DenyCode> {
    match decide(policy, analysis) {
        PolicyDecision::Allow => None,
        PolicyDecision::Deny(reason) => Some(reason.code()),
    }
}

/// The detail a policy denied with, if any.
pub(crate) fn denied_detail(policy: &dyn Policy, analysis: &QueryAnalysis) -> Option<String> {
    match decide(policy, analysis) {
        PolicyDecision::Allow => None,
        PolicyDecision::Deny(reason) => reason.internal_detail().map(str::to_owned),
    }
}

/// A policy that never objects. Proves the engine evaluates everything.
#[derive(Debug)]
pub(crate) struct AlwaysAllow(pub(crate) &'static str);

impl Policy for AlwaysAllow {
    fn name(&self) -> &'static str {
        self.0
    }

    fn evaluate(&self, _input: &PolicyInput<'_>) -> PolicyDecision {
        PolicyDecision::Allow
    }
}

/// A policy that always objects with a fixed code.
#[derive(Debug)]
pub(crate) struct AlwaysDeny(pub(crate) &'static str, pub(crate) DenyCode);

impl Policy for AlwaysDeny {
    fn name(&self) -> &'static str {
        self.0
    }

    fn evaluate(&self, _input: &PolicyInput<'_>) -> PolicyDecision {
        PolicyDecision::Deny(DenyReason::with_detail(self.1, "synthetic denial"))
    }
}

/// An object policy that objects to every object it sees.
#[derive(Debug)]
pub(crate) struct DenyEveryObject;

impl ObjectAccessPolicy for DenyEveryObject {
    fn name(&self) -> &'static str {
        "deny_every_object"
    }

    fn check(&self, object: &ObjectRef, _context: &PolicyContext<'_>) -> PolicyDecision {
        PolicyDecision::Deny(DenyReason::with_detail(
            DenyCode::ObjectNotAllowed,
            object.qualified_name(),
        ))
    }
}
