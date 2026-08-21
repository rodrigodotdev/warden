//! The two policy contracts.
//!
//! Both are synchronous and dyn-compatible. Neither returns a future: policy
//! evaluation performs no network, database, or LLM call (ADR-0012), so there is
//! nothing to await and no reason for `warden-policy` to know a runtime exists.

use warden_core::analysis::ObjectRef;

use crate::decision::PolicyDecision;
use crate::input::{PolicyContext, PolicyInput};

/// One rule about a statement.
///
/// `name` is a stable identifier that appears in audit records and metric labels.
/// The engine stamps it onto every denial the policy produces, so a policy cannot
/// attribute its denial to another policy.
pub trait Policy: Send + Sync {
    /// The stable name of this rule.
    fn name(&self) -> &'static str;

    /// Decides whether this rule objects to the statement.
    ///
    /// A policy that allows has stated only that it has no objection. Authorization
    /// is the engine's conclusion after every policy has spoken.
    fn evaluate(&self, input: &PolicyInput<'_>) -> PolicyDecision;
}

/// One rule about a database object.
///
/// A separate contract because it applies to `query`, `explain`, `search_schema`,
/// and `describe_schema` alike (`docs/security.md` section 5.2). A denied table that
/// stays describable teaches the agent the whole data model.
///
/// **This is not a read-scope boundary.** It operates on names extracted from an
/// AST, and a name does not determine what a relation reads: an allowed view can
/// read a denied table. The dedicated role's `GRANT SELECT` is the boundary
/// (ADR-0023).
pub trait ObjectAccessPolicy: Send + Sync {
    /// The stable name of this rule.
    fn name(&self) -> &'static str;

    /// Decides whether this rule objects to touching the object.
    fn check(&self, object: &ObjectRef, context: &PolicyContext<'_>) -> PolicyDecision;
}
