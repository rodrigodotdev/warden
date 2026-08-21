//! The default policies: one rule per file.
//!
//! Splitting them this way is deliberate. `docs/testing.md` section 3 warns against
//! hiding security expectations inside one large procedural test, and the same
//! applies to the rules themselves: a reviewer should be able to read one file and
//! decide whether one invariant from SPEC section 6 holds.
//!
//! Every policy that matches a `warden-core` security enum matches it
//! **exhaustively**. There is no `_ =>` arm anywhere in this module, so adding a
//! `StatementKind`, `RiskFlag`, or `FunctionClassification` variant breaks this
//! crate's build instead of passing silently through a wildcard (ADR-0021).

pub mod analysis_integrity;
pub mod function_safety;
pub mod locking_read;
pub mod nested_write;
pub mod object_access;
pub mod risk_evidence;
pub mod root_statement;
pub mod session_mutation;
pub mod single_statement;

pub use analysis_integrity::AnalysisIntegrityPolicy;
pub use function_safety::FunctionSafetyPolicy;
pub use locking_read::LockingReadPolicy;
pub use nested_write::NestedWritePolicy;
pub use object_access::{ObjectRule, ObjectRuleError, SchemaAllowListPolicy, TableAllowDenyPolicy};
pub use risk_evidence::RiskEvidencePolicy;
pub use root_statement::ReadOnlyRootStatementPolicy;
pub use session_mutation::SessionMutationPolicy;
pub use single_statement::SingleStatementPolicy;

use crate::policy::{ObjectAccessPolicy, Policy};
use crate::settings::{ObjectRules, Relaxations};

/// The default statement policies, in evaluation order.
///
/// Order does not change the outcome — every policy is evaluated and the reasons are
/// sorted by [`crate::DenyCode`] precedence afterwards — but it does decide the order
/// of equal codes in an audit record, so it is fixed and tested.
///
/// The list is deliberately redundant. `RiskEvidencePolicy` would catch a locking
/// read on its own, and `ReadOnlyRootStatementPolicy` would catch a session change
/// on its own. Independent controls that overlap are what defense in depth means
/// (SPEC section 4), and the engine reports every one of them.
#[must_use]
pub fn default_policies(relaxations: Relaxations) -> Vec<Box<dyn Policy>> {
    vec![
        Box::new(AnalysisIntegrityPolicy),
        Box::new(SingleStatementPolicy),
        Box::new(ReadOnlyRootStatementPolicy),
        Box::new(NestedWritePolicy),
        Box::new(SessionMutationPolicy),
        Box::new(LockingReadPolicy::new(relaxations)),
        Box::new(FunctionSafetyPolicy::new(relaxations)),
        Box::new(RiskEvidencePolicy::new(relaxations)),
    ]
}

/// The default object policies for a set of configured rules.
///
/// A policy is built only when the corresponding rules exist, so an unrestricted
/// deployment carries no object policy at all instead of one that permits
/// everything.
pub fn default_object_policies(
    rules: &ObjectRules,
) -> Result<Vec<Box<dyn ObjectAccessPolicy>>, ObjectRuleError> {
    let mut policies: Vec<Box<dyn ObjectAccessPolicy>> = Vec::new();

    if let Some(schemas) = rules.schemas.as_ref() {
        policies.push(Box::new(SchemaAllowListPolicy::new(schemas.clone())));
    }

    let allow = rules
        .allow_tables
        .as_ref()
        .map(|entries| parse_rules(entries))
        .transpose()?;
    let deny = parse_rules(&rules.deny_tables)?;

    if allow.is_some() || !deny.is_empty() {
        policies.push(Box::new(TableAllowDenyPolicy::new(allow, deny)));
    }
    Ok(policies)
}

fn parse_rules(entries: &[String]) -> Result<Vec<ObjectRule>, ObjectRuleError> {
    entries
        .iter()
        .map(|entry| ObjectRule::parse(entry))
        .collect()
}
