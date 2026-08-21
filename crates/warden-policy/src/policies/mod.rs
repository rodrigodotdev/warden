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
