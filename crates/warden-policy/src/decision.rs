//! What a denial says: one fixed code for the agent, full detail for the audit.
//!
//! `docs/security.md` section 6 splits a denial in two. The agent receives a
//! [`DenyCode`] and curated fixed-table text that never contains a query
//! identifier or any policy configuration, because a specific message is an
//! iterative oracle: an agent that learns *which* table it may not read has
//! learned something the allowlist was meant to keep quiet. The audit receives
//! every reason, each with the name of the policy that produced it.

use std::fmt;

use warden_core::error::{PublicError, PublicErrorCode};

/// Why a statement was denied.
///
/// **Declaration order is precedence order.** The derived `Ord` is what
/// [`PolicyRejection`] sorts by, so moving a variant changes what the agent is told
/// and a test in this file has to be updated deliberately. The order runs from the
/// most categorical violation to the least specific, with `UnknownConstruct` last as
/// the residual code.
///
/// No `#[non_exhaustive]`: adding a variant must break every consumer that maps
/// codes (ADR-0021).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyCode {
    /// The input was not a single statement.
    MultipleStatements,
    /// The parser hit its recursion limit, so analysis never completed.
    ParserRecursionLimit,
    /// The root statement modifies data.
    WriteStatement,
    /// A nested statement modifies data.
    NestedWrite,
    /// The statement changes schema.
    Ddl,
    /// A recognized statement this tool does not accept, such as `SHOW` or `CALL`.
    StatementNotAllowed,
    /// The statement changes session state or a user variable.
    SessionMutation,
    /// The statement refers to an object the object rules do not permit.
    ObjectNotAllowed,
    /// The statement calls a function classified as dangerous.
    DangerousFunction,
    /// The statement calls a function that is not classified as safe.
    UnknownFunction,
    /// The statement takes row locks.
    LockingRead,
    /// The analyzer could not classify something. The residual code.
    UnknownConstruct,
}

impl DenyCode {
    /// Every code, in precedence order.
    pub const ALL: [Self; 12] = [
        Self::MultipleStatements,
        Self::ParserRecursionLimit,
        Self::WriteStatement,
        Self::NestedWrite,
        Self::Ddl,
        Self::StatementNotAllowed,
        Self::SessionMutation,
        Self::ObjectNotAllowed,
        Self::DangerousFunction,
        Self::UnknownFunction,
        Self::LockingRead,
        Self::UnknownConstruct,
    ];

    /// The stable name used in audit records, trace fields, and metric labels.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MultipleStatements => "multiple_statements",
            Self::ParserRecursionLimit => "parser_recursion_limit",
            Self::WriteStatement => "write_statement",
            Self::NestedWrite => "nested_write",
            Self::Ddl => "ddl",
            Self::StatementNotAllowed => "statement_not_allowed",
            Self::SessionMutation => "session_mutation",
            Self::ObjectNotAllowed => "object_not_allowed",
            Self::DangerousFunction => "dangerous_function",
            Self::UnknownFunction => "unknown_function",
            Self::LockingRead => "locking_read",
            Self::UnknownConstruct => "unknown_construct",
        }
    }

    /// The exact text the agent receives.
    ///
    /// Fixed `&'static str` by construction: there is no formatting argument, so no
    /// call site can interpolate a table name, a function name, or a configuration
    /// value into a message that crosses the MCP boundary
    /// (`docs/security.md` section 6).
    #[must_use]
    pub fn public_message(self) -> &'static str {
        match self {
            Self::MultipleStatements => "only one statement is allowed per call",
            Self::ParserRecursionLimit => "the query is nested too deeply to analyze",
            Self::WriteStatement => "only read-only SELECT statements are allowed",
            Self::NestedWrite => "a nested statement in this query modifies data",
            Self::Ddl => "statements that change schema are not allowed",
            Self::StatementNotAllowed => {
                "this statement type is not allowed; use the dedicated schema and \
                 explain tools"
            }
            Self::SessionMutation => "changing session state or variables is not allowed",
            Self::ObjectNotAllowed => "the query refers to an object that is not allowed",
            Self::DangerousFunction => "the query uses a function classified as dangerous",
            Self::UnknownFunction => "the query uses a function not classified as safe",
            Self::LockingRead => "locking reads are not allowed",
            Self::UnknownConstruct => {
                "the query uses a construct that could not be classified safely"
            }
        }
    }
}

impl fmt::Display for DenyCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One policy's denial, with the detail only an auditor sees.
///
/// Deliberately **not** `Serialize`. `internal_detail` exists for auditing and
/// tracing and must never cross the MCP boundary; making it unserializable is
/// stronger than remembering not to serialize it, and `tests/policy_rules.rs`
/// enforces it. The same reasoning `warden-core` applies to `ParameterValue`.
///
/// `internal_detail` cannot contain SQL or parameter values: a policy never sees
/// them, because [`crate::input::PolicyInput`] does not carry the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenyReason {
    code: DenyCode,
    policy: Option<&'static str>,
    internal_detail: Option<String>,
}

impl DenyReason {
    /// A denial with no further detail.
    #[must_use]
    pub fn new(code: DenyCode) -> Self {
        Self {
            code,
            policy: None,
            internal_detail: None,
        }
    }

    /// A denial with internal detail for the audit record.
    #[must_use]
    pub fn with_detail(code: DenyCode, internal_detail: impl Into<String>) -> Self {
        Self {
            code,
            policy: None,
            internal_detail: Some(internal_detail.into()),
        }
    }

    /// The code the agent receives.
    #[must_use]
    pub fn code(&self) -> DenyCode {
        self.code
    }

    /// The policy that produced this denial, once the engine has stamped it.
    #[must_use]
    pub fn policy(&self) -> Option<&'static str> {
        self.policy
    }

    /// Detail for auditing and tracing. Never crosses the MCP boundary.
    #[must_use]
    pub fn internal_detail(&self) -> Option<&str> {
        self.internal_detail.as_deref()
    }

    /// Records which policy produced this denial.
    ///
    /// `pub(crate)` on purpose: the engine stamps the name from `Policy::name`, so a
    /// policy cannot claim another policy's name in an audit record.
    pub(crate) fn attribute(&mut self, policy: &'static str) {
        self.policy = Some(policy);
    }
}

/// The outcome of evaluating one policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// This policy has no objection. It is not an authorization by itself.
    Allow,
    /// This policy denies the statement.
    Deny(DenyReason),
}

/// Every denial the engine collected, ordered by precedence.
///
/// `Display` prints only the primary code, which is fixed-table text, so logging a
/// rejection cannot leak an object name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("query rejected by policy: {primary}")]
pub struct PolicyRejection {
    primary: DenyCode,
    reasons: Vec<DenyReason>,
}

impl PolicyRejection {
    /// Builds a rejection, or `None` when nothing denied the statement.
    ///
    /// Returning `Option` is what makes "a rejection always has at least one reason"
    /// a type-level fact instead of a runtime check, so [`Self::primary_code`] needs
    /// no fallback.
    ///
    /// Reasons are sorted by [`DenyCode`] precedence. The sort is stable, so equal
    /// codes keep policy-evaluation order and the whole output is deterministic
    /// (ADR-0012).
    pub(crate) fn new(mut reasons: Vec<DenyReason>) -> Option<Self> {
        reasons.sort_by_key(DenyReason::code);
        let primary = reasons.first()?.code();
        Some(Self { primary, reasons })
    }

    /// The single code the agent receives.
    #[must_use]
    pub fn primary_code(&self) -> DenyCode {
        self.primary
    }

    /// The fixed text the agent receives.
    #[must_use]
    pub fn public_message(&self) -> &'static str {
        self.primary.public_message()
    }

    /// Every denial, in precedence order. This is what the audit record carries
    /// (`docs/security.md` section 11.2).
    #[must_use]
    pub fn reasons(&self) -> &[DenyReason] {
        &self.reasons
    }
}

impl PublicError for PolicyRejection {
    fn public_code(&self) -> PublicErrorCode {
        PublicErrorCode::QueryRejected
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn all_lists_every_code_exactly_once_in_precedence_order() {
        let names: BTreeSet<&str> = DenyCode::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(names.len(), DenyCode::ALL.len(), "duplicate spelling");

        let mut sorted = DenyCode::ALL;
        sorted.sort_unstable();
        assert_eq!(
            sorted,
            DenyCode::ALL,
            "ALL is no longer in precedence order; declaration order is the ranking"
        );
    }

    #[test]
    fn precedence_is_the_documented_order() {
        // Spelled out so that reordering the enum is a deliberate act with a visible
        // diff, not a side effect of adding a variant in a convenient place.
        let expected = [
            "multiple_statements",
            "parser_recursion_limit",
            "write_statement",
            "nested_write",
            "ddl",
            "statement_not_allowed",
            "session_mutation",
            "object_not_allowed",
            "dangerous_function",
            "unknown_function",
            "locking_read",
            "unknown_construct",
        ];
        let actual: Vec<&str> = DenyCode::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn every_code_serializes_to_its_stable_name() {
        for code in DenyCode::ALL {
            assert_eq!(
                serde_json::to_string(&code).unwrap(),
                format!("\"{}\"", code.as_str())
            );
        }
    }

    #[test]
    fn public_messages_are_distinct_and_carry_no_interpolation() {
        let messages: BTreeSet<&str> = DenyCode::ALL.iter().map(|c| c.public_message()).collect();
        assert_eq!(messages.len(), DenyCode::ALL.len(), "duplicate message");

        for code in DenyCode::ALL {
            let message = code.public_message();
            assert!(!message.is_empty(), "{code} has no message");
            // A message with a placeholder would be a message someone intended to
            // fill in with a table or function name.
            assert!(!message.contains('{'), "{code}: {message}");
            assert!(!message.contains('}'), "{code}: {message}");
        }
    }

    #[test]
    fn a_rejection_reports_the_highest_precedence_code() {
        let rejection = PolicyRejection::new(vec![
            DenyReason::new(DenyCode::LockingRead),
            DenyReason::new(DenyCode::WriteStatement),
            DenyReason::new(DenyCode::UnknownFunction),
        ])
        .unwrap();

        assert_eq!(rejection.primary_code(), DenyCode::WriteStatement);
        assert_eq!(
            rejection.public_message(),
            "only read-only SELECT statements are allowed"
        );
        // Every denial survives: fixing the first must not reveal the next one at a
        // time (ADR-0012).
        assert_eq!(rejection.reasons().len(), 3);
        assert_eq!(
            rejection
                .reasons()
                .iter()
                .map(DenyReason::code)
                .collect::<Vec<_>>(),
            [
                DenyCode::WriteStatement,
                DenyCode::UnknownFunction,
                DenyCode::LockingRead
            ]
        );
    }

    #[test]
    fn equal_codes_keep_evaluation_order() {
        let rejection = PolicyRejection::new(vec![
            DenyReason::with_detail(DenyCode::ObjectNotAllowed, "first"),
            DenyReason::with_detail(DenyCode::ObjectNotAllowed, "second"),
        ])
        .unwrap();
        assert_eq!(rejection.reasons()[0].internal_detail(), Some("first"));
        assert_eq!(rejection.reasons()[1].internal_detail(), Some("second"));
    }

    #[test]
    fn there_is_no_rejection_without_a_reason() {
        assert!(PolicyRejection::new(Vec::new()).is_none());
    }

    #[test]
    fn internal_detail_never_reaches_the_agent() {
        let rejection = PolicyRejection::new(vec![DenyReason::with_detail(
            DenyCode::ObjectNotAllowed,
            "app.customer_secrets",
        )])
        .unwrap();

        assert!(!rejection.public_message().contains("customer_secrets"));
        assert!(!rejection.to_string().contains("customer_secrets"));
        assert_eq!(rejection.public_code(), PublicErrorCode::QueryRejected);
        // The auditor still gets it.
        assert_eq!(
            rejection.reasons()[0].internal_detail(),
            Some("app.customer_secrets")
        );
    }

    #[test]
    fn attribution_is_absent_until_the_engine_stamps_it() {
        let mut reason = DenyReason::new(DenyCode::LockingRead);
        assert_eq!(reason.policy(), None);
        reason.attribute("locking_read");
        assert_eq!(reason.policy(), Some("locking_read"));
    }
}
