//! Which objects a connection may touch, in every tool that touches objects.
//!
//! **These rules are not a read-scope boundary.** They match names extracted from an
//! AST, and a name does not determine what a relation reads: `SELECT * FROM
//! public_report` passes while the view reads `users.password_hash`. The dedicated
//! role's `GRANT SELECT` is the boundary (ADR-0023). What these rules buy is a
//! smaller attack surface and a better error message, and public material must not
//! present them as more than that.

use warden_core::analysis::{ObjectRef, SqlIdentifier};
use warden_core::dialect::Dialect;

use crate::decision::{DenyCode, DenyReason, PolicyDecision};
use crate::folding::rule_matches;
use crate::input::PolicyContext;
use crate::policy::ObjectAccessPolicy;

/// A configured object rule that could not be understood.
///
/// Startup fails on one of these (`docs/operations.md` section 3.2). The rejected
/// text is echoed because an object rule is an operator-written table name, never a
/// secret, and an error that will not say which rule is wrong is an error nobody can
/// act on.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ObjectRuleError {
    /// The rule was empty or only whitespace.
    #[error("object rule {rule:?} is empty")]
    Empty {
        /// The rejected rule.
        rule: String,
    },
    /// One of the dot-separated parts was empty.
    #[error("object rule {rule:?} has an empty part")]
    EmptyPart {
        /// The rejected rule.
        rule: String,
    },
    /// The rule had more parts than `schema.name`.
    #[error("object rule {rule:?} has {parts} parts; expected \"name\" or \"schema.name\"")]
    TooManyParts {
        /// The rejected rule.
        rule: String,
        /// How many dot-separated parts it had.
        parts: usize,
    },
}

/// One entry of a table allowlist or denylist.
///
/// Written as `name` or `schema.name`. Three-part names are rejected rather than
/// guessed at: `docs/data-model.md` section 5 warns that a two-part name does not
/// mean the same thing on both engines, and inventing a catalog interpretation here
/// would encode an assumption in the one place that must not hold any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectRule {
    qualifier: Option<String>,
    name: String,
}

impl ObjectRule {
    /// Parses `name` or `schema.name`.
    ///
    /// # Errors
    ///
    /// - [`ObjectRuleError::Empty`] if `rule` is empty or only whitespace.
    /// - [`ObjectRuleError::EmptyPart`] if any dot-separated part is empty, so
    ///   `.users` and `app.` are refused rather than read as one-part names.
    /// - [`ObjectRuleError::TooManyParts`] for three or more parts, which are
    ///   rejected rather than guessed at.
    pub fn parse(rule: &str) -> Result<Self, ObjectRuleError> {
        let trimmed = rule.trim();
        if trimmed.is_empty() {
            return Err(ObjectRuleError::Empty {
                rule: rule.to_owned(),
            });
        }
        let parts: Vec<&str> = trimmed.split('.').map(str::trim).collect();
        if parts.iter().any(|part| part.is_empty()) {
            return Err(ObjectRuleError::EmptyPart {
                rule: rule.to_owned(),
            });
        }
        // `[..]` rather than `_`: this crate contains no wildcard match arm at all,
        // and `tests/policy_rules.rs` scans for one.
        match parts.as_slice() {
            [name] => Ok(Self {
                qualifier: None,
                name: (*name).to_owned(),
            }),
            [qualifier, name] => Ok(Self {
                qualifier: Some((*qualifier).to_owned()),
                name: (*name).to_owned(),
            }),
            [..] => Err(ObjectRuleError::TooManyParts {
                rule: rule.to_owned(),
                parts: parts.len(),
            }),
        }
    }

    /// The schema or catalog part, when the rule has one.
    #[must_use]
    pub fn qualifier(&self) -> Option<&str> {
        self.qualifier.as_deref()
    }

    /// The object name part.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// The object's nearest qualifier: its schema, or its catalog when it has no schema.
///
/// Which slot an adapter fills is the adapter's decision, because a two-part name
/// means different things on MySQL and PostgreSQL. Policy compares the nearest one.
fn qualifier_of(object: &ObjectRef) -> Option<&SqlIdentifier> {
    object.schema.as_ref().or(object.catalog.as_ref())
}

/// Restricts which schemas a connection may touch.
///
/// An **unqualified** object is not matched against this list, and passes. The
/// connection fixes `search_path` and the default database at connect time
/// (`docs/operations.md` section 5.1), so an unqualified name resolves inside the
/// configured set; rejecting every unqualified query would deny almost all real
/// agent SQL for no gain, given that the `GRANT` is the boundary either way.
#[derive(Debug, Clone)]
pub struct SchemaAllowListPolicy {
    allowed: Option<Vec<String>>,
}

impl SchemaAllowListPolicy {
    /// A policy that permits every schema.
    ///
    /// Spelled out rather than reached through `Default`, so that "this deployment
    /// restricts no schema" is a sentence someone wrote on purpose.
    #[must_use]
    pub fn unrestricted() -> Self {
        Self { allowed: None }
    }

    /// A policy that permits only the named schemas.
    #[must_use]
    pub fn new(schemas: Vec<String>) -> Self {
        Self {
            allowed: Some(schemas),
        }
    }
}

impl ObjectAccessPolicy for SchemaAllowListPolicy {
    fn name(&self) -> &'static str {
        "schema_allow_list"
    }

    fn check(&self, object: &ObjectRef, context: &PolicyContext<'_>) -> PolicyDecision {
        let Some(allowed) = self.allowed.as_ref() else {
            return PolicyDecision::Allow;
        };
        let Some(qualifier) = qualifier_of(object) else {
            return PolicyDecision::Allow;
        };
        let dialect = context.dialect();
        if allowed
            .iter()
            .any(|schema| rule_matches(dialect, schema, qualifier))
        {
            return PolicyDecision::Allow;
        }
        PolicyDecision::Deny(DenyReason::with_detail(
            DenyCode::ObjectNotAllowed,
            format!("schema not allowed: {}", object.qualified_name()),
        ))
    }
}

/// Restricts which tables a connection may touch.
///
/// The two sides use different qualifier rules, because a symmetric rule would make
/// one of them permissive:
///
/// ```text
/// allow  an unqualified object never satisfies a qualified rule   (matches less)
/// deny   an unqualified object matches a qualified rule           (matches more)
/// ```
///
/// So `deny = ["app.secrets"]` still stops `SELECT * FROM secrets`, and
/// `allow = ["app.orders"]` does not accept a bare `orders` it cannot prove is the
/// same table. Both sides err toward denial (ADR-0011).
///
/// The asymmetry above is about the *object* side of the comparison — whether the
/// query's reference is qualified. The *rule* side is symmetric and deliberately
/// broad in the other direction: an **unqualified** rule, `allow = ["orders"]` or
/// `deny = ["secrets"]`, has no qualifier to compare, so it matches that table name
/// in every schema (`internal.orders`, `staging.orders`, ...), not just an
/// unqualified reference. Write `allow = ["app.orders"]` to restrict a rule to one
/// schema.
#[derive(Debug, Clone)]
pub struct TableAllowDenyPolicy {
    allow: Option<Vec<ObjectRule>>,
    deny: Vec<ObjectRule>,
}

impl TableAllowDenyPolicy {
    /// Builds the policy. `allow` of `None` permits every table not denied.
    #[must_use]
    pub fn new(allow: Option<Vec<ObjectRule>>, deny: Vec<ObjectRule>) -> Self {
        Self { allow, deny }
    }

    /// Strict matching, used for the allowlist.
    fn allows(rule: &ObjectRule, object: &ObjectRef, dialect: Dialect) -> bool {
        if !rule_matches(dialect, rule.name(), &object.name) {
            return false;
        }
        match (rule.qualifier(), qualifier_of(object)) {
            (None, _) => true,
            (Some(expected), Some(actual)) => rule_matches(dialect, expected, actual),
            (Some(_), None) => false,
        }
    }

    /// Fail-closed matching, used for the denylist.
    fn denies(rule: &ObjectRule, object: &ObjectRef, dialect: Dialect) -> bool {
        if !rule_matches(dialect, rule.name(), &object.name) {
            return false;
        }
        match (rule.qualifier(), qualifier_of(object)) {
            (None, _) | (_, None) => true,
            (Some(expected), Some(actual)) => rule_matches(dialect, expected, actual),
        }
    }
}

impl ObjectAccessPolicy for TableAllowDenyPolicy {
    fn name(&self) -> &'static str {
        "table_allow_deny"
    }

    fn check(&self, object: &ObjectRef, context: &PolicyContext<'_>) -> PolicyDecision {
        let dialect = context.dialect();

        // Deny wins. An operator who lists a table on both sides meant to keep it
        // out.
        if self
            .deny
            .iter()
            .any(|rule| Self::denies(rule, object, dialect))
        {
            return PolicyDecision::Deny(DenyReason::with_detail(
                DenyCode::ObjectNotAllowed,
                format!("table denied: {}", object.qualified_name()),
            ));
        }
        if let Some(allow) = self.allow.as_ref()
            && !allow.iter().any(|rule| Self::allows(rule, object, dialect))
        {
            return PolicyDecision::Deny(DenyReason::with_detail(
                DenyCode::ObjectNotAllowed,
                format!("table not in the allowlist: {}", object.qualified_name()),
            ));
        }
        PolicyDecision::Allow
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use warden_core::analysis::ObjectKind;

    use super::*;
    use crate::testing;

    fn decide(
        policy: &dyn ObjectAccessPolicy,
        object: &ObjectRef,
        dialect: Dialect,
    ) -> PolicyDecision {
        let context = testing::request_context();
        let connection = testing::connection(dialect);
        policy.check(object, &PolicyContext::new(&context, &connection))
    }

    fn allowed(policy: &dyn ObjectAccessPolicy, object: &ObjectRef, dialect: Dialect) -> bool {
        decide(policy, object, dialect) == PolicyDecision::Allow
    }

    fn rules(entries: &[&str]) -> Vec<ObjectRule> {
        entries
            .iter()
            .map(|entry| ObjectRule::parse(entry).unwrap())
            .collect()
    }

    #[test]
    fn a_rule_parses_one_or_two_parts() {
        let bare = ObjectRule::parse("orders").unwrap();
        assert_eq!(bare.qualifier(), None);
        assert_eq!(bare.name(), "orders");

        let qualified = ObjectRule::parse(" app . orders ").unwrap();
        assert_eq!(qualified.qualifier(), Some("app"));
        assert_eq!(qualified.name(), "orders");
    }

    #[test]
    fn malformed_rules_are_rejected_by_name() {
        assert_eq!(
            ObjectRule::parse("   ").unwrap_err(),
            ObjectRuleError::Empty {
                rule: "   ".to_owned()
            }
        );
        assert_eq!(
            ObjectRule::parse("app.").unwrap_err(),
            ObjectRuleError::EmptyPart {
                rule: "app.".to_owned()
            }
        );
        assert_eq!(
            ObjectRule::parse("shop.app.orders").unwrap_err(),
            ObjectRuleError::TooManyParts {
                rule: "shop.app.orders".to_owned(),
                parts: 3
            }
        );
    }

    #[test]
    fn an_unrestricted_schema_policy_permits_everything() {
        let policy = SchemaAllowListPolicy::unrestricted();
        assert!(allowed(
            &policy,
            &testing::table(Some("anything"), "orders"),
            Dialect::MySql
        ));
    }

    #[test]
    fn a_schema_allowlist_matches_case_insensitively_and_denies_the_rest() {
        let policy = SchemaAllowListPolicy::new(vec!["app".to_owned(), "public".to_owned()]);

        for dialect in [Dialect::MySql, Dialect::PostgreSql] {
            assert!(allowed(
                &policy,
                &testing::table(Some("APP"), "orders"),
                dialect
            ));
            assert!(!allowed(
                &policy,
                &testing::table(Some("internal"), "orders"),
                dialect
            ));
        }
    }

    #[test]
    fn a_schema_allowlist_does_not_match_unqualified_objects() {
        // Documented behavior, not an oversight: `search_path` and the default
        // database are fixed at connect time, and the GRANT is the boundary.
        let policy = SchemaAllowListPolicy::new(vec!["app".to_owned()]);
        assert!(allowed(
            &policy,
            &testing::table(None, "orders"),
            Dialect::PostgreSql
        ));
    }

    #[test]
    fn the_catalog_is_used_when_there_is_no_schema() {
        let policy = SchemaAllowListPolicy::new(vec!["app".to_owned()]);
        let object = ObjectRef {
            catalog: Some(SqlIdentifier::unquoted("other")),
            schema: None,
            name: SqlIdentifier::unquoted("orders"),
            kind: ObjectKind::Table,
        };
        assert!(!allowed(&policy, &object, Dialect::MySql));
    }

    #[test]
    fn a_denylist_entry_stops_an_unqualified_reference() {
        // The fail-closed half: `deny = ["app.secrets"]` must still stop
        // `SELECT * FROM secrets`, which the connection resolves to `app.secrets`.
        let policy = TableAllowDenyPolicy::new(None, rules(&["app.secrets"]));
        assert!(!allowed(
            &policy,
            &testing::table(None, "secrets"),
            Dialect::PostgreSql
        ));
        assert!(!allowed(
            &policy,
            &testing::table(Some("app"), "SECRETS"),
            Dialect::PostgreSql
        ));
        assert!(allowed(
            &policy,
            &testing::table(Some("app"), "orders"),
            Dialect::PostgreSql
        ));
    }

    #[test]
    fn an_unqualified_denylist_entry_matches_every_schema() {
        let policy = TableAllowDenyPolicy::new(None, rules(&["secrets"]));
        assert!(!allowed(
            &policy,
            &testing::table(Some("anything"), "secrets"),
            Dialect::MySql
        ));
    }

    #[test]
    fn an_allowlist_does_not_accept_a_name_it_cannot_place() {
        // The other fail-closed half: a bare `orders` is not provably `app.orders`.
        let policy = TableAllowDenyPolicy::new(Some(rules(&["app.orders"])), Vec::new());
        assert!(allowed(
            &policy,
            &testing::table(Some("app"), "orders"),
            Dialect::PostgreSql
        ));
        assert!(!allowed(
            &policy,
            &testing::table(None, "orders"),
            Dialect::PostgreSql
        ));
        assert!(!allowed(
            &policy,
            &testing::table(Some("other"), "orders"),
            Dialect::PostgreSql
        ));
    }

    #[test]
    fn an_unqualified_allowlist_entry_accepts_any_schema() {
        let policy = TableAllowDenyPolicy::new(Some(rules(&["orders"])), Vec::new());
        assert!(allowed(
            &policy,
            &testing::table(Some("app"), "orders"),
            Dialect::MySql
        ));
        assert!(allowed(
            &policy,
            &testing::table(None, "orders"),
            Dialect::MySql
        ));
    }

    #[test]
    fn deny_wins_over_allow() {
        let policy = TableAllowDenyPolicy::new(
            Some(rules(&["app.orders", "app.secrets"])),
            rules(&["app.secrets"]),
        );
        assert!(allowed(
            &policy,
            &testing::table(Some("app"), "orders"),
            Dialect::MySql
        ));
        assert!(!allowed(
            &policy,
            &testing::table(Some("app"), "secrets"),
            Dialect::MySql
        ));
    }

    #[test]
    fn the_denial_detail_names_the_object_and_the_message_does_not() {
        let policy = TableAllowDenyPolicy::new(None, rules(&["app.secrets"]));
        let PolicyDecision::Deny(reason) = decide(
            &policy,
            &testing::table(Some("app"), "secrets"),
            Dialect::MySql,
        ) else {
            panic!("a denied table must be denied");
        };
        assert_eq!(reason.code(), DenyCode::ObjectNotAllowed);
        assert_eq!(reason.internal_detail(), Some("table denied: app.secrets"));
        // The agent learns that some object was refused, never which one: a
        // specific message is an enumeration oracle.
        assert!(!reason.code().public_message().contains("secrets"));
    }

    #[test]
    fn a_quoted_postgres_name_does_not_match_a_lowercase_rule() {
        // The bypass `docs/security.md` section 5.1 names: `"Users"` and `users` are
        // two relations, and a deny rule for one must not be read as covering both.
        let policy = TableAllowDenyPolicy::new(None, vec![ObjectRule::parse("users").unwrap()]);
        let quoted = testing::quoted_table(None, "Users");
        assert!(matches!(
            testing::check_object_against(&policy, &quoted, Dialect::PostgreSql),
            PolicyDecision::Allow
        ));
        assert!(matches!(
            testing::check_object_against(&policy, &quoted, Dialect::MySql),
            PolicyDecision::Deny(_)
        ));
    }
}
