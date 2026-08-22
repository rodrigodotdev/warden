//! Database objects and functions named by a statement.

use std::fmt;

/// Whether the statement quoted an identifier.
///
/// PostgreSQL folds an unquoted identifier to lowercase and leaves a quoted one
/// exactly as written, so `Users` and `"Users"` are two different relations. A
/// comparison that cannot tell them apart has silent false negatives
/// (`docs/security.md` section 5.1), which is the bypass the allowlist exists to
/// reduce.
///
/// Same `#[non_exhaustive]` reasoning as [`super::statement::StatementKind`]:
/// `warden-policy` is downstream and must be broken by a new variant, not given a
/// wildcard (ADR-0021).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentifierQuoting {
    /// The statement wrote the name without quotes.
    Unquoted,
    /// The statement wrote the name inside the dialect's quote characters.
    Quoted,
}

impl IdentifierQuoting {
    /// Every quoting. Folding tests iterate this.
    pub const ALL: [Self; 2] = [Self::Unquoted, Self::Quoted];
}

/// One part of a name a statement wrote, with the quoting it was written under.
///
/// The value never contains the quote characters. They are syntax, and storing them
/// inside the value would make escaping and comparison implicit — the analyzer would
/// have to re-decide, at every call site, whether `` `Orders` `` means the four
/// characters or the six.
///
/// This is **not** a validated newtype in the sense of AGENTS.md, and deliberately
/// implements neither `TryFrom<String>` nor `FromStr`: a bare string cannot say
/// whether it was quoted, so a conversion from one would have to guess, and guessing
/// is exactly the ambiguity this type removes. Only an analyzer holding the parsed
/// token can build one. It implements no `Deref`, for the usual reason.
///
/// Folding belongs to policy comparison (`warden_policy::folding`), not here.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub struct SqlIdentifier {
    value: String,
    quoting: IdentifierQuoting,
}

impl SqlIdentifier {
    /// A name the statement wrote without quotes.
    #[must_use]
    pub fn unquoted(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            quoting: IdentifierQuoting::Unquoted,
        }
    }

    /// A name the statement wrote inside the dialect's quote characters.
    ///
    /// Pass the value without the quotes; the parser has already stripped them.
    #[must_use]
    pub fn quoted(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            quoting: IdentifierQuoting::Quoted,
        }
    }

    /// The name without its quote characters.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    /// How the statement spelled it.
    #[must_use]
    pub fn quoting(&self) -> IdentifierQuoting {
        self.quoting
    }
}

impl fmt::Display for SqlIdentifier {
    /// Writes the value, never the quotes: this feeds diagnostics, not SQL.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.value)
    }
}

impl AsRef<str> for SqlIdentifier {
    fn as_ref(&self) -> &str {
        &self.value
    }
}

/// What a referenced name denotes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    /// A base table.
    Table,
    /// A view.
    View,
    /// A materialized view.
    MaterializedView,
    /// A sequence.
    Sequence,
    /// A function used as a relation.
    Function,
    /// Anything the analyzer could not classify.
    Unknown,
}

impl ObjectKind {
    /// Every kind.
    pub const ALL: [Self; 6] = [
        Self::Table,
        Self::View,
        Self::MaterializedView,
        Self::Sequence,
        Self::Function,
        Self::Unknown,
    ];
}

/// A database object a statement refers to.
///
/// CTE names and subquery aliases are **not** `ObjectRef` values: in
/// `WITH x AS (SELECT * FROM secrets) SELECT * FROM x`, `secrets` is the object and
/// `x` is not (`docs/security.md` section 5.1).
///
/// The parts are stored exactly as written. Case folding is dialect-specific and
/// belongs to policy comparison in the adapters, not to this type.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub struct ObjectRef {
    /// Catalog or database qualifier, when the statement wrote one.
    pub catalog: Option<SqlIdentifier>,
    /// Schema qualifier, when the statement wrote one.
    pub schema: Option<SqlIdentifier>,
    /// The object's own name.
    pub name: SqlIdentifier,
    /// What the name denotes, as far as the analyzer could tell.
    pub kind: ObjectKind,
}

impl ObjectRef {
    /// Joins the parts with `.` for error messages and policy diagnostics.
    ///
    /// This is a display helper, not a comparison key: two spellings of the same
    /// object can produce different strings, which is precisely why the read-scope
    /// boundary is the database role's `GRANT`, not a name allowlist
    /// (SPEC section 7).
    #[must_use]
    pub fn qualified_name(&self) -> String {
        let mut parts: Vec<&str> = Vec::with_capacity(3);
        parts.extend(self.catalog.as_ref().map(SqlIdentifier::value));
        parts.extend(self.schema.as_ref().map(SqlIdentifier::value));
        parts.push(self.name.value());
        parts.join(".")
    }
}

/// How safe a function is, as far as the analyzer can tell.
///
/// The mapping to a decision (`KnownSafe` is eligible, everything else is denied)
/// belongs to `warden-policy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FunctionClassification {
    /// On the adapter's allowlist.
    KnownSafe,
    /// On the adapter's denylist, such as `SLEEP` or `pg_advisory_lock`.
    KnownDangerous,
    /// Not classified. Denied by default; a `SELECT` can still have side effects.
    Unknown,
}

impl FunctionClassification {
    /// Every classification. Policy tests iterate this.
    pub const ALL: [Self; 3] = [Self::KnownSafe, Self::KnownDangerous, Self::Unknown];
}

/// A function a statement invokes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub struct FunctionRef {
    /// The function name as written.
    pub name: SqlIdentifier,
    /// Schema qualifier, when the statement wrote one.
    pub schema: Option<SqlIdentifier>,
    /// The adapter's classification.
    pub classification: FunctionClassification,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn object(catalog: Option<&str>, schema: Option<&str>, name: &str) -> ObjectRef {
        ObjectRef {
            catalog: catalog.map(SqlIdentifier::unquoted),
            schema: schema.map(SqlIdentifier::unquoted),
            name: SqlIdentifier::unquoted(name),
            kind: ObjectKind::Table,
        }
    }

    #[test]
    fn qualified_name_joins_only_the_parts_that_exist() {
        assert_eq!(object(None, None, "orders").qualified_name(), "orders");
        assert_eq!(
            object(None, Some("app"), "orders").qualified_name(),
            "app.orders"
        );
        assert_eq!(
            object(Some("shop"), Some("app"), "orders").qualified_name(),
            "shop.app.orders"
        );
    }

    #[test]
    fn quoting_is_recorded_next_to_the_value_not_inside_it() {
        // `Orders` and `` `Orders` `` produce the same value; only the quoting tells
        // them apart, and a PostgreSQL comparison needs that bit
        // (`docs/security.md` section 5.1).
        let bare = SqlIdentifier::unquoted("Orders");
        let quoted = SqlIdentifier::quoted("Orders");
        assert_eq!(bare.value(), quoted.value());
        assert_ne!(bare, quoted);
        assert_eq!(bare.quoting(), IdentifierQuoting::Unquoted);
        assert_eq!(quoted.quoting(), IdentifierQuoting::Quoted);
        assert_eq!(quoted.to_string(), "Orders");
    }

    #[test]
    fn unknown_is_a_real_classification() {
        assert!(FunctionClassification::ALL.contains(&FunctionClassification::Unknown));
        assert!(ObjectKind::ALL.contains(&ObjectKind::Unknown));
    }
}
