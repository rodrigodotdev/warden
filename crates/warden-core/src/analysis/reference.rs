//! Database objects and functions named by a statement.

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
    pub catalog: Option<String>,
    /// Schema qualifier, when the statement wrote one.
    pub schema: Option<String>,
    /// The object's own name.
    pub name: String,
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
        let mut parts = Vec::with_capacity(3);
        parts.extend(self.catalog.as_deref());
        parts.extend(self.schema.as_deref());
        parts.push(&self.name);
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
    pub name: String,
    /// Schema qualifier, when the statement wrote one.
    pub schema: Option<String>,
    /// The adapter's classification.
    pub classification: FunctionClassification,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn object(catalog: Option<&str>, schema: Option<&str>, name: &str) -> ObjectRef {
        ObjectRef {
            catalog: catalog.map(str::to_owned),
            schema: schema.map(str::to_owned),
            name: name.to_owned(),
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
    fn names_are_preserved_verbatim() {
        // Folding is dialect-specific and happens during policy comparison; storing
        // a folded name here would silently lose the quoted/unquoted distinction.
        assert_eq!(object(None, None, "Orders").name, "Orders");
    }

    #[test]
    fn unknown_is_a_real_classification() {
        assert!(FunctionClassification::ALL.contains(&FunctionClassification::Unknown));
        assert!(ObjectKind::ALL.contains(&ObjectKind::Unknown));
    }
}
