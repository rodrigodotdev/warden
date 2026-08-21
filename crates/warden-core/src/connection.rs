//! Connection identity and the metadata a model is allowed to see.

use std::fmt;
use std::str::FromStr;

use crate::dialect::Dialect;
use crate::identifier::{IdentifierError, validate_identifier};

/// Longest accepted connection name.
///
/// Connection names appear in tool responses, audit records, and metric labels, so
/// the bound keeps those outputs predictable.
pub const MAX_CONNECTION_NAME_LEN: usize = 64;

/// Longest accepted environment name.
pub const MAX_ENVIRONMENT_LEN: usize = 32;

/// The validated name of a configured connection.
///
/// Deliberately does not implement `Deref`: that would expose the whole `String`
/// API and erase the newtype's purpose (`docs/data-model.md` section 1).
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(try_from = "String")]
pub struct ConnectionName(String);

impl ConnectionName {
    /// Borrows the validated name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ConnectionName {
    type Error = IdentifierError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        validate_identifier("connection name", &value, MAX_CONNECTION_NAME_LEN)?;
        Ok(Self(value))
    }
}

impl FromStr for ConnectionName {
    type Err = IdentifierError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value.to_owned())
    }
}

impl fmt::Display for ConnectionName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for ConnectionName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// The deployment environment of a connection.
///
/// This is metadata and policy input, not authorization by itself
/// (`docs/data-model.md` section 1).
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Environment {
    /// A developer machine or an ephemeral environment.
    Development,
    /// A pre-production environment.
    Staging,
    /// Production.
    Production,
    /// Any other operator-defined environment.
    Other(String),
}

impl TryFrom<String> for Environment {
    type Error = IdentifierError;

    /// Matching is exact and lowercase so that `Production` and `production` cannot
    /// become two different environments in audit records.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(match value.as_str() {
            "development" => Self::Development,
            "staging" => Self::Staging,
            "production" => Self::Production,
            _ => {
                validate_identifier("environment", &value, MAX_ENVIRONMENT_LEN)?;
                Self::Other(value)
            }
        })
    }
}

impl FromStr for Environment {
    type Err = IdentifierError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value.to_owned())
    }
}

impl From<Environment> for String {
    fn from(value: Environment) -> Self {
        value.to_string()
    }
}

impl fmt::Display for Environment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl AsRef<str> for Environment {
    fn as_ref(&self) -> &str {
        match self {
            Self::Development => "development",
            Self::Staging => "staging",
            Self::Production => "production",
            Self::Other(name) => name,
        }
    }
}

/// The public description of one connection.
///
/// This is the entire `list_connections` payload (`docs/mcp.md` section 2). It has
/// no DSN, user, host, or password field, so no serialization path can leak one:
/// the type simply cannot hold it (SPEC section 6, invariant 20).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ConnectionMetadata {
    /// The name an agent passes to every tool.
    pub name: ConnectionName,
    /// The dialect, which determines placeholder syntax.
    pub dialect: Dialect,
    /// The deployment environment.
    pub environment: Environment,
    /// The default database or catalog, for the agent's orientation.
    pub database: String,
}

/// What an adapter can actually do.
///
/// Services inspect capabilities instead of matching on `Dialect`, except where the
/// user-visible behavior is inherently dialect-specific
/// (`docs/architecture.md` section 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    /// The engine supports an explicit read-only transaction.
    pub read_only_transactions: bool,
    /// The engine can return a structured plan.
    pub structured_explain: bool,
    /// The engine enforces a server-side statement timeout.
    pub server_statement_timeout: bool,
    /// The adapter implements schema search.
    pub schema_search: bool,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use std::collections::BTreeSet;

    use super::*;

    #[derive(Debug, serde::Deserialize)]
    struct ConfigFragment {
        name: ConnectionName,
    }

    #[test]
    fn accepts_and_borrows_a_valid_name() {
        let name: ConnectionName = "production-mysql.1".parse().unwrap();
        assert_eq!(name.as_str(), "production-mysql.1");
        assert_eq!(name.as_ref() as &str, "production-mysql.1");
        assert_eq!(name.to_string(), "production-mysql.1");
    }

    #[test]
    fn rejects_empty_long_and_unsupported_names() {
        assert!("".parse::<ConnectionName>().is_err());
        assert!(
            "a".repeat(MAX_CONNECTION_NAME_LEN)
                .parse::<ConnectionName>()
                .is_ok()
        );
        assert!(
            "a".repeat(MAX_CONNECTION_NAME_LEN + 1)
                .parse::<ConnectionName>()
                .is_err()
        );
        assert!("prod mysql".parse::<ConnectionName>().is_err());
        assert!("prod/mysql".parse::<ConnectionName>().is_err());
    }

    #[test]
    fn deserialization_runs_the_constructor() {
        // Without `#[serde(try_from = "String")]` this would produce an invalid
        // ConnectionName straight from TOML.
        let error = toml::from_str::<ConfigFragment>("name = \"bad name\"").unwrap_err();
        assert!(
            error.to_string().contains("unsupported character"),
            "{error}"
        );
        let ok = toml::from_str::<ConfigFragment>("name = \"good-name\"").unwrap();
        assert_eq!(ok.name.as_str(), "good-name");
    }

    #[test]
    fn environment_maps_known_names_and_validates_the_rest() {
        assert_eq!(
            "production".parse::<Environment>().unwrap(),
            Environment::Production
        );
        assert_eq!(
            "canary".parse::<Environment>().unwrap(),
            Environment::Other("canary".to_owned())
        );
        // A different case is not the same environment: it becomes `Other`, so
        // audit records never silently merge `Production` with `production`.
        assert_eq!(
            "Production".parse::<Environment>().unwrap(),
            Environment::Other("Production".to_owned())
        );
        assert!("two words".parse::<Environment>().is_err());
    }

    #[test]
    fn environment_round_trips_through_serde() {
        for environment in [
            Environment::Development,
            Environment::Staging,
            Environment::Production,
            Environment::Other("canary".to_owned()),
        ] {
            let json = serde_json::to_string(&environment).unwrap();
            assert_eq!(
                serde_json::from_str::<Environment>(&json).unwrap(),
                environment
            );
        }
    }

    #[test]
    fn metadata_exposes_only_public_fields() {
        let metadata = ConnectionMetadata {
            name: "production-mysql".parse().unwrap(),
            dialect: Dialect::MySql,
            environment: Environment::Production,
            database: "app".to_owned(),
        };
        let json = serde_json::to_value(&metadata).unwrap();
        let keys: BTreeSet<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        // Exactly these four. A DSN, user, host, or password field would have to be
        // added here first, which is the review moment this test creates.
        assert_eq!(
            keys,
            BTreeSet::from(["name", "dialect", "environment", "database"])
        );
    }
}
