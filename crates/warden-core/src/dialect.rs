//! The SQL dialects Warden implements natively.

use std::fmt;
use std::str::FromStr;

/// The value did not name a supported dialect.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unsupported dialect {value:?}; expected \"mysql\" or \"postgresql\"")]
pub struct DialectError {
    /// The rejected value. This is a configuration keyword, never a secret.
    pub value: String,
}

/// A SQL dialect.
///
/// Configuration converts text to this enum once, at startup; nothing downstream
/// carries a dialect as a string (`docs/data-model.md` section 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase", try_from = "String")]
pub enum Dialect {
    /// MySQL. Placeholders are positional `?`.
    MySql,
    /// PostgreSQL. Placeholders are numbered `$1`.
    PostgreSql,
}

impl Dialect {
    /// The canonical name used in configuration and tool responses.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MySql => "mysql",
            Self::PostgreSql => "postgresql",
        }
    }

    /// An example cast that turns a value of an unsupported type into text.
    ///
    /// `docs/data-model.md` section 8.1, rule 5 allows the error to suggest a cast.
    /// The suggestion has to be in the dialect the agent is writing, or it is one
    /// more thing that fails.
    #[must_use]
    pub fn text_cast_example(self, column: &str) -> String {
        match self {
            Self::MySql => format!("CAST({column} AS CHAR)"),
            Self::PostgreSql => format!("{column}::text"),
        }
    }
}

impl TryFrom<String> for Dialect {
    type Error = DialectError;

    /// Accepts only the canonical spellings. Aliases such as `postgres` are
    /// rejected so that configuration cannot drift into several spellings of the
    /// same thing.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            "mysql" => Ok(Self::MySql),
            "postgresql" => Ok(Self::PostgreSql),
            _ => Err(DialectError { value }),
        }
    }
}

impl FromStr for Dialect {
    type Err = DialectError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value.to_owned())
    }
}

impl fmt::Display for Dialect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn serializes_to_the_configuration_spelling() {
        assert_eq!(
            serde_json::to_string(&Dialect::PostgreSql).unwrap(),
            "\"postgresql\""
        );
        assert_eq!(serde_json::to_string(&Dialect::MySql).unwrap(), "\"mysql\"");
    }

    #[test]
    fn deserializes_only_the_canonical_spellings() {
        assert_eq!(
            serde_json::from_str::<Dialect>("\"mysql\"").unwrap(),
            Dialect::MySql
        );
        assert!(serde_json::from_str::<Dialect>("\"postgres\"").is_err());
        assert!(serde_json::from_str::<Dialect>("\"MySQL\"").is_err());
    }

    #[test]
    fn from_str_and_display_round_trip() {
        for dialect in [Dialect::MySql, Dialect::PostgreSql] {
            assert_eq!(dialect.to_string().parse::<Dialect>().unwrap(), dialect);
        }
    }
}
