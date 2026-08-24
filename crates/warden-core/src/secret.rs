//! The DSN, and the single place it can be read back.
//!
//! # Why this is not an ordinary validated newtype
//!
//! `AGENTS.md` asks a validated newtype for `TryFrom<String>`, `FromStr`, `Display`
//! and `AsRef<str>`. [`Dsn`] implements the first two and deliberately implements
//! neither of the last two: `Display` is what puts a password into `tracing::info!`
//! and `AsRef<str>` is what lets it be handed to anything expecting a string.
//! ADR-0019 governs a secret and takes precedence over the identifier rule, so the
//! only read-back is [`Dsn::expose_secret`] — one name, greppable across the
//! repository.
//!
//! # What the zeroization actually covers
//!
//! `Dsn` wraps `secrecy::SecretString`, so the configuration path's copy is zeroed
//! on drop. The drivers are a different matter: `MySqlConnectOptions` and
//! `PgConnectOptions` hold the password in a plain `String`, and a pool keeps an
//! `Arc` of its connect options for its whole lifetime. This type bounds how long
//! Warden's own configuration path holds the secret; it does not bound SQLx.

use std::fmt;
use std::str::FromStr;

use secrecy::{ExposeSecret, SecretString};

use crate::dialect::Dialect;

/// Longest accepted DSN.
///
/// Generous enough for a hostname, credentials, a database name and TLS parameters,
/// small enough that a pasted file cannot become a connection string.
pub const MAX_DSN_LEN: usize = 4096;

/// Longest accepted URL scheme, which bounds parser work before rejection.
const MAX_SCHEME_LEN: usize = 32;

/// Why a string is not a usable DSN.
///
/// No variant carries the DSN or any substring of it, so no variant can quote a
/// password (SPEC section 6, invariant 21).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DsnError {
    /// The value was empty.
    #[error("the DSN is empty")]
    Empty,
    /// The value exceeded [`MAX_DSN_LEN`].
    #[error("the DSN is {actual} bytes; the limit is {limit}")]
    TooLong {
        /// Length of the rejected value.
        actual: usize,
        /// The limit.
        limit: usize,
    },
    /// The value had no `scheme://` prefix.
    #[error("the DSN has no `scheme://` prefix")]
    MissingScheme,
    /// The prefix was not a syntactically valid URL scheme.
    ///
    /// Carries nothing: a value that fails this check is not known to be a scheme at
    /// all, so quoting it could quote arbitrary DSN bytes.
    #[error("the DSN prefix is not a valid URL scheme")]
    MalformedScheme,
    /// The scheme named no dialect Warden implements.
    #[error("the DSN scheme is unsupported; expected \"mysql\", \"postgres\", or \"postgresql\"")]
    UnsupportedScheme,
}

/// A database connection string, and the dialect its scheme names.
///
/// Constructing one is the only way to carry a DSN through Warden. It derives no
/// `Serialize`, implements no `Display` and no `AsRef<str>`, and redacts `Debug`, so
/// there is no accidental path from configuration to a log line or a tool response
/// (ADR-0019; SPEC section 6, invariants 20–21).
///
/// It is deliberately not `Clone`: one connection owns one DSN, and
/// `secrecy::SecretString` would need a `CloneableSecret` opt-in that exists to make
/// exactly this decision explicit.
///
/// ```compile_fail
/// use warden_core::secret::Dsn;
///
/// fn duplicate(dsn: Dsn) -> Dsn {
///     dsn.clone()
/// }
/// ```
///
/// ```compile_fail
/// use warden_core::secret::Dsn;
///
/// fn render(dsn: Dsn) -> String {
///     dsn.to_string()
/// }
/// ```
///
/// ```compile_fail
/// use warden_core::secret::Dsn;
///
/// fn borrow(dsn: &Dsn) -> &str {
///     dsn.as_ref()
/// }
/// ```
///
/// ```compile_fail
/// use warden_core::secret::Dsn;
///
/// fn dereference(dsn: &Dsn) {
///     let _borrow = &**dsn;
/// }
/// ```
///
/// ```compile_fail
/// use warden_core::secret::Dsn;
///
/// fn serialize(dsn: &Dsn) -> String {
///     serde_json::to_string(dsn).unwrap()
/// }
/// ```
pub struct Dsn {
    dialect: Dialect,
    secret: SecretString,
}

impl Dsn {
    /// The dialect this DSN's scheme names.
    ///
    /// SQLx does **not** check the scheme: `MySqlConnectOptions::from_str` parses a
    /// `postgres://` URL without complaint and would then point the MySQL protocol at
    /// a PostgreSQL port. Each adapter compares this value against its own dialect
    /// before it parses anything.
    #[must_use]
    pub fn dialect(&self) -> Dialect {
        self.dialect
    }

    /// The connection string itself.
    ///
    /// The only legitimate caller is an adapter building driver connect options. The
    /// name is deliberately conspicuous: `rg expose_secret` lists every site that
    /// reads a secret back.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.secret.expose_secret()
    }
}

impl TryFrom<String> for Dsn {
    type Error = DsnError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(DsnError::Empty);
        }
        if value.len() > MAX_DSN_LEN {
            return Err(DsnError::TooLong {
                actual: value.len(),
                limit: MAX_DSN_LEN,
            });
        }

        let (scheme, _rest) = value.split_once("://").ok_or(DsnError::MissingScheme)?;
        if scheme.len() > MAX_SCHEME_LEN || !is_url_scheme(scheme) {
            return Err(DsnError::MalformedScheme);
        }

        // Both spellings are standard URL schemes and both are what operators paste,
        // so both are accepted here. This is not the same question as `Dialect`'s
        // configuration keyword, which accepts only `postgresql` so that one setting
        // cannot drift into two spellings.
        let dialect = match scheme {
            "mysql" => Dialect::MySql,
            "postgres" | "postgresql" => Dialect::PostgreSql,
            _ => {
                return Err(DsnError::UnsupportedScheme);
            }
        };

        Ok(Self {
            dialect,
            secret: SecretString::from(value),
        })
    }
}

impl FromStr for Dsn {
    type Err = DsnError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::try_from(value.to_owned())
    }
}

/// Prints the dialect and nothing else.
///
/// Hand-written rather than derived: a derived `Debug` would still be safe today
/// because `SecretString` redacts itself, but it would silently start printing any
/// future field, and this type exists to have exactly one read-back.
impl fmt::Debug for Dsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dsn")
            .field("dialect", &self.dialect.as_str())
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// RFC 3986 section 3.1: `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`.
fn is_url_scheme(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && characters.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    const MYSQL: &str = "mysql://warden:hunter2@db-01.internal:3306/app";
    const POSTGRES: &str = "postgresql://warden:hunter2@db-02.internal:5432/analytics";

    #[test]
    fn a_scheme_selects_the_dialect_and_the_string_survives_intact() {
        assert_eq!(MYSQL.parse::<Dsn>().unwrap().dialect(), Dialect::MySql);
        assert_eq!(
            POSTGRES.parse::<Dsn>().unwrap().dialect(),
            Dialect::PostgreSql
        );
        // The alias `postgres://` is accepted here even though `Dialect`'s
        // configuration keyword rejects it; both are standard URL schemes.
        assert_eq!(
            "postgres://u@h/db".parse::<Dsn>().unwrap().dialect(),
            Dialect::PostgreSql
        );
        assert_eq!(MYSQL.parse::<Dsn>().unwrap().expose_secret(), MYSQL);
    }

    #[test]
    fn debug_prints_the_dialect_and_never_the_credentials() {
        let rendered = format!("{:?}", MYSQL.parse::<Dsn>().unwrap());
        assert!(rendered.contains("mysql"), "{rendered}");
        assert!(rendered.contains("REDACTED"), "{rendered}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains("db-01.internal"), "{rendered}");
    }

    #[test]
    fn every_rejection_reports_a_reason_without_quoting_the_input() {
        // `unwrap_err` rather than comparing the whole `Result`: `Dsn` implements no
        // `PartialEq`, deliberately — comparing two secrets byte by byte is not an
        // operation this type wants to make convenient.
        assert_eq!("".parse::<Dsn>().unwrap_err(), DsnError::Empty);
        assert_eq!(
            "warden:hunter2@h/db".parse::<Dsn>().unwrap_err(),
            DsnError::MissingScheme
        );
        assert_eq!(
            "1mysql://warden:hunter2@h/db".parse::<Dsn>().unwrap_err(),
            DsnError::MalformedScheme
        );
        assert_eq!(
            "redis://warden:hunter2@h/db".parse::<Dsn>().unwrap_err(),
            DsnError::UnsupportedScheme
        );

        let long = format!("mysql://{}", "a".repeat(MAX_DSN_LEN));
        assert_eq!(
            long.parse::<Dsn>().unwrap_err(),
            DsnError::TooLong {
                actual: long.len(),
                limit: MAX_DSN_LEN,
            }
        );

        for error in [
            DsnError::Empty,
            DsnError::MissingScheme,
            DsnError::MalformedScheme,
            DsnError::UnsupportedScheme,
        ] {
            let rendered = error.to_string();
            assert!(!rendered.contains("hunter2"), "{rendered}");
            assert!(!rendered.contains("db-01.internal"), "{rendered}");
        }
    }

    #[test]
    fn an_unsupported_scheme_cannot_echo_a_secret_like_prefix() {
        let input = "hunter2://db.internal/app";
        let error = input.parse::<Dsn>().unwrap_err();
        assert_eq!(error, DsnError::UnsupportedScheme);
        assert!(
            !error.to_string().contains("hunter2"),
            "{error} leaked the unsupported scheme"
        );
    }

    #[test]
    fn an_overlong_prefix_cannot_smuggle_a_password_into_the_error() {
        // Without the length bound, a value whose first `://` is far into the string
        // would put everything before it into `UnsupportedScheme`.
        let smuggled = format!("{}://h/db", "a".repeat(MAX_SCHEME_LEN + 1));
        assert_eq!(
            smuggled.parse::<Dsn>().unwrap_err(),
            DsnError::MalformedScheme
        );
    }
}
