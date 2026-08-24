//! The DSN, and the single place it can be read back.
//!
//! # A DSN is a complete connection target, and nothing else
//!
//! [`Dsn`] parses and validates the whole connection string at construction: the
//! scheme names a dialect, and the authority names a TCP host, a user, and a
//! database. A query string or a fragment is refused outright (ADR-0031), so an
//! operator cannot paste `?sslmode=disable`, `?options=-c row_security%3Doff`, or
//! `?socket=…` and quietly overrule the settings Warden decided. Every connection
//! setting comes from configuration; the DSN carries only where to connect and as
//! whom.
//!
//! Because the target is parsed here, no adapter hands a connection string to a
//! driver's own URL parser. That matters most for PostgreSQL, whose parser seeds
//! itself from `PG*` environment variables and `~/.pgpass` and logs what it does not
//! recognize — including passwords — before any hardening call can run. Both
//! adapters instead set every field explicitly from the accessors below.
//!
//! # Why this is not an ordinary validated newtype
//!
//! `AGENTS.md` asks a validated newtype for `TryFrom<String>`, `FromStr`, `Display`
//! and `AsRef<str>`. [`Dsn`] implements the first two and deliberately implements
//! neither of the last two: `Display` is what puts a password into `tracing::info!`
//! and `AsRef<str>` is what lets it be handed to anything expecting a string.
//! ADR-0019 governs a secret and takes precedence over the identifier rule, so the
//! only read-back is [`Dsn::expose_password`] — one conspicuous name, greppable
//! across the repository. The host, port, user and database are not secrets and have
//! ordinary accessors. The connection string itself is never handed back: it is
//! consumed during validation and zeroized there.
//!
//! # What the zeroization actually covers
//!
//! The string a `Dsn` is built from is wrapped in `secrecy::SecretString` for the
//! length of the parse and zeroed when it drops, and the password it parsed out is
//! held the same way for the `Dsn`'s life. The drivers are a different matter:
//! `MySqlConnectOptions` and `PgConnectOptions` hold the password in a plain
//! `String`, and a pool keeps an `Arc` of its connect options for its whole
//! lifetime. This type bounds how long Warden's own configuration path holds the
//! secret; it does not bound SQLx.

use std::fmt;
use std::str::FromStr;

use percent_encoding::percent_decode_str;
use secrecy::{ExposeSecret, SecretString};
use url::Url;

use crate::dialect::Dialect;

/// Longest accepted DSN.
///
/// Generous enough for a hostname, credentials and a database name, small enough
/// that a pasted file cannot become a connection string.
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
    /// The value was not a URL, or one of its fields was not valid UTF-8.
    #[error("the DSN is not a valid URL")]
    MalformedUrl,
    /// The value carried a query string or a fragment.
    ///
    /// Both drivers read connection settings out of the query string — TLS mode,
    /// certificate paths, statement-cache capacity, PostgreSQL startup options, a
    /// Unix socket path — so a DSN that carries one is a second, unreviewed source
    /// of connection policy (ADR-0031).
    #[error(
        "the DSN carries a query string or fragment; connection settings come from \
         Warden's configuration, and the DSN names only the target"
    )]
    UnsupportedParameter,
    /// The authority named no host Warden can dial.
    #[error(
        "the DSN names no usable host; a host name or IP address is required, and a \
         Unix socket path is not supported"
    )]
    UnsupportedHost,
    /// The authority named no user.
    ///
    /// Both drivers substitute one when the DSN omits it — MySQL uses `root` and
    /// PostgreSQL the operating-system user — so an omitted user is a connection
    /// whose identity nobody chose (ADR-0016).
    #[error("the DSN names no user")]
    MissingUsername,
    /// The path named no database.
    ///
    /// `docs/security.md` section 5.1 requires an explicit database: it is the
    /// MySQL counterpart of a fixed `search_path`, and PostgreSQL would otherwise
    /// fall back to `PGDATABASE` or to the user's name.
    #[error("the DSN names no database")]
    MissingDatabase,
}

/// A validated database connection target, with its credentials still secret.
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
    host: String,
    port: Option<u16>,
    username: String,
    password: Option<SecretString>,
    database: String,
}

impl Dsn {
    /// The dialect this DSN's scheme names.
    ///
    /// SQLx does **not** check the scheme: `MySqlConnectOptions::from_str` parses a
    /// `postgres://` URL without complaint and would then point the MySQL protocol at
    /// a PostgreSQL port. Each adapter compares this value against its own dialect
    /// before it builds anything.
    #[must_use]
    pub fn dialect(&self) -> Dialect {
        self.dialect
    }

    /// The host to dial, percent-decoded.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port the DSN named, if it named one.
    ///
    /// The default belongs to the adapter, which is the only place that knows its
    /// dialect's port.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// The user to authenticate as, percent-decoded.
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    /// The database to connect to, percent-decoded.
    #[must_use]
    pub fn database(&self) -> &str {
        &self.database
    }

    /// The password, percent-decoded, if the DSN carried one.
    ///
    /// The only legitimate caller is an adapter building driver connect options. The
    /// name is deliberately conspicuous: `rg expose_` lists every site that reads a
    /// secret back.
    #[must_use]
    pub fn expose_password(&self) -> Option<&str> {
        self.password.as_ref().map(ExposeSecret::expose_secret)
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

        // The scheme is checked before `Url::parse` so that a malformed value is
        // rejected by the most specific rule it breaks, and so that the bounded
        // prefix — not arbitrary DSN bytes — is what the scheme errors describe.
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
            _ => return Err(DsnError::UnsupportedScheme),
        };

        // From here the string is a secret with a bounded life: it is zeroized when
        // this function returns, whether it returns a `Dsn` or an error.
        let value = SecretString::from(value);
        let url = Url::parse(value.expose_secret()).map_err(|_error| DsnError::MalformedUrl)?;
        if url.query().is_some() || url.fragment().is_some() {
            return Err(DsnError::UnsupportedParameter);
        }

        // `mysql` and `postgres` are not special schemes, so the host is opaque: the
        // URL parser neither lowercases nor percent-decodes it, and both drivers
        // read a leading slash as a Unix socket directory. Requiring the decoded and
        // raw forms to agree keeps that path unreachable and keeps this crate's view
        // of the host identical to the one `MySqlConnectOptions::from_str` builds.
        let host = url.host_str().ok_or(DsnError::UnsupportedHost)?;
        let decoded_host = decode(host)?;
        if decoded_host.is_empty() || decoded_host != host {
            return Err(DsnError::UnsupportedHost);
        }

        let username = decode(url.username())?;
        if username.is_empty() {
            return Err(DsnError::MissingUsername);
        }

        let database = decode(url.path().trim_start_matches('/'))?;
        if database.is_empty() {
            return Err(DsnError::MissingDatabase);
        }

        let password = match url.password() {
            Some(password) => Some(SecretString::from(decode(password)?)),
            None => None,
        };

        Ok(Self {
            dialect,
            host: decoded_host,
            port: url.port(),
            username,
            password,
            database,
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
/// Hand-written rather than derived: a derived `Debug` would still redact the
/// secret fields, but it would print the host, the user and the database, and it
/// would silently start printing any future field. This type exists to have exactly
/// one shape in a log line.
impl fmt::Debug for Dsn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dsn")
            .field("dialect", &self.dialect.as_str())
            .field("target", &"[REDACTED]")
            .finish()
    }
}

/// Percent-decodes one URL field, rejecting a sequence that is not UTF-8.
fn decode(value: &str) -> Result<String, DsnError> {
    percent_decode_str(value)
        .decode_utf8()
        .map(|decoded| decoded.into_owned())
        .map_err(|_error| DsnError::MalformedUrl)
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
    fn a_scheme_selects_the_dialect() {
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
    }

    #[test]
    fn the_target_is_parsed_once_and_read_back_field_by_field() {
        let dsn = POSTGRES.parse::<Dsn>().unwrap();
        assert_eq!(dsn.host(), "db-02.internal");
        assert_eq!(dsn.port(), Some(5432));
        assert_eq!(dsn.username(), "warden");
        assert_eq!(dsn.expose_password(), Some("hunter2"));
        assert_eq!(dsn.database(), "analytics");
    }

    #[test]
    fn an_omitted_port_and_password_stay_the_adapters_decision() {
        let dsn = "mysql://warden@db-01.internal/app".parse::<Dsn>().unwrap();
        assert_eq!(dsn.port(), None);
        assert_eq!(dsn.expose_password(), None);
    }

    #[test]
    fn credentials_are_percent_decoded_exactly_once() {
        // `p%40ss` is the password `p@ss`; without decoding, the driver would
        // authenticate with the literal escape and the operator would see a login
        // failure with no explanation.
        let dsn = "mysql://war%64en:p%40ss@db-01.internal/re%70orting"
            .parse::<Dsn>()
            .unwrap();
        assert_eq!(dsn.username(), "warden");
        assert_eq!(dsn.expose_password(), Some("p@ss"));
        assert_eq!(dsn.database(), "reporting");
    }

    #[test]
    fn debug_prints_the_dialect_and_never_the_target() {
        let rendered = format!("{:?}", MYSQL.parse::<Dsn>().unwrap());
        assert!(rendered.contains("mysql"), "{rendered}");
        assert!(rendered.contains("REDACTED"), "{rendered}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains("db-01.internal"), "{rendered}");
        assert!(!rendered.contains("warden"), "{rendered}");
        assert!(!rendered.contains("app"), "{rendered}");
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
        assert_eq!(
            "mysql://warden:hunter2@h:99999/db"
                .parse::<Dsn>()
                .unwrap_err(),
            DsnError::MalformedUrl
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
            DsnError::MalformedUrl,
            DsnError::UnsupportedParameter,
            DsnError::UnsupportedHost,
            DsnError::MissingUsername,
            DsnError::MissingDatabase,
        ] {
            let rendered = error.to_string();
            assert!(!rendered.contains("hunter2"), "{rendered}");
            assert!(!rendered.contains("db-01.internal"), "{rendered}");
        }
    }

    #[test]
    fn a_dsn_that_carries_connection_settings_is_refused() {
        // Every one of these is a setting one of the two drivers honours out of the
        // query string, and every one of them is a setting Warden decides itself.
        for parameter in [
            "?sslmode=disable",
            "?ssl-mode=disabled",
            "?sslrootcert=/tmp/attacker.pem",
            "?ssl-ca=/tmp/attacker.pem",
            "?sslcert=/tmp/client.pem",
            "?sslkey=/tmp/client.key",
            "?statement-cache-capacity=100",
            "?options=-c%20row_security%3Doff",
            "?socket=/tmp/mysql.sock",
            "?dbname=other",
            "?anything=at-all",
            "?",
            "#fragment",
        ] {
            let raw = format!("postgres://warden:hunter2@h:5432/app{parameter}");
            let error = raw.parse::<Dsn>().unwrap_err();
            assert_eq!(error, DsnError::UnsupportedParameter, "{parameter}");
            assert!(!error.to_string().contains("hunter2"), "{parameter}");
        }
    }

    #[test]
    fn a_dsn_must_name_a_host_a_user_and_a_database() {
        assert_eq!(
            "mysql://warden:hunter2@h:3306".parse::<Dsn>().unwrap_err(),
            DsnError::MissingDatabase
        );
        assert_eq!(
            "mysql://warden:hunter2@h:3306/".parse::<Dsn>().unwrap_err(),
            DsnError::MissingDatabase
        );
        // Both spellings of an omitted user: no `@` at all, and an empty user
        // before one. MySQL would connect as `root` and PostgreSQL as the operating
        // system user, so neither may reach the driver.
        assert_eq!(
            "mysql://db-01.internal:3306/app"
                .parse::<Dsn>()
                .unwrap_err(),
            DsnError::MissingUsername
        );
        assert_eq!(
            "mysql://@db-01.internal:3306/app"
                .parse::<Dsn>()
                .unwrap_err(),
            DsnError::MissingUsername
        );
        assert_eq!(
            "mysql:///app".parse::<Dsn>().unwrap_err(),
            DsnError::UnsupportedHost
        );
    }

    #[test]
    fn a_unix_socket_host_is_refused_rather_than_dialed() {
        // `%2Fvar%2Frun%2Fpostgresql` is how libpq-compatible tooling spells a socket
        // directory in a URL, and both drivers act on the leading slash. Warden
        // connects over TCP so that its TLS policy means something.
        assert_eq!(
            "postgres://warden@%2Fvar%2Frun%2Fpostgresql/app"
                .parse::<Dsn>()
                .unwrap_err(),
            DsnError::UnsupportedHost
        );
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
