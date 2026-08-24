//! The one place a DSN becomes PostgreSQL connect options.
//!
//! Warden applies values after parsing the DSN. SQLx appends `options`, so the last
//! `-c` assignment wins over a hostile DSN assignment.

use std::str::FromStr;
use std::time::Duration;

use sqlx::ConnectOptions;
use sqlx::postgres::{PgConnectOptions, PgSslMode};
use warden_core::dialect::Dialect;
use warden_core::secret::Dsn;
use warden_core::tls::{TlsMode, TlsSettings};

use crate::connection::SearchPath;
use crate::error::ConnectError;

/// Reported to `pg_stat_activity`, so a DBA can attribute a session to Warden.
pub(crate) const APPLICATION_NAME: &str = "warden";
/// How long an open transaction may be idle before the server ends it.
pub(crate) const IDLE_IN_TRANSACTION_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a statement may wait for a lock.
pub(crate) const LOCK_TIMEOUT: Duration = Duration::from_secs(1);

/// Which of a connection's two pools the options are for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PoolRole {
    Agent,
    Control,
}

/// Startup settings Warden pins and later verifies through `pg_settings`.
pub(crate) fn expected_settings(
    statement_timeout: Duration,
    search_path: &SearchPath,
) -> [(&'static str, String); 5] {
    [
        ("statement_timeout", millis(statement_timeout)),
        (
            "idle_in_transaction_session_timeout",
            millis(IDLE_IN_TRANSACTION_TIMEOUT),
        ),
        ("lock_timeout", millis(LOCK_TIMEOUT)),
        ("default_transaction_read_only", "on".to_owned()),
        ("search_path", search_path.as_option_value().to_owned()),
    ]
}

/// Builds hardened connect options for one pool.
pub(crate) fn connect_options(
    dsn: &Dsn,
    tls: &TlsSettings,
    search_path: &SearchPath,
    statement_timeout: Duration,
    role: PoolRole,
) -> Result<PgConnectOptions, ConnectError> {
    if dsn.dialect() != Dialect::PostgreSql {
        return Err(ConnectError::DialectMismatch {
            actual: dsn.dialect(),
        });
    }
    if !dsn_has_database_path(dsn) {
        return Err(ConnectError::MissingDatabase);
    }
    let parsed = PgConnectOptions::from_str(dsn.expose_secret())
        .map_err(|_error| ConnectError::InvalidDsn)?;
    if parsed.get_database().is_none() {
        return Err(ConnectError::MissingDatabase);
    }
    let mut options = parsed
        .ssl_mode(ssl_mode(tls.mode))
        .application_name(APPLICATION_NAME)
        .disable_statement_logging()
        .options(expected_settings(statement_timeout, search_path));
    if let Some(root) = &tls.root_certificate {
        options = options.ssl_root_cert(root);
    }
    Ok(match role {
        PoolRole::Agent => options.statement_cache_capacity(0),
        PoolRole::Control => options,
    })
}

/// Whether the bounded raw DSN itself contains a non-empty database path.
///
/// SQLx seeds PostgreSQL options from environment variables before overlaying URL
/// fields, so its `get_database` result cannot distinguish `/analytics` from an
/// ambient `PGDATABASE`. `Dsn` already validates and bounds the URL-like input;
/// this deliberately small check only identifies the path delimiter and ignores
/// query and fragment text rather than introducing a second URL parser.
fn dsn_has_database_path(dsn: &Dsn) -> bool {
    let Some((_, remainder)) = dsn.expose_secret().split_once("://") else {
        return false;
    };
    let before_query = remainder.split('?').next().unwrap_or(remainder);
    let before_fragment = before_query.split('#').next().unwrap_or(before_query);
    let Some((_, path)) = before_fragment.split_once('/') else {
        return false;
    };
    !path.is_empty()
}

/// Converts a deadline to PostgreSQL milliseconds, never zero.
fn millis(value: Duration) -> String {
    u128::max(value.as_millis(), 1).to_string()
}

/// Maps Warden's TLS policy onto the driver's mode exhaustively.
fn ssl_mode(mode: TlsMode) -> PgSslMode {
    match mode {
        TlsMode::Disabled => PgSslMode::Disable,
        TlsMode::Required => PgSslMode::Require,
        TlsMode::VerifyCa => PgSslMode::VerifyCa,
        TlsMode::VerifyIdentity => PgSslMode::VerifyFull,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]
    use std::process::Command;

    use super::*;

    fn dsn(raw: &str) -> Dsn {
        raw.parse().unwrap()
    }
    fn search_path() -> SearchPath {
        SearchPath::new(["app", "public"]).unwrap()
    }
    fn options(raw: &str, tls: TlsSettings) -> PgConnectOptions {
        connect_options(
            &dsn(raw),
            &tls,
            &search_path(),
            Duration::from_secs(5),
            PoolRole::Agent,
        )
        .unwrap()
    }

    fn local_is_mut_options(local: &syn::Local) -> bool {
        matches!(
            &local.pat,
            syn::Pat::Ident(identifier)
                if identifier.ident == "options" && identifier.mutability.is_some()
        )
    }

    fn connect_options_logging_is_disabled(source: &str) -> Result<(), String> {
        let file = syn::parse_file(source).map_err(|error| error.to_string())?;
        let functions: Vec<_> = file
            .items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Fn(function) if function.sig.ident == "connect_options" => {
                    Some(function)
                }
                _ => None,
            })
            .collect();
        let [function] = functions.as_slice() else {
            return Err("expected exactly one production connect_options function".to_owned());
        };

        let locals: Vec<_> = function
            .block
            .stmts
            .iter()
            .filter_map(|statement| match statement {
                syn::Stmt::Local(local) if local_is_mut_options(local) => Some(local),
                _ => None,
            })
            .collect();
        let [options] = locals.as_slice() else {
            return Err("expected exactly one top-level `let mut options`".to_owned());
        };
        let mut expression = options
            .init
            .as_ref()
            .map(|initializer| initializer.expr.as_ref())
            .ok_or_else(|| "`let mut options` needs an initializer".to_owned())?;

        let mut disable_calls = 0_usize;
        while let syn::Expr::MethodCall(method_call) = expression {
            if method_call.method == "disable_statement_logging" {
                disable_calls += 1;
            }
            expression = method_call.receiver.as_ref();
        }
        if disable_calls == 1 {
            Ok(())
        } else {
            Err(format!(
                "the direct `let mut options` method chain calls disable_statement_logging {disable_calls} times"
            ))
        }
    }

    #[test]
    fn a_mysql_dsn_is_refused_before_the_driver_sees_it() {
        assert_eq!(
            connect_options(
                &dsn("mysql://warden:pw@h:3306/app"),
                &TlsSettings::default(),
                &search_path(),
                Duration::from_secs(5),
                PoolRole::Agent
            )
            .unwrap_err(),
            ConnectError::DialectMismatch {
                actual: Dialect::MySql
            }
        );
    }
    #[test]
    fn a_dsn_without_a_database_is_refused() {
        assert_eq!(
            connect_options(
                &dsn("postgres://warden:pw@h:5432"),
                &TlsSettings::default(),
                &search_path(),
                Duration::from_secs(5),
                PoolRole::Agent
            )
            .unwrap_err(),
            ConnectError::MissingDatabase
        );
    }

    #[test]
    fn a_dsn_without_a_path_is_not_filled_from_pgdatabase() {
        const CHILD_MARKER: &str = "WARDEN_POSTGRES_OPTIONS_PGDATABASE_CHILD";
        const TEST_NAME: &str =
            "options::tests::a_dsn_without_a_path_is_not_filled_from_pgdatabase";

        if std::env::var_os(CHILD_MARKER).is_some() {
            assert_eq!(
                connect_options(
                    &dsn("postgres://warden:pw@h:5432"),
                    &TlsSettings::default(),
                    &search_path(),
                    Duration::from_secs(5),
                    PoolRole::Agent,
                )
                .unwrap_err(),
                ConnectError::MissingDatabase
            );
            return;
        }

        let executable = std::env::current_exe().expect("test executable path");
        let status = Command::new(executable)
            .arg("--exact")
            .arg(TEST_NAME)
            .arg("--nocapture")
            .env(CHILD_MARKER, "1")
            .env("PGDATABASE", "shadow_database")
            .status()
            .expect("run isolated PGDATABASE regression child");
        assert!(status.success(), "the child test failed: {status}");
    }

    #[test]
    fn a_database_named_only_in_query_or_fragment_is_refused() {
        assert_eq!(
            connect_options(
                &dsn("postgres://warden:pw@h:5432/?dbname=shadow_database#analytics"),
                &TlsSettings::default(),
                &search_path(),
                Duration::from_secs(5),
                PoolRole::Agent,
            )
            .unwrap_err(),
            ConnectError::MissingDatabase
        );
    }
    #[test]
    fn a_dsn_cannot_downgrade_tls() {
        assert!(matches!(
            options(
                "postgres://warden:pw@h:5432/app?sslmode=disable",
                TlsSettings::default()
            )
            .get_ssl_mode(),
            PgSslMode::VerifyFull
        ));
    }

    #[test]
    fn connect_options_disables_driver_statement_logging_once() {
        connect_options_logging_is_disabled(include_str!("options.rs")).unwrap();
    }

    #[test]
    fn statement_logging_guard_accepts_a_direct_method_chain() {
        let fixture = r#"
            fn connect_options() {
                let mut options = parsed.ssl_mode(mode).disable_statement_logging();
            }
        "#;
        connect_options_logging_is_disabled(fixture).unwrap();
    }

    #[test]
    fn statement_logging_guard_rejects_comments_strings_and_dead_code() {
        let fixture = r#"
            fn connect_options() {
                // .disable_statement_logging()
                let message = ".disable_statement_logging()";
                let mut options = if false {
                    parsed.disable_statement_logging()
                } else {
                    parsed
                };
            }
        "#;
        assert!(connect_options_logging_is_disabled(fixture).is_err());
    }
    #[test]
    fn wardens_startup_options_are_written_after_the_dsns_own() {
        let built = options(
            "postgres://warden:pw@h:5432/app?options=-c%20statement_timeout%3D0",
            TlsSettings::default(),
        );
        let rendered = built.get_options().unwrap_or_default();
        let hostile = rendered.find("statement_timeout=0").expect("DSN option");
        let ours = rendered
            .rfind("statement_timeout=5000")
            .expect("Warden option");
        assert!(hostile < ours, "{rendered:?}");
        for setting in [
            "idle_in_transaction_session_timeout=10000",
            "lock_timeout=1000",
            "default_transaction_read_only=on",
            "search_path=app,public",
        ] {
            assert!(
                rendered.contains(setting),
                "{setting} missing: {rendered:?}"
            );
        }
    }
    #[test]
    fn every_tls_mode_maps_to_the_drivers_equivalent() {
        for mode in [
            TlsMode::Disabled,
            TlsMode::Required,
            TlsMode::VerifyCa,
            TlsMode::VerifyIdentity,
        ] {
            let built = options(
                "postgres://warden:pw@h:5432/app",
                TlsSettings {
                    mode,
                    root_certificate: None,
                },
            );
            match (mode, built.get_ssl_mode()) {
                (TlsMode::Disabled, PgSslMode::Disable)
                | (TlsMode::Required, PgSslMode::Require)
                | (TlsMode::VerifyCa, PgSslMode::VerifyCa)
                | (TlsMode::VerifyIdentity, PgSslMode::VerifyFull) => {}
                _ => panic!("TLS mode did not map to the driver's equivalent"),
            }
        }
        assert!(matches!(PgSslMode::default(), PgSslMode::Prefer));
    }
    #[test]
    fn a_sub_millisecond_deadline_never_becomes_no_deadline() {
        assert_eq!(millis(Duration::from_secs(5)), "5000");
        assert_eq!(millis(Duration::from_nanos(1)), "1");
    }
}
