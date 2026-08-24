//! The one place a DSN becomes MySQL connect options.
//!
//! # Everything is applied after the parse
//!
//! `MySqlConnectOptions::from_str` honours `?ssl-mode=` and
//! `?statement-cache-capacity=` from the DSN. Hardening applied before the parse
//! would therefore be silently overwritten by whatever an operator pasted, and the
//! deployment would look configured while running with the driver's own weaker
//! choices. Every call below runs on the parsed value.
//!
//! # What is decided here rather than inherited
//!
//! * **TLS mode**, always, because `MySqlSslMode` defaults to `Preferred`, which
//!   falls back to cleartext when the server declines (ADR-0030).
//! * **Statement logging**, off, because `LogSettings::default()` logs every
//!   statement at `DEBUG` and every statement slower than a second at `WARN`,
//!   through `tracing`, with the SQL in a `db.statement` field. That is SPEC section
//!   6, invariant 22 violated by a default nobody wrote down.
//! * **The statement cache**, zero on the agent pool, because agent SQL is an
//!   unbounded variety of one-off statements. MySQL needs only this: `sqlx-mysql`
//!   sends `StmtClose` unconditionally on the uncached path, so nothing accumulates
//!   server-side (`docs/operations.md` section 4). PostgreSQL is different and needs
//!   a second control.

use std::str::FromStr;

use sqlx::ConnectOptions;
use sqlx::mysql::{MySqlConnectOptions, MySqlSslMode};
use warden_core::dialect::Dialect;
use warden_core::secret::Dsn;
use warden_core::tls::{TlsMode, TlsSettings};

use crate::error::ConnectError;

/// Which of a connection's two pools the options are for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PoolRole {
    /// Agent SQL and `EXPLAIN`: an unbounded variety of one-off statements.
    Agent,
    /// Warden's own static SQL: health checks and schema introspection.
    Control,
}

/// Builds hardened connect options for one pool.
pub(crate) fn connect_options(
    dsn: &Dsn,
    tls: &TlsSettings,
    role: PoolRole,
) -> Result<MySqlConnectOptions, ConnectError> {
    if dsn.dialect() != Dialect::MySql {
        return Err(ConnectError::DialectMismatch {
            actual: dsn.dialect(),
        });
    }

    let parsed =
        MySqlConnectOptions::from_str(dsn.expose_secret()).map_err(|_| ConnectError::InvalidDsn)?;

    if parsed.get_database().is_none() {
        return Err(ConnectError::MissingDatabase);
    }

    let mut options = parsed
        .ssl_mode(ssl_mode(tls.mode))
        .disable_statement_logging();

    if let Some(root) = &tls.root_certificate {
        options = options.ssl_ca(root);
    }

    Ok(match role {
        PoolRole::Agent => options.statement_cache_capacity(0),
        PoolRole::Control => options,
    })
}

/// Maps Warden's TLS policy onto the driver's mode.
///
/// Exhaustive on purpose: a new `TlsMode` variant must break this build rather than
/// fall through a wildcard into something weaker (ADR-0030).
fn ssl_mode(mode: TlsMode) -> MySqlSslMode {
    match mode {
        TlsMode::Disabled => MySqlSslMode::Disabled,
        TlsMode::Required => MySqlSslMode::Required,
        TlsMode::VerifyCa => MySqlSslMode::VerifyCa,
        TlsMode::VerifyIdentity => MySqlSslMode::VerifyIdentity,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use sqlx::mysql::MySqlSslMode;
    use warden_core::dialect::Dialect;
    use warden_core::secret::Dsn;
    use warden_core::tls::{TlsMode, TlsSettings};

    use crate::error::ConnectError;

    fn dsn(raw: &str) -> Dsn {
        raw.parse().unwrap()
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
    fn a_postgres_dsn_is_refused_before_the_driver_sees_it() {
        let error = connect_options(
            &dsn("postgres://warden:pw@h:5432/app"),
            &TlsSettings::default(),
            PoolRole::Agent,
        )
        .unwrap_err();
        assert_eq!(
            error,
            ConnectError::DialectMismatch {
                actual: Dialect::PostgreSql
            }
        );
    }

    #[test]
    fn a_dsn_without_a_database_is_refused() {
        let error = connect_options(
            &dsn("mysql://warden:pw@h:3306"),
            &TlsSettings::default(),
            PoolRole::Agent,
        )
        .unwrap_err();
        assert_eq!(error, ConnectError::MissingDatabase);
    }

    #[test]
    fn a_dsn_cannot_downgrade_tls() {
        let options = connect_options(
            &dsn("mysql://warden:pw@h:3306/app?ssl-mode=disabled"),
            &TlsSettings::default(),
            PoolRole::Agent,
        )
        .unwrap();
        assert!(matches!(
            options.get_ssl_mode(),
            MySqlSslMode::VerifyIdentity
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
    fn every_tls_mode_maps_to_the_drivers_equivalent() {
        for mode in [
            TlsMode::Disabled,
            TlsMode::Required,
            TlsMode::VerifyCa,
            TlsMode::VerifyIdentity,
        ] {
            let options = connect_options(
                &dsn("mysql://warden:pw@h:3306/app"),
                &TlsSettings {
                    mode,
                    root_certificate: None,
                },
                PoolRole::Control,
            )
            .unwrap();
            match (mode, options.get_ssl_mode()) {
                (TlsMode::Disabled, MySqlSslMode::Disabled)
                | (TlsMode::Required, MySqlSslMode::Required)
                | (TlsMode::VerifyCa, MySqlSslMode::VerifyCa)
                | (TlsMode::VerifyIdentity, MySqlSslMode::VerifyIdentity) => {}
                _ => panic!("TLS mode did not map to the driver's equivalent"),
            }
        }
        assert!(matches!(MySqlSslMode::default(), MySqlSslMode::Preferred));
    }

    #[test]
    fn an_unparseable_dsn_reports_no_part_of_itself() {
        let error = connect_options(
            &dsn("mysql://warden:hunter2@db-01.internal:not-a-port/app"),
            &TlsSettings::default(),
            PoolRole::Agent,
        )
        .unwrap_err();
        assert_eq!(error, ConnectError::InvalidDsn);
        let rendered = error.to_string();
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains("db-01.internal"), "{rendered}");
    }
}
