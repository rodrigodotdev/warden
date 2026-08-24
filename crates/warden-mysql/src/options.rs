//! The one place a DSN becomes MySQL connect options.
//!
//! # Every field is set, none is parsed out of a string
//!
//! `MySqlConnectOptions::from_str` would parse the DSN again, and its parser honours
//! `?ssl-mode=`, `?ssl-ca=`, `?sslcert=`, `?sslkey=`, `?socket=`,
//! `?statement-cache-capacity=`, `?charset=` and `?timezone=` — eight settings
//! Warden decides itself. [`Dsn`] already refuses a DSN that carries any of them
//! (ADR-0031), so the parser would have nothing left to do; setting each field from
//! the validated target instead removes the question entirely, and keeps this
//! adapter shaped like `warden-postgres`, where the driver's parser is unusable for
//! stronger reasons.
//!
//! `MySqlConnectOptions::new()` supplies the rest of the driver's defaults, none of
//! which is read from the environment. The three it supplies that matter — host
//! `localhost`, user `root`, and no database — are all overwritten below, and `Dsn`
//! guarantees the values to overwrite them with.
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

use sqlx::ConnectOptions;
use sqlx::mysql::{MySqlConnectOptions, MySqlSslMode};
use warden_core::dialect::Dialect;
use warden_core::secret::Dsn;
use warden_core::tls::{TlsMode, TlsSettings};

use crate::error::ConnectError;

/// The port used when the DSN names none.
pub(crate) const DEFAULT_PORT: u16 = 3306;

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
    Ok(hardened_options(dsn, tls, role))
}

/// Applies every hardening decision to one pool's options.
///
/// Split from [`connect_options`] so the settings can be asserted without a
/// `Result` in the way of every assertion.
fn hardened_options(dsn: &Dsn, tls: &TlsSettings, role: PoolRole) -> MySqlConnectOptions {
    let mut options = MySqlConnectOptions::new()
        .host(dsn.host())
        .port(dsn.port().unwrap_or(DEFAULT_PORT))
        .username(dsn.username())
        .database(dsn.database())
        .ssl_mode(ssl_mode(tls.mode))
        .disable_statement_logging();

    if let Some(password) = dsn.expose_password() {
        options = options.password(password);
    }
    if let Some(root) = &tls.root_certificate {
        options = options.ssl_ca(root);
    }

    match role {
        PoolRole::Agent => options.statement_cache_capacity(0),
        PoolRole::Control => options,
    }
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

    use syn::visit::Visit;

    use super::*;

    /// Constructors that would put the driver's own URL parser back on the path to a
    /// connection, where the DSN's query string would decide eight settings again.
    const FORBIDDEN_CALLS: &[&str] = &[
        "MySqlConnectOptions::from_str",
        "MySqlConnectOptions::from_url",
        "parse_from_url",
    ];

    fn dsn(raw: &str) -> Dsn {
        raw.parse().unwrap()
    }

    fn options(raw: &str, tls: TlsSettings) -> MySqlConnectOptions {
        hardened_options(&dsn(raw), &tls, PoolRole::Agent)
    }

    /// Collects every called function and method name in the production code.
    #[derive(Default)]
    struct CalledNames(Vec<String>);

    impl<'ast> Visit<'ast> for CalledNames {
        fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
            self.0.push(node.method.to_string());
            syn::visit::visit_expr_method_call(self, node);
        }

        fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = node.func.as_ref() {
                let name: Vec<String> = path
                    .path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect();
                self.0.push(name.join("::"));
            }
            syn::visit::visit_expr_call(self, node);
        }
    }

    /// The production items of this file, with the test module removed.
    fn production_items(source: &str) -> Vec<syn::Item> {
        let file = syn::parse_file(source).expect("this file must parse");
        file.items
            .into_iter()
            .filter(|item| !matches!(item, syn::Item::Mod(module) if module.ident == "tests"))
            .collect()
    }

    /// Every call the production code makes, resolved through the AST rather than
    /// through the text, so a comment or a string literal cannot satisfy or trip it.
    fn production_calls(source: &str) -> Vec<String> {
        let mut calls = CalledNames::default();
        for item in production_items(source) {
            calls.visit_item(&item);
        }
        calls.0
    }

    /// Checks the single hardening chain: where it starts and what it must contain.
    fn hardening_chain(source: &str) -> Result<Vec<String>, String> {
        let functions: Vec<syn::ItemFn> = production_items(source)
            .into_iter()
            .filter_map(|item| match item {
                syn::Item::Fn(function) if function.sig.ident == "hardened_options" => {
                    Some(function)
                }
                _ => None,
            })
            .collect();
        let [function] = functions.as_slice() else {
            return Err("expected exactly one `hardened_options` function".to_owned());
        };

        let locals: Vec<&syn::Local> = function
            .block
            .stmts
            .iter()
            .filter_map(|statement| match statement {
                syn::Stmt::Local(local)
                    if matches!(&local.pat, syn::Pat::Ident(identifier)
                        if identifier.ident == "options" && identifier.mutability.is_some()) =>
                {
                    Some(local)
                }
                _ => None,
            })
            .collect();
        let [binding] = locals.as_slice() else {
            return Err("expected exactly one top-level `let mut options`".to_owned());
        };

        let mut expression = binding
            .init
            .as_ref()
            .map(|initializer| initializer.expr.as_ref())
            .ok_or_else(|| "`let mut options` needs an initializer".to_owned())?;
        let mut chain = Vec::new();
        while let syn::Expr::MethodCall(call) = expression {
            chain.push(call.method.to_string());
            expression = call.receiver.as_ref();
        }
        chain.reverse();

        let syn::Expr::Call(root) = expression else {
            return Err("the chain must start at a constructor call".to_owned());
        };
        let syn::Expr::Path(path) = root.func.as_ref() else {
            return Err("the chain's constructor must be a plain path".to_owned());
        };
        let root_name: Vec<String> = path
            .path
            .segments
            .iter()
            .map(|segment| segment.ident.to_string())
            .collect();
        if root_name.join("::") != "MySqlConnectOptions::new" {
            return Err(format!("the chain starts at {}", root_name.join("::")));
        }
        Ok(chain)
    }

    #[test]
    fn the_options_chain_sets_every_field_and_disables_logging_once() {
        let chain = hardening_chain(include_str!("options.rs")).unwrap();
        assert_eq!(
            chain
                .iter()
                .filter(|method| *method == "disable_statement_logging")
                .count(),
            1,
            "{chain:?}"
        );
        for method in ["host", "port", "username", "database", "ssl_mode"] {
            assert!(chain.iter().any(|called| called == method), "{chain:?}");
        }
    }

    #[test]
    fn the_hardening_chain_guard_rejects_the_drivers_own_parser() {
        let fixture = r#"
            fn hardened_options() {
                let mut options = MySqlConnectOptions::from_str(raw)
                    .disable_statement_logging();
            }
        "#;
        assert!(hardening_chain(fixture).is_err());
    }

    #[test]
    fn the_hardening_chain_guard_ignores_comments_strings_and_dead_code() {
        let fixture = r#"
            fn hardened_options() {
                // .disable_statement_logging()
                let message = ".disable_statement_logging()";
                let mut options = if false {
                    MySqlConnectOptions::new()
                } else {
                    fallback()
                };
            }
        "#;
        assert!(hardening_chain(fixture).is_err());
    }

    #[test]
    fn no_production_call_reaches_the_drivers_url_parser() {
        let calls = production_calls(include_str!("options.rs"));
        for forbidden in FORBIDDEN_CALLS {
            assert!(
                !calls.iter().any(|call| call == forbidden),
                "{forbidden} is called; the DSN's query string would decide TLS, the \
                 statement cache, the socket and the character set again (ADR-0031)"
            );
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
    fn the_connection_target_comes_from_the_dsn_and_nothing_else() {
        let built = options(
            "mysql://warden:pw@db-01.internal:3307/reporting",
            TlsSettings::default(),
        );
        assert_eq!(built.get_host(), "db-01.internal");
        assert_eq!(built.get_port(), 3307);
        assert_eq!(built.get_username(), "warden");
        assert_eq!(built.get_database(), Some("reporting"));
        assert_eq!(built.get_socket(), None);
    }

    #[test]
    fn a_dsn_without_a_port_gets_the_documented_default() {
        let built = options("mysql://warden:pw@h/app", TlsSettings::default());
        assert_eq!(built.get_port(), DEFAULT_PORT);
    }

    #[test]
    fn every_tls_mode_maps_to_the_drivers_equivalent() {
        for mode in [
            TlsMode::Disabled,
            TlsMode::Required,
            TlsMode::VerifyCa,
            TlsMode::VerifyIdentity,
        ] {
            let built = hardened_options(
                &dsn("mysql://warden:pw@h:3306/app"),
                &TlsSettings {
                    mode,
                    root_certificate: None,
                },
                PoolRole::Control,
            );
            match (mode, built.get_ssl_mode()) {
                (TlsMode::Disabled, MySqlSslMode::Disabled)
                | (TlsMode::Required, MySqlSslMode::Required)
                | (TlsMode::VerifyCa, MySqlSslMode::VerifyCa)
                | (TlsMode::VerifyIdentity, MySqlSslMode::VerifyIdentity) => {}
                _ => panic!("TLS mode did not map to the driver's equivalent"),
            }
        }
        // The default the adapter never reaches, pinned so that an upstream change
        // to it is visible here rather than in a deployment.
        assert!(matches!(MySqlSslMode::default(), MySqlSslMode::Preferred));
    }
}
