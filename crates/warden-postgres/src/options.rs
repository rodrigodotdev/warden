//! The one place a DSN becomes PostgreSQL connect options.
//!
//! # Why this builds the options instead of parsing them
//!
//! `PgConnectOptions::from_str` looks like the obvious call and is the wrong one.
//! Its parser starts from `PgConnectOptions::new_without_pgpass`, which seeds the
//! host, port, user, **password**, TLS mode, root certificate, client certificate,
//! client key, application name and startup options from `PG*` environment
//! variables; it finishes with `apply_pgpass`, which reads `~/.pgpass` and logs a
//! malformed line — password included — through `tracing::warn!`; and it logs every
//! query parameter it does not recognize, key and value, at the same level. All
//! three run before Warden can call `disable_statement_logging`, so a secret can
//! reach a log line before the connection exists at all (SPEC section 6,
//! invariants 20–22).
//!
//! So this module never hands a string to the driver. [`Dsn`] has already parsed and
//! validated the connection target (ADR-0031), and every field below is set
//! explicitly from it. `warden-mysql` can still use its driver's parser, because
//! `MySqlConnectOptions::from_str` reads no environment and logs nothing.
//!
//! # What is decided here rather than inherited
//!
//! * **TLS mode**, always, because `PgSslMode` defaults to `Prefer`, which falls
//!   back to cleartext when the server declines (ADR-0030).
//! * **Statement logging**, off, because `LogSettings::default()` logs every
//!   statement at `DEBUG` and every statement slower than a second at `WARN`,
//!   through `tracing`, with the SQL in a `db.statement` field.
//! * **The startup options**, because `statement_timeout`, `lock_timeout`,
//!   `idle_in_transaction_session_timeout`, `default_transaction_read_only` and
//!   `search_path` are the server-side half of ADR-0024 and the fixed name
//!   resolution of `docs/security.md` section 5.1.
//! * **The statement cache**, zero on the agent pool. PostgreSQL also needs
//!   `crate::query::agent_query`: the capacity alone would leave every named
//!   prepared statement on the connection forever (ADR-0025).

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
/// The port used when the DSN names none.
pub(crate) const DEFAULT_PORT: u16 = 5432;

/// Every environment variable `PgConnectOptions` reads for itself.
///
/// Read out of `sqlx-postgres` 0.9.0 `options/mod.rs`, plus `PGPASSFILE`, which only
/// `apply_pgpass` reads and which this module never calls. Refusing that one too
/// keeps the rule total: no PostgreSQL connection input comes from the environment,
/// with no exception a reader has to verify against the driver's source.
///
/// Refusing is the only available answer. `PgConnectOptions` offers no way to clear
/// `ssl_root_cert`, `ssl_client_cert` or `ssl_client_key` once a constructor has
/// filled them in, so a `PGSSLCERT` in the environment would change who the
/// connection authenticates as with nothing in Warden's configuration saying so.
pub(crate) const AMBIENT_VARIABLES: &[&str] = &[
    "PGAPPNAME",
    "PGDATABASE",
    "PGHOST",
    "PGHOSTADDR",
    "PGOPTIONS",
    "PGPASSFILE",
    "PGPASSWORD",
    "PGPORT",
    "PGSSLCERT",
    "PGSSLKEY",
    "PGSSLMODE",
    "PGSSLROOTCERT",
    "PGUSER",
];

/// Which of a connection's two pools the options are for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PoolRole {
    /// Agent SQL and `EXPLAIN`: an unbounded variety of one-off statements.
    Agent,
    /// Warden's own static SQL: health checks and schema introspection.
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
///
/// The two refusals come first: an adapter that speaks the wrong protocol to a
/// server, and an environment that would still be a second source of connection
/// settings.
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
    reject_ambient_inputs()?;
    Ok(hardened_options(
        dsn,
        tls,
        search_path,
        statement_timeout,
        role,
    ))
}

/// Applies every hardening decision to one pool's options.
///
/// Split from [`connect_options`] so that the settings can be asserted without the
/// process environment deciding whether the test runs at all.
fn hardened_options(
    dsn: &Dsn,
    tls: &TlsSettings,
    search_path: &SearchPath,
    statement_timeout: Duration,
    role: PoolRole,
) -> PgConnectOptions {
    let mut options = PgConnectOptions::new_without_pgpass()
        .host(dsn.host())
        .port(dsn.port().unwrap_or(DEFAULT_PORT))
        .username(dsn.username())
        .database(dsn.database())
        .ssl_mode(ssl_mode(tls.mode))
        .application_name(APPLICATION_NAME)
        .options(expected_settings(statement_timeout, search_path))
        .disable_statement_logging();

    if let Some(password) = dsn.expose_password() {
        options = options.password(password);
    }
    if let Some(root) = &tls.root_certificate {
        options = options.ssl_root_cert(root);
    }

    match role {
        PoolRole::Agent => options.statement_cache_capacity(0),
        PoolRole::Control => options,
    }
}

/// Refuses to build a connection while the environment can still influence it.
fn reject_ambient_inputs() -> Result<(), ConnectError> {
    for variable in AMBIENT_VARIABLES {
        if std::env::var_os(variable).is_some() {
            return Err(ConnectError::AmbientConnectionInput { variable });
        }
    }
    Ok(())
}

/// Converts a deadline to PostgreSQL milliseconds, never zero.
///
/// `statement_timeout = 0` means **no limit**, so a sub-millisecond timeout that
/// rounded down would remove the server-side deadline instead of tightening it
/// (ADR-0024). `crate::execute` uses the same rounding for its per-request
/// `SET LOCAL statement_timeout`, so neither path turns a deadline into no limit.
pub(crate) fn millis(value: Duration) -> String {
    u128::max(value.as_millis(), 1).to_string()
}

/// Maps Warden's TLS policy onto the driver's mode.
///
/// Exhaustive on purpose: a new `TlsMode` variant must break this build rather than
/// fall through a wildcard into something weaker (ADR-0030).
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

    use syn::visit::Visit;

    use super::*;

    /// Constructors and helpers that would put the driver's own parser, the
    /// environment, or `~/.pgpass` back on the path to a connection.
    const FORBIDDEN_CALLS: &[&str] = &[
        "PgConnectOptions::new",
        "PgConnectOptions::default",
        "PgConnectOptions::from_str",
        "PgConnectOptions::from_url",
        "apply_pgpass",
        "parse_from_url",
    ];

    fn dsn(raw: &str) -> Dsn {
        raw.parse().unwrap()
    }

    fn search_path() -> SearchPath {
        SearchPath::new(["app", "public"]).unwrap()
    }

    fn options(raw: &str, tls: TlsSettings) -> PgConnectOptions {
        hardened_options(
            &dsn(raw),
            &tls,
            &search_path(),
            Duration::from_secs(5),
            PoolRole::Agent,
        )
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
        if root_name.join("::") != "PgConnectOptions::new_without_pgpass" {
            return Err(format!("the chain starts at {}", root_name.join("::")));
        }
        Ok(chain)
    }

    #[test]
    fn the_options_chain_starts_without_pgpass_and_disables_logging_once() {
        let chain = hardening_chain(include_str!("options.rs")).unwrap();
        assert_eq!(
            chain
                .iter()
                .filter(|method| *method == "disable_statement_logging")
                .count(),
            1,
            "{chain:?}"
        );
        for method in [
            "host", "port", "username", "database", "ssl_mode", "options",
        ] {
            assert!(chain.iter().any(|called| called == method), "{chain:?}");
        }
    }

    #[test]
    fn the_hardening_chain_guard_rejects_the_drivers_own_parser() {
        let fixture = r#"
            fn hardened_options() {
                let mut options = PgConnectOptions::from_str(raw)
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
                    PgConnectOptions::new_without_pgpass()
                } else {
                    fallback()
                };
            }
        "#;
        assert!(hardening_chain(fixture).is_err());
    }

    /// Every `.rs` file in this crate, so the scan cannot be satisfied by the one
    /// file that happens to hold the guard.
    fn crate_sources() -> Vec<(String, String)> {
        fn collect(directory: &std::path::Path, found: &mut Vec<(String, String)>) {
            let entries = std::fs::read_dir(directory)
                .unwrap_or_else(|error| panic!("could not read {}: {error}", directory.display()));
            for entry in entries {
                let path = entry.expect("unreadable directory entry").path();
                if path.is_dir() {
                    collect(&path, found);
                } else if path.extension().is_some_and(|extension| extension == "rs") {
                    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| {
                        panic!("could not read {}: {error}", path.display())
                    });
                    found.push((path.display().to_string(), text));
                }
            }
        }

        let mut found = Vec::new();
        collect(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut found,
        );
        assert!(
            !found.is_empty(),
            "no source files found; did the layout change?"
        );
        found
    }

    #[test]
    fn no_production_call_in_this_crate_reaches_the_environment_or_pgpass() {
        // Scans the whole crate, not just this file: a second module that built
        // `PgConnectOptions` for itself would reopen the `PG*` and `~/.pgpass` paths
        // while every test in `options.rs` still passed.
        for (path, source) in crate_sources() {
            let calls = production_calls(&source);
            for forbidden in FORBIDDEN_CALLS {
                assert!(
                    !calls.iter().any(|call| call == forbidden),
                    "{path} calls {forbidden}; it would let the driver read the \
                     environment, `~/.pgpass`, or a URL it can log before hardening \
                     (ADR-0031)"
                );
            }
        }
        // `var_os` is the one deliberate environment read, and it only refuses.
        let calls = production_calls(include_str!("options.rs"));
        assert!(calls.iter().any(|call| call == "std::env::var_os"));
    }

    #[test]
    fn a_mysql_dsn_is_refused_before_the_driver_sees_it() {
        assert_eq!(
            connect_options(
                &dsn("mysql://warden:pw@h:3306/app"),
                &TlsSettings::default(),
                &search_path(),
                Duration::from_secs(5),
                PoolRole::Agent,
            )
            .unwrap_err(),
            ConnectError::DialectMismatch {
                actual: Dialect::MySql
            }
        );
    }

    #[test]
    fn the_connection_target_comes_from_the_dsn_and_nothing_else() {
        let built = options(
            "postgres://warden:pw@db-02.internal:6432/analytics",
            TlsSettings::default(),
        );
        assert_eq!(built.get_host(), "db-02.internal");
        assert_eq!(built.get_port(), 6432);
        assert_eq!(built.get_username(), "warden");
        assert_eq!(built.get_database(), Some("analytics"));
        assert_eq!(built.get_application_name(), Some(APPLICATION_NAME));
        assert_eq!(built.get_socket(), None);
    }

    #[test]
    fn a_dsn_without_a_port_gets_the_documented_default() {
        let built = options("postgres://warden:pw@h/app", TlsSettings::default());
        assert_eq!(built.get_port(), DEFAULT_PORT);
    }

    #[test]
    fn every_ambient_connection_input_refuses_the_connection() {
        // Each variable runs in its own child process: `std::env::set_var` is unsafe
        // in edition 2024 and would race every other test in this binary anyway.
        const CHILD: &str = "WARDEN_POSTGRES_AMBIENT_CHILD";
        const TEST: &str = "options::tests::every_ambient_connection_input_refuses_the_connection";

        if let Some(variable) = std::env::var_os(CHILD) {
            let variable = variable.to_str().expect("the child marker is ASCII");
            let expected = AMBIENT_VARIABLES
                .iter()
                .find(|candidate| **candidate == variable)
                .expect("the child marker names an ambient variable");
            assert_eq!(
                connect_options(
                    &dsn("postgres://warden:pw@h:5432/app"),
                    &TlsSettings::default(),
                    &search_path(),
                    Duration::from_secs(5),
                    PoolRole::Agent,
                )
                .unwrap_err(),
                ConnectError::AmbientConnectionInput { variable: expected }
            );
            return;
        }

        let executable = std::env::current_exe().expect("test executable path");
        for variable in AMBIENT_VARIABLES {
            let mut command = Command::new(&executable);
            command.arg("--exact").arg(TEST).arg("--nocapture");
            for cleared in AMBIENT_VARIABLES {
                command.env_remove(cleared);
            }
            let status = command
                .env(CHILD, variable)
                .env(variable, "set-by-the-operating-environment")
                .status()
                .expect("run the isolated ambient-input child");
            assert!(status.success(), "{variable} did not refuse the connection");
        }
    }

    #[test]
    fn the_ambient_refusal_names_the_variable_and_no_value() {
        let error = ConnectError::AmbientConnectionInput {
            variable: "PGPASSWORD",
        }
        .to_string();
        assert!(error.contains("PGPASSWORD"), "{error}");
        assert!(!error.contains("hunter2"), "{error}");
    }

    #[test]
    fn wardens_startup_options_are_the_only_ones() {
        let built = options("postgres://warden:pw@h:5432/app", TlsSettings::default());
        let rendered = built.get_options().unwrap_or_default();
        for setting in [
            "statement_timeout=5000",
            "idle_in_transaction_session_timeout=10000",
            "lock_timeout=1000",
            "default_transaction_read_only=on",
            "search_path=app,public",
        ] {
            assert_eq!(
                rendered.matches(setting).count(),
                1,
                "{setting} in {rendered:?}"
            );
        }
        assert_eq!(rendered.matches("-c").count(), 5, "{rendered:?}");
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
        // The default the adapter never reaches, pinned so that an upstream change
        // to it is visible here rather than in a deployment.
        assert!(matches!(PgSslMode::default(), PgSslMode::Prefer));
    }

    #[test]
    fn a_sub_millisecond_deadline_never_becomes_no_deadline() {
        assert_eq!(millis(Duration::from_secs(5)), "5000");
        assert_eq!(millis(Duration::from_nanos(1)), "1");
    }
}
