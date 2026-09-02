//! Mechanical guards for `warden-config` rules the Rust compiler cannot express, plus
//! the one behavioral test that needs a process-global environment variable. Rust runs
//! unit tests in threads, so that test cannot live next to `secrets.rs`'s own tests
//! without racing them; it lives here, in its own process, instead. It sets the
//! variable on a spawned child process's environment rather than this process's own,
//! because `std::env::set_var` is `unsafe` in this edition and `unsafe_code = "forbid"`
//! (`AGENTS.md`) admits no exception for a test.
//!
//! The struct and derive guards parse `src/model.rs` and the crate's other source
//! files with `syn` — the technique `crates/warden-service/tests/service_rules.rs` and
//! both `crates/warden-mysql/tests/adapter_rules.rs` /
//! `crates/warden-postgres/tests/adapter_rules.rs` already use — so that a comment
//! mentioning `deny_unknown_fields` or `Serialize` cannot satisfy or trip a check that
//! is really about an attribute or a derive list.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use warden_config::ConfigError;
use warden_core::connection::ConnectionName;
use warden_core::dialect::Dialect;

fn crate_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn read(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

/// Every `.rs` file directly in `src`, sorted, so a new file is covered automatically
/// rather than silently skipped.
fn source_files() -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = fs::read_dir(crate_src())
        .expect("crate_src must exist")
        .map(|entry| entry.expect("unreadable directory entry").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
        .collect();
    assert!(
        !found.is_empty(),
        "no source files found; did the layout change?"
    );
    found.sort();
    found
}

/// One file's top-level items with `mod tests` removed, so a test fixture's own
/// derives or struct shapes cannot satisfy or trip a guard meant for production code.
fn production_items(source: &str) -> Vec<syn::Item> {
    let file = syn::parse_file(source).expect("source must parse");
    file.items
        .into_iter()
        .filter(|item| !matches!(item, syn::Item::Mod(module) if module.ident == "tests"))
        .collect()
}

/// Whether a `#[serde(deny_unknown_fields)]` attribute is present.
fn has_deny_unknown_fields(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        if !attribute.path().is_ident("serde") {
            return false;
        }
        let mut found = false;
        let _ = attribute.parse_nested_meta(|meta| {
            if meta.path.is_ident("deny_unknown_fields") {
                found = true;
            }
            Ok(())
        });
        found
    })
}

/// The names inside every `#[derive(...)]` attribute on one item.
fn derive_names(attributes: &[syn::Attribute]) -> Vec<String> {
    let mut names = Vec::new();
    for attribute in attributes {
        if !attribute.path().is_ident("derive") {
            continue;
        }
        let _ = attribute.parse_nested_meta(|meta| {
            let name = meta
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string())
                .unwrap_or_default();
            names.push(name);
            Ok(())
        });
    }
    names
}

#[test]
fn every_pub_struct_in_model_denies_unknown_fields() {
    let source = read(&crate_src().join("model.rs"));
    let file = syn::parse_file(&source).expect("model.rs must parse");

    let mut missing = Vec::new();
    for item in &file.items {
        if let syn::Item::Struct(item_struct) = item
            && matches!(item_struct.vis, syn::Visibility::Public(_))
            && !has_deny_unknown_fields(&item_struct.attrs)
        {
            missing.push(item_struct.ident.to_string());
        }
    }

    assert!(
        missing.is_empty(),
        "these `pub struct`s in model.rs carry no #[serde(deny_unknown_fields)]: \
         {missing:?}\n\n\
         Without it, a misspelled field such as `allow_locking_read` is silently \
         ignored, the default applies, and the operator believes the deployment is \
         hardened when it is not (`docs/operations.md` section 3.1)."
    );
}

#[test]
fn nothing_in_the_crate_derives_serialize() {
    let mut violations = Vec::new();
    for path in source_files() {
        let source = read(&path);
        for item in production_items(&source) {
            let (name, attrs): (String, Vec<syn::Attribute>) = match item {
                syn::Item::Struct(item_struct) => {
                    (item_struct.ident.to_string(), item_struct.attrs)
                }
                syn::Item::Enum(item_enum) => (item_enum.ident.to_string(), item_enum.attrs),
                _ => continue,
            };
            if derive_names(&attrs)
                .iter()
                .any(|derive| derive == "Serialize")
            {
                violations.push(format!("{}: {name}", path.display()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "these types derive Serialize: {violations:?}\n\n\
         `warden-config` emits core types and plain strings, never something a wrapper \
         could accidentally serialize into a tool response; `Dsn`'s own non-Serialize \
         guarantee must not be undone by a wrapper around it \
         (`docs/operations.md` section 3.3)."
    );
}

/// Exhaustive by construction: a variant added to `ConfigError` without a matching
/// arm here fails the build, which is the signal to add it to the sample table in
/// `config_error_display_never_carries_a_secret` below.
fn assert_every_variant_is_covered(error: &ConfigError) {
    match error {
        ConfigError::Unreadable { .. }
        | ConfigError::Malformed { .. }
        | ConfigError::UnsupportedVersion { .. }
        | ConfigError::MalformedDuration { .. }
        | ConfigError::NoConnections
        | ConfigError::DuplicateConnection { .. }
        | ConfigError::UnknownProfile { .. }
        | ConfigError::ConflictingPolicy { .. }
        | ConfigError::DsnSourceAmbiguous { .. }
        | ConfigError::DsnVariableMissing { .. }
        | ConfigError::DsnFileUnreadable { .. }
        | ConfigError::InvalidDsn { .. }
        | ConfigError::DialectMismatch { .. }
        | ConfigError::SearchPathOnMySql { .. }
        | ConfigError::InvalidSettings { .. } => {}
    }
}

#[test]
fn config_error_display_never_carries_a_secret() {
    let name: ConnectionName = "production-mysql".parse().unwrap();
    let dsn_like = "mysql://warden_ro:hunter2@db.internal:3306/app";

    let samples: Vec<ConfigError> = vec![
        ConfigError::Unreadable {
            path: PathBuf::from("/etc/warden/config.toml"),
            message: "permission denied".to_owned(),
        },
        ConfigError::Malformed {
            message: "missing field `version`".to_owned(),
        },
        ConfigError::UnsupportedVersion {
            found: 2,
            supported: 1,
        },
        ConfigError::MalformedDuration {
            value: "5".to_owned(),
        },
        ConfigError::NoConnections,
        ConfigError::DuplicateConnection { name: name.clone() },
        ConfigError::UnknownProfile {
            connection: name.clone(),
            profile: "missing".to_owned(),
        },
        ConfigError::ConflictingPolicy {
            first: "production".to_owned(),
            second: "relaxed".to_owned(),
            field: "allow_unknown_functions",
        },
        ConfigError::DsnSourceAmbiguous {
            connection: name.clone(),
        },
        ConfigError::DsnVariableMissing {
            connection: name.clone(),
            variable: "WARDEN_PRODUCTION_MYSQL_DSN".to_owned(),
        },
        ConfigError::DsnFileUnreadable {
            connection: name.clone(),
            path: PathBuf::from("/run/secrets/warden-mysql-dsn"),
            message: "no such file or directory".to_owned(),
        },
        ConfigError::InvalidDsn {
            connection: name.clone(),
            message: "the DSN carries a query string or fragment".to_owned(),
        },
        ConfigError::DialectMismatch {
            connection: name.clone(),
            declared: Dialect::MySql,
            actual: Dialect::PostgreSql,
        },
        ConfigError::SearchPathOnMySql {
            connection: name.clone(),
        },
        ConfigError::InvalidSettings {
            connection: name,
            message: "execution limit `max_rows` must be greater than zero".to_owned(),
        },
    ];

    for error in &samples {
        assert_every_variant_is_covered(error);
        let rendered = error.to_string();
        assert!(!rendered.contains("password"), "{rendered}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(!rendered.contains(dsn_like), "{rendered}");
    }
}

/// A minimal configuration whose only connection reads its DSN from `variable`.
fn toml_naming(variable: &str) -> String {
    format!(
        "version = 1\n\
         [[connections]]\n\
         name = \"db\"\n\
         dialect = \"postgresql\"\n\
         environment = \"development\"\n\
         database = \"app\"\n\
         dsn_env = \"{variable}\"\n\
         policy = \"p\"\n\
         [policies.p]\n"
    )
}

/// `WARDEN_TEST_DSN_TASK_2_CHILD` names the marker this test sets only on the child
/// process it spawns, so this test function can tell which process it is running as.
const CHILD_MARKER: &str = "WARDEN_TEST_DSN_TASK_2_CHILD";

#[test]
fn an_environment_variable_supplies_a_dsn_and_its_absence_names_the_variable() {
    // `std::env::set_var` is `unsafe` in this edition because it is process-global, and
    // `unsafe_code = "forbid"` (`AGENTS.md`) admits no exception for a test. The variable
    // is instead set on a child process's environment through `Command::env`, which is
    // ordinary, safe API — the same pattern
    // `crates/warden-postgres/src/options.rs`'s `every_ambient_connection_input_refuses_
    // the_connection` uses for the same reason.
    const VARIABLE: &str = "WARDEN_TEST_DSN_TASK_2";

    if std::env::var_os(CHILD_MARKER).is_some() {
        let config = warden_config::Config::from_toml_str(&toml_naming(VARIABLE))
            .unwrap()
            .resolve()
            .unwrap();
        assert_eq!(config.connections[0].dsn.database(), "analytics");
        return;
    }

    let executable = std::env::current_exe().expect("test executable path");
    let status = std::process::Command::new(&executable)
        .arg("--exact")
        .arg("an_environment_variable_supplies_a_dsn_and_its_absence_names_the_variable")
        .env(CHILD_MARKER, "1")
        .env(VARIABLE, "postgres://warden_ro:pw@db:5432/analytics")
        .status()
        .expect("run the isolated child process");
    assert!(status.success(), "the child process assertion failed");

    // This (parent) process never set the variable, so resolving here exercises its
    // absence without racing the child's own environment.
    let error = warden_config::Config::from_toml_str(&toml_naming(VARIABLE))
        .unwrap()
        .resolve()
        .unwrap_err();
    let rendered = error.to_string();
    assert!(rendered.contains(VARIABLE), "{rendered}");
    assert!(!rendered.contains("pw"), "{rendered}");
}
