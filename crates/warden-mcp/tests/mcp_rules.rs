//! Mechanical guards for `warden-mcp` rules the Rust compiler cannot express.
//!
//! Parses this crate's own `src/` with `syn`, the technique
//! `crates/warden-service/tests/service_rules.rs` and `crates/warden-config/tests/config_rules.rs`
//! already use, so a comment mentioning `structured_error` or `format!` cannot satisfy or
//! trip a check that is really about code. Five rules live here:
//!
//! - `src/error.rs` is the only file that builds a failed [`rmcp::model::CallToolResult`].
//! - No tool path formats an error: `src/server.rs` and `src/stdio.rs` never call `format!`,
//!   never call `.to_string()` on a binding named `error` or `source`, and never interpolate
//!   `{error}` / `{err}` / `{e}` (`docs/security.md` section 10).
//! - `error.rs`'s `public_message` match has exactly `PublicErrorCode::ALL.len()` arms and no
//!   wildcard (ADR-0021).
//! - No adapter, driver, or parser identifier — `sqlx`, `sqlparser`, `warden_mysql`,
//!   `warden_postgres`, `MySqlPool`, `PgPool` — appears on a line of code anywhere in `src/`.
//!   Lines are trimmed and comment lines are skipped before the scan, exactly as
//!   `crates/warden-mysql/tests/adapter_rules.rs` does: this crate's own module docs
//!   explain, by name, which crates it must not depend on, and those explanations must not
//!   trip the check that enforces the rule.
//! - No tool description names a dialect-specific tool (`docs/mcp.md` section 1).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use proc_macro2::TokenTree;
use syn::visit::Visit;
use warden_core::error::PublicErrorCode;
use warden_mcp::WardenServer;

fn crate_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn read(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

/// Every `.rs` file under `src/`, recursively, sorted. Recursing rather than reading one
/// directory level keeps this list correct if the crate ever grows a submodule directory.
fn source_files() -> Vec<PathBuf> {
    fn collect(directory: &Path, files: &mut Vec<PathBuf>) {
        for entry in fs::read_dir(directory)
            .unwrap_or_else(|error| panic!("could not read {}: {error}", directory.display()))
        {
            let entry = entry.expect("unreadable directory entry");
            let path = entry.path();
            if entry.file_type().expect("unreadable file type").is_dir() {
                collect(&path, files);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(path);
            }
        }
    }

    let mut files = Vec::new();
    collect(&crate_src(), &mut files);
    assert!(
        !files.is_empty(),
        "no source files found; did the layout change?"
    );
    files.sort();
    files
}

// ---------------------------------------------------------------------------------
// Rule 1: only error.rs builds a failed result.
// ---------------------------------------------------------------------------------

/// Whether `source` contains an assignment to a field named `is_error`, found through
/// `syn` rather than text so `result.is_error` (a read, as every test's own assertion
/// does) is never confused with `result.is_error = ...` (a write).
fn sets_is_error(source: &str) -> bool {
    #[derive(Default)]
    struct SetsIsError(bool);

    impl<'ast> Visit<'ast> for SetsIsError {
        fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
            if let syn::Expr::Field(field) = node.left.as_ref()
                && let syn::Member::Named(name) = &field.member
                && name == "is_error"
            {
                self.0 = true;
            }
            syn::visit::visit_expr_assign(self, node);
        }
    }

    let file = syn::parse_file(source).expect("source must parse");
    let mut visitor = SetsIsError::default();
    visitor.visit_file(&file);
    visitor.0
}

#[test]
fn only_error_rs_builds_a_failed_result() {
    let error_rs = crate_src().join("error.rs");
    let mut violations = Vec::new();
    for path in source_files() {
        if path == error_rs {
            continue;
        }
        let source = read(&path);
        if source.contains("structured_error") {
            violations.push(format!("{} mentions structured_error", path.display()));
        }
        if sets_is_error(&source) {
            violations.push(format!("{} sets is_error", path.display()));
        }
    }

    assert!(
        violations.is_empty(),
        "a failed CallToolResult is built outside error.rs:\n{}\n\n\
         `error.rs` is the one place an internal failure becomes something a model may \
         see; a second call site is a second place that rule can be gotten wrong.",
        violations.join("\n")
    );
}

// ---------------------------------------------------------------------------------
// Rule 2: no tool path formats an error.
// ---------------------------------------------------------------------------------

/// One file's top-level items with `mod tests` removed, so a test fixture's own
/// `.to_string()` or `format!` cannot trip a guard meant for production code.
fn production_items(source: &str) -> Vec<syn::Item> {
    syn::parse_file(source)
        .expect("source must parse")
        .items
        .into_iter()
        .filter(|item| !matches!(item, syn::Item::Mod(module) if module.ident == "tests"))
        .collect()
}

/// Whether a macro's token stream carries a string literal containing `{error}`,
/// `{err}`, or `{e}` — the shape of an accidental `tracing::error!("... {error}")` or a
/// `format!` message that repeats the value it was told to name only by code
/// (`docs/security.md` section 10). Descends into groups because a literal's siblings in
/// the same macro invocation can themselves sit inside a nested token group.
fn macro_carries_forbidden_interpolation(tokens: proc_macro2::TokenStream) -> bool {
    tokens.into_iter().any(|token| match token {
        TokenTree::Literal(literal) => syn::parse_str::<syn::LitStr>(&literal.to_string())
            .is_ok_and(|literal| {
                let value = literal.value();
                ["{error}", "{err}", "{e}"]
                    .iter()
                    .any(|placeholder| value.contains(placeholder))
            }),
        TokenTree::Group(group) => macro_carries_forbidden_interpolation(group.stream()),
        TokenTree::Ident(_) | TokenTree::Punct(_) => false,
    })
}

#[derive(Default)]
struct ErrorFormattingScan {
    format_macro: bool,
    to_string_on_error_binding: bool,
    forbidden_interpolation: bool,
}

impl<'ast> Visit<'ast> for ErrorFormattingScan {
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if node.path.is_ident("format") {
            self.format_macro = true;
        }
        if macro_carries_forbidden_interpolation(node.tokens.clone()) {
            self.forbidden_interpolation = true;
        }
        syn::visit::visit_macro(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let receiver_is_error_or_source = matches!(node.receiver.as_ref(), syn::Expr::Path(path)
            if path.path.get_ident().is_some_and(|ident| ident == "error" || ident == "source"));
        if node.method == "to_string" && receiver_is_error_or_source {
            self.to_string_on_error_binding = true;
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}

fn error_formatting_scan(source: &str) -> ErrorFormattingScan {
    let mut scan = ErrorFormattingScan::default();
    for item in production_items(source) {
        scan.visit_item(&item);
    }
    scan
}

#[test]
fn no_tool_path_formats_an_error() {
    for file in ["server.rs", "stdio.rs"] {
        let source = read(&crate_src().join(file));
        let scan = error_formatting_scan(&source);
        assert!(
            !scan.format_macro,
            "{file} calls format!; docs/security.md section 10 forbids building a \
             message that could carry driver detail on the tool path"
        );
        assert!(
            !scan.to_string_on_error_binding,
            "{file} calls .to_string() on a binding named `error` or `source`; that is \
             the shape a leaked driver message would take"
        );
        assert!(
            !scan.forbidden_interpolation,
            "{file} interpolates {{error}}, {{err}}, or {{e}} into a string"
        );
    }
}

// ---------------------------------------------------------------------------------
// Rule 3: public_message matches every code with no wildcard.
// ---------------------------------------------------------------------------------

/// The arm count and wildcard presence of `error.rs`'s `public_message` match.
fn public_message_match_shape() -> (usize, bool) {
    let source = read(&crate_src().join("error.rs"));
    let file = syn::parse_file(&source).expect("error.rs must parse");
    let function = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == "public_message" => Some(function),
            _ => None,
        })
        .expect("error.rs no longer declares public_message");
    let match_expr = function
        .block
        .stmts
        .iter()
        .find_map(|stmt| match stmt {
            syn::Stmt::Expr(syn::Expr::Match(match_expr), _) => Some(match_expr),
            _ => None,
        })
        .expect("public_message's body is no longer a single match expression");
    let has_wildcard = match_expr
        .arms
        .iter()
        .any(|arm| matches!(arm.pat, syn::Pat::Wild(_)));
    (match_expr.arms.len(), has_wildcard)
}

#[test]
fn public_message_matches_every_code_with_no_wildcard() {
    let (arm_count, has_wildcard) = public_message_match_shape();
    assert!(
        !has_wildcard,
        "public_message has a wildcard arm; a new PublicErrorCode variant must not \
         compile until someone writes its sentence (ADR-0021)"
    );
    assert_eq!(
        arm_count,
        PublicErrorCode::ALL.len(),
        "public_message's arm count drifted from PublicErrorCode::ALL"
    );
}

// ---------------------------------------------------------------------------------
// Rule 4: no adapter, driver, or parser name appears anywhere in src/.
// ---------------------------------------------------------------------------------

/// Identifiers that would tell an agent what Warden is built on. The manifest already
/// forbids `warden-mcp` depending on `sqlx` or `sqlparser` as crates; this catches the
/// same words spelled out in a string, a log line, or an error message instead.
const FORBIDDEN_NAMES: &[&str] = &[
    "sqlx",
    "sqlparser",
    "warden_mysql",
    "warden_postgres",
    "MySqlPool",
    "PgPool",
];

/// Lines of code, trimmed, with comment lines removed.
///
/// A comment line is one whose trimmed text starts with `//` — `///` and `//!` included,
/// since both start with `//`. This crate's own module docs (`lib.rs`, `server.rs`) name
/// `sqlx` and `sqlparser` by name to explain that they must never be depended on; those
/// explanations must not trip the check that enforces them, exactly as
/// `crates/warden-mysql/tests/adapter_rules.rs`'s own `code_lines` documents.
fn code_lines(path: &Path) -> Vec<(usize, String)> {
    read(path)
        .lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line.trim().to_owned()))
        .filter(|(_, line)| !line.starts_with("//"))
        .collect()
}

/// Whether `line` names `word` as an identifier rather than as a substring, so
/// `PgPool` does not fire on an unrelated `PgPoolOptions` and `sqlx` does not fire on
/// `postgresqlxyz`.
fn names_word(line: &str, word: &str) -> bool {
    line.match_indices(word).any(|(start, _)| {
        let before = line[..start].chars().next_back();
        let after = line[start + word.len()..].chars().next();
        let boundary = |character: Option<char>| {
            character.is_none_or(|character| !character.is_alphanumeric() && character != '_')
        };
        boundary(before) && boundary(after)
    })
}

#[test]
fn no_adapter_driver_or_parser_name_appears_in_src() {
    let mut violations = Vec::new();
    for path in source_files() {
        for (number, line) in code_lines(&path) {
            for name in FORBIDDEN_NAMES {
                if names_word(&line, name) {
                    violations.push(format!("  {}:{number}: {line}", path.display()));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "an adapter, driver, or parser name appears in src/:\n{}\n\n\
         Nothing in warden-mcp may tell an agent what Warden is built on \
         (docs/architecture.md section 3).",
        violations.join("\n")
    );
}

// ---------------------------------------------------------------------------------
// Rule 5: no tool description names a dialect-specific tool.
// ---------------------------------------------------------------------------------

#[test]
fn no_tool_description_names_a_dialect_specific_tool() {
    // docs/mcp.md section 1: the selected connection chooses the backend, and adding
    // PostgreSQL must never create a second set of tool names.
    for tool in WardenServer::tool_router().list_all() {
        let description = tool.description.as_deref().unwrap_or_default();
        for forbidden in ["mysql_query", "postgres_query"] {
            assert!(
                !description.contains(forbidden),
                "{}'s description names {forbidden}: {description}",
                tool.name
            );
        }
    }
}

// ---------------------------------------------------------------------------------
// The scans are alive.
// ---------------------------------------------------------------------------------

#[test]
fn the_scans_detect_the_violations_they_exist_to_catch() {
    assert!(sets_is_error(
        "fn f(r: &mut R) { r.is_error = Some(true); }"
    ));
    assert!(!sets_is_error("fn f(r: &R) { let _ = r.is_error; }"));

    let scan = error_formatting_scan(
        r#"
        fn production() {
            let error = std::io::Error::other("x");
            let _ = error.to_string();
            let _ = format!("boom");
        }
        "#,
    );
    assert!(scan.format_macro);
    assert!(scan.to_string_on_error_binding);

    assert!(macro_carries_forbidden_interpolation(
        syn::parse_str::<syn::ExprMacro>(r#"tracing::error!("boom {error}")"#)
            .unwrap()
            .mac
            .tokens
    ));
    assert!(!macro_carries_forbidden_interpolation(
        syn::parse_str::<syn::ExprMacro>(r#"tracing::error!(%error, "boom")"#)
            .unwrap()
            .mac
            .tokens
    ));

    assert!(names_word("use sqlx::MySqlPool;", "sqlx"));
    assert!(!names_word("postgresqlx", "sqlx"));
    assert!(!names_word("PgPoolOptions", "PgPool"));

    assert!(
        source_files().iter().any(|path| path.ends_with("error.rs")),
        "error.rs moved; the source layout the guards assume needs updating"
    );
}
