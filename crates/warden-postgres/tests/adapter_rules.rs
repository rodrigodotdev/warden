//! Mechanical guards for rules the Rust compiler cannot express.
//!
//! The MySQL counterpart of this file shipped in Milestone 4 and AGENTS.md recorded
//! that `warden-postgres` owed the same check. This is it. It runs as a separate
//! crate so it sees exactly the surface `warden-service` will see.
//!
//! The scans skip comment lines: the documentation explains why the AST must stay
//! inside, and those explanations must not trip the check that enforces them.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

/// The only files allowed to declare a `pub` item. Everything else is internal.
const PUBLIC_FILES: &[&str] = &["lib.rs", "analyzer.rs"];

/// Type names that would carry a parser AST across the crate boundary.
const AST_TYPES: &[&str] = &[
    "sqlparser",
    "Statement",
    "Expr",
    "ObjectName",
    "ObjectNamePart",
    "Ident",
    "TableFactor",
    "SetExpr",
    "UtilityOption",
    "Visitor",
    "VisitorMut",
    "Parser",
    "ParserError",
    "Token",
    "Tokenizer",
];

fn source_files() -> Vec<PathBuf> {
    fn collect(directory: &Path, found: &mut Vec<PathBuf>) {
        let entries = fs::read_dir(directory)
            .unwrap_or_else(|error| panic!("could not read {}: {error}", directory.display()));
        for entry in entries {
            let path = entry.expect("unreadable directory entry").path();
            if path.is_dir() {
                collect(&path, found);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                found.push(path);
            }
        }
    }

    let mut found = Vec::new();
    collect(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut found,
    );
    assert!(
        !found.is_empty(),
        "no source files found; did the layout change?"
    );
    found.sort();
    found
}

/// Lines of code, with comment lines and the `#[cfg(test)]` module removed.
///
/// The cut point is a line whose *trimmed* text is exactly `#[cfg(test)]`, not
/// the first place that string occurs anywhere in the file. A substring match
/// would let a doc comment that happens to mention `#[cfg(test)]` earlier in
/// the file silently hide every real line below it — export guard included —
/// while the tests kept passing.
fn code_lines(path: &Path) -> Vec<(usize, String)> {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    text.lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line.trim().to_owned()))
        .take_while(|(_, line)| line != "#[cfg(test)]")
        .filter(|(_, line)| !line.starts_with("//"))
        .collect()
}

/// A `pub` item declaration that is not `pub(crate)` or `pub(super)`.
fn is_exported(line: &str) -> bool {
    line.starts_with("pub ") && !line.starts_with("pub(")
}

/// Whether `line` names `type_name` as an identifier rather than as a substring.
///
/// Without the boundary check, `Statement` would match `StatementKind` and the scan
/// would fire on every classification signature. A scan that cries wolf gets
/// exempted, so it has to be precise enough to stay on.
fn names_type(line: &str, type_name: &str) -> bool {
    line.match_indices(type_name).any(|(start, _)| {
        let before = line[..start].chars().next_back();
        let after = line[start + type_name.len()..].chars().next();
        let boundary = |c: Option<char>| c.is_none_or(|c| !c.is_alphanumeric() && c != '_');
        boundary(before) && boundary(after)
    })
}

#[test]
fn only_the_analyzer_and_the_crate_root_export_anything() {
    let mut violations = Vec::new();
    for path in source_files() {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if PUBLIC_FILES.contains(&name) {
            continue;
        }
        for (number, line) in code_lines(&path) {
            if is_exported(&line) {
                violations.push(format!("  {}:{number}: {line}", path.display()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "these internal items are exported:\n{}\n\n\
         Keeping the crate's public surface to `PostgreSqlAnalyzer` is what makes \
         \"no parser AST leaves the adapter\" checkable at all (ADR-0007). Use \
         `pub(crate)`.",
        violations.join("\n")
    );
}

#[test]
fn no_public_signature_names_a_parser_type() {
    // Deliberately not filtered by `is_exported`: Rust forbids `pub` inside a
    // trait-impl block, so `impl QueryAnalyzer for PostgreSqlAnalyzer`'s methods —
    // the actual public contract `warden-service` calls — start with `fn`, not
    // `pub fn`, and would be invisible to a `pub`-only scan. The two public
    // files are small and reviewed, so scanning every non-comment line in them
    // is precise enough; `names_type`'s word-boundary check still keeps
    // `StatementKind` from matching `Statement`.
    let mut violations = Vec::new();
    for path in source_files() {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if !PUBLIC_FILES.contains(&name) {
            continue;
        }
        for (number, line) in code_lines(&path) {
            for ast_type in AST_TYPES {
                if names_type(&line, ast_type) {
                    violations.push(format!("  {}:{number}: {line}", path.display()));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "a `sqlparser` type appears in the crate's public surface:\n{}\n\n\
         SPEC section 6, invariant 28 and ADR-0007 keep parser ASTs inside adapter \
         crates; that is the seam that lets a future adapter replace `sqlparser` \
         without touching MCP, core, policy, or audit models. This scan covers \
         every line of `lib.rs` and `analyzer.rs`, not only `pub`-prefixed ones, \
         because a trait-impl method such as `QueryAnalyzer::analyze` is public \
         without ever writing the word `pub`.",
        violations.join("\n")
    );
}

/// Whether `current` is a wildcard arm whose *preceding* arm's pattern side names a
/// `warden-core` security enum.
///
/// Only the pattern side of `previous` — the text before its first `=>` — is
/// checked. Scanning the whole line produces a false positive when rustfmt splits a
/// multi-line arm across lines: `visit.rs` has a `BinaryOperator::Assignment` arm
/// whose *body* calls `self.flag(RiskFlag::SessionMutation)`, so the line right
/// before a later `_ => {}` (over `Expr`, the deliberate exception documented in
/// `lib.rs`) mentions `RiskFlag::` only on the right-hand side of an unrelated arm.
/// The rule is about what is being *matched*, not what an arm's body does, exactly
/// as the comment on the scan itself says.
///
/// This still catches a real violation: a `StatementKind::Unknown => ...` pattern
/// arm immediately followed by `_ =>` still carries `StatementKind::` in the pattern
/// text of the preceding line, and a multi-line `|`-chained pattern still ends with
/// pattern text (not a call) on the line right before the wildcard.
///
/// Known blind spot, left as a comment rather than fixed: an arm whose *body* is a
/// braced block puts a bare `}` on the line preceding the wildcard, with the guarded
/// enum name several lines further up. Neither this function nor a whole-line scan
/// catches that shape.
fn wildcard_follows_guarded_pattern(previous: &str, current: &str, guarded: &[&str]) -> bool {
    let is_wildcard = current.starts_with("_ =>") || current.starts_with("_ if");
    let pattern = previous.split("=>").next().unwrap_or(previous);
    is_wildcard && guarded.iter().any(|prefix| pattern.contains(prefix))
}

#[test]
fn no_wildcard_arm_matches_a_warden_core_security_enum() {
    // Wildcards over `sqlparser` enums are required (AGENTS.md, "Modeling") and map
    // to Unknown. Wildcards over a `warden-core` security enum are forbidden: a new
    // variant must break this build (ADR-0021). The two are told apart by whether
    // the *pattern side* of the arm preceding the wildcard names a `warden-core`
    // enum — see `wildcard_follows_guarded_pattern`.
    let guarded = [
        "StatementKind::",
        "RiskFlag::",
        "FunctionClassification::",
        "ObjectKind::",
    ];
    let mut violations = Vec::new();

    for path in source_files() {
        let lines = code_lines(&path);
        for window in lines.windows(2) {
            let (previous, current) = (&window[0].1, &window[1]);
            if wildcard_follows_guarded_pattern(previous, &current.1, &guarded) {
                violations.push(format!("  {}:{}: {}", path.display(), current.0, current.1));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "a wildcard arm follows a `warden-core` security enum:\n{}\n\n\
         Adding a variant there must break this crate's build, not slip through a \
         wildcard (ADR-0021).",
        violations.join("\n")
    );
}

#[test]
fn the_scans_are_alive() {
    // A scan that finds nothing because its inputs are empty passes forever.
    assert!(names_type("pub fn f(s: &Statement)", "Statement"));
    assert!(!names_type("pub fn f(k: StatementKind)", "Statement"));
    assert!(!names_type("pub fn f(r: QueryRequest)", "Statement"));
    assert!(is_exported("pub struct PostgreSqlAnalyzer;"));
    assert!(!is_exported("pub(crate) fn kind_of()"));
    assert!(
        source_files().iter().any(|p| p.ends_with("analyzer.rs")),
        "the analyzer module moved; the public-surface scan needs updating"
    );
    assert!(
        source_files().len() >= 7,
        "fewer modules than Milestone 5 shipped; the scans may be reading the wrong \
         directory"
    );

    // The AST-containment scan no longer filters on `is_exported`, because a
    // trait-impl method — `QueryAnalyzer::analyze`'s own signature, for
    // instance — is public without ever writing `pub`. Prove the detection
    // primitive still fires on that shape, so the widened scan would catch it.
    assert!(
        names_type(
            "fn analyze(&self, s: &Statement) -> Result<Foo, Bar> {",
            "Statement"
        ),
        "a parser type in a trait-impl method signature, which never starts \
         with `pub`, must still be caught now that the scan is not gated on \
         `is_exported`"
    );

    // The wildcard scan must fire in both directions, not merely fail to fire.
    let guarded = [
        "StatementKind::",
        "RiskFlag::",
        "FunctionClassification::",
        "ObjectKind::",
    ];
    assert!(
        wildcard_follows_guarded_pattern(
            "StatementKind::Unknown => evidence.flag(RiskFlag::UnknownConstruct),",
            "_ => {}",
            &guarded
        ),
        "a real violation — a wildcard following a pattern arm that names a \
         warden-core enum — must be caught"
    );
    assert!(
        !wildcard_follows_guarded_pattern(
            "} => self.flag(RiskFlag::SessionMutation),",
            "_ => {}",
            &guarded
        ),
        "a wildcard over `Expr` must not be flagged merely because the previous \
         arm's body, not its pattern, mentions a warden-core enum \
         (the false positive this scan was narrowed to avoid)"
    );
}
