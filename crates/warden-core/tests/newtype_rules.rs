//! Mechanical guards for rules the Rust compiler cannot express.
//!
//! `tests/architecture.rs` at the workspace root does this for the dependency
//! graph; this file does it for the core's own modeling rules. Both exist because a
//! rule that lives only in prose fails silently.
//!
//! The scans deliberately skip comment lines: the documentation explains why `Deref`
//! and `#[non_exhaustive]` are forbidden, and those explanations must not trip the
//! check that enforces them.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use warden_core::error::PublicErrorCode;

/// Every `.rs` file in this crate's `src` directory.
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

/// Lines of code, with comment lines removed.
fn code_lines(path: &Path) -> Vec<(usize, String)> {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    text.lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line.trim().to_owned()))
        .filter(|(_, line)| !line.starts_with("//"))
        .collect()
}

#[test]
fn no_newtype_implements_deref() {
    let mut violations = Vec::new();
    for path in source_files() {
        for (number, line) in code_lines(&path) {
            if line.starts_with("impl") && line.contains("Deref") {
                violations.push(format!("  {}:{number}: {line}", path.display()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "a validated newtype implements Deref:\n{}\n\n\
         `Deref` exposes the whole `String` API through the newtype and erases its \
         purpose (`docs/data-model.md` section 1; AGENTS.md, \"Modeling\"). Add an \
         `as_str` accessor instead.",
        violations.join("\n")
    );
}

#[test]
fn no_security_enum_is_non_exhaustive() {
    let mut violations = Vec::new();
    for path in source_files() {
        for (number, line) in code_lines(&path) {
            if line.contains("#[non_exhaustive]") {
                violations.push(format!("  {}:{number}", path.display()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "`#[non_exhaustive]` appears in warden-core:\n{}\n\n\
         It affects only downstream crates, and `warden-policy` is downstream: the \
         attribute would force a `_ =>` arm there and let a new variant compile \
         silently through the wildcard. The required property is the opposite \
         (ADR-0021).",
        violations.join("\n")
    );
}

#[test]
fn the_public_error_codes_match_the_security_document() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/security.md");
    let document = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));

    let (_, after) = document
        .split_once("Canonical public codes:")
        .expect("`docs/security.md` no longer lists canonical public codes");
    let block = after
        .split("```")
        .nth(1)
        .expect("the canonical code list is no longer a fenced block");

    // The first token is the fence's `text` language tag.
    let documented: BTreeSet<&str> = block.split_whitespace().skip(1).collect();
    let implemented: BTreeSet<&str> = PublicErrorCode::ALL.iter().map(|c| c.as_str()).collect();

    assert_eq!(
        documented, implemented,
        "the public error codes drifted from `docs/security.md` section 10.\n\
         These codes are a user-facing contract from the first release \
         (SPEC section 10), so the enum and the document change together or not at \
         all."
    );
}

#[test]
fn the_dsn_implements_no_stringifying_trait() {
    // `Debug` is present and hand-written; `TryFrom`/`FromStr` are required. These
    // five are the ones that would turn a secret back into a printable string or
    // duplicate it, and
    // the module comment explains why the general newtype rule does not apply
    // (ADR-0019) — which is exactly why the rule needs a check rather than prose.
    const FORBIDDEN: &[&str] = &["Clone", "Display", "AsRef", "Deref", "Serialize"];

    let mut violations = Vec::new();
    for path in source_files() {
        let mut header = String::new();
        let mut header_line = 0;
        for (number, line) in code_lines(&path) {
            if header.is_empty() {
                if !line.starts_with("impl") {
                    continue;
                }
                header_line = number;
                header.push_str(&line);
            } else {
                header.push(' ');
                header.push_str(&line);
            }

            if !header.contains('{') {
                continue;
            }

            if let Some((implemented_traits, target)) = header.split_once(" for ") {
                let targets_dsn = target
                    .split(|character: char| !character.is_ascii_alphanumeric())
                    .any(|part| part == "Dsn");
                if targets_dsn {
                    for trait_name in FORBIDDEN {
                        if implemented_traits
                            .split(|character: char| !character.is_ascii_alphanumeric())
                            .any(|part| part == *trait_name)
                        {
                            violations
                                .push(format!("  {}:{header_line}: {header}", path.display()));
                        }
                    }
                }
            }

            header.clear();
        }
    }

    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/secret.rs");
    let lines = code_lines(&path);
    let mut pending_derives = String::new();
    let mut in_derive = false;
    for (number, line) in lines {
        if in_derive {
            pending_derives.push_str(&line);
            if line.ends_with(")]") {
                in_derive = false;
            }
            continue;
        }

        if line.starts_with("#[derive") {
            pending_derives.push_str(&line);
            in_derive = !line.ends_with(")]");
            continue;
        }

        if line.is_empty() || line.starts_with("#[") {
            continue;
        }

        if line == "pub struct Dsn {" {
            for trait_name in FORBIDDEN {
                if pending_derives
                    .split(|character: char| !character.is_ascii_alphanumeric())
                    .any(|derived| derived == *trait_name)
                {
                    violations.push(format!(
                        "  {}:{number}: a derive immediately preceding `Dsn` includes {trait_name}",
                        path.display()
                    ));
                }
            }
            break;
        }

        pending_derives.clear();
    }

    assert!(
        violations.is_empty(),
        "`Dsn` implements or derives a forbidden secret trait:\n{}\n\n\
         A DSN carries a password. `Display` is what puts it into a log line, \
         `AsRef<str>` is what hands it to anything expecting a string, and \
         `Serialize` is what puts it into a tool response (ADR-0019; SPEC section 6, \
         invariants 20-21). `Clone` duplicates a secret. The only read-back is \
         `expose_password`.",
        violations.join("\n")
    );
}
