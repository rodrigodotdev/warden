//! Mechanical guards for rules the Rust compiler cannot express.
//!
//! `tests/architecture.rs` does this for the dependency graph and
//! `warden-core/tests/newtype_rules.rs` for the core's modeling rules. This file
//! does it for the capability token and the denial vocabulary, and it runs as a
//! separate crate so it sees the same public surface `warden-mcp` would.
//!
//! The scans skip comment lines: the documentation explains why `Deref`,
//! `Deserialize`, and wildcard arms are forbidden, and those explanations must not
//! trip the checks that enforce them.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use warden_policy::DenyCode;

/// Files exempt from the wildcard-arm scan. Empty, and a diff has to say why it is
/// not.
const WILDCARD_EXEMPT: &[&str] = &[];

fn crate_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

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
    collect(&crate_src(), &mut found);
    assert!(
        !found.is_empty(),
        "no source files found; did the layout change?"
    );
    found.sort();
    found
}

fn read(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()))
}

/// Lines of code, with comment lines removed.
fn code_lines(path: &Path) -> Vec<(usize, String)> {
    read(path)
        .lines()
        .enumerate()
        .map(|(index, line)| (index + 1, line.trim().to_owned()))
        .filter(|(_, line)| !line.starts_with("//"))
        .collect()
}

/// The `#[derive(...)]` names attached to `pub struct <name>`.
fn derives_for(source: &str, type_name: &str) -> BTreeSet<String> {
    let lines: Vec<&str> = source.lines().map(str::trim).collect();
    let declaration = format!("pub struct {type_name} ");
    let index = lines
        .iter()
        .position(|line| {
            line.starts_with(&declaration) || *line == format!("pub struct {type_name}")
        })
        .unwrap_or_else(|| panic!("`pub struct {type_name}` not found"));

    let mut derives = BTreeSet::new();
    for line in lines[..index].iter().rev() {
        if line.is_empty() || line.starts_with("///") || line.starts_with("//") {
            continue;
        }
        if let Some(list) = line
            .strip_prefix("#[derive(")
            .and_then(|rest| rest.strip_suffix(")]"))
        {
            derives.extend(list.split(',').map(|name| name.trim().to_owned()));
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        break;
    }
    derives
}

/// Signatures of `pub fn` items inside `impl <type_name>` that return the type.
fn public_constructors(source: &str, type_name: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut inside = false;
    let mut signature = String::new();

    for raw in source.lines() {
        let line = raw.trim();
        if line == format!("impl {type_name} {{") {
            inside = true;
            continue;
        }
        if inside && raw == "}" {
            break;
        }
        if !inside {
            continue;
        }
        if signature.is_empty() && !line.starts_with("pub fn ") {
            continue;
        }
        signature.push_str(line);
        signature.push(' ');
        if !line.contains('{') {
            continue;
        }
        if signature.contains("-> Self") || signature.contains(&format!("-> {type_name}")) {
            found.push(signature.trim().to_owned());
        }
        signature.clear();
    }
    found
}

/// `MultipleStatements` -> `multiple_statements`.
fn snake(camel: &str) -> String {
    let mut out = String::new();
    for (index, character) in camel.chars().enumerate() {
        if character.is_ascii_uppercase() {
            if index > 0 {
                out.push('_');
            }
            out.push(character.to_ascii_lowercase());
        } else {
            out.push(character);
        }
    }
    out
}

fn security_document() -> String {
    read(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/security.md"))
}

#[test]
fn no_type_implements_deref() {
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
        "a type in warden-policy implements Deref:\n{}\n\n\
         `Deref` on a security state would expose the wrapped value's whole API and \
         erase the state's purpose (AGENTS.md, \"Modeling\"). Add a named accessor.",
        violations.join("\n")
    );
}

#[test]
fn no_enum_is_non_exhaustive() {
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
        "`#[non_exhaustive]` appears in warden-policy:\n{}\n\n\
         It would force downstream crates into a `_ =>` arm and let a new variant \
         compile silently through the wildcard. The required property is the \
         opposite (ADR-0021).",
        violations.join("\n")
    );
}

#[test]
fn no_wildcard_match_arm_exists() {
    let mut violations = Vec::new();
    for path in source_files() {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if WILDCARD_EXEMPT.contains(&name) {
            continue;
        }
        for (number, line) in code_lines(&path) {
            if line.contains("_ =>") {
                violations.push(format!("  {}:{number}: {line}", path.display()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "a wildcard match arm appears in warden-policy:\n{}\n\n\
         Policy matches every variant by name so that adding one to warden-core \
         breaks this crate instead of falling through to whatever the wildcard \
         says (ADR-0011, ADR-0021; AGENTS.md, \"Modeling\"). Name the variant. If \
         the match is genuinely not over a security enum, use a non-wildcard \
         pattern such as `[..]`, or add the file to WILDCARD_EXEMPT with a reason \
         in the commit message.",
        violations.join("\n")
    );
}

#[test]
fn nothing_in_this_crate_deserializes() {
    let mut violations = Vec::new();
    for path in source_files() {
        for (number, line) in code_lines(&path) {
            if line.contains("Deserialize") || line.contains("deserialize") {
                violations.push(format!("  {}:{number}: {line}", path.display()));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "warden-policy mentions deserialization:\n{}\n\n\
         Policy state is produced by evaluation, never parsed. A `Deserialize` impl \
         on any type here would let a JSON document or a TOML file materialize an \
         `AllowDecision`, an `AuthorizedQuery`, or a `DenyReason` that no policy \
         ever agreed to (ADR-0010).",
        violations.join("\n")
    );
}

#[test]
fn deny_reason_never_serializes() {
    let source = read(&crate_src().join("decision.rs"));
    let derives = derives_for(&source, "DenyReason");

    // The guard is worthless if it cannot see a derive list at all, so prove it can
    // by checking for one that is definitely there.
    assert!(
        derives.contains("Debug"),
        "the scan found no derives on `DenyReason`, which derives `Debug`; \
         the parser in this test is broken, not the code it checks"
    );

    assert!(
        !derives.contains("serde::Serialize") && !derives.contains("Serialize"),
        "`DenyReason` derives Serialize: {derives:?}\n\n\
         `internal_detail` is for auditing and tracing and must never cross the MCP \
         boundary (`docs/security.md` section 6). Making the type unserializable is \
         stronger than remembering not to serialize it; serialize `DenyCode` \
         instead."
    );
    assert!(
        !source.contains("impl serde::Serialize for DenyReason"),
        "`DenyReason` implements Serialize by hand"
    );
}

#[test]
fn the_capability_token_cannot_be_derived_into_existence() {
    let source = read(&crate_src().join("state.rs"));

    let allowed: BTreeSet<String> = ["Debug", "PartialEq", "Eq"]
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    let decision = derives_for(&source, "AllowDecision");

    // The guard is worthless if it cannot see a derive list at all, so prove it can
    // by checking for one that is definitely there.
    assert!(
        decision.contains("Debug"),
        "the scan found no derives on `AllowDecision`, which derives `Debug`; \
         the parser in this test is broken, not the code it checks"
    );

    assert!(
        decision.is_subset(&allowed),
        "`AllowDecision` derives more than {allowed:?}: {decision:?}\n\n\
         `Clone` would let a holder transplant an authorization onto different SQL, \
         `Default` would conjure one from nothing, and `Deserialize` would parse \
         one from a document. Each defeats ADR-0010."
    );

    let authorized = derives_for(&source, "AuthorizedQuery");
    let allowed_authorized: BTreeSet<String> = ["Debug", "PartialEq"]
        .iter()
        .map(|name| (*name).to_owned())
        .collect();
    assert!(
        authorized.is_subset(&allowed_authorized),
        "`AuthorizedQuery` derives more than {allowed_authorized:?}: {authorized:?}\n\n\
         It contains an `AllowDecision`, so anything that copies or fabricates it \
         copies or fabricates the token."
    );
}

#[test]
fn the_capability_token_has_no_public_constructor() {
    let source = read(&crate_src().join("state.rs"));
    let constructors = public_constructors(&source, "AllowDecision");

    assert!(
        constructors.is_empty(),
        "`AllowDecision` has a public constructor:\n  {}\n\n\
         Only `warden-policy` may produce the token, so every function returning one \
         is `pub(crate)` (ADR-0010). Making this public would let any crate build an \
         `AuthorizedQuery` around arbitrary SQL.",
        constructors.join("\n  ")
    );

    // The guard is worthless if it cannot see a constructor at all, so prove it can
    // by pointing it at a type that has one.
    assert!(
        !public_constructors(&source, "AnalyzedQuery").is_empty(),
        "the scan found no public constructor on `AnalyzedQuery`, which has one; \
         the parser in this test is broken, not the code it checks"
    );
}

#[test]
fn a_policy_cannot_reach_the_statement() {
    let source = read(&crate_src().join("input.rs"));
    for forbidden in ["QueryRequest", "ParameterValue"] {
        assert!(
            !source
                .lines()
                .map(str::trim)
                .filter(|line| !line.starts_with("//"))
                .any(|line| line.contains(forbidden)),
            "`PolicyInput` mentions `{forbidden}`.\n\n\
             A policy evaluates evidence, not text. Handing it the request would \
             invite matching on SQL, which SPEC section 5.3 rules out, and would let \
             a denial detail carry SQL or a parameter value into an audit record \
             (SPEC section 6, invariants 22-23)."
        );
    }
}

#[test]
fn the_deny_codes_match_the_security_document() {
    let document = security_document();
    let (_, after) = document
        .split_once("pub enum DenyCode {")
        .expect("`docs/security.md` no longer declares DenyCode");
    let block = after
        .split_once('}')
        .expect("the DenyCode declaration is no longer closed")
        .0;

    let documented: Vec<String> = block
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//"))
        .map(|line| snake(line.trim_end_matches(',')))
        .collect();
    let implemented: Vec<String> = DenyCode::ALL
        .iter()
        .map(|code| code.as_str().to_owned())
        .collect();

    assert_eq!(
        documented, implemented,
        "the deny codes drifted from `docs/security.md` section 6.\n\
         The order matters as much as the set: declaration order is precedence \
         order, so the enum and the document change together or not at all."
    );
}

#[test]
fn the_documented_public_messages_are_the_implemented_ones() {
    let document = security_document();
    let expected = [
        (DenyCode::LockingRead, "LockingRead"),
        (DenyCode::UnknownFunction, "UnknownFunction"),
    ];

    for (code, name) in expected {
        let line = document
            .lines()
            .map(str::trim)
            .find(|line| line.starts_with(name) && line.contains("->"))
            .unwrap_or_else(|| panic!("`docs/security.md` no longer shows the {name} message"));
        let documented = line
            .split_once("->")
            .and_then(|(_, rest)| rest.trim().strip_prefix('"'))
            .and_then(|rest| rest.strip_suffix('"'))
            .unwrap_or_else(|| panic!("the {name} message is no longer a quoted string"));

        assert_eq!(
            documented,
            code.public_message(),
            "the {name} message drifted from `docs/security.md` section 6. This text \
             is what the agent reads, so it is a user-facing contract."
        );
    }
}
