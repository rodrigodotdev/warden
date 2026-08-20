//! Mechanical tests for architecture rules that the Rust compiler alone does not
//! enforce, including dependency direction and workspace-lint inheritance.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

/// Forbidden dependency-graph edges from `docs/architecture.md` section 3 and SPEC
/// section 6, invariants 27–28.
///
/// `sqlparser` is included beyond the explicit section 3 list because keeping parser
/// ASTs inside adapters is sustainable only when the parser crate stays there too.
/// The disposable `warden-tracer` intentionally depends on both SQLx and rmcp.
const FORBIDDEN_EDGES: &[(&str, &[&str])] = &[
    ("warden-core", &["sqlx", "rmcp", "sqlparser"]),
    ("warden-policy", &["sqlx", "rmcp", "sqlparser"]),
    ("warden-ports", &["sqlx", "rmcp", "sqlparser"]),
    ("warden-config", &["sqlx", "rmcp", "sqlparser"]),
    ("warden-service", &["sqlx", "sqlparser"]),
    ("warden-mcp", &["sqlx", "sqlparser"]),
    ("warden-mysql", &["rmcp"]),
    ("warden-postgres", &["rmcp"]),
];

/// Expected workspace crates. Adding one requires an explicit boundary decision.
const EXPECTED_MEMBERS: &[&str] = &[
    "warden",
    "warden-config",
    "warden-core",
    "warden-mcp",
    "warden-mysql",
    "warden-policy",
    "warden-ports",
    "warden-postgres",
    "warden-service",
    // Remove this entry with the disposable M0.5 crate after Milestone 12.
    "warden-tracer",
];

fn metadata() -> Value {
    let output = Command::new(env!("CARGO"))
        .args(["metadata", "--format-version", "1"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("failed to execute `cargo metadata`");

    assert!(
        output.status.success(),
        "`cargo metadata` failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    serde_json::from_slice(&output.stdout).expect("`cargo metadata` returned invalid JSON")
}

/// Maps package IDs to names.
fn package_names(md: &Value) -> BTreeMap<String, String> {
    md["packages"]
        .as_array()
        .expect("missing `packages` field")
        .iter()
        .map(|p| {
            (
                p["id"].as_str().expect("package has no id").to_owned(),
                p["name"].as_str().expect("package has no name").to_owned(),
            )
        })
        .collect()
}

/// Dependency graph excluding dev-dependency edges.
///
/// Dev dependencies do not enter production artifacts. Build dependencies remain
/// included because build scripts execute arbitrary code during compilation and are
/// part of the trust surface even when they are not linked into the final artifact.
fn graph(md: &Value) -> BTreeMap<String, BTreeSet<String>> {
    md["resolve"]["nodes"]
        .as_array()
        .expect("missing `resolve.nodes`; did `cargo metadata` run with --no-deps?")
        .iter()
        .map(|node| {
            let id = node["id"].as_str().expect("node has no id").to_owned();
            let deps = node["deps"]
                .as_array()
                .expect("node has no `deps`")
                .iter()
                .filter(|d| {
                    d["dep_kinds"]
                        .as_array()
                        .map(|kinds| {
                            kinds
                                .iter()
                                .any(|k| k["kind"].is_null() || k["kind"].as_str() == Some("build"))
                        })
                        .unwrap_or(true)
                })
                .map(|d| {
                    d["pkg"]
                        .as_str()
                        .expect("dependency has no package")
                        .to_owned()
                })
                .collect();
            (id, deps)
        })
        .collect()
}

/// Returns a dependency path from `from` to a package named `target`, if one exists.
fn reaches(
    graph: &BTreeMap<String, BTreeSet<String>>,
    names: &BTreeMap<String, String>,
    from: &str,
    target: &str,
) -> Option<Vec<String>> {
    let start = names
        .iter()
        .find(|(_, name)| name.as_str() == from)
        .map(|(id, _)| id.clone())?;

    let mut queue = vec![vec![start]];
    let mut seen = BTreeSet::new();

    while let Some(path) = queue.pop() {
        let current = path.last().expect("empty path").clone();
        if !seen.insert(current.clone()) {
            continue;
        }
        if names.get(&current).map(String::as_str) == Some(target) && path.len() > 1 {
            return Some(path.iter().map(|id| names[id].clone()).collect());
        }
        for dep in graph.get(&current).into_iter().flatten() {
            let mut next = path.clone();
            next.push(dep.clone());
            queue.push(next);
        }
    }

    None
}

#[test]
fn dependency_direction_is_respected() {
    let md = metadata();
    let names = package_names(&md);
    let graph = graph(&md);

    let mut violations = Vec::new();

    for (member, forbidden) in FORBIDDEN_EDGES {
        for target in *forbidden {
            if let Some(path) = reaches(&graph, &names, member, target) {
                violations.push(format!(
                    "  {} → {}  (via {})",
                    member,
                    target,
                    path.join(" → ")
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "forbidden dependency edges (docs/architecture.md section 3):\n{}\n\n\
         If this change is deliberate, write an ADR in docs/adr/ before relaxing \
         the rule (AGENTS.md, process rule 4).",
        violations.join("\n")
    );
}

#[test]
fn every_workspace_member_inherits_workspace_lints() {
    let md = metadata();
    let names = package_names(&md);

    let members: Vec<&str> = md["workspace_members"]
        .as_array()
        .expect("missing `workspace_members` field")
        .iter()
        .map(|id| names[id.as_str().expect("invalid package id")].as_str())
        .collect();

    let mut missing = Vec::new();

    for package in md["packages"].as_array().expect("missing `packages` field") {
        let name = package["name"].as_str().expect("package has no name");
        if !members.contains(&name) {
            continue;
        }

        let manifest_path = PathBuf::from(
            package["manifest_path"]
                .as_str()
                .expect("package has no manifest_path"),
        );
        let raw = std::fs::read_to_string(&manifest_path)
            .unwrap_or_else(|e| panic!("could not read {}: {e}", manifest_path.display()));
        let manifest: toml::Value = toml::from_str(&raw)
            .unwrap_or_else(|e| panic!("invalid TOML in {}: {e}", manifest_path.display()));

        let inherits = manifest
            .get("lints")
            .and_then(|l| l.get("workspace"))
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);

        if !inherits {
            missing.push(name.to_owned());
        }
    }

    assert!(
        missing.is_empty(),
        "these member crates do not declare `[lints] workspace = true` and therefore \
         inherit no workspace lints, including `unsafe_code = \"forbid\"`:\n  {}\n\n\
         See docs/operations.md section 12.1. This test exists because the failure \
         would otherwise be silent.",
        missing.join("\n  ")
    );
}

#[test]
fn workspace_members_match_the_expected_set() {
    let md = metadata();
    let names = package_names(&md);

    let mut actual: Vec<String> = md["workspace_members"]
        .as_array()
        .expect("missing `workspace_members` field")
        .iter()
        .map(|id| names[id.as_str().expect("invalid package id")].clone())
        .collect();
    actual.sort();

    let expected: Vec<String> = EXPECTED_MEMBERS.iter().map(|s| (*s).to_owned()).collect();

    assert_eq!(
        actual, expected,
        "the workspace member set changed. A new crate needs an entry in \
         FORBIDDEN_EDGES and a boundary justification (docs/architecture.md \
         section 2: \"Do not add crates without a concrete boundary reason\")."
    );
}

#[test]
fn no_workspace_member_is_publishable() {
    let md = metadata();

    let publishable: Vec<&str> = md["packages"]
        .as_array()
        .expect("missing `packages` field")
        .iter()
        .filter(|p| p["source"].is_null())
        .filter(|p| p["publish"].as_array().map(Vec::is_empty) != Some(true))
        .map(|p| p["name"].as_str().expect("package has no name"))
        .collect();

    assert!(
        publishable.is_empty(),
        "these crates can be published to crates.io: {publishable:?}\n\
         Warden is an application; security-gateway internals must not become public \
         APIs accidentally. Use `publish = false`."
    );
}

#[test]
fn sqlx_any_feature_is_never_enabled() {
    let md = metadata();
    let names = package_names(&md);

    for node in md["resolve"]["nodes"]
        .as_array()
        .expect("missing `resolve.nodes`")
    {
        let id = node["id"].as_str().expect("node has no id");
        if names.get(id).map(String::as_str) != Some("sqlx") {
            continue;
        }

        let features: Vec<&str> = node["features"]
            .as_array()
            .expect("node has no `features`")
            .iter()
            .filter_map(Value::as_str)
            .collect();

        assert!(
            !features.contains(&"any"),
            "SQLx feature `any` is enabled, exposing `sqlx::AnyPool` in violation \
             of ADR-0005. Resolved features: {features:?}\n\
             A dependency enabled it through feature unification; locate it with \
             `cargo tree -e features -i sqlx`."
        );
        assert!(
            !features.contains(&"migrate"),
            "SQLx feature `migrate` is enabled, compiling a DDL migration executor \
             into a declared read-only gateway. Resolved features: {features:?}"
        );
    }
}
