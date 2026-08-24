//! Mechanical tests for architecture rules that the Rust compiler alone does not
//! enforce, including dependency direction and workspace-lint inheritance.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;
use sha2::{Digest, Sha256};

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

const WEBPKI_ROOTS_LICENSE: &str =
    include_str!("../LICENSES/webpki-roots-1.0.9-CDLA-Permissive-2.0.txt");
const WEBPKI_ROOTS_LICENSE_SHA256: &str =
    "e271993808fec50ab29350b39539cdec611a9103f827e0aa26d61da70e2d33f8";

/// The notice CDLA-Permissive-2.0 requires a redistribution to carry.
const REQUIRED_NOTICE: &str = "LICENSES/webpki-roots-1.0.9-CDLA-Permissive-2.0.txt";
/// Where `docs/operations.md` section 2.7 says a release image keeps it.
const LICENSE_DESTINATION: &str = "/opt/warden/LICENSES";

fn container_build_files(directory: &Path, files: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", directory.display()))
    {
        let entry = entry.unwrap_or_else(|error| panic!("could not read directory entry: {error}"));
        let path = entry.path();
        if path.is_dir() {
            let ignored = matches!(
                path.file_name().and_then(|name| name.to_str()),
                Some(".git" | ".superpowers" | "target")
            );
            if !ignored {
                container_build_files(&path, files);
            }
            continue;
        }
        if matches!(
            path.file_name().and_then(|name| name.to_str()),
            Some("Dockerfile" | "Containerfile")
        ) {
            files.push(path);
        }
    }
}

fn logical_docker_instructions(contents: &str) -> Vec<String> {
    let mut instructions = Vec::new();
    let mut current = String::new();

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let continued = line.ends_with('\\');
        let fragment = if continued {
            &line[..line.len() - 1]
        } else {
            line
        };
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(fragment.trim_end());
        if !continued {
            instructions.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        instructions.push(current);
    }

    instructions
}

fn strip_copy_flags(mut arguments: &str) -> Option<&str> {
    loop {
        arguments = arguments.trim_start();
        if !arguments.starts_with("--") {
            return Some(arguments);
        }
        let flag_end = arguments.find(char::is_whitespace)?;
        let flag = &arguments[..flag_end];
        arguments = &arguments[flag_end..];
        if !flag.contains('=') && matches!(flag, "--chown" | "--chmod" | "--exclude") {
            let value_end = arguments.trim_start().find(char::is_whitespace)?;
            arguments = &arguments.trim_start()[value_end..];
        }
    }
}

fn shell_words(arguments: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut escaped = false;

    for character in arguments.chars() {
        if escaped {
            word.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' && quote != Some('\'') {
            escaped = true;
            continue;
        }
        if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            } else {
                word.push(character);
            }
            continue;
        }
        if character.is_whitespace() && quote.is_none() {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
        } else {
            word.push(character);
        }
    }
    if escaped || quote.is_some() {
        return None;
    }
    if !word.is_empty() {
        words.push(word);
    }
    Some(words)
}

/// The sources and the destination of one `COPY`, in either syntax.
fn copy_paths(instruction: &str) -> Option<(Vec<String>, String)> {
    let (keyword, arguments) = instruction.trim().split_once(char::is_whitespace)?;
    if !keyword.eq_ignore_ascii_case("COPY") {
        return None;
    }
    let arguments = strip_copy_flags(arguments)?;
    let mut paths = if arguments.starts_with('[') {
        serde_json::from_str::<Vec<String>>(arguments).ok()?
    } else {
        shell_words(arguments)?
    };
    if paths.len() < 2 {
        return None;
    }
    let destination = paths.pop()?;
    Some((paths, destination))
}

/// The instructions of the image that actually ships, and no earlier stage's.
///
/// A notice copied into a builder stage is discarded with that stage. Only the last
/// `FROM` opens the stage a release artifact is built from.
fn final_stage_instructions(contents: &str) -> Vec<String> {
    let instructions = logical_docker_instructions(contents);
    let last_from = instructions.iter().rposition(|instruction| {
        instruction
            .split_once(char::is_whitespace)
            .is_some_and(|(keyword, _)| keyword.eq_ignore_ascii_case("FROM"))
    });
    match last_from {
        Some(index) => instructions[index + 1..].to_vec(),
        None => Vec::new(),
    }
}

/// Whether a `COPY` source is the notice itself or the directory holding it.
///
/// A normalized path only: `./LICENSES` and `../LICENSES` are rejected because the
/// check has to describe one build context, not every spelling of one.
fn is_required_license_source(source: &str) -> bool {
    source == "LICENSES" || source == REQUIRED_NOTICE
}

/// Whether a `COPY` destination is the documented notice directory, or the notice's
/// own path inside it.
fn is_license_destination(destination: &str) -> bool {
    let trimmed = destination.strip_suffix('/').unwrap_or(destination);
    let notice = REQUIRED_NOTICE
        .strip_prefix("LICENSES/")
        .unwrap_or(REQUIRED_NOTICE);
    trimmed == LICENSE_DESTINATION || trimmed == format!("{LICENSE_DESTINATION}/{notice}")
}

/// Whether the shipping image carries the required notice at its documented path.
fn dockerfile_copies_licenses(contents: &str) -> bool {
    final_stage_instructions(contents)
        .iter()
        .filter_map(|instruction| copy_paths(instruction))
        .any(|(sources, destination)| {
            is_license_destination(&destination)
                && sources
                    .iter()
                    .any(|source| is_required_license_source(source))
        })
}

fn sha256_hex(contents: &str) -> String {
    use std::fmt::Write as _;

    let digest = Sha256::digest(contents.as_bytes());
    let mut hexadecimal = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut hexadecimal, "{byte:02x}").expect("writing to a String cannot fail");
    }
    hexadecimal
}

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

/// The features `cargo metadata` resolved for one node.
fn resolved_features(node: &Value) -> Vec<&str> {
    node["features"]
        .as_array()
        .expect("node has no `features`")
        .iter()
        .filter_map(Value::as_str)
        .collect()
}

/// The features one resolved package ended up with, by package name.
fn features_of<'a>(md: &'a Value, package: &str) -> Vec<&'a str> {
    let names = package_names(md);
    md["resolve"]["nodes"]
        .as_array()
        .expect("missing `resolve.nodes`")
        .iter()
        .find(|node| {
            let id = node["id"].as_str().expect("node has no id");
            names.get(id).map(String::as_str) == Some(package)
        })
        .map(resolved_features)
        .unwrap_or_else(|| panic!("{package} is not in the dependency graph"))
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

        let features: Vec<&str> = resolved_features(node);

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

#[test]
fn sqlx_core_still_compiles_the_migration_and_any_modules() {
    // Not an aspiration: a pin on a limitation ADR-0004 records. `sqlx` 0.9.0
    // declares `sqlx-core` with `features = ["migrate"]` unconditionally and inherits
    // its defaults, which include `any`, so both modules compile no matter what the
    // facade's features say. The test above is what keeps the *API* out of reach;
    // this one fails the day upstream changes that, so the ADR is revisited rather
    // than quietly outdated.
    let md = metadata();
    let features = features_of(&md, "sqlx-core");
    for compiled in ["migrate", "any"] {
        assert!(
            features.contains(&compiled),
            "sqlx-core no longer compiles `{compiled}`. ADR-0004 records that it \
             does and that Warden accepts it; update the ADR and this pin together. \
             Resolved features: {features:?}"
        );
    }
}

#[test]
fn distributed_webpki_roots_license_is_complete_and_future_images_copy_licenses() {
    assert_eq!(
        sha256_hex(WEBPKI_ROOTS_LICENSE),
        WEBPKI_ROOTS_LICENSE_SHA256,
        "the vendored third-party notice must remain byte-for-byte faithful to \
         webpki-roots@1.0.9's LICENSE"
    );

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut container_files = Vec::new();
    container_build_files(&root, &mut container_files);
    for file in container_files {
        let contents = std::fs::read_to_string(&file)
            .unwrap_or_else(|error| panic!("could not read {}: {error}", file.display()));
        assert!(
            dockerfile_copies_licenses(&contents),
            "{} must copy LICENSES, or the webpki-roots notice itself, to \
             {LICENSE_DESTINATION} in its final stage; CDLA-Permissive-2.0 requires \
             the license text to accompany the redistributed root data",
            file.display()
        );
    }
}

#[test]
fn docker_copy_parser_accepts_normalized_license_source_with_flags_and_continuation() {
    let fixture = r#"
        FROM scratch AS final
        COPY --chown=warden:warden --chmod=0644 \
          LICENSES/webpki-roots-1.0.9-CDLA-Permissive-2.0.txt /opt/warden/LICENSES/
    "#;
    assert!(dockerfile_copies_licenses(fixture));
}

#[test]
fn docker_copy_parser_accepts_normalized_license_source_in_json_form() {
    assert!(dockerfile_copies_licenses(
        r#"
            FROM scratch AS final
            COPY ["LICENSES", "/opt/warden/LICENSES/"]
        "#
    ));
}

#[test]
fn docker_copy_parser_rejects_license_destination_and_non_normalized_source() {
    let destination_only = "FROM scratch\nCOPY --link app /opt/warden/LICENSES";
    let non_normalized_source = "FROM scratch\nCOPY ./LICENSES /opt/warden/LICENSES";
    assert!(!dockerfile_copies_licenses(destination_only));
    assert!(!dockerfile_copies_licenses(non_normalized_source));
}

#[test]
fn docker_copy_parser_rejects_an_unrelated_child_of_licenses() {
    let fixture = "FROM scratch\nCOPY LICENSES/unrelated.txt /opt/warden/LICENSES/";
    assert!(!dockerfile_copies_licenses(fixture));
}

#[test]
fn docker_copy_parser_rejects_the_required_notice_at_the_wrong_destination() {
    let fixture = concat!(
        "FROM scratch\n",
        "COPY LICENSES/webpki-roots-1.0.9-CDLA-Permissive-2.0.txt /tmp/notice.txt",
    );
    assert!(!dockerfile_copies_licenses(fixture));
}

#[test]
fn docker_copy_parser_rejects_a_notice_copied_only_into_a_builder_stage() {
    let fixture = concat!(
        "FROM rust:1 AS builder\n",
        "COPY LICENSES /opt/warden/LICENSES/\n",
        "FROM scratch AS final\n",
        "COPY --from=builder /app/warden /usr/local/bin/warden\n",
    );
    assert!(!dockerfile_copies_licenses(fixture));
}
