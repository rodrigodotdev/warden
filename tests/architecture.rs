//! Mechanical tests for architecture rules that the Rust compiler alone does not
//! enforce, including dependency direction and workspace-lint inheritance.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use proc_macro2::TokenStream;
use serde_json::Value;
use sha2::{Digest, Sha256};
use syn::parse::{Parse, ParseStream};
use syn::visit::Visit;

/// Forbidden dependency-graph edges from `docs/architecture.md` section 3 and SPEC
/// section 6, invariants 27–28.
///
/// `sqlparser` is included beyond the explicit section 3 list because keeping parser
/// ASTs inside adapters is sustainable only when the parser crate stays there too.
const FORBIDDEN_EDGES: &[(&str, &[&str])] = &[
    ("warden-core", &["sqlx", "rmcp", "sqlparser"]),
    ("warden-policy", &["sqlx", "rmcp", "sqlparser"]),
    ("warden-ports", &["sqlx", "rmcp", "sqlparser"]),
    ("warden-config", &["sqlx", "rmcp", "sqlparser"]),
    ("warden-service", &["sqlx", "sqlparser", "rmcp"]),
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
];

const WEBPKI_ROOTS_LICENSE: &str =
    include_str!("../LICENSES/webpki-roots-1.0.9-CDLA-Permissive-2.0.txt");
const WEBPKI_ROOTS_LICENSE_SHA256: &str =
    "e271993808fec50ab29350b39539cdec611a9103f827e0aa26d61da70e2d33f8";

fn rust_source_files_at(directory: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", directory.display()))
    {
        let entry = entry.unwrap_or_else(|error| panic!("could not read directory entry: {error}"));
        let path = entry.path();
        if path.is_dir() {
            rust_source_files_at(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

fn workspace_source_files() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();

    rust_source_files_at(&root.join("src"), &mut files);
    for entry in fs::read_dir(root.join("crates")).expect("could not read workspace crates") {
        let path = entry.expect("could not read crate directory entry").path();
        let source = path.join("src");
        if source.is_dir() {
            rust_source_files_at(&source, &mut files);
        }
    }

    files.sort();
    files
}

fn documented_span_names(operations: &str) -> BTreeSet<String> {
    let section = operations
        .split_once("### 10.1 Spans")
        .expect("docs/operations.md has no section 10.1")
        .1
        .split("\n### ")
        .next()
        .expect("docs/operations.md section 10.1 has no body");
    let mut in_text_block = false;
    let mut names = BTreeSet::new();

    for line in section.lines() {
        match line.trim() {
            "```text" => in_text_block = true,
            "```" if in_text_block => in_text_block = false,
            line if in_text_block => {
                if let Some(name) = line.split_whitespace().last()
                    && name.contains('.')
                    && name.chars().all(|character| {
                        character.is_ascii_lowercase()
                            || character.is_ascii_digit()
                            || character == '_'
                            || character == '.'
                    })
                {
                    names.insert(name.to_owned());
                }
            }
            _ => {}
        }
    }

    names
}

fn cfg_requires_test(meta: &syn::Meta) -> bool {
    match meta {
        syn::Meta::Path(path) => path.is_ident("test"),
        syn::Meta::List(list) if list.path.is_ident("all") => list
            .parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            )
            .is_ok_and(|conditions| conditions.iter().any(cfg_requires_test)),
        syn::Meta::List(list) if list.path.is_ident("any") => list
            .parse_args_with(
                syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
            )
            .is_ok_and(|conditions| {
                !conditions.is_empty() && conditions.iter().all(cfg_requires_test)
            }),
        syn::Meta::List(_) | syn::Meta::NameValue(_) => false,
    }
}

fn is_cfg_test(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("cfg")
            && attribute
                .parse_args::<syn::Meta>()
                .is_ok_and(|meta| cfg_requires_test(&meta))
    })
}

fn module_directory(source: &Path) -> PathBuf {
    let parent = source.parent().expect("Rust source file has no parent");
    match source.file_stem().and_then(|stem| stem.to_str()) {
        Some("lib" | "main" | "mod") => parent.to_owned(),
        Some(stem) => parent.join(stem),
        None => panic!("Rust source file has no UTF-8 stem: {}", source.display()),
    }
}

fn path_override(attributes: &[syn::Attribute]) -> Option<PathBuf> {
    attributes.iter().find_map(|attribute| {
        let syn::Meta::NameValue(name_value) = &attribute.meta else {
            return None;
        };
        if !name_value.path.is_ident("path") {
            return None;
        }
        let syn::Expr::Lit(expression) = &name_value.value else {
            return None;
        };
        let syn::Lit::Str(path) = &expression.lit else {
            return None;
        };
        Some(PathBuf::from(path.value()))
    })
}

fn normalized_path(path: PathBuf) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if normalized.file_name().is_some_and(|name| name != "..") {
                    normalized.pop();
                } else if !normalized.has_root() {
                    normalized.push(component.as_os_str());
                }
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    normalized
}

fn resolved_module_path(directory: &Path, path: PathBuf) -> PathBuf {
    normalized_path(directory.join(path))
}

fn module_sources(
    module: &syn::ItemMod,
    directory: &Path,
    sources: &BTreeMap<PathBuf, syn::File>,
) -> Vec<PathBuf> {
    if let Some(path) = path_override(&module.attrs) {
        let source = resolved_module_path(directory, path);
        return sources
            .contains_key(&source)
            .then_some(source)
            .into_iter()
            .collect();
    }

    let module_path = directory.join(module.ident.to_string());
    [module_path.with_extension("rs"), module_path.join("mod.rs")]
        .into_iter()
        .filter(|source| sources.contains_key(source))
        .collect()
}

fn inline_module_directory(module: &syn::ItemMod, directory: &Path) -> PathBuf {
    path_override(&module.attrs).map_or_else(
        || directory.join(module.ident.to_string()),
        |path| resolved_module_path(directory, path),
    )
}

fn referenced_module_sources(
    items: &[syn::Item],
    directory: &Path,
    sources: &BTreeMap<PathBuf, syn::File>,
    referenced: &mut BTreeSet<PathBuf>,
) {
    for item in items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        if let Some((_brace, items)) = &module.content {
            referenced_module_sources(
                items,
                &inline_module_directory(module, directory),
                sources,
                referenced,
            );
        } else {
            referenced.extend(module_sources(module, directory, sources));
        }
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum SourceReachability {
    Production,
    TestOnly,
}

fn visit_reachable_items(
    items: &[syn::Item],
    directory: &Path,
    reachability: SourceReachability,
    sources: &BTreeMap<PathBuf, syn::File>,
    visited: &mut BTreeSet<(PathBuf, PathBuf, SourceReachability)>,
    active: &mut BTreeSet<(PathBuf, SourceReachability)>,
    production_sources: &mut BTreeSet<PathBuf>,
) {
    for item in items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        let child_reachability =
            if reachability == SourceReachability::TestOnly || is_cfg_test(&module.attrs) {
                SourceReachability::TestOnly
            } else {
                SourceReachability::Production
            };
        if let Some((_brace, items)) = &module.content {
            visit_reachable_items(
                items,
                &inline_module_directory(module, directory),
                child_reachability,
                sources,
                visited,
                active,
                production_sources,
            );
        } else {
            for source in module_sources(module, directory, sources) {
                visit_reachable_source(
                    &source,
                    &directory.join(module.ident.to_string()),
                    child_reachability,
                    sources,
                    visited,
                    active,
                    production_sources,
                );
            }
        }
    }
}

fn visit_reachable_source(
    source: &Path,
    directory: &Path,
    reachability: SourceReachability,
    sources: &BTreeMap<PathBuf, syn::File>,
    visited: &mut BTreeSet<(PathBuf, PathBuf, SourceReachability)>,
    active: &mut BTreeSet<(PathBuf, SourceReachability)>,
    production_sources: &mut BTreeSet<PathBuf>,
) {
    let Some(syntax) = sources.get(source) else {
        return;
    };
    let visit = (source.to_owned(), directory.to_owned(), reachability);
    if !visited.insert(visit) {
        return;
    }
    if reachability == SourceReachability::Production {
        production_sources.insert(source.to_owned());
    }
    let active_visit = (source.to_owned(), reachability);
    if !active.insert(active_visit.clone()) {
        return;
    }
    visit_reachable_items(
        &syntax.items,
        directory,
        reachability,
        sources,
        visited,
        active,
        production_sources,
    );
    active.remove(&active_visit);
}

fn next_is_metadata(input: ParseStream<'_>, expected: &str) -> bool {
    let ahead = input.fork();
    let Ok(name) = ahead.parse::<syn::Ident>() else {
        return false;
    };
    name == expected && ahead.peek(syn::Token![:])
}

fn parse_metadata(input: ParseStream<'_>) -> syn::Result<()> {
    let _name: syn::Ident = input.parse()?;
    let _colon: syn::Token![:] = input.parse()?;
    let _value: syn::Expr = input.parse()?;
    let _comma: syn::Token![,] = input.parse()?;
    Ok(())
}

struct SpanMacroHeader {
    name: syn::Expr,
}

impl Parse for SpanMacroHeader {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        if next_is_metadata(input, "target") {
            parse_metadata(input)?;
        }
        if next_is_metadata(input, "parent") {
            parse_metadata(input)?;
        }
        let name = input.parse()?;
        let _remaining: TokenStream = input.parse()?;
        Ok(Self { name })
    }
}

fn span_name_literal(tokens: TokenStream) -> Option<String> {
    let header = syn::parse2::<SpanMacroHeader>(tokens).ok()?;
    let syn::Expr::Lit(expression) = header.name else {
        return None;
    };
    let syn::Lit::Str(name) = expression.lit else {
        return None;
    };
    Some(name.value())
}

#[derive(Default)]
struct SpanNameVisitor {
    names: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for SpanNameVisitor {
    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        if is_cfg_test(&module.attrs) {
            return;
        }
        syn::visit::visit_item_mod(self, module);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let is_span = node.path.segments.last().is_some_and(|segment| {
            matches!(
                segment.ident.to_string().as_str(),
                "info_span" | "debug_span" | "trace_span" | "warn_span" | "error_span"
            )
        });
        if is_span && let Some(name) = span_name_literal(node.tokens.clone()) {
            self.names.insert(name);
        }
        syn::visit::visit_macro(self, node);
    }
}

fn created_span_names(paths: &[PathBuf]) -> BTreeSet<String> {
    let sources: BTreeMap<_, _> = paths
        .iter()
        .map(|path| {
            let source = fs::read_to_string(path)
                .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
            let syntax = syn::parse_file(&source)
                .unwrap_or_else(|error| panic!("could not parse {}: {error}", path.display()));
            (path.to_owned(), syntax)
        })
        .collect();
    let mut referenced = BTreeSet::new();
    for (path, syntax) in &sources {
        referenced_module_sources(
            &syntax.items,
            &module_directory(path),
            &sources,
            &mut referenced,
        );
    }

    let roots: Vec<_> = sources
        .keys()
        .filter(|path| {
            matches!(
                path.file_name().and_then(|name| name.to_str()),
                Some("lib.rs" | "main.rs")
            ) || !referenced.contains(*path)
        })
        .cloned()
        .collect();
    let mut visited = BTreeSet::new();
    let mut active = BTreeSet::new();
    let mut production_sources = BTreeSet::new();
    for root in roots {
        visit_reachable_source(
            &root,
            &module_directory(&root),
            SourceReachability::Production,
            &sources,
            &mut visited,
            &mut active,
            &mut production_sources,
        );
    }

    let mut visitor = SpanNameVisitor::default();
    for (path, syntax) in sources {
        if production_sources.contains(&path) {
            visitor.visit_file(&syntax);
        }
    }
    visitor.names
}

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

/// Span names Warden creates, read out of the workspace's own source.
///
/// `docs/operations.md` section 10.1 is the tree an operator reads, and a tree that
/// drifts from the code is worse than no tree: it sends someone hunting for a span
/// that no longer exists. This parses both and compares them (ADR-0044).
#[test]
fn the_documented_span_tree_is_the_one_the_workspace_creates() {
    let documented = documented_span_names(&fs::read_to_string("docs/operations.md").unwrap());
    let created = created_span_names(&workspace_source_files());
    assert_eq!(created, documented);
}

#[test]
fn span_source_parser_ignores_test_only_modules() {
    let syntax = syn::parse_file(
        r#"
        fn production() {
            tracing::debug_span!("production.phase");
        }

        #[cfg(test)]
        mod tests {
            fn helper() {
                tracing::debug_span!("test.helper");
            }
        }
        "#,
    )
    .unwrap();
    let mut visitor = SpanNameVisitor::default();
    visitor.visit_file(&syntax);
    assert_eq!(
        visitor.names,
        BTreeSet::from(["production.phase".to_owned()])
    );
}

#[test]
fn span_source_parser_reads_the_name_slot_for_every_supported_macro() {
    let syntax = syn::parse_file(
        r#"
        fn production(parent: &tracing::Span, dynamic_name: &'static str) {
            tracing::info_span!("plain.info", detail = "not.a.name");
            tracing::debug_span!(
                target: "warden.db",
                "targeted.debug",
                detail = "also.not.a.name"
            );
            tracing::trace_span!(parent: parent, "parented.trace", detail = "not.this");
            tracing::warn_span!(
                target: "warden.db",
                parent: parent,
                "targeted.parented.warn",
                detail = "nor.this"
            );
            tracing::error_span!("plain.error");
            tracing::debug_span!(dynamic_name, detail = "field.value.is.not.a.name");
        }
        "#,
    )
    .unwrap();
    let mut visitor = SpanNameVisitor::default();
    visitor.visit_file(&syntax);
    assert_eq!(
        visitor.names,
        BTreeSet::from([
            "parented.trace".to_owned(),
            "plain.error".to_owned(),
            "plain.info".to_owned(),
            "targeted.debug".to_owned(),
            "targeted.parented.warn".to_owned(),
        ])
    );
}

#[test]
fn span_source_discovery_skips_direct_nested_and_path_test_modules() {
    let fixture = SourceFixture::new();
    fixture.write(
        "lib.rs",
        r#"
        fn production() {
            tracing::info_span!("production.root");
        }

        #[cfg(test)]
        mod direct;

        #[cfg(test)]
        mod directory_form;

        #[cfg(test)]
        mod tests {
            mod support;
        }

        #[cfg(test)]
        #[path = "custom.rs"]
        mod custom_tests;
        "#,
    );
    fixture.write(
        "direct.rs",
        r#"fn helper() { tracing::debug_span!("test.direct"); }"#,
    );
    fixture.write(
        "directory_form/mod.rs",
        r#"fn helper() { tracing::debug_span!("test.directory.form"); }"#,
    );
    fixture.write(
        "tests/support.rs",
        r#"fn helper() { tracing::trace_span!("test.nested.support"); }"#,
    );
    fixture.write(
        "custom.rs",
        r#"fn helper() { tracing::warn_span!("test.path.override"); }"#,
    );

    assert_eq!(
        created_span_names(&fixture.source_files()),
        BTreeSet::from(["production.root".to_owned()])
    );
}

#[test]
fn span_source_discovery_skips_path_directory_below_an_inline_test_module() {
    let fixture = SourceFixture::new();
    fixture.write(
        "lib.rs",
        r#"
        fn production() {
            tracing::info_span!("production.root");
        }

        #[cfg(test)]
        #[path = "thread_files"]
        mod thread {
            #[path = "tls.rs"]
            mod local_data;
        }
        "#,
    );
    fixture.write(
        "thread_files/tls.rs",
        r#"fn helper() { tracing::debug_span!("test.path.directory"); }"#,
    );

    assert_eq!(
        created_span_names(&fixture.source_files()),
        BTreeSet::from(["production.root".to_owned()])
    );
}

#[test]
fn span_source_discovery_skips_test_only_path_aliases() {
    let fixture = SourceFixture::new();
    fixture.write(
        "lib.rs",
        r#"
        fn production() {
            tracing::info_span!("production.root");
        }

        #[cfg(test)]
        mod tests {
            #[path = "../test_support.rs"]
            mod support;
        }
        "#,
    );
    fixture.write(
        "test_support.rs",
        r#"fn helper() { tracing::debug_span!("test.path.alias"); }"#,
    );

    assert_eq!(
        created_span_names(&fixture.source_files()),
        BTreeSet::from(["production.root".to_owned()])
    );
}

#[test]
fn span_source_discovery_terminates_on_absolute_path_alias_cycles() {
    let fixture = SourceFixture::new();
    let source = fixture.root.join("shared.rs");
    let source = source.to_string_lossy();
    fixture.write("lib.rs", &format!(r#"#[path = "{source}"] mod first;"#));
    fixture.write(
        "shared.rs",
        &format!(
            r#"
            #[path = "{source}"]
            mod second;

            fn production() {{
                tracing::info_span!("production.cycle");
            }}
            "#
        ),
    );

    assert_eq!(
        created_span_names(&fixture.source_files()),
        BTreeSet::from(["production.cycle".to_owned()])
    );
}

#[test]
fn span_source_discovery_keeps_a_file_with_production_and_test_reachability() {
    let fixture = SourceFixture::new();
    fixture.write(
        "lib.rs",
        r#"
        mod production;

        #[cfg(test)]
        #[path = "production.rs"]
        mod test_support;
        "#,
    );
    fixture.write(
        "production.rs",
        r#"fn production() { tracing::error_span!("production.shared"); }"#,
    );

    assert_eq!(
        created_span_names(&fixture.source_files()),
        BTreeSet::from(["production.shared".to_owned()])
    );
}

static NEXT_SOURCE_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct SourceFixture {
    root: PathBuf,
}

impl SourceFixture {
    fn new() -> Self {
        let sequence = NEXT_SOURCE_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "warden-architecture-span-source-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        Self { root }
    }

    fn write(&self, relative: &str, source: &str) {
        let path = self.root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, source).unwrap();
    }

    fn source_files(&self) -> Vec<PathBuf> {
        let mut files = Vec::new();
        rust_source_files_at(&self.root, &mut files);
        files.sort();
        files
    }
}

impl Drop for SourceFixture {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.root);
    }
}
