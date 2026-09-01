//! Mechanical guards for service-layer rules the Rust compiler cannot express.
//!
//! `tests/architecture.rs` guards the dependency graph and this separate crate sees
//! the same public surface as `warden-mcp` and the composition root. These narrow
//! syntax checks deliberately complement behavioral tests for invariants that have
//! no compiler representation (R5).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use proc_macro2::{Ident, TokenStream, TokenTree};
use syn::visit::Visit;
use tokio_util::sync::CancellationToken;
use warden_core::connection::{ConnectionMetadata, ConnectionName, Environment};
use warden_core::dialect::Dialect;
use warden_policy::{PolicyEngine, PolicySettings};
use warden_ports::{AuditAttempt, AuditError, AuditOutcomeEvent, BoxFuture, ConnectionError};
use warden_service::{
    AuditSink, ConnectionRegistry, ConnectionRuntime, ConnectionRuntimeParts, ExplainService,
    QueryService, RedactionRuleError, RedactionSettings, RuntimeError, SchemaService,
    ServiceBuildError, ServiceParts, Services,
};

/// Runtime methods that reach a database or take a concurrency slot. `pipeline.rs`
/// is the only source file allowed to name them (ADR-0038). Schema inspection uses
/// the separate control pool and is deliberately outside this gate.
const GATED_CALLS: &[&str] = &[".executor()", ".explainer()", ".acquire_query_permit()"];

/// Every `ConnectionRuntime` accessor that hands out a port or a permit — the surface
/// [`GATED_CALLS`] is a decision *about*, rather than an unrelated list beside it.
///
/// `inspector` is the one documented exception: a catalog read runs on the separate
/// control pool with adapter-owned SQL, so it takes no agent slot and is deliberately
/// not gated (`src/schema.rs`; ADR-0025). The other three are.
///
/// `the_gated_list_covers_every_accessor_that_hands_out_a_port_or_a_permit` reads this
/// set back out of `crates/warden-ports/src/runtime.rs`, so a fifth such accessor turns
/// that test red until someone decides whether it belongs in [`GATED_CALLS`].
const PORT_AND_PERMIT_ACCESSORS: &[&str] =
    &["acquire_query_permit", "executor", "explainer", "inspector"];

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn ports_src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../warden-ports/src")
}

fn rust_source_files() -> Vec<PathBuf> {
    let root = src_dir();
    let test_only_modules = cfg_test_modules(&fs::read_to_string(root.join("lib.rs")).unwrap());
    rust_source_files_at(&root)
        .unwrap()
        .into_iter()
        .filter(|path| path != &root.join("testing.rs") || !test_only_modules.contains("testing"))
        .collect()
}

fn rust_source_files_at(root: &Path) -> io::Result<Vec<PathBuf>> {
    fn collect(directory: &Path, files: &mut Vec<PathBuf>) -> io::Result<()> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let path = entry.path();
            if file_type.is_dir() {
                collect(&path, files)?;
            } else if file_type.is_file()
                && path.extension().is_some_and(|extension| extension == "rs")
            {
                files.push(path);
            }
        }
        Ok(())
    }

    let mut files = Vec::new();
    collect(root, &mut files)?;
    files.sort();
    Ok(files)
}

fn is_cfg_test(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("cfg")
            && attribute
                .parse_args::<syn::Ident>()
                .is_ok_and(|condition| condition == "test")
    })
}

fn item_attributes(item: &syn::Item) -> &[syn::Attribute] {
    match item {
        syn::Item::Const(item) => &item.attrs,
        syn::Item::Enum(item) => &item.attrs,
        syn::Item::ExternCrate(item) => &item.attrs,
        syn::Item::Fn(item) => &item.attrs,
        syn::Item::ForeignMod(item) => &item.attrs,
        syn::Item::Impl(item) => &item.attrs,
        syn::Item::Macro(item) => &item.attrs,
        syn::Item::Mod(item) => &item.attrs,
        syn::Item::Static(item) => &item.attrs,
        syn::Item::Struct(item) => &item.attrs,
        syn::Item::Trait(item) => &item.attrs,
        syn::Item::TraitAlias(item) => &item.attrs,
        syn::Item::Type(item) => &item.attrs,
        syn::Item::Union(item) => &item.attrs,
        syn::Item::Use(item) => &item.attrs,
        syn::Item::Verbatim(_) => &[],
        _ => &[],
    }
}

fn impl_item_attributes(item: &syn::ImplItem) -> &[syn::Attribute] {
    match item {
        syn::ImplItem::Const(item) => &item.attrs,
        syn::ImplItem::Fn(item) => &item.attrs,
        syn::ImplItem::Type(item) => &item.attrs,
        syn::ImplItem::Macro(item) => &item.attrs,
        syn::ImplItem::Verbatim(_) => &[],
        _ => &[],
    }
}

fn trait_item_attributes(item: &syn::TraitItem) -> &[syn::Attribute] {
    match item {
        syn::TraitItem::Const(item) => &item.attrs,
        syn::TraitItem::Fn(item) => &item.attrs,
        syn::TraitItem::Type(item) => &item.attrs,
        syn::TraitItem::Macro(item) => &item.attrs,
        syn::TraitItem::Verbatim(_) => &[],
        _ => &[],
    }
}

fn foreign_item_attributes(item: &syn::ForeignItem) -> &[syn::Attribute] {
    match item {
        syn::ForeignItem::Fn(item) => &item.attrs,
        syn::ForeignItem::Static(item) => &item.attrs,
        syn::ForeignItem::Type(item) => &item.attrs,
        syn::ForeignItem::Macro(item) => &item.attrs,
        syn::ForeignItem::Verbatim(_) => &[],
        _ => &[],
    }
}

fn gated_call(method: &str) -> Option<&'static str> {
    GATED_CALLS.iter().copied().find(|call| {
        call.strip_prefix('.')
            .and_then(|call| call.strip_suffix("()"))
            .is_some_and(|name| method == name)
    })
}

fn normalized_identifier(identifier: &Ident) -> String {
    let identifier = identifier.to_string();
    identifier
        .strip_prefix("r#")
        .unwrap_or(&identifier)
        .to_owned()
}

fn path_ends_with(path: &syn::Path, expected: &str) -> bool {
    path.segments
        .last()
        .is_some_and(|segment| normalized_identifier(&segment.ident) == expected)
}

fn type_ends_with(ty: &syn::Type, expected: &str) -> bool {
    matches!(ty, syn::Type::Path(path) if path_ends_with(&path.path, expected))
}

/// The bare method names behind [`GATED_CALLS`]'s `.method()` spelling.
fn gated_call_names() -> BTreeSet<String> {
    GATED_CALLS
        .iter()
        .map(|call| {
            call.strip_prefix('.')
                .and_then(|call| call.strip_suffix("()"))
                .expect("every gated call is spelled `.method()`")
                .to_owned()
        })
        .collect()
}

/// Every identifier a type names, including through references, generic arguments, and
/// `dyn` bounds — so `&dyn QueryExecutor` and `Result<QueryPermit, ConnectionError>` are
/// both visible as the names they mention.
#[derive(Default)]
struct TypeIdentifiers {
    names: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for TypeIdentifiers {
    fn visit_ident(&mut self, node: &'ast Ident) {
        self.names.insert(normalized_identifier(node));
    }
}

fn return_type_identifiers(output: &syn::ReturnType) -> BTreeSet<String> {
    let mut identifiers = TypeIdentifiers::default();
    if let syn::ReturnType::Type(_, ty) = output {
        identifiers.visit_type(ty);
    }
    identifiers.names
}

/// The `warden-ports` traits whose calls leave this process.
///
/// The discriminator is a declared [`warden_ports::BoxFuture`] return, not merely
/// `pub`: ADR-0013 requires every dynamically dispatched call that runs SQL to spell
/// its future out as that alias, so it is `warden-ports`' own marker for "this port
/// reaches a database". `QueryAnalyzer` is deliberately not one — `analyze` is
/// synchronous and touches nothing — which is why `ConnectionRuntime::analyzer()`
/// hands out a port yet stays outside the gate.
#[derive(Default)]
struct IoPortTraits {
    traits: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for IoPortTraits {
    fn visit_item(&mut self, node: &'ast syn::Item) {
        if is_cfg_test(item_attributes(node)) {
            return;
        }
        syn::visit::visit_item(self, node);
    }

    fn visit_item_trait(&mut self, node: &'ast syn::ItemTrait) {
        let runs_off_process_work = node.items.iter().any(|item| {
            matches!(item, syn::TraitItem::Fn(function)
                if return_type_identifiers(&function.sig.output).contains("BoxFuture"))
        });
        if runs_off_process_work {
            self.traits.insert(normalized_identifier(&node.ident));
        }
        syn::visit::visit_item_trait(self, node);
    }
}

fn io_port_traits() -> BTreeSet<String> {
    let mut analysis = IoPortTraits::default();
    for path in rust_source_files_at(&ports_src_dir()).unwrap() {
        let source = fs::read_to_string(&path).unwrap();
        analysis.visit_file(&syn::parse_file(&source).expect("warden-ports source must parse"));
    }
    analysis.traits
}

/// The public inherent `ConnectionRuntime` methods that hand out one of those ports or
/// the connection's concurrency permit, discriminated by what the signature *returns*:
/// naming an I/O port trait or `QueryPermit`. `metadata`, `capabilities`, and `limits`
/// return plain description; `available_permits` returns a count, not a slot.
struct PortAndPermitAccessors {
    io_ports: BTreeSet<String>,
    accessors: BTreeSet<String>,
}

impl<'ast> Visit<'ast> for PortAndPermitAccessors {
    fn visit_item(&mut self, node: &'ast syn::Item) {
        if is_cfg_test(item_attributes(node)) {
            return;
        }
        syn::visit::visit_item(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if node.trait_.is_none() && type_ends_with(node.self_ty.as_ref(), "ConnectionRuntime") {
            for item in &node.items {
                if let syn::ImplItem::Fn(function) = item
                    && matches!(function.vis, syn::Visibility::Public(_))
                    && !is_cfg_test(&function.attrs)
                {
                    let returned = return_type_identifiers(&function.sig.output);
                    if returned.contains("QueryPermit")
                        || returned.iter().any(|name| self.io_ports.contains(name))
                    {
                        self.accessors
                            .insert(normalized_identifier(&function.sig.ident));
                    }
                }
            }
        }
        syn::visit::visit_item_impl(self, node);
    }
}

fn port_and_permit_accessors(io_ports: BTreeSet<String>) -> BTreeSet<String> {
    let source = fs::read_to_string(ports_src_dir().join("runtime.rs")).unwrap();
    let mut analysis = PortAndPermitAccessors {
        io_ports,
        accessors: BTreeSet::new(),
    };
    analysis.visit_file(&syn::parse_file(&source).expect("warden-ports source must parse"));
    analysis.accessors
}

fn names(entries: &[&str]) -> BTreeSet<String> {
    entries.iter().map(|name| (*name).to_owned()).collect()
}

fn punct_is(token: Option<&TokenTree>, expected: char) -> bool {
    matches!(token, Some(TokenTree::Punct(punctuation)) if punctuation.as_char() == expected)
}

fn macro_path_marker_before(tokens: &[TokenTree], index: usize) -> bool {
    punct_is(
        index.checked_sub(1).and_then(|index| tokens.get(index)),
        '.',
    ) || (punct_is(
        index.checked_sub(1).and_then(|index| tokens.get(index)),
        ':',
    ) && punct_is(
        index.checked_sub(2).and_then(|index| tokens.get(index)),
        ':',
    ))
}

fn macro_stream_generates_public_error_impl(tokens: &[TokenTree]) -> bool {
    let mut inside_impl = false;
    let mut generic_depth = 0_u32;
    let mut saw_trait_identifier = false;
    let mut last_trait_is_public_error = false;

    for (index, token) in tokens.iter().enumerate() {
        match token {
            TokenTree::Ident(identifier)
                if identifier == "impl" && (!inside_impl || generic_depth == 0) =>
            {
                inside_impl = true;
                generic_depth = 0;
                saw_trait_identifier = false;
                last_trait_is_public_error = false;
            }
            TokenTree::Punct(punctuation) if inside_impl && punctuation.as_char() == '<' => {
                generic_depth = generic_depth.saturating_add(1);
            }
            TokenTree::Punct(punctuation) if inside_impl && punctuation.as_char() == '>' => {
                generic_depth = generic_depth.saturating_sub(1);
            }
            TokenTree::Ident(identifier)
                if inside_impl && generic_depth == 0 && identifier == "for" =>
            {
                let starts_higher_ranked_bound = punct_is(tokens.get(index + 1), '<');
                if !starts_higher_ranked_bound && last_trait_is_public_error {
                    return true;
                }
                if !starts_higher_ranked_bound && saw_trait_identifier {
                    inside_impl = false;
                }
            }
            TokenTree::Ident(identifier) if inside_impl && generic_depth == 0 => {
                saw_trait_identifier = true;
                last_trait_is_public_error = normalized_identifier(identifier) == "PublicError";
            }
            TokenTree::Group(_)
            | TokenTree::Ident(_)
            | TokenTree::Literal(_)
            | TokenTree::Punct(_) => {}
        }
    }

    false
}

fn scan_macro_tokens(tokens: TokenStream, analysis: &mut SourceAnalysis) {
    let tokens = tokens.into_iter().collect::<Vec<_>>();
    if macro_stream_generates_public_error_impl(&tokens) {
        analysis.implements_public_error_for_service_build = true;
    }
    for (index, token) in tokens.iter().enumerate() {
        match token {
            TokenTree::Group(group) => scan_macro_tokens(group.stream(), analysis),
            TokenTree::Ident(identifier) => {
                let identifier = normalized_identifier(identifier);
                // Macro expansion can correlate definitions and invocations that no
                // individual token stream can prove safe. Startup-only errors therefore
                // stay in explicit Rust, where the exact impl visitor can reason about them.
                if identifier == "ServiceBuildError" {
                    analysis.implements_public_error_for_service_build = true;
                }
                if macro_path_marker_before(&tokens, index) {
                    analysis.calls.push(identifier);
                }
            }
            // Literals are intentionally atomic: text that looks like Rust inside a
            // string, raw string, byte string, or character must never trigger R5.
            TokenTree::Literal(_) | TokenTree::Punct(_) => {}
        }
    }
}

#[derive(Default)]
struct SourceAnalysis {
    calls: Vec<String>,
    cfg_test_modules: BTreeSet<String>,
    implements_public_error_for_service_build: bool,
    error_message_contains_detail: bool,
}

impl<'ast> Visit<'ast> for SourceAnalysis {
    fn visit_item(&mut self, node: &'ast syn::Item) {
        if is_cfg_test(item_attributes(node)) {
            if let syn::Item::Mod(module) = node {
                self.cfg_test_modules.insert(module.ident.to_string());
            }
            return;
        }
        syn::visit::visit_item(self, node);
    }

    fn visit_impl_item(&mut self, node: &'ast syn::ImplItem) {
        if is_cfg_test(impl_item_attributes(node)) {
            return;
        }
        syn::visit::visit_impl_item(self, node);
    }

    fn visit_trait_item(&mut self, node: &'ast syn::TraitItem) {
        if is_cfg_test(trait_item_attributes(node)) {
            return;
        }
        syn::visit::visit_trait_item(self, node);
    }

    fn visit_foreign_item(&mut self, node: &'ast syn::ForeignItem) {
        if is_cfg_test(foreign_item_attributes(node)) {
            return;
        }
        syn::visit::visit_foreign_item(self, node);
    }

    fn visit_local(&mut self, node: &'ast syn::Local) {
        if is_cfg_test(&node.attrs) {
            return;
        }
        syn::visit::visit_local(self, node);
    }

    fn visit_stmt_macro(&mut self, node: &'ast syn::StmtMacro) {
        if is_cfg_test(&node.attrs) {
            return;
        }
        syn::visit::visit_stmt_macro(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        self.calls.push(normalized_identifier(&node.method));
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if (node.qself.is_some() || node.path.segments.len() > 1)
            && let Some(segment) = node.path.segments.last()
        {
            self.calls.push(normalized_identifier(&segment.ident));
        }
        syn::visit::visit_expr_path(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        // Syn cannot expand macros. Token trees still preserve gated path
        // punctuation and every non-literal ServiceBuildError identifier.
        scan_macro_tokens(node.tokens.clone(), self);
        syn::visit::visit_macro(self, node);
    }

    fn visit_item_impl(&mut self, node: &'ast syn::ItemImpl) {
        if node
            .trait_
            .as_ref()
            .is_some_and(|(_, path, _)| path_ends_with(path, "PublicError"))
            && type_ends_with(node.self_ty.as_ref(), "ServiceBuildError")
        {
            self.implements_public_error_for_service_build = true;
        }
        syn::visit::visit_item_impl(self, node);
    }

    fn visit_attribute(&mut self, node: &'ast syn::Attribute) {
        if node.path().is_ident("error")
            && node
                .parse_args::<syn::LitStr>()
                .is_ok_and(|message| message.value().contains("{detail"))
        {
            self.error_message_contains_detail = true;
        }
        syn::visit::visit_attribute(self, node);
    }
}

fn analyze_source(source: &str) -> SourceAnalysis {
    let file = syn::parse_file(source).expect("guard fixture/source must be valid Rust syntax");
    let mut analysis = SourceAnalysis::default();
    analysis.visit_file(&file);
    analysis
}

fn gated_calls(source: &str) -> Vec<&'static str> {
    analyze_source(source)
        .calls
        .iter()
        .filter_map(|call| gated_call(call))
        .collect()
}

fn calls_method(source: &str, method: &str) -> bool {
    analyze_source(source)
        .calls
        .iter()
        .any(|call| call == method)
}

fn implements_public_error_for_service_build(source: &str) -> bool {
    analyze_source(source).implements_public_error_for_service_build
}

fn cfg_test_modules(source: &str) -> BTreeSet<String> {
    analyze_source(source).cfg_test_modules
}

struct ListedRegistry {
    listed: Vec<ConnectionMetadata>,
}

impl ConnectionRegistry for ListedRegistry {
    fn get(&self, name: &ConnectionName) -> Result<Arc<ConnectionRuntime>, ConnectionError> {
        Err(ConnectionError::NotFound { name: name.clone() })
    }

    fn list(&self) -> Vec<ConnectionMetadata> {
        self.listed.clone()
    }
}

struct Sink;

impl AuditSink for Sink {
    fn record_attempt<'a>(
        &'a self,
        _event: &'a AuditAttempt,
    ) -> BoxFuture<'a, Result<(), AuditError>> {
        Box::pin(async { Ok(()) })
    }

    fn record_outcome<'a>(
        &'a self,
        _event: &'a AuditOutcomeEvent,
    ) -> BoxFuture<'a, Result<(), AuditError>> {
        Box::pin(async { Ok(()) })
    }
}

fn metadata(name: &str) -> ConnectionMetadata {
    ConnectionMetadata {
        name: name.parse().unwrap(),
        dialect: Dialect::PostgreSql,
        environment: Environment::Production,
        database: "analytics".to_owned(),
    }
}

fn parts(redaction: RedactionSettings) -> ServiceParts {
    ServiceParts {
        registry: Arc::new(ListedRegistry {
            listed: vec![metadata("primary")],
        }),
        engine: Arc::new(PolicyEngine::with_defaults(&PolicySettings::default()).unwrap()),
        audit: Arc::new(Sink),
        redaction,
        shutdown: CancellationToken::new(),
    }
}

#[test]
fn only_the_gate_may_reach_a_database_or_take_a_permit() {
    let pipeline = src_dir().join("pipeline.rs");
    for path in rust_source_files() {
        let source = fs::read_to_string(&path).unwrap();
        for call in gated_calls(&source) {
            assert!(
                path == pipeline,
                "{} calls {call}; only pipeline.rs may, so the audit attempt \
                 and permit-to-connection pairing stay structural (ADR-0038)",
                path.display()
            );
        }
    }
}

#[test]
fn the_gated_list_covers_every_accessor_that_hands_out_a_port_or_a_permit() {
    let io_ports = io_port_traits();
    assert!(
        io_ports.contains("QueryExecutor")
            && io_ports.contains("Explainer")
            && io_ports.contains("SchemaInspector"),
        "the discriminator found no I/O ports at all, so it proves nothing: {io_ports:?}"
    );
    assert!(
        !io_ports.contains("QueryAnalyzer"),
        "the discriminator is `returns a BoxFuture`, not `is a port`: `analyze` is \
         synchronous, which is why `analyzer()` is outside the gate"
    );

    let accessors = port_and_permit_accessors(io_ports);
    assert_eq!(
        accessors,
        names(PORT_AND_PERMIT_ACCESSORS),
        "ConnectionRuntime's port-and-permit surface changed. Decide whether the new \
         accessor is gated, add it to GATED_CALLS if it is, and only then update \
         PORT_AND_PERMIT_ACCESSORS (ADR-0038)"
    );

    let mut expected_gated = names(PORT_AND_PERMIT_ACCESSORS);
    assert!(
        expected_gated.remove("inspector"),
        "`inspector` is the documented control-pool exception and must stay in the \
         accessor list it is excepted from"
    );
    assert_eq!(
        gated_call_names(),
        expected_gated,
        "GATED_CALLS and ConnectionRuntime drifted apart: every accessor that hands \
         out an agent-path port or a permit is gated, and nothing else is (ADR-0038)"
    );
}

#[test]
fn the_gate_guard_ignores_line_and_nested_block_comments_but_not_code() {
    let source = r#"
        // runtime.executor()
        /* runtime.explainer()
           /* runtime.acquire_query_permit() */
        */
        fn production(runtime: &ConnectionRuntime) {
            let executor = runtime.executor();
        }
    "#;
    assert_eq!(gated_calls(source), vec![".executor()"]);
}

#[test]
fn the_gate_guard_checks_production_code_but_ignores_cfg_test_modules() {
    let source = r#"
        fn production(runtime: &Runtime) {
            runtime.executor();
        }

        #[cfg(test)]
        mod tests {
            fn exercises_the_port(runtime: &Runtime) {
                runtime.explainer();
                runtime.acquire_query_permit();
            }
        }
    "#;
    assert_eq!(gated_calls(source), vec![".executor()"]);
}

#[test]
fn every_response_path_redacts_before_it_returns() {
    for (file, call) in [
        ("query.rs", "redact_result"),
        ("explain.rs", "redact_plan"),
        ("schema.rs", "redact_description"),
    ] {
        let source = fs::read_to_string(src_dir().join(file)).unwrap();
        assert!(
            calls_method(&source, call),
            "{file} must call {call}: redaction happens after normalization and \
             before serialization (docs/security.md section 8)"
        );
    }
}

#[test]
fn a_startup_only_error_implements_no_public_error() {
    let source = fs::read_to_string(src_dir().join("error.rs")).unwrap();
    assert!(
        !implements_public_error_for_service_build(&source),
        "ServiceBuildError is raised before any transport serves, so it has no \
         public code to leak"
    );
    let _: fn(RedactionRuleError) -> ServiceBuildError = ServiceBuildError::from;
}

#[test]
fn all_composition_types_cross_task_boundaries() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ServiceParts>();
    assert_send_sync::<QueryService>();
    assert_send_sync::<ExplainService>();
    assert_send_sync::<SchemaService>();
    assert_send_sync::<Services>();
}

#[test]
fn all_service_accessors_have_the_public_types_the_mcp_layer_needs() {
    let _: fn(&Services) -> &QueryService = Services::query;
    let _: fn(&Services) -> &ExplainService = Services::explain;
    let _: fn(&Services) -> &SchemaService = Services::schema;
    let _: fn(&Services) -> &dyn ConnectionRegistry = Services::registry;
    let _: Option<ConnectionRuntimeParts> = None;
    let _: Option<RuntimeError> = None;
}

#[test]
fn invalid_redaction_rules_fail_the_build_before_any_service_is_used() {
    let error = Services::new(parts(RedactionSettings {
        columns: vec!["password".to_owned()],
        ..RedactionSettings::default()
    }))
    .unwrap_err();
    assert_eq!(
        error,
        ServiceBuildError::Redaction(RedactionRuleError::Malformed {
            rule: "password".to_owned(),
        })
    );
}

#[test]
fn the_exposed_registry_is_the_authority_supplied_at_startup() {
    let parts = parts(RedactionSettings::default());
    let registry = Arc::clone(&parts.registry);
    let services = Services::new(parts).unwrap();
    assert!(std::ptr::eq(services.registry(), registry.as_ref()));
    assert_eq!(services.registry().list(), vec![metadata("primary")]);
}

#[test]
fn debug_output_contains_only_safe_composition_metadata() {
    let parts = parts(RedactionSettings {
        columns: vec!["accounts.ultra-secret-token".to_owned()],
        ..RedactionSettings::default()
    });
    let parts_debug = format!("{parts:?}");
    assert!(parts_debug.contains("ServiceParts"));
    assert!(parts_debug.contains("connection_count"));
    assert!(parts_debug.contains("redaction_rule_count"));
    assert!(!parts_debug.contains("ultra-secret-token"));
    assert!(!parts_debug.contains("CancellationToken"));

    let services = Services::new(parts).unwrap();
    let services_debug = format!("{services:?}");
    assert!(services_debug.contains("Services"));
    assert!(services_debug.contains("connection_count"));
    assert!(services_debug.contains("redactor_is_empty"));
    assert!(!services_debug.contains("Sink"));
    assert!(!services_debug.contains("CancellationToken"));
}

#[test]
fn no_service_error_prints_an_internal_detail() {
    let source = fs::read_to_string(src_dir().join("error.rs")).unwrap();
    assert!(!analyze_source(&source).error_message_contains_detail);
}

#[test]
fn syntax_guard_detects_method_and_ufcs_calls_across_comments_and_whitespace() {
    let source = r#"
        fn bypasses(runtime: &ConnectionRuntime) {
            runtime
                . /* gap */ executor /* gap */ ();
            ConnectionRuntime /* gap */ :: explainer(
                runtime,
            );
            ConnectionRuntime::acquire_query_permit /* gap */ (runtime);
        }
    "#;
    assert_eq!(
        gated_calls(source),
        vec![".executor()", ".explainer()", ".acquire_query_permit()"]
    );
}

#[test]
fn syntax_guard_ignores_normal_raw_byte_and_raw_byte_string_literals() {
    let source = r###"
        const NORMAL: &str = "runtime.executor()";
        const RAW: &str = r#"ConnectionRuntime::explainer(&runtime)"#;
        const BYTE: &[u8] = b"runtime.acquire_query_permit()";
        const RAW_BYTE: &[u8] = br#"runtime.executor()"#;
        const CHARACTER: char = 'x';
        const BYTE_CHARACTER: u8 = b'x';
    "###;
    assert!(gated_calls(source).is_empty());
}

#[test]
fn syntax_guard_keeps_production_items_after_a_cfg_test_module_visible() {
    let source = r#"
        #[cfg(test)]
        mod tests {
            fn permitted_direct_port_test(runtime: &ConnectionRuntime) {
                runtime.executor();
            }
        }

        fn production_after_tests(runtime: &ConnectionRuntime) {
            runtime.explainer();
        }
    "#;
    assert_eq!(gated_calls(source), vec![".explainer()"]);
}

#[test]
fn syntax_guard_visits_calls_inside_inline_submodules() {
    let source = r#"
        mod nested {
            fn bypasses(runtime: &ConnectionRuntime) {
                runtime.acquire_query_permit();
            }
        }
    "#;
    assert_eq!(gated_calls(source), vec![".acquire_query_permit()"]);
}

#[test]
fn startup_error_guard_detects_qualified_impl_with_comments_and_whitespace() {
    let source = r#"
        impl warden_core::error::PublicError
            for /* gap */ crate::error::ServiceBuildError
        {
            fn public_code(&self) -> PublicErrorCode { todo!() }
        }
    "#;
    assert!(implements_public_error_for_service_build(source));
}

#[test]
fn source_collection_recurses_and_rejects_non_rust_files_and_rs_directories() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/source-tree");
    let relative = rust_source_files_at(&root)
        .unwrap()
        .into_iter()
        .map(|path| path.strip_prefix(&root).unwrap().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        relative,
        vec![PathBuf::from("nested/child.rs"), PathBuf::from("root.rs")]
    );
}

#[test]
fn testing_file_exclusion_requires_a_cfg_test_module_link() {
    assert!(cfg_test_modules("#[cfg(test)] mod testing;").contains("testing"));
    assert!(!cfg_test_modules("mod testing;").contains("testing"));
}

#[test]
fn test_support_file_is_cfg_test_linked_by_the_real_crate_root() {
    let source = fs::read_to_string(src_dir().join("lib.rs")).unwrap();
    assert!(cfg_test_modules(&source).contains("testing"));
}

#[test]
fn syntax_guard_detects_gated_calls_inside_macro_token_trees() {
    let source = r#"
        async fn waits(runtime: &ConnectionRuntime) {
            tokio::select! {
                note = "ConnectionRuntime::executor(runtime)" => note,
                permit = runtime /* gap */ . acquire_query_permit /* gap */ () => permit,
            }
        }
    "#;
    assert_eq!(gated_calls(source), vec![".acquire_query_permit()"]);
}

#[test]
fn syntax_guard_detects_parenthesized_and_aliased_function_item_paths() {
    let source = r#"
        fn bypasses(runtime: &ConnectionRuntime) {
            (ConnectionRuntime::executor)(runtime);
            let run = ConnectionRuntime::explainer;
            run(runtime);
        }
    "#;
    assert_eq!(gated_calls(source), vec![".executor()", ".explainer()"]);
}

#[test]
fn startup_error_guard_detects_an_impl_generated_inside_a_macro() {
    let source = r#"
        generate! {
            impl warden_core::error::PublicError for crate::error::ServiceBuildError {
                fn public_code(&self) -> PublicErrorCode { code() }
            }
        }
    "#;
    assert!(implements_public_error_for_service_build(source));
}

#[test]
fn startup_error_guard_rejects_service_build_error_split_across_macro_streams() {
    let source = r#"
        macro_rules! expose {
            ($ty:ty) => {
                impl PublicError for $ty {}
            };
        }

        expose!(ServiceBuildError);
    "#;
    assert!(implements_public_error_for_service_build(source));
}

#[test]
fn startup_error_guard_rejects_an_alias_passed_to_a_public_error_impl_macro() {
    let source = r#"
        type StartupError = ServiceBuildError;

        macro_rules! expose {
            ($ty:ty) => {
                impl PublicError for $ty {}
            };
        }

        expose!(StartupError);
    "#;
    assert!(implements_public_error_for_service_build(source));
}

#[test]
fn startup_error_guard_normalizes_raw_public_error_in_macro_impl_heads() {
    let source = r#"
        type StartupError = ServiceBuildError;

        macro_rules! expose {
            ($ty:ty) => {
                impl r#PublicError for $ty {}
            };
        }

        expose!(StartupError);
    "#;
    assert!(implements_public_error_for_service_build(source));
}

#[test]
fn startup_error_guard_normalizes_raw_service_build_error_in_macro_tokens() {
    let source = "passthrough!(r#ServiceBuildError);";
    assert!(implements_public_error_for_service_build(source));
}

#[test]
fn gated_call_guard_normalizes_raw_method_and_ufcs_identifiers_in_macros() {
    let source = r#"
        passthrough! {
            runtime.r#executor();
            ConnectionRuntime::r#explainer(runtime);
            runtime.r#acquire_query_permit();
        }
    "#;
    assert_eq!(
        gated_calls(source),
        vec![".executor()", ".explainer()", ".acquire_query_permit()"]
    );
}

#[test]
fn gated_call_guard_normalizes_raw_method_and_ufcs_identifiers_in_explicit_rust() {
    let source = r#"
        fn bypasses(runtime: &ConnectionRuntime) {
            runtime.r#executor();
            ConnectionRuntime::r#explainer(runtime);
            runtime.r#acquire_query_permit();
        }
    "#;
    assert_eq!(
        gated_calls(source),
        vec![".executor()", ".explainer()", ".acquire_query_permit()"]
    );
}

#[test]
fn startup_error_guard_normalizes_raw_identifiers_in_explicit_impls() {
    let source = "impl r#PublicError for r#ServiceBuildError {}";
    assert!(implements_public_error_for_service_build(source));
}

#[test]
fn startup_error_guard_allows_explicit_non_impl_uses_and_literals() {
    let source = r#"
        type StartupError = ServiceBuildError;
        const ERROR_NAME: &str = "ServiceBuildError";
    "#;
    assert!(!implements_public_error_for_service_build(source));
}

#[test]
fn macro_scan_ignores_local_gated_names_and_literals() {
    let source = r#"
        passthrough! {
            let executor = callback;
            executor(runtime);
            let note = "runtime.explainer()";
        }
    "#;
    assert!(gated_calls(source).is_empty());
    assert!(!implements_public_error_for_service_build(source));
}

#[test]
fn startup_error_guard_ignores_macros_without_a_public_error_impl_and_literals() {
    let source = r#"
        macro_rules! internal_impl {
            ($ty:ty) => {
                impl<T: r#PublicError> InternalTrait for $ty {}
            };
        }

        macro_rules! accepts_public_error {
            () => {
                fn accepts(_: r#PublicError) {}
            };
        }

        passthrough! {
            let r#executor = callback;
            r#executor(runtime);
            r#InternalTrait;
        }
        describe!("impl PublicError for ServiceBuildError");
        describe!("impl r#PublicError for r#ServiceBuildError");
    "#;
    assert!(gated_calls(source).is_empty());
    assert!(!implements_public_error_for_service_build(source));
}

#[test]
fn cfg_test_associated_items_are_ignored_but_production_siblings_are_scanned() {
    let source = r#"
        impl Service {
            #[cfg(test)]
            fn direct_port_test(runtime: &ConnectionRuntime) {
                runtime.executor();
            }

            fn production(runtime: &ConnectionRuntime) {
                runtime.explainer();
            }
        }

        trait ServicePort {
            #[cfg(test)]
            fn test_only(runtime: &ConnectionRuntime) {
                runtime.acquire_query_permit();
            }

            fn production(runtime: &ConnectionRuntime) {
                runtime.explainer();
            }
        }
    "#;
    assert_eq!(gated_calls(source), vec![".explainer()", ".explainer()"]);
}

#[test]
fn cfg_test_local_statements_are_ignored_but_production_siblings_are_scanned() {
    let source = r#"
        fn production(runtime: &ConnectionRuntime) {
            #[cfg(test)]
            let _test_only = runtime.executor();
            runtime.explainer();
        }
    "#;
    assert_eq!(gated_calls(source), vec![".explainer()"]);
}
