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

use proc_macro2::{TokenStream, TokenTree};
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

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
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

fn path_ends_with(path: &syn::Path, expected: &str) -> bool {
    path.segments
        .last()
        .is_some_and(|segment| segment.ident == expected)
}

fn type_ends_with(ty: &syn::Type, expected: &str) -> bool {
    matches!(ty, syn::Type::Path(path) if path_ends_with(&path.path, expected))
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

fn scan_macro_tokens(tokens: TokenStream, analysis: &mut SourceAnalysis) {
    fn collect_identifiers(tokens: &[TokenTree], identifiers: &mut Vec<String>) {
        for token in tokens {
            match token {
                TokenTree::Group(group) => {
                    let nested = group.stream().into_iter().collect::<Vec<_>>();
                    collect_identifiers(&nested, identifiers);
                }
                TokenTree::Ident(identifier) => identifiers.push(identifier.to_string()),
                // Literals are intentionally atomic: text that looks like Rust inside a
                // string, raw string, byte string, or character must never trigger R5.
                TokenTree::Literal(_) | TokenTree::Punct(_) => {}
            }
        }
    }

    fn has_generated_public_error_impl(identifiers: &[String]) -> bool {
        identifiers
            .iter()
            .enumerate()
            .filter(|(_, identifier)| identifier.as_str() == "impl")
            .any(|(impl_index, _)| {
                identifiers[impl_index + 1..]
                    .iter()
                    .position(|identifier| identifier == "PublicError")
                    .map(|index| impl_index + 1 + index)
                    .and_then(|public_error_index| {
                        identifiers[public_error_index + 1..]
                            .iter()
                            .position(|identifier| identifier == "for")
                            .map(|index| public_error_index + 1 + index)
                    })
                    .is_some_and(|for_index| {
                        identifiers[for_index + 1..]
                            .iter()
                            .any(|identifier| identifier == "ServiceBuildError")
                    })
            })
    }

    fn parsed_item_implements_public_error_for_service_build(item: &syn::Item) -> bool {
        if is_cfg_test(item_attributes(item)) {
            return false;
        }
        match item {
            syn::Item::Impl(item) => {
                item.trait_
                    .as_ref()
                    .is_some_and(|(_, path, _)| path_ends_with(path, "PublicError"))
                    && type_ends_with(item.self_ty.as_ref(), "ServiceBuildError")
            }
            syn::Item::Mod(module) => module.content.as_ref().is_some_and(|(_, items)| {
                items
                    .iter()
                    .any(parsed_item_implements_public_error_for_service_build)
            }),
            _ => false,
        }
    }

    let tokens = tokens.into_iter().collect::<Vec<_>>();
    for (index, token) in tokens.iter().enumerate() {
        match token {
            TokenTree::Group(group) => scan_macro_tokens(group.stream(), analysis),
            TokenTree::Ident(identifier) if macro_path_marker_before(&tokens, index) => {
                analysis.calls.push(identifier.to_string());
            }
            TokenTree::Ident(_) | TokenTree::Literal(_) | TokenTree::Punct(_) => {}
        }
    }

    let mut identifiers = Vec::new();
    collect_identifiers(&tokens, &mut identifiers);
    let parsed_items = syn::parse2::<syn::File>(tokens.iter().cloned().collect());
    let implements_public_error = match parsed_items {
        Ok(file) => file
            .items
            .iter()
            .any(parsed_item_implements_public_error_for_service_build),
        // Macro DSLs need not be Rust syntax. For those only, conservatively
        // recognize the ordered impl/trait/for/type identifiers.
        Err(_) => has_generated_public_error_impl(&identifiers),
    };
    if implements_public_error {
        analysis.implements_public_error_for_service_build = true;
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
        self.calls.push(node.method.to_string());
        syn::visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast syn::ExprPath) {
        if (node.qself.is_some() || node.path.segments.len() > 1)
            && let Some(segment) = node.path.segments.last()
        {
            self.calls.push(segment.ident.to_string());
        }
        syn::visit::visit_expr_path(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        // Syn cannot parse arbitrary macro input as Rust AST. Token trees still
        // preserve the punctuation needed to distinguish `.executor` and
        // `Type::executor` from an unrelated local identifier named `executor`.
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
fn macro_scan_ignores_local_gated_names_and_non_target_impls() {
    let source = r#"
        passthrough! {
            let executor = callback;
            executor(runtime);
            let note = "runtime.explainer()";
        }

        generate! {
            impl<T: PublicError> InternalTrait for ServiceBuildError {
                fn internal(&self) {}
            }
        }
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
