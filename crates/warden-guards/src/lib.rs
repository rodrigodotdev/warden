//! AST machinery the workspace's mechanical source guards share (ADR-0046).
//!
//! Every rule the compiler cannot express — no `sqlparser` type in an adapter's public
//! signature, no wildcard arm over a security enum, no `Deref` on a newtype — is a
//! question about the source. This crate is where the reading of that source lives, so
//! that it is done once, on a parsed tree, rather than nine times against line text.
//!
//! # Why not line scanning
//!
//! Hand-rolled lexing is where a guard goes quietly blind. Both adapters' guards used
//! to cut each file at the first line reading exactly `#[cfg(test)]`, on the assumption
//! that it introduced the trailing `mod tests`. In both adapters it did not — a
//! `#[cfg(test)] impl` sits well above the real test module in `connection.rs` — so the
//! tail of each file was outside every scan, and no scan could have said so. There is
//! no cutoff here: [`production_items`] prunes on parsed attributes, at every level.
//!
//! # What this crate may depend on
//!
//! `syn`, `proc-macro2` and `std`. **No Warden crate, not even in tests.** A guard that
//! can see the code it guards is a guard that can be made to pass, and
//! `tests/architecture.rs` pins that in `FORBIDDEN_EDGES`.

use std::path::{Path, PathBuf};

use proc_macro2::TokenStream;
use syn::spanned::Spanned as _;
use syn::visit::Visit;

/// Every `.rs` file under `directory`, recursively, in sorted order.
///
/// Sorted so a guard's failure list is stable between runs and between machines: a
/// diff in a CI log should mean a diff in the code.
///
/// # Panics
///
/// If `directory` cannot be read. A guard that silently scans nothing is the failure
/// mode this crate exists to prevent, so an unreadable tree is loud.
#[must_use]
pub fn source_files(directory: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_rust_files(directory, &mut files);
    files.sort();
    files
}

fn collect_rust_files(directory: &Path, files: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", directory.display()));
    for entry in entries {
        let path = entry
            .unwrap_or_else(|error| panic!("could not read a directory entry: {error}"))
            .path();
        if path.is_dir() {
            collect_rust_files(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

/// Parses one Rust source file.
///
/// # Panics
///
/// If the file cannot be read or does not parse. Both are guard failures rather than
/// findings: a scan that skips what it cannot read proves nothing.
#[must_use]
pub fn parse_file(path: &Path) -> syn::File {
    let source = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    syn::parse_file(&source)
        .unwrap_or_else(|error| panic!("could not parse {}: {error}", path.display()))
}

/// Whether a `cfg` condition requires `test` to hold.
///
/// `all(...)` requires `test` when **any** of its conditions does, because every one of
/// them must hold. `any(...)` requires it only when **every** alternative does, because
/// one that does not is a way in without `test`. Getting this backwards is how an item
/// gated `any(test, feature = "x")` would be pruned from a production scan while
/// shipping under `x`.
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

/// Whether these attributes make an item test-only.
///
/// Covers `#[cfg(test)]` and any `cfg` predicate that requires `test`, such as
/// `#[cfg(all(test, feature = "docker"))]`, which both adapters use for container work.
///
/// **`#[cfg_attr(test, ...)]` does not make an item test-only**, and treating it as if
/// it did would recreate this crate's founding bug with the opposite sign: a production
/// item no guard can see. `cfg_attr` makes the *attribute* conditional, not the item —
/// something carrying `#[cfg_attr(test, derive(Debug))]` ships in every build and
/// merely derives less. Only `cfg` decides whether an item exists at all.
#[must_use]
pub fn is_test_only(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("cfg")
            && attribute
                .parse_args::<syn::Meta>()
                .is_ok_and(|meta| cfg_requires_test(&meta))
    })
}

/// The items in `path` that ship, with every test-only item pruned at every level.
///
/// This is the security-critical function in this crate. It is what decides that a
/// rule does not apply to an item, and a mistake here makes every guard built on it
/// quietly narrower than it reads. Modules are kept and their contents pruned, so a
/// caller still sees module structure; nothing is cut by position.
///
/// # Panics
///
/// If the file cannot be read or parsed. See [`parse_file`].
#[must_use]
pub fn production_items(path: &Path) -> Vec<syn::Item> {
    prune(parse_file(path).items)
}

/// [`production_items`] on source text rather than a path.
///
/// The pruning is the part that has to be right, and it is pure. Keeping it reachable
/// without a file is what lets its negative controls be fixtures rather than a
/// directory tree, so each spelling of a test gate gets its own named case.
///
/// # Panics
///
/// If `source` does not parse.
#[must_use]
pub fn production_items_of(source: &str) -> Vec<syn::Item> {
    let file =
        syn::parse_file(source).unwrap_or_else(|error| panic!("fixture does not parse: {error}"));
    prune(file.items)
}

fn prune(items: Vec<syn::Item>) -> Vec<syn::Item> {
    items
        .into_iter()
        .filter(|item| !item_is_test_only(item))
        .map(|item| match item {
            syn::Item::Mod(mut module) => {
                if let Some((brace, content)) = module.content.take() {
                    module.content = Some((brace, prune(content)));
                }
                syn::Item::Mod(module)
            }
            other => other,
        })
        .collect()
}

fn item_is_test_only(item: &syn::Item) -> bool {
    attributes_of(item).is_some_and(is_test_only)
}

fn attributes_of(item: &syn::Item) -> Option<&[syn::Attribute]> {
    Some(match item {
        syn::Item::Const(i) => &i.attrs,
        syn::Item::Enum(i) => &i.attrs,
        syn::Item::ExternCrate(i) => &i.attrs,
        syn::Item::Fn(i) => &i.attrs,
        syn::Item::ForeignMod(i) => &i.attrs,
        syn::Item::Impl(i) => &i.attrs,
        syn::Item::Macro(i) => &i.attrs,
        syn::Item::Mod(i) => &i.attrs,
        syn::Item::Static(i) => &i.attrs,
        syn::Item::Struct(i) => &i.attrs,
        syn::Item::Trait(i) => &i.attrs,
        syn::Item::TraitAlias(i) => &i.attrs,
        syn::Item::Type(i) => &i.attrs,
        syn::Item::Union(i) => &i.attrs,
        syn::Item::Use(i) => &i.attrs,
        _ => return None,
    })
}

/// One place in the source a guard can point at.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Finding {
    /// One-based line, so a failure message matches an editor.
    pub line: usize,
    /// What the guard saw there, in the guard's own vocabulary.
    pub detail: String,
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: {}", self.line, self.detail)
    }
}

fn line_of(span: proc_macro2::Span) -> usize {
    span.start().line
}

/// Whether an item is exported outside its crate — `pub`, not `pub(crate)`.
#[must_use]
pub fn is_exported(visibility: &syn::Visibility) -> bool {
    matches!(visibility, syn::Visibility::Public(_))
}

/// The names of the `pub` items among `items`, at this level only.
///
/// `pub(crate)` and `pub(super)` are not exports: they cannot be named from outside the
/// crate, which is what an export guard is about.
#[must_use]
pub fn exported_names(items: &[syn::Item]) -> Vec<Finding> {
    let mut found = Vec::new();
    for item in items {
        let (visibility, name, span) = match item {
            syn::Item::Const(i) => (&i.vis, i.ident.to_string(), i.ident.span()),
            syn::Item::Enum(i) => (&i.vis, i.ident.to_string(), i.ident.span()),
            syn::Item::Fn(i) => (&i.vis, i.sig.ident.to_string(), i.sig.ident.span()),
            syn::Item::Mod(i) => (&i.vis, i.ident.to_string(), i.ident.span()),
            syn::Item::Static(i) => (&i.vis, i.ident.to_string(), i.ident.span()),
            syn::Item::Struct(i) => (&i.vis, i.ident.to_string(), i.ident.span()),
            syn::Item::Trait(i) => (&i.vis, i.ident.to_string(), i.ident.span()),
            syn::Item::Type(i) => (&i.vis, i.ident.to_string(), i.ident.span()),
            syn::Item::Union(i) => (&i.vis, i.ident.to_string(), i.ident.span()),
            syn::Item::Use(i) => {
                if is_exported(&i.vis) {
                    found.push(Finding {
                        line: line_of(i.use_token.span),
                        detail: "pub use".to_owned(),
                    });
                }
                continue;
            }
            _ => continue,
        };
        if is_exported(visibility) {
            found.push(Finding {
                line: line_of(span),
                detail: name,
            });
        }
    }
    found
}

/// Whether a scan reads the signatures of trait `impl` blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraitImpls {
    /// Read them. A trait-impl method is public through its trait and never writes
    /// `pub`, so a scan that is really asking "what can a caller outside this crate
    /// name" has to include it.
    Included,
    /// Skip them. Their signatures are fixed by the trait, so a rule about what *this*
    /// crate chose to expose is answered where the trait is declared instead.
    Excluded,
}

/// Every type path named anywhere in the public API surface of `items`.
///
/// "Public API surface" is what a caller outside the crate can name: the argument and
/// return types of `pub fn`, the fields of a `pub struct`, the variants of a `pub enum`,
/// the signatures of a `pub trait`'s methods, and the target of a `pub type` alias.
/// Generic arguments count — `Result<Statement, E>` names `Statement`.
///
/// Inherent `impl` blocks are included when the method is `pub`, because an inherent
/// `pub fn` on a `pub` type is reachable. Trait `impl` blocks are not: their signatures
/// are fixed by the trait, which is guarded where the trait is declared.
#[must_use]
pub fn public_signature_types(items: &[syn::Item], trait_impls: TraitImpls) -> Vec<Finding> {
    let mut visitor = PublicTypeVisitor {
        trait_impls,
        found: Vec::new(),
    };
    visitor.visit_items(items);
    visitor.found
}

struct PublicTypeVisitor {
    trait_impls: TraitImpls,
    found: Vec<Finding>,
}

impl PublicTypeVisitor {
    fn visit_items(&mut self, items: &[syn::Item]) {
        for item in items {
            match item {
                syn::Item::Fn(function) if is_exported(&function.vis) => {
                    self.record_signature(&function.sig);
                }
                syn::Item::Struct(structure) if is_exported(&structure.vis) => {
                    for field in &structure.fields {
                        if is_exported(&field.vis) {
                            self.record_type(&field.ty);
                        }
                    }
                }
                syn::Item::Enum(enumeration) if is_exported(&enumeration.vis) => {
                    for variant in &enumeration.variants {
                        for field in &variant.fields {
                            self.record_type(&field.ty);
                        }
                    }
                }
                syn::Item::Trait(declaration) if is_exported(&declaration.vis) => {
                    for trait_item in &declaration.items {
                        if let syn::TraitItem::Fn(method) = trait_item {
                            self.record_signature(&method.sig);
                        }
                    }
                }
                syn::Item::Type(alias) if is_exported(&alias.vis) => {
                    self.record_type(&alias.ty);
                }
                syn::Item::Impl(block) => {
                    let reads_every_method = match (&block.trait_, self.trait_impls) {
                        // A trait impl's methods cannot be written `pub`, so gating on
                        // visibility here would read nothing at all.
                        (Some(_), TraitImpls::Included) => true,
                        (Some(_), TraitImpls::Excluded) => continue,
                        (None, _) => false,
                    };
                    for impl_item in &block.items {
                        if let syn::ImplItem::Fn(method) = impl_item
                            && (reads_every_method || is_exported(&method.vis))
                        {
                            self.record_signature(&method.sig);
                        }
                    }
                }
                syn::Item::Mod(module) => {
                    if let Some((_, content)) = &module.content {
                        self.visit_items(content);
                    }
                }
                _ => {}
            }
        }
    }

    fn record_signature(&mut self, signature: &syn::Signature) {
        for argument in &signature.inputs {
            if let syn::FnArg::Typed(typed) = argument {
                self.record_type(&typed.ty);
            }
        }
        if let syn::ReturnType::Type(_, return_type) = &signature.output {
            self.record_type(return_type);
        }
    }

    fn record_type(&mut self, node: &syn::Type) {
        TypePathVisitor {
            found: &mut self.found,
        }
        .visit_type(node);
    }
}

struct TypePathVisitor<'a> {
    found: &'a mut Vec<Finding>,
}

impl<'ast> Visit<'ast> for TypePathVisitor<'_> {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        for segment in &path.segments {
            self.found.push(Finding {
                line: line_of(segment.ident.span()),
                detail: segment.ident.to_string(),
            });
        }
        syn::visit::visit_path(self, path);
    }
}

/// Every local name that ultimately refers to one of `roots`.
///
/// A guard banning a type from a public signature has to ban its aliases too, or the
/// ban is one `use ... as ...` away from being decorative. This follows both spellings
/// to a fixed point: an import rename (`use sqlx::MySqlPool as Handle;`) and a type
/// alias chain (`type Handle = MySqlPool; type Alias = Handle;`).
///
/// `roots` are matched as whole path segments, so `Pool` does not match `PoolSettings`.
/// The returned set includes `roots` themselves, so a caller has one set to test.
#[must_use]
pub fn aliases_of(items: &[syn::Item], roots: &[&str]) -> std::collections::BTreeSet<String> {
    let mut known: std::collections::BTreeSet<String> =
        roots.iter().map(|root| (*root).to_owned()).collect();
    let mut visitor = AliasVisitor::default();
    for item in items {
        visitor.visit_item(item);
    }
    // A chain resolves in as many passes as it has links; bounded by the number of
    // aliases, so a cycle terminates instead of looping.
    for _ in 0..=visitor.edges.len() {
        let mut grew = false;
        for (name, target) in &visitor.edges {
            if !known.contains(name) && target.iter().any(|segment| known.contains(segment)) {
                known.insert(name.clone());
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    known
}

#[derive(Default)]
struct AliasVisitor {
    /// `(local name, every path segment its definition mentions)`.
    edges: Vec<(String, Vec<String>)>,
}

impl<'ast> Visit<'ast> for AliasVisitor {
    fn visit_item_type(&mut self, node: &'ast syn::ItemType) {
        let mut names = Vec::new();
        collect_path_segments(&node.ty, &mut names);
        self.edges.push((node.ident.to_string(), names));
        syn::visit::visit_item_type(self, node);
    }

    fn visit_use_rename(&mut self, node: &'ast syn::UseRename) {
        self.edges
            .push((node.rename.to_string(), vec![node.ident.to_string()]));
        syn::visit::visit_use_rename(self, node);
    }
}

fn collect_path_segments(node: &syn::Type, names: &mut Vec<String>) {
    struct Collector<'a>(&'a mut Vec<String>);
    impl<'ast> Visit<'ast> for Collector<'_> {
        fn visit_path_segment(&mut self, segment: &'ast syn::PathSegment) {
            self.0.push(segment.ident.to_string());
            syn::visit::visit_path_segment(self, segment);
        }
    }
    Collector(names).visit_type(node);
}

/// One catch-all match arm, with enough context to judge what it covers.
#[derive(Debug, Clone)]
pub struct WildcardArm {
    /// One-based line of the arm's pattern.
    pub line: usize,
    /// The matched expression as written, e.g. `analysis.root_kind()`.
    pub subject: String,
    /// Every other arm's pattern in the same `match`, as written.
    ///
    /// This is what tells a wildcard over a `sqlparser` enum — required, and mapped to
    /// `Unknown` — from one over a `warden-core` security enum, which must break the
    /// build when a variant is added (ADR-0021). The predecessor guard read the
    /// *immediately preceding line* instead, and documented its own blind spot: an arm
    /// whose body is a braced block puts a bare `}` on that line, with the enum name
    /// several lines further up. Every sibling pattern is available here, so the shape
    /// of an arm's body cannot hide what the `match` is over.
    pub sibling_patterns: Vec<String>,
}

/// Every catch-all match arm in `items`.
///
/// A bare binding (`other => ...`) is a catch-all too: it is the same hole spelled with
/// a name, and it admits a new enum variant just as silently.
#[must_use]
pub fn wildcard_arms(items: &[syn::Item]) -> Vec<WildcardArm> {
    let mut visitor = WildcardVisitor::default();
    for item in items {
        visitor.visit_item(item);
    }
    visitor.found
}

#[derive(Default)]
struct WildcardVisitor {
    found: Vec<WildcardArm>,
}

impl<'ast> Visit<'ast> for WildcardVisitor {
    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        let subject = tokens_to_string(&node.expr);
        let named: Vec<String> = node
            .arms
            .iter()
            .filter(|arm| !pattern_is_wildcard(&arm.pat))
            .map(|arm| tokens_to_string(&arm.pat))
            .collect();
        for arm in &node.arms {
            if pattern_is_wildcard(&arm.pat) {
                self.found.push(WildcardArm {
                    line: line_of(arm.pat.span()),
                    subject: subject.clone(),
                    sibling_patterns: named.clone(),
                });
            }
        }
        syn::visit::visit_expr_match(self, node);
    }
}

fn pattern_is_wildcard(pattern: &syn::Pat) -> bool {
    match pattern {
        syn::Pat::Wild(_) => true,
        // `_ | Other` still admits anything the wildcard admits.
        syn::Pat::Or(or) => or.cases.iter().any(pattern_is_wildcard),
        // A bare binding with no subpattern (`other => ...`) matches everything too.
        syn::Pat::Ident(ident) => ident.subpat.is_none() && ident.by_ref.is_none(),
        _ => false,
    }
}

/// One macro invocation: its path as written, and its unparsed body.
#[derive(Debug, Clone)]
pub struct MacroCall {
    /// One-based line of the macro's name.
    pub line: usize,
    /// The last segment of the macro path, e.g. `format` for `std::format!`.
    pub name: String,
    /// The tokens between the delimiters, which `syn` does not interpret.
    pub tokens: TokenStream,
}

/// Every macro invocation in `items`, including those in expression position.
///
/// `syn` leaves a macro body as an opaque token stream, so a guard asserting on what a
/// `format!` builds has to read the tokens itself. This is the seam for that.
#[must_use]
pub fn macro_calls(items: &[syn::Item]) -> Vec<MacroCall> {
    let mut visitor = MacroVisitor::default();
    for item in items {
        visitor.visit_item(item);
    }
    visitor.found
}

#[derive(Default)]
struct MacroVisitor {
    found: Vec<MacroCall>,
}

impl<'ast> Visit<'ast> for MacroVisitor {
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        if let Some(segment) = node.path.segments.last() {
            self.found.push(MacroCall {
                line: line_of(segment.ident.span()),
                name: segment.ident.to_string(),
                tokens: node.tokens.clone(),
            });
        }
        syn::visit::visit_macro(self, node);
    }
}

/// Every method call in `items`, by method name.
///
/// The detail is the receiver as written, so a guard can tell
/// `query.fetch_all(pool)` from `rows.fetch_all(pool)`.
#[must_use]
pub fn method_calls(items: &[syn::Item], method: &str) -> Vec<Finding> {
    let mut visitor = MethodVisitor {
        method: method.to_owned(),
        found: Vec::new(),
    };
    for item in items {
        visitor.visit_item(item);
    }
    visitor.found
}

struct MethodVisitor {
    method: String,
    found: Vec<Finding>,
}

impl<'ast> Visit<'ast> for MethodVisitor {
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if node.method == self.method {
            self.found.push(Finding {
                line: line_of(node.method.span()),
                detail: tokens_to_string(&node.receiver),
            });
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}

/// Every `allow` attribute in a parsed file, inner (`#![allow]`) and outer (`#[allow]`).
///
/// The detail is the allow's arguments as written, so a guard can require one exact
/// spelling. This reads the whole file rather than [`production_items`], because the
/// sanctioned allow lives inside a `#[cfg(test)]` module and pruning would hide the
/// very attributes being counted.
#[must_use]
pub fn allow_attributes(file: &syn::File) -> Vec<Finding> {
    let mut visitor = AllowVisitor::default();
    for attribute in &file.attrs {
        visitor.record(attribute);
    }
    visitor.visit_file(file);
    visitor.found
}

#[derive(Default)]
struct AllowVisitor {
    found: Vec<Finding>,
}

impl AllowVisitor {
    fn record(&mut self, attribute: &syn::Attribute) {
        if !attribute.path().is_ident("allow") {
            return;
        }
        let syn::Meta::List(list) = &attribute.meta else {
            return;
        };
        self.found.push(Finding {
            line: line_of(list.path.segments[0].ident.span()),
            detail: normalise_spacing(&list.tokens.to_string()),
        });
    }
}

/// `TokenStream::to_string` spaces tokens its own way; a guard comparing against a
/// written attribute needs the two to agree.
fn normalise_spacing(text: &str) -> String {
    text.replace(" :: ", "::").replace(" , ", ", ")
}

impl<'ast> Visit<'ast> for AllowVisitor {
    fn visit_attribute(&mut self, node: &'ast syn::Attribute) {
        self.record(node);
        syn::visit::visit_attribute(self, node);
    }
}

/// Every function and method path called anywhere in `items`, as written.
///
/// A guard asking "does this runner contain its work in a task" is asking whether one
/// call appears in one body. Reading calls from the tree means a reformat, a comment,
/// or a name that appears in a string cannot change the answer.
#[must_use]
pub fn called_paths_in_impl_items(items: &[syn::ImplItem]) -> Vec<String> {
    let mut visitor = CallVisitor::default();
    for item in items {
        visitor.visit_impl_item(item);
    }
    visitor.found
}

#[derive(Default)]
struct CallVisitor {
    found: Vec<String>,
}

impl<'ast> Visit<'ast> for CallVisitor {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = node.func.as_ref() {
            self.found.push(
                path.path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::"),
            );
        }
        syn::visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        self.found.push(node.method.to_string());
        syn::visit::visit_expr_method_call(self, node);
    }
}

/// Every string literal in `items`, in order.
///
/// A guard asking "does this file still issue `DEALLOCATE ALL`" is asking about a
/// literal, not about a line: reading it from the tree means a reformat, a raw string,
/// or a split declaration cannot change the answer.
#[must_use]
pub fn literals(items: &[syn::Item]) -> Vec<Finding> {
    let mut visitor = LiteralVisitor::default();
    for item in items {
        visitor.visit_item(item);
    }
    visitor.found
}

#[derive(Default)]
struct LiteralVisitor {
    found: Vec<Finding>,
}

impl<'ast> Visit<'ast> for LiteralVisitor {
    fn visit_lit_str(&mut self, node: &'ast syn::LitStr) {
        self.found.push(Finding {
            line: line_of(node.span()),
            detail: node.value(),
        });
        syn::visit::visit_lit_str(self, node);
    }

    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        // A macro body is opaque to `syn`, so its literals need the token walk.
        for text in string_literals(node.tokens.clone()) {
            self.found.push(Finding {
                line: line_of(
                    node.path
                        .segments
                        .last()
                        .map_or_else(proc_macro2::Span::call_site, |segment| segment.ident.span()),
                ),
                detail: text,
            });
        }
        syn::visit::visit_macro(self, node);
    }
}

/// The string literals a token stream contains, in order.
///
/// Guards that assert on what a `format!` builds need the literal, not the tokens.
#[must_use]
pub fn string_literals(tokens: TokenStream) -> Vec<String> {
    let mut found = Vec::new();
    collect_string_literals(tokens, &mut found);
    found
}

fn collect_string_literals(tokens: TokenStream, found: &mut Vec<String>) {
    for tree in tokens {
        match tree {
            proc_macro2::TokenTree::Literal(literal) => {
                if let Ok(syn::Lit::Str(text)) = syn::parse_str::<syn::Lit>(&literal.to_string()) {
                    found.push(text.value());
                }
            }
            proc_macro2::TokenTree::Group(group) => {
                collect_string_literals(group.stream(), found);
            }
            proc_macro2::TokenTree::Ident(_) | proc_macro2::TokenTree::Punct(_) => {}
        }
    }
}

/// Renders a `syn` node back to text, so a failing guard can quote what it saw.
fn tokens_to_string<T: quote::ToTokens>(node: &T) -> String {
    quote::ToTokens::to_token_stream(node).to_string()
}
