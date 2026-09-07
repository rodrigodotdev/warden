//! Mechanical guards for the audit record format, read from outside the module.
//!
//! This is the most security-sensitive format in the product — `docs/security.md`
//! section 11.3 and SPEC section 6, invariants 22–23 — and until ADR-0048 it had the
//! weakest mechanical protection of any boundary in the workspace. Its forbidden-field
//! list was a `#[cfg(test)] const` *inside the module it guards*, so a field added
//! beside it inherited the exemption. Every other boundary here has a guard file that
//! reads it from the outside; this is the audit format's.
//!
//! The unit tests in `src/record.rs` stay: they assert on serialized *values*, which
//! only a running serializer can produce. This file asserts on the *declaration* — the
//! names a type can carry at all — which the source answers and a test that builds one
//! record cannot.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use warden_guards::{literals, production_items, source_files};

/// Names no record may ever carry (`docs/operations.md` section 10.2).
///
/// Deliberately duplicated from `src/record.rs`'s own list rather than imported: a
/// guard that reads its expectations from the thing it guards proves nothing. If the
/// two ever disagree, that disagreement is the finding.
const FORBIDDEN_FIELDS: &[&str] = &[
    "sql",
    "raw_sql",
    "statement",
    "parameters",
    "raw_parameters",
    "password",
    "dsn",
];

fn crate_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Every field name any `Serialize` type in this crate declares, including the name a
/// `#[serde(rename)]` puts on the wire.
fn serialized_field_names() -> BTreeSet<(String, String)> {
    let mut names = BTreeSet::new();
    for path in source_files(&crate_src()) {
        let file = path.file_name().unwrap().to_string_lossy().into_owned();
        for item in production_items(&path) {
            let syn::Item::Struct(declaration) = item else {
                continue;
            };
            if !derives_serialize(&declaration.attrs) {
                continue;
            }
            for field in &declaration.fields {
                let Some(ident) = &field.ident else {
                    continue;
                };
                names.insert((file.clone(), serde_name(field, ident)));
            }
        }
    }
    names
}

fn derives_serialize(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("derive")
            && attribute
                .parse_args_with(
                    syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
                )
                .is_ok_and(|paths| {
                    paths
                        .iter()
                        .any(|path| path.segments.last().is_some_and(|s| s.ident == "Serialize"))
                })
    })
}

/// The name a field goes onto the wire under: its `#[serde(rename = "...")]` if it has
/// one, otherwise its own identifier.
fn serde_name(field: &syn::Field, ident: &syn::Ident) -> String {
    for attribute in &field.attrs {
        if !attribute.path().is_ident("serde") {
            continue;
        }
        let mut renamed = None;
        let _ = attribute.parse_nested_meta(|meta| {
            if meta.path.is_ident("rename")
                && let Ok(value) = meta.value()
                && let Ok(syn::Lit::Str(text)) = value.parse::<syn::Lit>()
            {
                renamed = Some(text.value());
            }
            Ok(())
        });
        if let Some(name) = renamed {
            return name;
        }
    }
    ident.to_string()
}

#[test]
fn no_serialized_type_declares_a_field_a_statement_or_a_secret_could_occupy() {
    let declared = serialized_field_names();
    assert!(
        !declared.is_empty(),
        "no serializable record type was found, so this guard passed on an absence"
    );

    let mut violations = Vec::new();
    for (file, name) in &declared {
        if FORBIDDEN_FIELDS.contains(&name.as_str()) {
            violations.push(format!("  src/{file}: {name}"));
        }
    }

    assert!(
        violations.is_empty(),
        "an audit record declares a field a statement or a secret could occupy:\n{}\n\n\
         SPEC section 6, invariants 22–23: the trail records that a request happened \
         and what was decided, never the statement text, a parameter value, or a \
         credential. A fingerprint is the most a record may carry about a statement \
         (ADR-0043).",
        violations.join("\n")
    );
}

#[test]
fn the_forbidden_names_never_appear_as_a_literal_in_this_crate() {
    // The field-name scan reads declarations. A record can also gain a key from a
    // literal — a `tracing` field name, a `serde_json::json!` member — and those never
    // pass through a struct definition. `docs/operations.md` section 10.2 forbids the
    // name, not the mechanism.
    let mut violations = Vec::new();
    for path in source_files(&crate_src()) {
        for literal in literals(&production_items(&path)) {
            if FORBIDDEN_FIELDS.contains(&literal.detail.as_str()) {
                violations.push(format!(
                    "  {}:{}: \"{}\"",
                    path.display(),
                    literal.line,
                    literal.detail
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "a forbidden record key appears as a literal:\n{}",
        violations.join("\n")
    );
}

#[test]
fn both_sinks_project_the_same_record_declaration() {
    // The stderr sink and the file sink must write one format. They did diverge once —
    // the field list used to be duplicated between a `tracing` call and a constant
    // beside it — and `record.rs` exists to be the single declaration. This asserts
    // that neither sink has grown a second one: every record type in the crate lives in
    // `record.rs`, so neither sink can declare a shape of its own.
    let declared = serialized_field_names();
    let elsewhere: Vec<&(String, String)> = declared
        .iter()
        .filter(|(file, _)| file != "record.rs")
        .collect();

    assert!(
        elsewhere.is_empty(),
        "a serializable record type is declared outside `record.rs`: {elsewhere:?}\n\n\
         One declaration is what keeps the two sinks writing one format (ADR-0043). \
         A shape declared beside a sink is a shape only that sink writes."
    );
}

#[test]
fn the_scans_are_alive() {
    // Each scan, exercised on a fixture that violates it, so a passing suite means the
    // guards can still fail.
    let offending = warden_guards::production_items_of(
        r#"
        #[derive(serde::Serialize)]
        struct Leaky {
            attempt_id: Uuid,
            #[serde(rename = "sql")]
            statement_text: String,
        }
        "#,
    );
    let syn::Item::Struct(declaration) = &offending[0] else {
        panic!("expected a struct");
    };
    assert!(derives_serialize(&declaration.attrs));

    let renamed: Vec<String> = declaration
        .fields
        .iter()
        .filter_map(|field| field.ident.as_ref().map(|ident| serde_name(field, ident)))
        .collect();
    assert_eq!(
        renamed,
        ["attempt_id", "sql"],
        "a `#[serde(rename)]` must be read as the name that reaches the wire; a scan \
         that reads the Rust identifier instead would miss exactly the rename a leak \
         would use"
    );
    assert!(
        renamed
            .iter()
            .any(|name| FORBIDDEN_FIELDS.contains(&name.as_str()))
    );

    // And a type that does not derive `Serialize` is not a record.
    let inert = warden_guards::production_items_of("struct NotARecord { sql: String }");
    let syn::Item::Struct(inert) = &inert[0] else {
        panic!("expected a struct");
    };
    assert!(!derives_serialize(&inert.attrs));
}
