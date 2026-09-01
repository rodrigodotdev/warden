//! Mechanical guards for service-layer rules the Rust compiler cannot express.
//!
//! `tests/architecture.rs` guards the dependency graph and this separate crate sees
//! the same public surface as `warden-mcp` and the composition root. These narrow
//! textual checks deliberately complement behavioral tests for invariants that have
//! no compiler representation (R5).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
    fs::read_dir(src_dir())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_file())
        .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
        .collect()
}

fn uncommented_source(source: &str) -> String {
    let mut code = String::with_capacity(source.len());
    let mut characters = source.chars().peekable();
    let mut block_depth = 0_u32;
    let mut in_line_comment = false;
    let mut in_string = false;
    let mut escaped = false;

    while let Some(character) = characters.next() {
        if in_line_comment {
            if character == '\n' {
                in_line_comment = false;
                code.push(character);
            }
            continue;
        }
        if block_depth > 0 {
            if character == '/' && characters.peek() == Some(&'*') {
                characters.next();
                block_depth += 1;
            } else if character == '*' && characters.peek() == Some(&'/') {
                characters.next();
                block_depth -= 1;
            } else if character == '\n' {
                code.push(character);
            }
            continue;
        }
        if in_string {
            code.push(character);
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            continue;
        }
        if character == '"' {
            in_string = true;
            code.push(character);
        } else if character == '/' && characters.peek() == Some(&'/') {
            characters.next();
            in_line_comment = true;
        } else if character == '/' && characters.peek() == Some(&'*') {
            characters.next();
            block_depth = 1;
        } else {
            code.push(character);
        }
    }

    code
}

fn production_source(source: &str) -> String {
    uncommented_source(source)
        .lines()
        .take_while(|line| line.trim() != "#[cfg(test)]")
        .collect::<Vec<_>>()
        .join("\n")
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
    for path in rust_source_files() {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name == "pipeline.rs" || name == "testing.rs" {
            continue;
        }
        let source = production_source(&fs::read_to_string(&path).unwrap());
        for call in GATED_CALLS {
            assert!(
                !source.contains(call),
                "{name} calls {call}; only pipeline.rs may, so the audit attempt \
                 and permit-to-connection pairing stay structural (ADR-0038)"
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
        let executor = runtime.executor();
    "#;
    let code = uncommented_source(source);
    assert_eq!(code.matches(".executor()").count(), 1);
    assert!(!code.contains(".explainer()"));
    assert!(!code.contains(".acquire_query_permit()"));
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
    let code = production_source(source);
    assert!(code.contains(".executor()"));
    assert!(!code.contains(".explainer()"));
    assert!(!code.contains(".acquire_query_permit()"));
}

#[test]
fn the_gate_guard_scans_only_regular_rust_files() {
    assert!(rust_source_files().iter().all(|path| {
        path.is_file() && path.extension().is_some_and(|extension| extension == "rs")
    }));
}

#[test]
fn every_response_path_redacts_before_it_returns() {
    for (file, call) in [
        ("query.rs", "redact_result"),
        ("explain.rs", "redact_plan"),
        ("schema.rs", "redact_description"),
    ] {
        let source = production_source(&fs::read_to_string(src_dir().join(file)).unwrap());
        assert!(
            source.contains(call),
            "{file} must call {call}: redaction happens after normalization and \
             before serialization (docs/security.md section 8)"
        );
    }
}

#[test]
fn a_startup_only_error_implements_no_public_error() {
    let source = production_source(&fs::read_to_string(src_dir().join("error.rs")).unwrap());
    assert!(
        !source.contains("impl PublicError for ServiceBuildError"),
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
    let services = Services::new(parts(RedactionSettings::default())).unwrap();
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
    let source = production_source(&fs::read_to_string(src_dir().join("error.rs")).unwrap());
    for line in source.lines() {
        assert!(
            !line.contains("{detail"),
            "an error message must not interpolate a detail field: {line}"
        );
    }
}
