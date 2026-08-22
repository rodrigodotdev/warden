//! Mechanical guards for rules the Rust compiler cannot express.
//!
//! `tests/architecture.rs` does this for the dependency graph,
//! `warden-core/tests/newtype_rules.rs` for the core's modeling rules, and
//! `warden-policy/tests/policy_rules.rs` for the capability token. This file does it
//! for the port boundary, and it runs as a separate crate so it sees the same public
//! surface `warden-mysql` and `warden-service` will.
//!
//! The scans skip comment lines: the documentation explains why `async-trait` and a
//! raw-SQL parameter are forbidden, and those explanations must not trip the checks
//! that enforce them.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use warden_core::connection::{ConnectionMetadata, ConnectionName};
use warden_core::dialect::Dialect;
use warden_core::explain::QueryPlan;
use warden_core::query::QueryRequest;
use warden_core::result::ResultSet;
use warden_core::schema::{
    SchemaDescribeRequest, SchemaDescription, SchemaSearchRequest, SchemaSearchResult,
};
use warden_policy::{AnalyzedQuery, AuthorizedQuery};
use warden_ports::{
    AnalyzeError, AuditAttempt, AuditError, AuditOutcomeEvent, AuditSink, BoxFuture,
    ConnectionError, ConnectionRegistry, ConnectionRuntime, ExecuteError, ExplainError, Explainer,
    QueryAnalyzer, QueryExecutor, SchemaError, SchemaInspector,
};

/// The complete port inventory. Adding a port means adding it here and to
/// `docs/architecture.md`, which is the review moment this test creates.
const PORTS: &[(&str, &str, &[&str])] = &[
    ("analyzer.rs", "QueryAnalyzer", &["dialect", "analyze"]),
    ("executor.rs", "QueryExecutor", &["execute_read_only"]),
    (
        "inspector.rs",
        "SchemaInspector",
        &["search_schema", "describe_schema"],
    ),
    ("explainer.rs", "Explainer", &["explain"]),
    (
        "audit.rs",
        "AuditSink",
        &["record_attempt", "record_outcome"],
    ),
    ("registry.rs", "ConnectionRegistry", &["get", "list"]),
];

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn read(file: &str) -> String {
    fs::read_to_string(src_dir().join(file)).unwrap_or_else(|error| panic!("{file}: {error}"))
}

/// Every non-comment line of a file.
fn code_lines(source: &str) -> Vec<&str> {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect()
}

/// The body of one `pub trait` block, as non-comment lines.
///
/// rustfmt puts a top-level item's closing brace in column zero, which is what makes
/// this reliable without parsing Rust.
fn trait_body<'a>(source: &'a str, name: &str) -> Vec<&'a str> {
    let opener = format!("pub trait {name}");
    let mut inside = false;
    let mut body = Vec::new();
    for line in source.lines() {
        if line.starts_with(&opener) {
            inside = true;
            continue;
        }
        if inside {
            if line == "}" {
                return body;
            }
            if !line.trim_start().starts_with("//") {
                body.push(line);
            }
        }
    }
    panic!("no `pub trait {name}` block found");
}

#[test]
fn every_port_is_dyn_compatible() {
    // Constructing the trait object is the assertion: the connection is chosen at
    // runtime, so a port that stopped being dyn-compatible would break every
    // adapter, and it would do so with a confusing error far from here.
    let _analyzer: Arc<dyn QueryAnalyzer> = Arc::new(Stub);
    let _executor: Arc<dyn QueryExecutor> = Arc::new(Stub);
    let _inspector: Arc<dyn SchemaInspector> = Arc::new(Stub);
    let _explainer: Arc<dyn Explainer> = Arc::new(Stub);
    let _sink: Arc<dyn AuditSink> = Arc::new(Stub);
    let _registry: Arc<dyn ConnectionRegistry> = Arc::new(Stub);
}

#[test]
fn no_port_hides_its_future_behind_a_macro() {
    for (file, name, _) in PORTS {
        let source = read(file);
        assert!(
            !code_lines(&source)
                .iter()
                .any(|line| line.contains("async_trait")),
            "{file} mentions async_trait; ADR-0013 requires an explicit BoxFuture"
        );
        for line in trait_body(&source, name) {
            assert!(
                !line.contains("async fn"),
                "{name} declares an async fn, which is not dyn-compatible: {line}"
            );
            if line.contains("Future") {
                assert!(
                    line.contains("BoxFuture"),
                    "{name} returns a future that is not the BoxFuture alias: {line}"
                );
            }
        }
    }
}

#[test]
fn no_port_method_accepts_raw_sql() {
    // `docs/architecture.md` section 5: no port exposes an `execute(sql: &str)` API.
    // A port that took a string could be handed unanalyzed input, which is the
    // bypass the whole type pipeline exists to prevent.
    for (file, name, _) in PORTS {
        let source = read(file);
        for line in trait_body(&source, name) {
            assert!(
                !line.contains("&str") && !line.contains("String"),
                "{name} has a string-typed parameter: {line}"
            );
        }
    }
}

#[test]
fn every_port_is_shareable_across_tasks() {
    for (file, name, _) in PORTS {
        let source = read(file);
        let declaration = format!("pub trait {name}: Send + Sync");
        assert!(
            source.contains(&declaration),
            "{file}: {name} must declare `: Send + Sync`; every port is shared \
             between concurrent requests"
        );
    }
}

#[test]
fn every_port_and_method_is_documented_in_the_architecture() {
    let document = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/architecture.md"),
    )
    .unwrap();
    for (file, name, methods) in PORTS {
        let source = read(file);
        assert!(
            document.contains(name),
            "{name} is not mentioned in docs/architecture.md"
        );
        for method in *methods {
            assert!(
                source.contains(&format!("fn {method}")),
                "{file} does not declare {method}"
            );
            assert!(
                document.contains(method),
                "{name}::{method} is not mentioned in docs/architecture.md"
            );
        }
    }
}

#[test]
fn an_audit_record_cannot_be_serialized() {
    let source = read("audit.rs");
    assert!(
        !code_lines(&source)
            .iter()
            .any(|line| line.contains("Serialize")),
        "an audit record must not derive Serialize: it carries DenyReason's \
         internal detail, which never crosses the MCP boundary"
    );
    // The same file must not grow a field for the statement or its parameters.
    for forbidden in ["pub sql", "pub parameters"] {
        assert!(
            !source.contains(forbidden),
            "audit.rs declares `{forbidden}`; raw SQL and parameters are off by \
             default (docs/security.md section 11.3)"
        );
    }
}

/// A startup-only failure has no public code to leak.
///
/// `RuntimeError` is raised by the composition root while it is assembling a
/// `ConnectionRuntime`, before any transport is serving requests, so it never
/// crosses the MCP boundary and has nothing for a model to observe. `error.rs`'s own
/// test documents that intent in prose; this is the mechanical proof the comment
/// there promises, so the two cannot drift apart unnoticed.
#[test]
fn a_startup_only_error_implements_no_public_error() {
    let source = read("error.rs");
    assert!(
        !code_lines(&source)
            .iter()
            .any(|line| line.contains("impl PublicError for RuntimeError")),
        "error.rs must not implement PublicError for RuntimeError: it is a \
         startup-only failure that never reaches a model, so it has no public code \
         to leak"
    );
}

/// One type implementing every port, used only to prove dyn compatibility.
///
/// Each method is unreachable in this test; none of them is ever called.
struct Stub;

impl QueryAnalyzer for Stub {
    fn dialect(&self) -> Dialect {
        Dialect::MySql
    }

    fn analyze(&self, _request: QueryRequest) -> Result<AnalyzedQuery, AnalyzeError> {
        Err(AnalyzeError::RecursionLimit)
    }
}

impl QueryExecutor for Stub {
    fn execute_read_only<'a>(
        &'a self,
        _query: &'a AuthorizedQuery,
        _deadline: Instant,
        _cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<ResultSet, ExecuteError>> {
        Box::pin(async { Err(ExecuteError::Cancelled) })
    }
}

impl SchemaInspector for Stub {
    fn search_schema<'a>(
        &'a self,
        _request: &'a SchemaSearchRequest,
        _deadline: Instant,
        _cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<SchemaSearchResult, SchemaError>> {
        Box::pin(async { Err(SchemaError::Cancelled) })
    }

    fn describe_schema<'a>(
        &'a self,
        _request: &'a SchemaDescribeRequest,
        _deadline: Instant,
        _cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<SchemaDescription, SchemaError>> {
        Box::pin(async { Err(SchemaError::Cancelled) })
    }
}

impl Explainer for Stub {
    fn explain<'a>(
        &'a self,
        _query: &'a AuthorizedQuery,
        _deadline: Instant,
        _cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<QueryPlan, ExplainError>> {
        Box::pin(async { Err(ExplainError::Cancelled) })
    }
}

impl AuditSink for Stub {
    fn record_attempt<'a>(
        &'a self,
        _event: &'a AuditAttempt,
    ) -> BoxFuture<'a, Result<(), AuditError>> {
        Box::pin(async { Err(AuditError::Timeout) })
    }

    fn record_outcome<'a>(
        &'a self,
        _event: &'a AuditOutcomeEvent,
    ) -> BoxFuture<'a, Result<(), AuditError>> {
        Box::pin(async { Err(AuditError::Timeout) })
    }
}

impl ConnectionRegistry for Stub {
    fn get(&self, name: &ConnectionName) -> Result<Arc<ConnectionRuntime>, ConnectionError> {
        Err(ConnectionError::NotFound { name: name.clone() })
    }

    fn list(&self) -> Vec<ConnectionMetadata> {
        Vec::new()
    }
}
