//! Fixtures and tracing helpers the workspace's test suites share (ADR-0049).
//!
//! Only what is genuinely identical lives here. Four crates carry a `testing` module,
//! and a clone scan found `connection`, `capabilities`, `parts` and `result_set`
//! byte-identical across three or four of them — four chances to drift on what the
//! tests are testing against. Those are here.
//!
//! **The port fakes are not.** They looked duplicated and are not: `FakeExecutor` holds
//! one field in `warden-ports`, seven in `warden-service` and two in `warden-mcp`,
//! because each carries the observation surface its own crate's tests assert on.
//! Merging them means giving every crate a union it mostly never reads, or making two
//! crates test through a poorer fake. Both are worse than the duplication.
//!
//! # Why a crate and not a feature
//!
//! A `testing` feature on a production crate can reach a release build through one
//! mistyped manifest line, and a fake audit sink in production is an audit sink that
//! records nothing. A crate that appears in no normal dependency edge cannot, and the
//! assertion that checks it is a simpler statement than one about feature unification.
//!
//! # Why the one standing `allow` appears here
//!
//! A fixture asserts by panicking exactly as a test does — that is what the standing
//! exception in `AGENTS.md` is for, and this crate is test code that happens to live in
//! a crate rather than in a `#[cfg(test)]` module. It is reached from
//! `[dev-dependencies]` alone and `tests/architecture.rs` proves it, so no panic here
//! can reach a request path (ADR-0049).
#![allow(clippy::unwrap_used, clippy::expect_used)]

pub mod tracing_interest;

use std::num::NonZeroUsize;
use std::time::Duration;

use warden_core::analysis::{QueryAnalysisParts, StatementKind};
use warden_core::connection::{Capabilities, ConnectionMetadata, Environment};
use warden_core::context::RequestContext;
use warden_core::dialect::Dialect;
use warden_core::result::{QueryStats, ResultColumn, ResultSet, ResultValue};

/// The identity every test request carries.
#[must_use]
pub fn request_context() -> RequestContext {
    RequestContext::new(
        "req-1".parse().unwrap(),
        "alice@example.com".parse().unwrap(),
        "Claude Code".parse().unwrap(),
    )
}

/// A production connection on the given dialect.
/// The connection every crate's tests describe.
#[must_use]
pub fn connection(dialect: Dialect) -> ConnectionMetadata {
    ConnectionMetadata {
        name: "production-db".parse().unwrap(),
        dialect,
        environment: Environment::Production,
        database: "app".to_owned(),
    }
}

/// An adapter that can do everything.
/// The capability set a fully featured adapter advertises.
#[must_use]
pub fn capabilities() -> Capabilities {
    Capabilities {
        read_only_transactions: true,
        structured_explain: true,
        server_statement_timeout: true,
        schema_search: true,
    }
}

/// The baseline evidence: one safe `SELECT`, no risks, no objects.
/// One read of `app.orders`, as the analyser reports it.
#[must_use]
pub fn parts(dialect: Dialect) -> QueryAnalysisParts {
    QueryAnalysisParts {
        dialect,
        statement_count: NonZeroUsize::MIN,
        root_kind: StatementKind::Select,
        nested_kinds: Vec::new(),
        objects: Vec::new(),
        functions: Vec::new(),
        risks: Vec::new(),
        has_locking_clause: false,
        has_side_effects: false,
        fingerprint: None,
    }
}

/// One normalized row, so a fake result is a valid result.
/// A small result the response path can carry end to end.
#[must_use]
pub fn result_set() -> ResultSet {
    ResultSet {
        columns: vec![ResultColumn {
            name: "id".to_owned(),
            database_type: "BIGINT".to_owned(),
            nullable: Some(false),
        }],
        rows: vec![vec![ResultValue::I64(1)]],
        truncated: false,
        stats: QueryStats {
            rows_returned: 1,
            bytes: 1,
            duration: Duration::from_millis(1),
        },
    }
}
