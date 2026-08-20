//! # DISPOSABLE — Milestone 0.5
//!
//! This crate retires integration risk rather than becoming production code. It
//! validates rmcp 3.x, SQLx 0.9, Testcontainers, and TLS **before** architectural
//! decisions depend on assumptions about those APIs.
//!
//! ## Rules
//!
//! - Production `warden-*` crates reference nothing here.
//! - This is not a production template. It deliberately talks to databases directly,
//!   outside the SPEC type boundaries.
//! - Remove it after Milestone 12, once the production crates cover the same ground.
//!
//! Tracked in `docs/open-questions.md` under "Removing `warden-tracer`."

/// Value returned by the tracer server's only tool.
pub const TRACER_TOOL_RESULT: &str = "warden-tracer-ok";

/// Name of the tracer server's only tool.
pub const TRACER_TOOL_NAME: &str = "tracer_ping";
