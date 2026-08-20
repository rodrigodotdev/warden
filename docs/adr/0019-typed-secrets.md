# ADR-0019 — Secrets are typed and redacted

**Status:** Accepted · 2026-08-19

## Context

DSNs contain passwords. They cross configuration, pool construction, logs, traces,
error messages, and debug formatting—many potential leak paths.

## Decision

DSN-bearing values use `secrecy` or an audited equivalent wrapper. A secret-bearing
struct does **not** derive `Serialize` and **redacts** its `Debug` output.

Configuration-validation errors never include secret values.

## Consequences

Accidental leakage through `{:?}` or MCP-model serialization becomes a compile error
instead of an incident.

The few legitimate sites require explicit `expose_secret()` calls, making them
auditable with a text search.
