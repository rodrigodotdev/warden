# ADR-0044 — Spans are the observability surface

**Status:** Accepted · 2026-09-04 · **New in Milestone 13**

## Context

`docs/operations.md` section 10.1 has carried a span tree since v0.3 while
explicitly saying that none of its labels were tracing spans. Every phase it names
is already a real code path, so the tree was a naming decision waiting to be made,
not an open design question.

## Decision

The names in section 10.1's tree are the span names. Each MCP tool call and its
service call have root spans at `info`; phase spans are at `debug`. The shipped
`warn,warden=info` filter therefore records one span per request by default, while
an operator can opt into the complete diagnostic tree.

Span fields are restricted to the audit record's identity fields: `request_id`,
`principal_id`, `client`, `connection`, `dialect`, `environment`, and `operation`.
No span may carry a statement, a parameter, or a `DenyReason` detail.

`tests/architecture.rs` parses section 10.1 and fails when code and documentation
disagree; that mechanical guard is introduced in Task 8.

## Consequences

The tree is load-bearing documentation. Renaming a span means editing section 10.1
in the same commit. OpenTelemetry export is deliberately not added: section 10.3
defers it until after the first vertical slice, and a stable span taxonomy is what
an exporter needs first.
