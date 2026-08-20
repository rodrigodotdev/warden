# ADR-0018 — Crate boundaries as an enforcement mechanism

**Status:** Accepted · 2026-08-19

## Context

Written dependency-direction rules are not self-enforcing. That is insufficient for
a security-sensitive project.

## Decision

Use separate `core`, `policy`, `ports`, `mysql`, `postgres`, `service`, `mcp`, and
`config` crates. The compiler enforces dependency direction, and inspecting
`Cargo.toml` verifies prohibitions such as `core -> sqlx` and `policy -> rmcp`.

Do not split further without concrete evidence of a boundary.

## Consequences

Builds take longer and there are more manifests. In exchange, "the core cannot depend
on SQLx" becomes a compile error instead of a matter of discipline.

Security review also becomes tractable: reviewers can examine `warden-policy` knowing
it cannot perform I/O.
