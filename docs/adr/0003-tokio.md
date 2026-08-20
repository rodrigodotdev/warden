# ADR-0003 — Tokio as the only runtime

**Status:** Accepted · 2026-08-19

## Context

MCP transport, SQLx, timeouts, cancellation boundaries, per-connection semaphores,
and asynchronous shutdown need the same runtime.

## Decision

Use Tokio, and only Tokio. Add `tokio-util` for `CancellationToken`.

## Consequences

Do not introduce a second async runtime. Dependency features must consistently
select Tokio, including SQLx's `runtime-tokio`. Mixing runtimes would create
hard-to-diagnose execution bugs in a security-sensitive path.
