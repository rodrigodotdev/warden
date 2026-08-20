# ADR-0022 — Two-phase auditing

**Status:** Accepted · 2026-08-19 · **New in v0.3 · Supersedes:** the single-event
model in specification v0.2 section 95

## Context

Version 0.2 defined one `AuditEvent` and `AuditSink::write -> Result<...>` but never
answered: **does a query execute if the sink fails?**

The question appears academic while the sink is `tracing`. Once someone adds the
explicitly anticipated persistent sink, default behavior accidentally becomes
security policy.

A single event also leaves no record of the attempt if the process dies during
execution—exactly when auditing matters most.

## Decision

```text
attempt -> written BEFORE execution.  Sink failure => deny the query (fail closed).
outcome -> written AFTER execution.   Sink failure => raise an alarm (fail open).
```

Record the attempt before acquiring the concurrency permit. It contains **all** policy
denials, not only the first.

## Consequences

Every attempt leaves a trace, even if the process dies midway. An unavailable sink
cannot create an unaudited execution window.

The sink enters the latency-critical path, and a slow sink degrades the gateway. The
attempt phase must therefore be cheap and time-bounded, and
`warden_audit_write_failures_total` is an alarm metric.

Failing open for the outcome is acceptable because execution has already occurred;
there is nothing left to prevent, and the attempt is already recorded.
