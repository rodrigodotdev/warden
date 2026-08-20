# ADR-0005 — Concrete pools, never `AnyPool`

**Status:** Accepted · 2026-08-19

## Context

SQLx provides `AnyPool` to abstract the backend. It appears attractive as a way to
reduce duplicated infrastructure code.

## Decision

Use concrete `MySqlPool` and `PgPool` values. `AnyPool` is not part of the
architecture.

Keep SQLx's `any` feature **disabled**, making violations compile errors instead of
written rules.

```rust
struct MySqlExecutor { agent_pool: MySqlPool, control_pool: MySqlPool }
struct PostgresExecutor { agent_pool: PgPool, control_pool: PgPool }
```

## Consequences

Each adapter contains more infrastructure code. In exchange, the domain knows its
backend—which is exactly what a security gateway needs because security semantics
differ between engines. Flattening them behind a common abstraction would be the
project's fatal mistake.

Generic behavior belongs above the executors, not inside the driver layer.
