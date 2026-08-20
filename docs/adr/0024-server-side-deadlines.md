# ADR-0024 — Server-side deadlines, not only client-side timeouts

**Status:** Accepted · 2026-08-19 · **New in v0.3 · Resolves:** the gap left open in
specification v0.2 section 52

## Context

Version 0.2 acknowledged that dropping a client future does not guarantee server-side
query termination, but deferred the MySQL solution because rewriting agent SQL to
inject an optimizer hint seemed risky.

Without server-side termination, Warden's concurrency limit bounds the load Warden
**observes**, not database load. Repeated timeouts leave orphaned queries, defeating
the promised availability guarantee.

A solution exists that does not touch agent SQL.

## Decision

**PostgreSQL**—apply these parameters at connect time, outside any agent-controlled
path:

```text
statement_timeout, idle_in_transaction_session_timeout, lock_timeout,
default_transaction_read_only=on, search_path
```

**MySQL**—run `SET SESSION MAX_EXECUTION_TIME` through
`PoolOptions::after_connect`. It applies to read-only `SELECT`, Warden's exact
profile.

**Ordering:** the server timeout is strictly shorter than the client timeout (5s vs.
6s). `tokio::time::timeout` becomes a safety net, not the primary path.

`QueryExecutor::execute_read_only` accepts `deadline` and `CancellationToken`
explicitly so adapters can issue real cancellation instead of merely being dropped.

## Consequences

Database load is effectively bounded.

Setting `default_transaction_read_only = on` during connection becomes a **fourth**
independent write barrier—parser, policy, transaction, and session—and a fixed
`search_path` removes one ADR-0023 naming ambiguity.

Because the server timeout fires first, the normal path returns a clean error and an
intact connection to the pool instead of dropping it mid-stream. This prevents the
pool exhaustion addressed by ADR-0025.

No agent SQL is rewritten, so the concern that blocked v0.2 does not apply.
