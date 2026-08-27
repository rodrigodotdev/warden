# ADR-0025 — Two pools per named connection

**Status:** Accepted · 2026-08-19 · **New in v0.3**

## Context

A client timeout during row streaming forces SQLx to discard the connection because
the protocol is in the middle of a result set. With `max_connections: 5`, repeated
slow queries can drain the pool and stop health checks and schema discovery.

Version 0.2 suggested reserving pool capacity for metadata operations if necessary,
which is more fragile than separating traffic.

There is an independent reason: Warden receives unbounded varieties of SQL. With a
nonzero prepared-statement cache, each new query can retain a server-side prepared
statement.

## Decision

Each `ConnectionRuntime` owns two pools:

| Pool | Use | Statement cache |
|---|---|---|
| `agent_pool` | agent queries and EXPLAIN | PostgreSQL: `capacity(0)` plus `.persistent(false)` for generic and static Warden statements; only the authorized parameter-bound query from `bind::statement` is temporarily named, deallocated on its pinned connection, or that connection is retired if cleanup is unconfirmed. MySQL: `capacity(0)` is sufficient |
| `control_pool` | health checks and schema introspection | default |

## Consequences

Agent-traffic saturation or poisoning cannot take down health checks or schema
discovery. Readiness remains reliable under adversarial load.

**Corrected by Milestone 0.5:** disabling the cache is insufficient and, alone, makes
the problem worse. In `sqlx-postgres` 0.9, `query()` defaults to `persistent: true`,
so PARSE creates a **named** statement. With the cache disabled, `Close::Statement`
is never emitted and the statement leaks for the connection lifetime. PostgreSQL
requires both `statement_cache_capacity(0)` **and** `.persistent(false)`; the latter
prevents the leak. MySQL differs: its driver unconditionally sends `StmtClose` after
execution on the uncached path, so `capacity(0)` is enough (`Prepared_stmt_count`
measured zero in both arrangements). PostgreSQL retained 21 rows in
`pg_prepared_statements` after 20 queries. See `docs/operations.md` section 4.

**Milestone 8 refinement:** only the authorized parameter-bound PostgreSQL query built
by `bind::statement` temporarily uses a named statement. SQLx resolves a custom result
type by issuing a simple query, and PostgreSQL discards the unnamed prepared statement
in doing so. The executor therefore pins the connection, rolls back its read-only
transaction, and sends `DEALLOCATE ALL` before returning it to `agent_pool`. The pinned
connection is armed for retirement before that named query can exist and disarmed only
after both confirmations. Thus a dropped request future, or a rollback/deallocation
failure or timeout, retires the physical connection instead of returning unknown session
state. The exception supports custom result normalization while preserving this ADR's
no-retained-statements invariant; every other agent statement, including static Warden
statements such as `set_config`, continues to use `.persistent(false)`.

Keep the cache enabled for known static SQL and disabled for one-off agent SQL. Two
pools allow each traffic profile to use appropriate settings.

The cost is more connections per named connection. `control_pool` is small (2) and
idle most of the time.
