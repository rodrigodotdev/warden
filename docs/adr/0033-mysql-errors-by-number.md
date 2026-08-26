# ADR-0033 — Classify MySQL failures by error number

**Status:** Accepted · 2026-08-24 · **New in Milestone 7**

## Context

`warden_ports::QueryExecutor::execute_read_only`'s own documentation states that the
ordinary path to `ExecuteError::Timeout` is a clean server error: the server-side
deadline (ADR-0024) is configured to fire before the client one, so a query that runs
too long usually ends as an intact connection returned to the pool with a database
error attached, not a dropped future. Reporting that error as a generic
`ExecuteError::Database` would give the agent `query_execution_error` for the one
failure it can actually act on by retrying with a narrower query — the same
information a `CancellationToken` firing (`ER_QUERY_INTERRUPTED`, from this
executor's own `KILL QUERY`) needs to reach `ExecuteError::Cancelled` rather than the
same generic code.

SQLSTATE cannot make either distinction. MySQL reports `ER_QUERY_TIMEOUT` (3024) and
`ER_QUERY_INTERRUPTED` (1317) both under SQLSTATE `HY000`, which the server also uses
as the general "unspecified" category for many unrelated errors. Telling these two
apart from a normal statement failure requires the server's own numeric error code,
which SQLSTATE does not carry.

## Decision

Classify a failed statement by `MySqlDatabaseError::number()`, reached through
`sqlx::Error::as_database_error()` and `DatabaseError::try_downcast_ref`:

| Number | Meaning | Mapped to |
|---|---|---|
| 3024 (`ER_QUERY_TIMEOUT`) | `MAX_EXECUTION_TIME` aborted the statement | `ExecuteError::Timeout` |
| 1317 (`ER_QUERY_INTERRUPTED`) | a `KILL QUERY` reached the statement | `ExecuteError::Cancelled` |
| anything else | an ordinary statement failure | `ExecuteError::Database { detail }` |

The driver's message is kept only in `detail`, never printed by `Display`, exactly as
`ConnectError::Driver` already does — the same rule `warden-ports/src/error.rs`
states for every adapter-facing error.

## Consequences

AGENTS.md's "do not use `Box<dyn Any>`, downcasting, or mutable global state" rule is
about Warden's own domain values: nothing in `warden-core`, `warden-policy`, or
`warden-ports` is ever downcast. `DatabaseError::try_downcast_ref` is SQLx's own typed
accessor for its `dyn DatabaseError` trait object, the only way to reach a driver's
error number at all, and it stays inside this one adapter function; no Warden type is
involved on either side of the cast.

The mapping depends on MySQL's own numbering, which this crate does not control. A
container test pins both numbers against a real server (`MAX_EXECUTION_TIME` and a
manual `KILL QUERY`) so that an upstream MySQL release changing either number is
caught by the workspace's own test suite rather than surfacing as a misclassified
error in production.

Any other server error — a syntax error the server rejects mid-transaction, a
permission failure, a constraint violation — falls through to
`ExecuteError::Database`, unchanged from before this ADR.
