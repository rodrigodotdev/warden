# ADR-0034 — Classify PostgreSQL failures by SQLSTATE

**Status:** Accepted · 2026-08-25 · **New in Milestone 8**

## Context

ADR-0033 had to reach for `MySqlDatabaseError::number()` because MySQL reports both
`ER_QUERY_TIMEOUT` and `ER_QUERY_INTERRUPTED` under SQLSTATE `HY000`, the same code
it uses for unrelated failures. PostgreSQL is the opposite case: its SQLSTATEs are
standardized and specific, and `sqlx`'s own `DatabaseError::code()` exposes them
without a downcast.

It has the opposite problem instead. `57014` `query_canceled` is the code for a
statement aborted by `statement_timeout` **and** for one stopped by a cancel
request. PostgreSQL separates them only in the message text — "canceling statement
due to statement timeout" against "canceling statement due to user request" — whose
language depends on `lc_messages`, a server setting Warden does not pin and would
have to pin for every deployment to make message matching sound.

## Decision

Classify a failed statement by `sqlx::Error::as_database_error()` and
`DatabaseError::code()`:

| SQLSTATE | Meaning | Mapped to |
|---|---|---|
| `57014` (`query_canceled`) | `statement_timeout` aborted the statement, or something cancelled it | `ExecuteError::Timeout` |
| anything else | an ordinary statement failure | `ExecuteError::Database { detail }` |

`57014` maps to `Timeout` because the server-side deadline firing before the client
one is the *designed* ordinary path (ADR-0024; `docs/operations.md` section 5.3), and
`query_timeout` is the code an agent can act on by narrowing its query.

There is no arm producing `ExecuteError::Cancelled`, and none is needed.
`PostgreSqlQueryExecutor` observes its own `CancellationToken` in a `biased`
`tokio::select!` and returns `Cancelled` from that arm without waiting for the
server's error, so Warden's own cancellation never reaches this function.

`lc_messages = 'C'` was considered and rejected. It would make message matching
reliable, but it is a sixth pinned startup setting that changes every error message
the deployment's own operators read, in exchange for distinguishing two outcomes an
agent responds to identically.

## Consequences

A statement cancelled by something **outside** Warden — a DBA running
`pg_cancel_backend`, or another tool's `pg_terminate_backend` — is reported to the
agent as `query_timeout` rather than `query_cancelled`. That is a deliberate
misnomer in a rare case, chosen over misreporting the common one. A container test
pins the ordinary direction: a statement that exceeds `statement_timeout` reaches
`PostgreSqlQueryExecutor` as `ExecuteError::Timeout` with the connection returned to
the pool intact.

Any other server error — a syntax error, a permission failure, a write refused by the
read-only transaction (`25006`) — falls through to `ExecuteError::Database`, whose
`Display` prints nothing of the driver's message.
