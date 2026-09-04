# ADR-0042 — Every database-touching tool is audited

**Status:** Accepted · 2026-09-04 · **New in Milestone 13**

## Context

`AuditAttempt` was statement-shaped: it required a `StatementKind`, a fingerprint, and
denial reasons, none of which describe a catalog read. Milestone 11 made
`search_schema` and `describe_schema` reach a real database and be filtered — and
`describe_schema` refused outright — by the request's object rules (ADR-0036), and
Milestone 12 put both tools in an agent's hands over MCP. Neither milestone changed the
audit path: `SchemaService` recorded no attempt and no outcome, so a denied
`describe_schema`, exactly the call an investigation most wants to see, left no trace.
`docs/open-questions.md` item 21 recorded the gap and deferred the event-shape decision
to this milestone.

## Decision

The attempt now carries an `AuditOperation` (`Query`, `Explain`, `SearchSchema`,
`DescribeSchema`) and an optional `StatementKind`, so a record can describe a catalog
read without inventing a statement it never submitted. Every tool that reaches a
database records an attempt before dispatch and an outcome after it: `query` and
`explain` as before, and now `search_schema` and `describe_schema` alongside them. The
attempt write fails closed for a catalog read exactly as it does for a statement
(ADR-0022): if the attempt cannot be recorded, the read does not happen.

`list_connections` is not audited. It reads an in-memory map, reaches no database, and
returns configuration metadata the agent must already have before it can call anything
else — there is no database-touching operation for an attempt or an outcome to
describe.

## Consequences

A catalog read's attempt carries no denial reasons, unlike a statement's. Object rules
are applied inside the adapter (ADR-0036), so a refusal is only known after dispatch,
not before it; the outcome carries it instead, with `error_code` set and `outcome`
reported as `Denied`. `rows_returned` and `result_bytes` stay absent for a catalog
read's outcome: a matched or described relation is not a row, and reporting a catalog
count under a result set's field name would make the record say something it does not
mean.

Two audit writes are added to a path that previously had none, both bounded by
`AUDIT_WRITE_TIMEOUT` like every other audit write in the gateway. `SchemaService::new`
gains the audit sink as its third constructor parameter, matching `QueryService::new`
and `ExplainService::new`.
