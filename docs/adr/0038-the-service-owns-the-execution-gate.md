# ADR-0038 — The service layer owns the execution gate

**Status:** Accepted · 2026-09-01 · **New in Milestone 11**

## Context

`docs/open-questions.md` item 14 asked whether anything besides convention stops a
caller from bypassing the audit attempt. ADR-0032 resolved the permit half: a call to
`execute_read_only` or `explain` without a `&QueryPermit` is a compile error. It
explicitly left two gaps. The permit carries no connection identity, so a permit from
one `ConnectionRuntime` type-checks against another runtime's executor, and nothing
orders permit acquisition against `AuditSink::record_attempt`, which ADR-0022 requires
to happen first.

Moving `execute_read_only` and `explain` onto `ConnectionRuntime` was considered again.
That would give `warden-ports` knowledge of deadlines, cancellation, and two unrelated
error types, and it would still not order the audit attempt before the permit.

## Decision

`warden-service` owns a private `ExecutionGate` with one constructor. The constructor
records the audit attempt and then acquires a permit from the same
`ConnectionRuntime` the gate stores and later dispatches to. Its `execute` and
`explain` methods take `self` by value, so returning from or dropping either call
releases the slot.

`crates/warden-service/tests/service_rules.rs` uses an AST- and token-aware source
guard to assert that no other production file in `warden-service` calls `executor()`,
`explainer()`, or `acquire_query_permit()`. This keeps the attempt-before-permit order
and the permit-to-connection pairing behind one private construction path.

## Consequences

Within `warden-service`, an authorized query or explain request cannot reach its
adapter before its audit attempt is recorded, and the permit comes from the runtime
that supplies the adapter. The guarantee is deliberately scoped to this crate. It
does not constrain a future crate that calls the ports directly, and it does not
replace database privileges as the final write boundary (ADR-0016).

`AuditOutcome::NotStarted` exists because the attempt now provably precedes permit
acquisition. An authorized statement can therefore end at `server_busy` without ever
reaching the database, and its audit outcome must not claim that execution failed.
