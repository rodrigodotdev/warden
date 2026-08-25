# ADR-0032 — The concurrency permit is a parameter

**Status:** Accepted · 2026-08-24 · **New in Milestone 7**

## Context

`docs/open-questions.md` item 14 asked whether anything besides convention stops an
adapter from bypassing the query permit or the audit attempt. For the permit, the
answer was no. `ConnectionRuntime::executor()` and `explainer()` hand out their trait
objects unconditionally, so `execute_read_only` and `explain` both compiled and ran
without the caller ever calling `acquire_query_permit`. SPEC section 6, invariant 17
therefore held only for as long as every call site remembered to acquire first — a
property that survives code review today and does not survive Milestone 7 adding the
first real adapter, or Milestone 11 adding a second call site in the service layer.
The same gap left `explain`'s concurrency bounded only by `agent_pool`, not by
`max_concurrent_queries`, even though planning runs real work on the server
(`docs/mcp.md` section 3.1).

Two resolutions were on the table. The first moves `execute_read_only` and `explain`
onto `ConnectionRuntime` itself, which would acquire the permit internally before
dispatching to the adapter and drop the `executor()`/`explainer()` accessors
entirely. The second adds a `&QueryPermit` witness parameter to both port methods, so
a call site cannot compile without holding a slot, while `executor()` and
`explainer()` keep handing out the trait objects as before.

## Decision

Add the witness parameter. `QueryExecutor::execute_read_only` and `Explainer::explain`
both take `permit: &QueryPermit` as an argument the trait itself never reads.

Moving the methods onto `ConnectionRuntime` was rejected for this milestone because it
also reshapes who owns dispatch: `ConnectionRuntime` would need to know about
deadlines, cancellation, and the specific error types of two unrelated ports, which
today live entirely in `warden-ports`'s trait definitions. The witness parameter gets
the same compile-time guarantee — no permit, no call — without moving that knowledge.
It costs one unused parameter per call site; the alternative costs a wider
`ConnectionRuntime` API that Milestone 11's service layer would have to work around
rather than build on.

`crates/warden-ports/tests/port_rules.rs` asserts mechanically that both trait
declarations carry `permit: &'a QueryPermit`, so a future port that runs work on the
server and skips the parameter fails the workspace test suite rather than shipping
silently.

## Consequences

A call to `execute_read_only` or `explain` without a held permit is now a compile
error at every call site, present and future, rather than a runtime gap that only a
review or an incident would catch.

The parameter proves *a* permit exists; it does not prove the permit came from *this*
connection. `&QueryPermit` carries no connection identity, so a caller that acquired a
slot on one `ConnectionRuntime` and passed it to another's executor would still type-
check. It also does not order the permit against `AuditSink::record_attempt`
(ADR-0022): nothing here forces the audit attempt to be written before execution
begins, only that execution cannot begin without a permit. Milestone 11 owns the
service layer that is expected to make both pairings — permit-to-connection and
attempt-before-execution — structural rather than left to the caller's discipline
this ADR removes from the permit alone.
