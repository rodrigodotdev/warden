# ADR-0055 — Tracked work is drained under one deadline before the runtime exits

**Status:** Accepted · 2026-09-15 · **New in Milestone 13.3**

## Context

rmcp 3.2.0 drains its own handler tasks for at most 5 s after EOF and 2 s after
cancellation (`service.rs`, `drain_timeout`), then returns. Warden's per-request task
(`run_in_task`) and the `OutcomeGuard`'s detached `abandoned` write were plain
`tokio::spawn`s: a request still running when the runtime was dropped lost its outcome,
with a stderr alarm as its only trace. A queued request also waited out
`max_queue_wait` after shutdown began, because nothing closed the semaphore that
`acquire_query_permit` already knew how to report as `Unavailable`.

An admission gate with its own state was considered and rejected: rmcp's loop is the
admission — after EOF or cancellation no handler is spawned — and a `TaskTracker`
accepts a late spawn after `close()`, so a straggler is tracked rather than lost.

## Decision

`Services` owns a `tokio_util::task::TaskTracker`. The MCP adapter spawns every tool
call on it; the outcome guard spawns its detached write on it. `Deployment::close`
runs after the SDK's drain and, under one 30-second deadline: cancels the root token,
closes every connection's query gate (queued callers return `connection_unavailable`
with a `not_started` outcome), closes the tracker and waits for it, then closes the
pools with the time left. It returns a `DrainReport`; an incomplete one is logged and
`serve` exits non-zero. Nothing is aborted, and nothing is claimed persisted that was
not.

## Consequences

A complete shutdown leaves no admitted request or outcome write behind. An incomplete
one is observable by exit status. On EOF the SDK's 5 s precede cancellation, so an
in-flight query keeps running during them; cancelling at EOF would need the transport
reader to know the token and is left as a refinement. `SIGKILL`, disk failure and the
deadline itself remain outside any durability promise.
