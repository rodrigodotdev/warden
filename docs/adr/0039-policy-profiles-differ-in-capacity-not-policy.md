# ADR-0039 — Policy profiles differ in capacity, not policy

**Status:** Accepted · 2026-09-02 · **New in Milestone 12**

## Context

`docs/operations.md` section 3 gives each connection a named policy profile, and SPEC
section 5.2 lists policy profiles per connection as a *should*. Milestone 11 shipped
`Services` holding one `Arc<PolicyEngine>`: relaxations (`allow_locking_reads`,
`allow_unknown_functions`) and object rules (`schemas`, `allow_tables`, `deny_tables`)
are baked into the engine at construction and apply to every request `Services`
dispatches. `ExecutionLimits` and pool capacity, by contrast, already live on each
`ConnectionRuntime`, one per connection.

A configuration file that names several profiles can therefore ask for two different
things depending on which fields differ. Two profiles that only change `max_rows` or
pool sizing ask for something the current architecture already supports: capacity is
per connection. Two profiles that disagree about `allow_locking_reads` or an object
rule ask for something it does not: one process, one policy engine, one answer to
"is this statement allowed."

## Decision

Startup accepts several named profiles and takes `ExecutionLimits` and pool settings
per connection, exactly as `ConnectionRuntime` already models them. It **fails** when
two profiles referenced by any configured connection disagree about
`allow_locking_reads`, `allow_unknown_functions`, `schemas`, `allow_tables`, or
`deny_tables`, naming both profiles and the field that differs
(`ConfigError::ConflictingPolicy`). Agreement is checked against object rule lists as
written: two spellings of one rule set are still two review surfaces, so the check
does not sort or deduplicate before comparing.

Silently applying one connection's policy to another connection that asked for a
different one was considered and rejected: it is the one outcome worse than refusing
to start, because the deployment would appear to be running the operator's intended
policy on a connection where it is not.

## Consequences

A deployment whose profiles agree on policy and differ only in capacity starts
normally, and `docs/operations.md` section 3's example is exactly this case with one
profile. A deployment that genuinely needs different object rules per connection
cannot start today, and gets a message naming the two profiles and the field they
disagree on, instead of a gateway that quietly applies one connection's allowlist to
another.

Giving each connection its own `PolicyEngine` — a `PolicyEngine` per
`ConnectionRuntime`, and a `Services` that resolves the right one per request — would
remove this restriction, but it is a service-layer change to `warden-service`'s
construction, not a configuration one, and it is out of scope for an MCP-transport
milestone. It is recorded as a new open question rather than folded into Milestone 12.
