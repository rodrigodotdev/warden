# ADR-0017 — Never expose `EXPLAIN ANALYZE`

**Status:** Accepted · 2026-08-19

## Context

`EXPLAIN ANALYZE` executes the underlying query. Exposing it through a plan-inspection
tool would create an execution path outside the `query` pipeline.

## Decision

Expose only non-executing variants: `EXPLAIN` / `EXPLAIN FORMAT=JSON` on MySQL and
`EXPLAIN (FORMAT JSON)` on PostgreSQL. Never enable `ANALYZE`.

The `explain` path runs **the same policies**, not a subset.

## Consequences

The agent does not receive actual execution timing, but `explain` is not an execution
vector.

`EXPLAIN` still **plans** the query, and PostgreSQL's planner constant-folds functions
marked `IMMUTABLE`. A malicious immutable UDF could run during planning, so function
policy applies in full here.
