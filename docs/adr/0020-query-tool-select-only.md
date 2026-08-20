# ADR-0020 — The `query` tool accepts only `SELECT`

**Status:** Accepted · 2026-08-19

## Context

"Read-only" is broader than `SELECT`: `SHOW`, `EXPLAIN`, and utility statements also
read. Accepting them through the generic tool expands the analysis surface without a
proportional benefit.

## Decision

The only root statement allowed by `query` is **`SELECT`**, including CTE-based
`SELECT` only when every nested statement is read-only.

`query` denies `SHOW`, `EXPLAIN`, `SET`, `BEGIN`, `COMMIT`, and `ROLLBACK`. Metadata
and EXPLAIN use dedicated, controlled tools.

## Consequences

This is deliberately narrower than a generic "read statement" executor. Each added
capability goes through a tool with its own contract and analysis instead of widening
the generic path.

Tool descriptions communicate this constraint to the agent (`docs/mcp.md` section
1.3).
