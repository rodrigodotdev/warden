# ADR-0007 — Parser ASTs never leave adapter crates

**Status:** Accepted · 2026-08-19 · **Non-negotiable without a new ADR**

## Context

Because both adapters use the same library, exposing the `sqlparser` AST as a shared
type would be tempting.

## Decision

`sqlparser` AST types never appear in a public adapter API, the core, policy, or MCP.
The core receives only a deliberately lossy, security-focused `QueryAnalysis`.

## Consequences

The parser is replaceable: a future PostgreSQL implementation can adopt
`libpg_query` without changing MCP, core, policy, query service, or audit models.

Parser upgrades no longer risk breaking the entire codebase. Policy needs security
facts, not a complete syntax tree, which also keeps its review surface small.

Each adapter must map its AST to `QueryAnalysis`; that mapping is security-sensitive
code and requires a corpus.
