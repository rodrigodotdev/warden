# ADR-0008 — MCP is an inbound adapter

**Status:** Accepted · 2026-08-19

## Context

The product is a secure query gateway. MCP is how agents communicate with it today;
MCP is not the domain.

## Decision

`warden-core`, `warden-policy`, `warden-ports`, and the adapter crates **do not
depend on `rmcp`**. Crate boundaries enforce the direction.

```text
warden-mcp -> warden-service -> warden-policy / ports / core <- adapters
```

## Consequences

A future transport such as gRPC, custom HTTP, or an embedded library does not require
rewriting the domain. Security review remains independent from MCP SDK evolution,
and protocol-version changes stay inside one crate.

The MCP crate must explicitly map domain types to protocol types. This is desirable:
it is where error sanitization occurs.
