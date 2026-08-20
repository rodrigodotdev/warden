# ADR-0015 — stdio first, Streamable HTTP later

**Status:** Accepted · 2026-08-19

## Context

stdio is the shortest path to a usable local vertical slice. HTTP requires
authentication, principal context, and a deployment model.

## Decision

MCP over stdio is the first transport (M12); Streamable HTTP follows in M14.

## Consequences

Product feedback arrives sooner. Local stdio **does not** protect a production DSN
stored in the same environment available to the agent. Remote mode is the recommended
production architecture, and `warden check` warns when stdio serves a `production`
profile.

With stdio, stdout carries protocol data only. `clippy::print_stdout = "deny"`
enforces this rule.
