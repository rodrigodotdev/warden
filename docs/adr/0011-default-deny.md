# ADR-0011 — Default deny

**Status:** Accepted · 2026-08-19

## Context

A security gateway needs defined behavior for input it cannot classify.

## Decision

```text
unknown -> deny             unsupported -> deny
parse failure -> deny       multiple statements -> deny
unclassified function -> deny   ambiguous side effect -> deny
```

During AST traversal, wildcard arms map to `Unknown` (denied), never to "ignore."

## Consequences

A false negative—a safe query rejected—is acceptable. A false positive—an unsafe
query authorized—is not.

The agent will occasionally have a legitimate query rejected because of parser
limitations. Error messages must be good enough for reformulation, and the corpus
must grow with real cases.
