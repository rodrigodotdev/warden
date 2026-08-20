# ADR-0009 — Read-only throughout the 0.x line

**Status:** Accepted · 2026-08-19

## Context

Agent-authorized writes are a different product with a different threat model.

## Decision

Version 0.x has no user-facing write executor. Writes are not hidden behind a
configuration flag.

## Consequences

If writes are ever introduced, they will be a separate capability with a separate
authorization model and explicit design review—not a boolean in `warden.toml`.

This greatly simplifies analysis: every write statement is denied without contextual
exceptions.
