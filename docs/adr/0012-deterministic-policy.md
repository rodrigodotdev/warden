# ADR-0012 — Deterministic policy, without an LLM

**Status:** Accepted · 2026-08-19

## Context

It is tempting to ask a model whether SQL is safe.

## Decision

Security decisions are deterministic. Policy evaluation is synchronous and performs
no network, database, or LLM call.

Policy **evaluates every rule** and aggregates all denials instead of stopping at the
first one.

## Consequences

Behavior is reproducible, testable, and auditable. The same query always produces the
same decision, a required property for a security control.

Evaluating every rule has negligible cost for a small in-memory struct. It prevents
the log from showing only the first violation, which would give the agent an iterative
oracle and leave the auditor with an incomplete picture.

The model is not a trusted security component, and the design reflects that.
