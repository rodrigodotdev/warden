# ADR-0021 — No `#[non_exhaustive]` on security domain enums

**Status:** Accepted · 2026-08-19 · **New in v0.3**

## Context

`#[non_exhaustive]` is an idiomatic reflex for a public enum expected to grow. Here
that intuition points in the wrong direction, so the reason must be explicit to
prevent a well-intentioned future "fix."

The required property, present since v0.2, is that **adding a `StatementKind` variant
breaks policy compilation**, forcing reconsideration.

`#[non_exhaustive]` affects only downstream crates, and `warden-policy` is downstream
of `warden-core`. Marking the enum would force `warden-policy` to add a `_ =>` arm;
new variants would then compile silently through the wildcard—the exact opposite of
the goal.

## Decision

`StatementKind`, `RiskFlag`, `DenyCode`, `FunctionClassification`, `ObjectKind`, and
similar enums **do not** use `#[non_exhaustive]`.

## Consequences

Adding a variant breaks workspace consumers, which is the intended behavior and the
only guaranteed point at which policy is reconsidered.

There is no API-stability cost: crate APIs are internal implementation details before
1.0 (SPEC section 10).

If a Warden crate is later published as a public library, revisit this decision in a
new ADR.
