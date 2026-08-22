# ADR-0027 — Identifier quoting is part of the analysis model

**Status:** Accepted · 2026-08-22

## Context

`ObjectRef` and `FunctionRef` stored each name part as a `String` and claimed to
preserve it "exactly as written". They did not: the parser strips the quotes before
the value reaches them, so `Orders` and `"Orders"` arrive as the same `String`.

`docs/security.md` section 5.1 requires PostgreSQL folding to distinguish the two —
an unquoted identifier folds to lowercase, a quoted one does not — and
`warden-policy` could not, so `folding.rs` compared both dialects
case-insensitively and documented the gap as work for the M4/M5 analyzers.

## Decision

Name parts are `SqlIdentifier { value, quoting }`. The value never contains quote
characters. `warden-policy` compares with
`rule_matches(dialect, rule: &str, identifier: &SqlIdentifier)`, which is
asymmetric on purpose: configuration has no quoting, statements do.

`SqlIdentifier` implements neither `TryFrom<String>` nor `FromStr`, unlike the
validated newtypes of `docs/data-model.md` section 1. A bare string cannot say
whether it was quoted, and a conversion that guessed would restore the ambiguity
this type exists to remove.

## Consequences

A PostgreSQL rule spelled `users` no longer matches the distinct relation
`"Users"`, removing a false positive, and a rule spelled `Users` now matches it,
removing a false negative. MySQL keeps case-insensitive comparison and documents
its dependency on `lower_case_table_names`.

Every analyzer must carry the quoting bit out of its parser. Nothing else can build
a `SqlIdentifier`, which is the intended constraint.

This does not change the read-scope boundary. The dedicated role's `GRANT SELECT`
remains it (ADR-0023); the allowlist gets more accurate, not more authoritative.
