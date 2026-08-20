# ADR-0023 — `GRANT` is the read-scope boundary

**Status:** Accepted · 2026-08-19 · **New in v0.3 · Resolves:** open question 13 from
specification v0.2

## Context

Version 0.2 treated `TableAllowDenyPolicy` as a security control and listed "should
views inherit table policy?" as an ergonomics question.

This is a structural gap, not an ergonomics issue. The allowlist operates on names
extracted from the AST, but names do not determine what a relation reads. Four
independent bypasses exist:

1. **Views**—`SELECT * FROM public_report` passes while the view reads
   `users.password_hash`; the parser sees only the view name.
2. **`search_path`** (PostgreSQL)—the session resolves unqualified names.
3. **Default database** (MySQL)—the same problem.
4. **Identifier folding**—PostgreSQL folds unquoted identifiers to lowercase, so an
   entry named `Users` would never match.

Resolving names against the catalog inside policy would violate synchronous,
I/O-free policy evaluation (ADR-0012), or introduce a TOCTOU-prone authorization
cache.

## Decision

**The dedicated role's `GRANT SELECT` bounds read scope.** The table allowlist reduces
attack surface and improves error messages; public material does not present it as a
security boundary.

Required supporting controls:

- Set `search_path` and the default database at connect time, not query time.
- Apply dialect-specific identifier-folding rules during policy comparison.
- Do not represent CTE names or subquery aliases as `ObjectRef`.
- Apply object policy to **every** object-touching tool, including `search_schema` and
  `describe_schema`; otherwise denied tables remain describable.

## Consequences

Policy remains pure and synchronous. The product guarantee is honest: operators who
grant broad `SELECT` privileges and trust Warden's allowlist are not protected, and
the documentation says so.

Rejected alternative: resolve names against the catalog. It is stronger but couples
policy to I/O and introduces TOCTOU. Revisit it only when concrete demand justifies a
separate optional capability.
