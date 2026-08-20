# ADR-0010 — Execution requires `AuthorizedQuery`, with `AllowDecision` as a token

**Status:** Accepted · 2026-08-19

## Context

An `executor.execute(sql: &str)` API would let any project code accidentally bypass
the security pipeline.

Restricting constructors across Rust crates is not straightforward: `pub(crate)` does
not cross crate boundaries, and adapters legitimately need to create `AnalyzedQuery`.

## Decision

The executor accepts `&AuthorizedQuery`. `AuthorizedQuery` contains an
`AllowDecision`, which lives in `warden-policy`, has private fields, and has **no
public constructor**.

Only `warden-policy` can produce an `AllowDecision`, so only it can produce an
`AuthorizedQuery`, even if `AuthorizedQuery::new` is public. `AllowDecision` is an
unforgeable capability token.

There is no public `AuthorizedQuery::new_unchecked`.

## Consequences

Crate boundaries let the compiler enforce the `AnalyzedQuery -> AuthorizedQuery`
transition.

**Honest scope:** this prevents accidental bypasses within Warden. It does not protect
against a malicious adapter crate; adapters are trusted by construction, and no type
system can solve that. It does not replace database privileges (ADR-0016).

**Rejected alternative:** restricting the constructor with `#[cfg(feature = ...)]`
does not work. Cargo feature unification enables the feature for the entire build as
soon as any workspace member requests it.
