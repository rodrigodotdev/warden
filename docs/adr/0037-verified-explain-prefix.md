# ADR-0037 — A prefixed statement is a verified type

**Status:** Accepted · 2026-08-29 · **New in Milestone 10**

## Context

SPEC section 6, invariant 19 requires executed SQL to be byte-for-byte the analyzed
SQL, and names exactly one exception: `explain`, which prefixes the statement.
`docs/mcp.md` section 3.2 states the compensating control — reparse the prefixed
string and verify that it is an `EXPLAIN` containing the analyzed statement — and
notes that this closes the entire class of comment- and quoting-based context breaks
cheaply.

Stated as a step, that control is a convention. A future change can build the
prefixed string somewhere else, or reorder the call, and the result still compiles,
still runs, and still returns plans. The failure would be silent: an unverified
prefix produces correct output for every statement that was not an attack.

The repository already has the shape that solves this. `AllowDecision` is
unforgeable outside `warden-policy`, so `AuthorizedQuery` cannot exist without a
policy evaluation (ADR-0010), and `QueryPermit` is a parameter rather than a
caller's discipline (ADR-0032).

## Decision

Each adapter declares a crate-private `VerifiedExplain` in its own `plan.rs`: a
newtype over `String` whose only constructor prefixes the analyzed SQL and then
reparses the result with that adapter's dialect parser. The port implementation can
obtain the string to send only by calling that constructor.

The verification asserts the shape it requires rather than enumerating the shapes it
forbids: exactly one statement; `Statement::Explain` with `analyze`, `verbose`,
`query_plan` and `estimate` all false; the dialect's exact JSON-format spelling —
`FORMAT=JSON` on MySQL, a single `FORMAT JSON` utility option on PostgreSQL — and an
inner statement equal to a standalone parse of the analyzed SQL. `sqlparser` compares
identifiers without their source spans, so the offset inner statement compares equal.

The single failure is `ExplainError::PrefixVerificationFailed`. It says that the
string did not match and nothing about which part differed, because the differing
part is the agent's own statement (`docs/security.md` section 10).

## Consequences

`explain` cannot send an unverified string without deleting a type, which is a
visible change rather than a reordered call.

Asserting a required shape means a `sqlparser` upgrade that changes how a prefixed
string parses fails loudly at the verification instead of passing through a
forbidden-list that never learned the new spelling. That is the intended direction:
`docs/testing.md` section 3.3 already requires reviewing new AST variants on upgrade.

Verification costs two parses per `explain` call, of a statement already capped at
64 KiB (`docs/data-model.md` section 2). `docs/mcp.md` section 3.2 already judged
that price worth paying.

This is not a claim that the plan path is safe because the string was verified. The
string is verified; the *statement* is safe because `PolicyEngine` authorized it, and
`Explainer::explain` takes an `AuthorizedQuery` for that reason (`docs/mcp.md`
section 3.1). Nor does it bound what planning costs on the server: the deadline, the
cancellation token and the permit do that.
