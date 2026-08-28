# ADR-0036 — The schema inspector filters objects at the source

**Status:** Accepted · 2026-08-27 · **New in Milestone 9**

## Context

`docs/security.md` section 5.2 requires `SchemaAllowListPolicy` and
`TableAllowDenyPolicy` to apply to every object-touching tool, and requires the
`SchemaInspector` to receive the rules and filter at the source rather than return
the whole catalog for a service to trim afterwards. Otherwise a table an agent may
not query stays describable, and the agent learns the entire data model from
`describe_schema`.

The Milestone 3 port could not do that. `search_schema` and `describe_schema` took a
request, a deadline and a cancellation token — no rules and no request identity — and
`SchemaError::Rejected` carries a `PolicyRejection` whose constructor is reachable
only from `PolicyEngine::authorize` or `PolicyEngine::check_object`, both of which
need a `PolicyContext` an adapter never held. `docs/open-questions.md` item 13
recorded the gap, established that a signature change was the only fix, and assigned
it to Milestone 9.

Filtering in the service instead was rejected there and is rejected here.
`describe_schema` could survive it; `search_schema` cannot. A denied relation the
adapter already found would consume an allowed relation's slot under the request's
own `limit` before anything downstream could remove it, so a broad search would
silently return fewer results than it should, and the number returned would itself
leak how many denied relations matched.

## Decision

`SchemaInspector::search_schema` and `SchemaInspector::describe_schema` take
`filter: ObjectFilter<'a>` as their second parameter.

`warden_policy::ObjectFilter` is a `Copy` view holding `&PolicyEngine` and
`PolicyContext<'a>`. It exposes `check`, which returns the real `PolicyRejection`,
and `permits`, which returns a bool. The engine stays startup state owned by the
composition root; the connection metadata and request identity stay per-request
values owned by the service. The adapter owns none of them and only asks questions.

`search_schema` drops a refused relation silently, before the response limit is
applied. `describe_schema` fails the call with `SchemaError::Rejected`. The
asymmetry is deliberate: a search the agent did not aim at a named table must not
report that a denied table exists, while a describe names the table itself, so
silence would answer a question about a name the agent already has.

`crates/warden-ports/tests/port_rules.rs` asserts mechanically that both declarations
carry the parameter.

## Consequences

`SchemaError::Rejected` has a producer for the first time, and the variant's
documented meaning becomes reachable rather than aspirational.

An adapter now depends on `warden-policy` in its port implementation, not only in its
analyzer. That direction was already permitted (`docs/architecture.md` section 3) and
does not widen the dependency graph.

This does not make the object rules a read-scope boundary. They match names, and a
granted view still reads a denied table (ADR-0023). What the change buys is that the
rules are applied consistently by every tool, which is the property section 5.2 asks
for.

The filter proves *which rules*, not *which connection*: `ObjectFilter` carries the
connection metadata it was built from, and nothing stops a caller from building one
over connection A and passing it to connection B's inspector. That is the same
residual gap ADR-0032 leaves for `QueryPermit`, and Milestone 11's service layer owns
both pairings.
