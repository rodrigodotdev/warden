# ADR-0040 — Structured content is the response

**Status:** Accepted · 2026-09-02 · **New in Milestone 12**

## Context

MCP says a tool with an output schema SHOULD also return the serialized JSON in a text
block, for backward compatibility with clients that read only `content`. rmcp's `Json<T>`
return type implements exactly that recommendation: it calls `CallToolResult::structured`,
which sets `structured_content` to the value and also pushes `value.to_string()` into a
text `ContentBlock`.

`docs/security.md` section 9 lists injection through returned data as a real,
only-partially-mitigated threat and adopts structured content as the most important
available structural improvement: separating database rows from instructions at the
protocol level, rather than trying to sanitize content that Warden does not and should
not interpret. That mitigation depends on rows staying in `structured_content` and out of
free text. A tool that follows the SDK's default puts them in both places at once, which
defeats the separation the moment it is drawn.

`docs/data-model.md` section 7 also names the number that actually matters for cost:
`max_result_bytes` bounds only `rows`, so the real amount of model context one response
can spend is `rows + columns` together — on the order of 0.5 MiB of column metadata alone
in the documented worst case, against a 256 KiB row budget — and asks Milestone 12 to
design the tool contract against that combined figure rather than against
`max_result_bytes` alone. A duplicated text block does not just risk the mitigation; it
doubles the number the milestone was asked to design against, for every successful call.

## Decision

A successful tool result carries the data in `structured_content` and exactly one
counting summary in `content` — a single line stating rows, columns, matches, tables,
schemas, or connections, and the flags that qualify them (`truncated`, an estimated-rows
presence), never a value. `output.rs`'s `ToolResponse::into_result` builds this by hand:
it starts from `CallToolResult::structured`, then replaces the `content` the constructor
filled in with the one summary line, because `CallToolResult` is `#[non_exhaustive]` and
cannot be assembled as a literal from this crate.

A failed result is the one exception, and keeps the duplicate: its payload is a fixed
[`PublicErrorCode`] and a fixed sentence from a closed table (`docs/security.md`
section 10) — no database content at all — so repeating it in `content` costs nothing and
helps a client that reads only text, exactly as the SDK's default is designed to.

## Consequences

This is a deliberate, bounded deviation from MCP's SHOULD, not an oversight. ADR-0041
records the other half of the reasoning: Warden advertises only protocol versions
`2025-11-25` and `2026-07-28`, both of which support structured content, so no client that
can negotiate a session with Warden depends on the text copy to read a result. A client
that reads only `content` still sees the summary and knows a call succeeded, with counts
and flags to act on — a visible, diagnosable difference in behavior, not a silently wrong
answer.

Model context spent per successful call is roughly halved relative to the SDK default,
directly serving the `rows + columns` bound `docs/data-model.md` section 7 names.

This does not change what `structured_content` itself may contain. A hostile stored value
still reaches the agent through it, unsanitized, exactly as `docs/security.md` section 9's
accepted residual risk already states; this decision only stops that same value from also
reaching the agent a second time, in the channel meant for instructions rather than data.
