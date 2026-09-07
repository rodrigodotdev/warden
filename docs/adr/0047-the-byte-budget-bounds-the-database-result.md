# ADR-0047 — The byte budget bounds the database result, not the redacted response

**Status:** Accepted · 2026-09-06

## Context

`ResultBuilder` enforces `max_rows`, `max_value_bytes` and `max_result_bytes` while
rows arrive from the driver, which is what makes the bound a streaming control rather
than a post-hoc check (`docs/operations.md` section 6.6). Redaction runs after that,
in `warden_service::Redactor::redact_result`, and `RedactionStrategy::Replace`
substitutes `"[REDACTED]"` — twelve encoded JSON bytes. A redacted `NULL` costs four
bytes and a small integer one to three, so redaction can make a response larger than
the budget Warden reported enforcing. `redact_result` recomputes `stats.bytes`
faithfully, but nothing re-checks it against the limit.

The overshoot is bounded and is not agent-controllable: redaction rules are operator
configuration, and the growth per matched cell is at most twelve bytes.

## Decision

The byte budget bounds the result **as the database produced it**. Warden does not
re-check or truncate after redaction.

Truncating rows post-redaction would discard data the agent was authorised to see
because a redaction rule applied to some *other* column of the same result. That is a
worse outcome than a response a few bytes over budget: it converts a formatting
control into a silent, rule-dependent loss of authorised data, and it makes the size
of a response depend on which columns happened to match.

An operator who needs the bound to hold after redaction configures
`strategy = "null"`, which replaces a value with JSON `null` and can therefore only
shrink a response.

## Consequences

`stats.bytes` on a redacted response may exceed `max_result_bytes` by at most twelve
bytes per matched cell. The figure is pinned by test
(`redaction::tests::replace_grows_a_response_by_at_most_twelve_bytes_per_cell`), so a
change to the `[REDACTED]` sentinel or to the JSON byte accounting fails the build
rather than silently widening the overshoot.

The budget keeps its real guarantee — a bound on what Warden reads from the database
and holds in memory — which is the resource control it exists to be. The response-size
guarantee an operator can rely on unconditionally is the one `strategy = "null"` gives.
