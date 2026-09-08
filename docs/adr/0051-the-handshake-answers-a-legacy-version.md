# ADR-0051 — An `initialize` handshake is answered with a legacy version

**Status:** Accepted · 2026-09-08 · **Refines ADR-0041**

## Context

ADR-0041 decided that `supported_protocol_versions` returns exactly
`[2025-11-25, 2026-07-28]`, that `initialize` is overridden so an unsupported revision is
refused rather than silently substituted, and that a supported revision is **echoed back**.
`get_info` advertised `2026-07-28` as the default. That last part is what this ADR changes.

A routine `cargo update` moved `rmcp` from 3.1.4 to 3.2.0, and
`initialization_reports_tools_and_echoes_the_requested_version` failed: an `initialize`
naming `2026-07-28` came back as `2025-11-25`. The first reading was that the SDK had
regressed into exactly the silent substitution ADR-0041 exists to prevent.

It had not. `rmcp`'s change (modelcontextprotocol/rust-sdk#1228) implements the
`2026-07-28` versioning specification, which is explicit: *an `initialize` request selects
legacy semantics, scoped to the stdio process or the HTTP session, as specified by the
negotiated legacy protocol version.* Versions from `2026-07-28` onward do not use a
handshake at all. A client that wants those semantics declares its version per request in
`_meta` and never sends `initialize`. So a server that receives `initialize` has, by that
fact alone, been told the session is legacy, and answering it with `2026-07-28` names a
lifecycle the session is not using.

The second reading was that Warden was advertising a lifecycle it had not implemented, and
should drop `2026-07-28` until Milestone 14. That was also wrong, and the tests say so.
`a_session_that_never_initializes_still_serves_a_supported_version` drives a full `query`
over the inline lifecycle at `2026-07-28` — no `initialize`, version in `_meta` — and
`an_unimplemented_version_declared_inline_is_refused_before_any_tool_runs` proves a
version Warden does not speak is refused on that same path before a tool runs. Both pass
under `rmcp` 3.2.0, and both passed before it. The inline lifecycle works because `rmcp`
validates each request's declared version against `supported_protocol_versions`. Removing
`2026-07-28` from that list would have deleted working, tested capability.

What was actually wrong was one line: `initialize` echoing `request.protocol_version`.

## Decision

`WARDEN_PROTOCOL_VERSIONS` is unchanged and still holds both revisions. It is what the
inline lifecycle is validated against, and `2026-07-28` earns its place there.

`WARDEN_HANDSHAKE_VERSION` is new and is `2025-11-25`: the newest **legacy** revision
Warden implements. `get_info` advertises it, and `initialize` answers with it whatever
version was requested, having first refused anything outside
`WARDEN_PROTOCOL_VERSIONS`.

The refusal half of ADR-0041 is untouched. A client naming `2024-11-05` still receives
`ErrorData::unsupported_protocol_version` carrying both supported revisions, on the
handshake path and on the inline path alike.

Naming the answer in Warden's own code rather than letting `rmcp` correct it is the point
of the change. `rmcp` 3.2 would produce the same bytes with `initialize` still echoing,
because `negotiate_protocol_version` overrides the handler afterwards. That works and
reads as a bug: the source would say Warden echoes the requested version while the wire
says otherwise. One answer, stated once, is worth more than a correct outcome nobody can
find in the code.

## Consequences

`initialize(2026-07-28)` now returns `2025-11-25`. A client that compares the response
against its request — the defence ADR-0041 says a client is not obliged to mount but may —
sees a difference where it previously saw none. That is the specification's intent rather
than a substitution: the client asked for a lifecycle by using a handshake, and it is told
which one it got.

Milestone 14 inherits a smaller question than it would have. Streamable HTTP is where
`2026-07-28`'s SEP-2243 headers matter, and the version list is already correct for it;
what M14 adds is the transport, not a protocol claim.

`initialize` no longer clones its request — `set_peer_info` takes it by value now that
nothing reads a field afterwards.

The handshake answer is pinned twice, once against the constant and once against the
literal `2025-11-25`, in `the_handshake_answer_is_the_newest_legacy_version`. A future
edit that redefines the constant has to change both, which is the point: the literal is
the specification's requirement, not an implementation detail.

This also raises Warden's `rmcp` floor in practice. The manifest still requires `3.1.3`,
which remains true — Warden now produces the correct answer on its own, so a 3.1.x build
behaves identically rather than depending on 3.2's correction.
