# ADR-0041 — Warden advertises only what it implements

**Status:** Accepted · 2026-09-02 · **New in Milestone 12**

## Context

`docs/mcp.md`'s preamble records what Milestone 0.5 measured against a real handshake.
The client, not the server, determines a session's effective version: `rmcp`'s
`negotiate_protocol_version` echoes any version the server lists as supported, and the
SDK's default `supported_protocol_versions` lists all five revisions it knows, from
`2024-11-05` through `2026-07-28`. Warden has implemented and tested none of the older
three — `2024-11-05`, `2025-03-26`, and `2025-06-18`.

Worse than the over-claim is what happens to a version nobody supports. M0.5 requested
`1999-01-01` and the server answered `2025-11-25` — `ProtocolVersion::LATEST` — with no
error, only a `tracing::warn!` on stderr that the client cannot see. The substitution is
silent by construction: `negotiate_protocol_version` returns a `ProtocolVersion`, not a
`Result`, so it offers no hook through which a server can refuse. The client's only
defence is to compare the response's `protocolVersion` against its own request, which a
client is not obliged to do.

The preamble deferred the decision to this milestone, "alongside the real handler",
rather than settling it in the disposable M0.5 crate.

## Decision

`ServerHandler::supported_protocol_versions` returns exactly
`[2025-11-25, 2026-07-28]`, and `get_info` advertises `2026-07-28` as the default.

`initialize` is **overridden** rather than left to the SDK. When the requested version is
not in that list, it returns `ErrorData::unsupported_protocol_version`, whose
`UNSUPPORTED_PROTOCOL_VERSION` code carries the requested version and the supported list
in the error's `data`. Only when the version is one Warden speaks does the override do
what the SDK's default does: record the peer info — which is what later gives every audit
record its client name — and echo the negotiated version back.

Overriding `initialize` is not a workaround for a missing hook. It is the same seam
`rmcp` itself uses: its own request dispatch validates a per-request protocol version
against `supported_protocol_versions` and answers an unsupported one with this exact
error. The override applies that rule one message earlier, at the handshake, where a
session's version is actually decided.

## Consequences

A client speaking an older revision fails loudly at `initialize`, with the two supported
versions in hand to retry with, instead of proceeding under a version neither side agreed
to. For a security gateway that is the whole point: a client that believes it negotiated
one revision while the server serves another is a silent mismatch, and every guarantee
either side reasons about downstream rests on that agreement being real.

Because both advertised revisions carry structured tool output, ADR-0040's decision to
send data in `structured_content` with a summary-only text block cannot strand a client
that negotiated successfully — the two decisions hold each other up.

Warden advertising `2026-07-28` is not a claim to the protocol's leading edge:
`ProtocolVersion::LATEST` is `2025-11-25`, and `2026-07-28` is the first revision that
requires SEP-2243 standard HTTP headers. Milestone 14 keeps it for that reason, when
Streamable HTTP makes those headers matter.

Adding a revision now means implementing and testing it and then extending one list,
rather than inheriting support for it from an SDK upgrade. That cost is the point: the
list states what Warden has actually done, and `warden_advertises_only_the_versions_it_implements`
fails the build if the two ever drift apart.
