# ADR-0016 — Database privileges are mandatory

**Status:** Accepted · 2026-08-19

## Context

Presenting SQL analysis as the product's security guarantee would be security theater:
a multi-dialect parser is not the server's parser, and no dangerous-function list is
provably complete.

## Decision

Parser and policy logic provide **defense in depth**, not the final boundary. The
dedicated role's `GRANT` is the write boundary.

Every production connection uses a dedicated Warden account without write
privileges. Integration tests verify that the **database** rejects writes, not merely
that policy rejects them.

## Consequences

The README and all public material must say this. Users who point Warden at a database
with application-owner credentials are not protected, and the product must be
explicit about that.

See ADR-0023 for the analogous consequence for **read** scope.
