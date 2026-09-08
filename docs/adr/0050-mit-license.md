# ADR-0050 — MIT is the project license

**Status:** Accepted · 2026-09-08

## Context

Open question 12 had been open since v0.2 and blocked more than a file at the root.
`deny.toml` carried `[licenses.private] ignore = true` with a comment saying the
project license was not selected, so cargo-deny checked dependencies and skipped
Warden's own crates. `README.md` said "all rights reserved", which is the correct
statement for an unlicensed repository and also means nobody may legally run, fork,
or redistribute it. No release artifact could be published without answering this.

The question framed the choice as Apache-2.0 against AGPL: a patent grant and common
use in security infrastructure on one side, prevention of closed-source SaaS resale on
the other. Both framings assume the value at stake is control over how others build on
Warden. That is the assumption this decision rejects.

Warden's value to its users is that it is *auditable* — 32 invariants, structural
default-deny, mechanical guards, and a test suite that proves the database role itself
refuses a write. A tool a security team is asked to place between an AI agent and a
production database is adopted by being read, not by being licensed cleverly. Every
license term that a legal review has to think about is friction on the only adoption
path that matters.

## Decision

Warden is licensed under the MIT license. `LICENSE` carries the text, and
`[workspace.package] license = "MIT"` is inherited by every member crate.

**Why not Apache-2.0.** Its patent grant is a real advantage and the reason it is
common in this space. It costs the shortest, most universally recognized license text
there is, plus a `NOTICE` convention and a §4 attribution procedure that a downstream
redistributor has to follow. Warden holds no patents and expects none. Trading a
guarantee against a risk that does not exist for friction in every downstream legal
review is the wrong trade at this size. If Warden ever acquires patentable subject
matter, this ADR is superseded rather than amended.

**Why not AGPL.** It would prevent closed-source SaaS resale, which is a real
protection for a product with a commercial plan behind it. Warden has none, and AGPL's
network-use clause is the single term most likely to stop a security team from
deploying the thing internally at all — precisely the user Warden is built for. A
license that deters the intended deployment to prevent a hypothetical competitor is
protecting the wrong asset.

**Permissiveness is not a security position.** MIT disclaims warranty, which changes
nothing about the guarantees: `SPEC.md` section 7 already states what Warden does and
does not promise, and those boundaries hold regardless of license.

## Consequences

`deny.toml` sets `[licenses.private] ignore = false`. Warden's own crates are now
checked against the same allowlist as its dependencies, so a member crate that omits
`license.workspace = true` fails CI instead of passing in silence. MIT was already on
the allowlist, so no dependency's status changes.

`publish = false` stays, and `no_workspace_member_is_publishable` in
`tests/architecture.rs` keeps it that way. The license makes the source usable; it does
not make nine security-gateway internals into public Rust APIs. `SPEC.md` section 10
already says crate APIs are internal before 1.0, and the distributed artifact is the
binary.

MIT requires the copyright notice and permission text to accompany every substantial
portion of the software, so `LICENSE` ships inside every release archive next to
`LICENSES/`, which carries the separate CDLA-Permissive-2.0 notice for the
redistributed `webpki-roots` data. `every_release_archive_carries_both_licenses` in
`tests/architecture.rs` enforces both against any workflow that builds an archive, the
same way the Dockerfile guard has enforced the notice against an image that does not
exist yet.

Contributions arrive under MIT by default. There is no CLA, and adding one later would
be a change of terms for existing contributors, not a clarification.
