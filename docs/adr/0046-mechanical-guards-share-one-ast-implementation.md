# ADR-0046 — Mechanical guards share one AST implementation

**Status:** Accepted · 2026-09-06

## Context

Nine test files enforce rules the compiler cannot express — no `sqlparser` type in an
adapter's public signature, no wildcard arm over a security enum, no `Deref` on a
newtype, no serialization of an audit record. They were written in two incompatible
techniques. Four (`tests/architecture.rs`, `service_rules.rs`, `mcp_rules.rs`,
`config_rules.rs`) parse the source with `syn`. Five (both adapters'
`adapter_rules.rs`, `port_rules.rs`, `policy_rules.rs`, `newtype_rules.rs`) re-derive
Rust lexing by hand: `brace_delta`, `is_exported`, `names_type`,
`declaration_header_end`, `struct_field_end`.

Hand-rolled lexing is where a guard goes quietly blind, and one already had. Every
scan in both adapters' `adapter_rules.rs` ran over `code_lines`, which cut the file at
the first line whose trimmed text is exactly `#[cfg(test)]`. The comment above it
explains, correctly, why a substring match would be unsound — and the chosen cutoff
has the same shape of problem, because it assumes the first `#[cfg(test)]` in a file
is the trailing `mod tests`. In both adapters it is not:
`warden-mysql/src/connection.rs:187` and `warden-postgres/src/connection.rs:305` carry
a `#[cfg(test)] impl` well above the real test module. Eighty-nine lines of one file
and a hundred and fifty-three of the other were outside every scan. Nothing violated a
rule there, but no guard could have said so.

A guard with an invisible region is worse than no guard, because the project's
security argument is that the guard is mechanical.

The same crate showed the inconsistency at its sharpest: both adapters already use
`syn` correctly inside `src/options.rs` to check the session-hardening chain, and
hand-rolled scanning in `tests/adapter_rules.rs`. Two techniques, one crate.

## Decision

Guard machinery lives once, in a `crates/warden-guards` workspace member, and every
guard reads the AST rather than the text.

`warden-guards` depends on `syn`, `proc-macro2` and `std`, and on **nothing else** —
in particular on no Warden crate, including for its own tests. A guard that can see
the code it guards is a guard that can be made to pass. It is `publish = false` and
appears only in `[dev-dependencies]`, so it is absent from every release artifact and
from the normal dependency graph `tests/architecture.rs` walks.

Its security-critical function is `production_items`, which is what decides that an
item is not test-only. It strips any `cfg` predicate whose condition requires `test` —
`#[cfg(test)]`, `#[cfg(all(test, feature = "docker"))]`, `#[cfg_attr(test, ...)]` — at
every level, not only on a trailing module, and it does so on parsed attributes rather
than on line text. It carries its own negative controls, including fixtures for each
of those spellings and for the mid-file `#[cfg(test)] impl` that produced this ADR.

## Consequences

The blind region is gone, and it cannot come back by formatting: an attribute inside a
string literal, a macro body, or unusual line breaks is no longer able to move a
scan's cutoff, because there is no cutoff.

Roughly eight hundred lines of hand-rolled lexing leave the tree, and the next guard
is cheaper to write than to skip — which is the property that keeps a mechanical rule
mechanical.

The negative controls move with the machinery rather than being reimplemented per
crate. `the_scans_are_alive` and the four `driver_surface_scan_*` tests stay in the
adapters, because what they prove is that *those* scans can still fail; the fixtures
that prove `production_items` sees a mid-file `#[cfg(test)]` belong to the crate that
owns it.

One workspace member is added, which `EXPECTED_MEMBERS` and `FORBIDDEN_EDGES` in
`tests/architecture.rs` must both name. That is deliberate friction: a guard crate
that quietly grew a dependency on a Warden crate is exactly what those two lists exist
to catch.
