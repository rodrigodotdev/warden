# ADR-0002 — Edition 2024 and MSRV policy

**Status:** Accepted · 2026-08-19 · **Supersedes:** the MSRV = 1.97 definition in
specification v0.2

## Context

Version 0.2 set the MSRV to 1.97.0, released about six weeks before the
specification was written. The dependencies require less: SQLx 0.9 requires 1.94,
and `rmcp` 3.x requires 1.88. Setting the floor to the newest stable release adds
friction to CI and distribution toolchains without an identified benefit.

`rust-toolchain.toml` and `rust-version` in `Cargo.toml` solve different problems,
but v0.2 treated them as one.

mise can also declare and activate Rust versions itself. Repeating the version and
components from `rust-toolchain.toml` in mise would create two authorities for the
development toolchain and require a separate check merely to keep them equal.

## Decision

Use Edition 2024 and `rust-version = "1.94"`, the highest MSRV among the
dependencies. `rust-toolchain.toml` pins the development toolchain to the current
stable release.

`rust-toolchain.toml` is the only hand-written source for the Rust version and
components. mise may read it as an idiomatic version file when provisioning the
toolchain, but does not repeat those values under `[tools]`; mise installs auxiliary
tools and runs development shortcuts.

Raising the MSRV requires naming the motivating language or library feature in this
ADR.

## Consequences

Development remains on current stable, while consumers and build environments can
use a slightly older toolchain. The MSRV becomes an explicit decision instead of a
side effect.

There is no mise/rustup synchronization guard because there are not two declarations
to synchronize. Cargo commands remain the canonical gate interface; mise tasks must
preserve their semantics rather than replace them with another runner.
