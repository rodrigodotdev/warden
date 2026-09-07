# ADR-0048 — The audit sink is an adapter

**Status:** Accepted · 2026-09-06

## Context

`AuditSink` is a port. It is declared in `warden-ports` beside `QueryExecutor`,
`Explainer` and `SchemaInspector`, and like them it is named through `dyn` at every
call site in `warden-service`. Those three have their implementations in adapter
crates. `AuditSink`'s two — a stderr sink and an append-only JSONL sink — lived in the
binary, which made it the only port in the system whose adapters did.

That was inertia rather than a decision. No ADR placed them there; ADR-0043 describes
what the persistent sink must *do*, never where it lives. A comment in the root
`Cargo.toml` recorded the history plainly: *"the audit module is no longer test-only
code that can borrow the dev-dependency."* It grew in place from Milestone 12.

The cost had become structural. `src/audit/` was 1 517 of the binary's 3 468 lines —
44 % — and `src/main.rs`'s own header claims the binary is "the only process-level code
that resolves `std::env::args()`, selects real descriptors, and maps errors to exit
codes." It was also hosting `rustix` syscalls, symlink and TOCTOU handling, an fsync
durability protocol, and a poisonable writer. None of that is composition.

Two consequences mattered more than the line count:

`tests/architecture.rs` could not express a boundary for it. The rule that the audit
sinks must not reach `sqlx`, `rmcp`, `sqlparser`, an adapter, `warden-service`,
`warden-policy` or `warden-config` was unenforceable, because the binary legitimately
depends on all of them.

And the record format had the weakest mechanical protection of any boundary in the
product. `FORBIDDEN_FIELDS` — the list of names an audit record may never carry
(`docs/security.md` section 11.3, SPEC section 6, invariants 22–23) — was a
`#[cfg(test)] const` *inside the module it guards*. Every other boundary in the
workspace has a guard file that reads it from outside.

## Decision

The audit sinks move to `crates/warden-audit`, an adapter crate. `src/audit.rs` keeps
only the twelve lines that choose between them from configuration, which genuinely is
composition.

`AuditMode` moves to **`warden-core`**, not to `warden-ports`.

A `warden-audit` that depended on `warden-config` would be the first non-binary
consumer of the configuration crate, and that edge contradicts the rule
`src/startup.rs` states for itself: `warden-config` emits core types and plain strings,
and turning a resolved profile into settings is the composition root's job.
`warden-ports` was the wrong destination for a different reason — it has no `serde`
dependency, and the crate whose entire job is to declare traits is not where a
serialization format belongs.

`warden-core` is where the precedent already is. `TlsMode` lives there, is
deserialized by `warden-config`, and is consumed by both adapters. `AuditMode`
describes what a *record* may contain, which is a domain value of exactly that kind.

`AuditDestination` stays in `warden-config`: it names a file path, which is
deployment, not domain. `startup.rs` maps it to a sink the same way it maps a policy
profile to `PolicySettings`.

## Consequences

`crates/warden-audit/tests/audit_rules.rs` asserts from outside the module that no
forbidden field name is reachable from any serialized type, and that both sinks
project the same field set. That is the guard the most security-sensitive format in
the product did not have.

`FORBIDDEN_EDGES` can now state what the audit adapter may not reach, and
`no_workspace_member_is_publishable` covers the new member. `rustix`, `same-file`,
`serde_json`, `time` and tokio's `fs`, `io-util` and `sync` features leave the binary's
manifest for the crate that uses them.

The file sink gains a public constructor seam: its tests used to build a
`FileAuditSink` by struct literal because they were inside the module, and a crate
boundary forces them through `open`.

`AGENTS.md` process rule 3 — "do not simplify the architecture to reduce the file
count" — does not oppose this. It forbids collapsing boundaries. This creates one.
