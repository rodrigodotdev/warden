# Warden implementation contract

This file governs any agent that writes code in this repository.
It complements `SPEC.md`; in case of conflict, `SPEC.md` section 6 (invariants)
prevails.

## Process rules

1. Implement **one milestone at a time** (`docs/milestones.md`). Do not generate
   the entire product in one pass.
2. Treat `SPEC.md` as the architectural source of truth.
3. Do not simplify the architecture to reduce the file count.
4. Before deliberately changing an architectural decision, write an ADR in
   `docs/adr/` or update the specification. Never make a silent change.
5. Check `sqlx`, `rmcp`, and `sqlparser` API details against their current
   official documentation before writing code. Do not copy feature flags from
   outdated examples.
6. Run `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
   and `cargo test --workspace` at the end of each milestone.
7. Explicitly list **every deviation** from the specification in each milestone
   report.

## Boundaries enforced by the compiler

| Never | Enforcement |
|---|---|
| `warden-core` depends on `sqlx` or `rmcp` | `Cargo.toml` |
| `warden-policy` depends on `sqlx` or `rmcp` | `Cargo.toml` |
| `warden-service` depends on `sqlx` | `Cargo.toml` |
| adapters depend on `rmcp` | `Cargo.toml` |
| a `sqlparser` AST type appears in an adapter's public signature | `crates/warden-mysql/tests/adapter_rules.rs` and `crates/warden-postgres/tests/adapter_rules.rs` (crate-local, one per adapter) |
| a `sqlx` type appears in an adapter's public signature | `crates/warden-mysql/tests/adapter_rules.rs` and `crates/warden-postgres/tests/adapter_rules.rs` (crate-local, one per adapter) |
| `AnyPool` | the sqlx `any` feature is disabled, causing a compile error |
| `sqlx::raw_sql` | `clippy.toml` -> `disallowed-methods` |
| `println!` / `print!` | `clippy::print_stdout = "deny"` |
| `unwrap` / `expect` outside tests | `clippy::unwrap_used`, `clippy::expect_used` |
| `unsafe` | `unsafe_code = "forbid"` |

Every rule in this table is deliberately mechanical. If proceeding requires
disabling one, stop and report it; do not annotate it with `#[allow]`.

**The one standing exception** is `#![allow(clippy::unwrap_used, clippy::expect_used)]`
at the top of a `#[cfg(test)]` module or a `tests/` file. A test asserts by panicking,
and the two lints exist to keep panics out of the request path, not out of assertions.
The allow is module-scoped and never appears on a production item, so a new `unwrap`
in shipping code still fails the build. No other lint may be allowed anywhere.

## Code rules

**Modeling**

- Use enums for closed domain sets and newtypes for identifiers.
- A validated newtype implements `TryFrom<String>`, `FromStr`, `Display`, and
  `AsRef<str>`—and **never** `Deref`.
- A validated newtype deserializes through `#[serde(try_from = "String")]`.
  Deriving `Deserialize` directly bypasses constructor validation.
- Configuration structs use `#[serde(deny_unknown_fields)]`.
- Keep all security-sensitive state private and expose read-only accessors.
- **Do not** use `#[non_exhaustive]` on security domain enums. It only affects
  downstream crates, and `warden-policy` is downstream of `warden-core`; the
  attribute would force a `_ =>` arm there, allowing new variants to compile
  silently. See ADR-0021.
- Match exhaustively in the policy engine. Adding a variant must break the build.
- During AST traversal, map wildcard arms to `Unknown` (which is denied),
  **never** to "ignore".

**Errors**

- Each reusable crate defines its own error enums with `thiserror`. Do not use
  one project-wide error enum.
- Use `anyhow` only in `main`, startup composition, and CLI diagnostics.
- Sanitize internal errors at the MCP boundary. Raw `sqlx` errors must never
  reach the model.

**Request path**

- Do not use `unwrap`, `expect`, `unreachable!`, `todo!`, or panic for validation.
- Run each request in its own task so a panic becomes `internal_error` instead
  of terminating the process.
- Do not use `Box<dyn Any>`, downcasting, or mutable global state.
- Use `Arc` only at shared service/runtime boundaries.

**Async**

- Dynamic-dispatch ports use explicit `BoxFuture`; do not use `async-trait`.
- Use a single runtime: Tokio.

## Test rules

- Every security-relevant parser rule has a test.
- Every discovered bypass becomes a permanent regression fixture.
- Policy tests use synthetic `QueryAnalysis` values and explicitly cover every
  unknown variant.
- Integration tests verify that the **database role** rejects writes, not only
  that policy rejects them.
- MCP tool schemas have snapshot tests.

## Milestone report

On completion, report files created, architectural choices, tests added,
commands run and their results, and every intentional deviation from the
specification.
