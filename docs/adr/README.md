# Architectural decisions

One decision per file. Before deliberately changing a decision, write a new ADR that
supersedes it; never change it silently.

| ADR | Decision |
|---|---|
| [0001](0001-rust.md) | Rust as the implementation language |
| [0002](0002-edition-2024-msrv.md) | Edition 2024 and MSRV policy |
| [0003](0003-tokio.md) | Tokio as the only runtime |
| [0004](0004-sqlx.md) | SQLx as the driver toolkit |
| [0005](0005-concrete-pools.md) | Concrete pools, never `AnyPool` |
| [0006](0006-sqlparser.md) | `sqlparser-rs` as the initial parser |
| [0007](0007-no-generic-ast.md) | ASTs never leave adapter crates |
| [0008](0008-mcp-inbound-adapter.md) | MCP is an inbound adapter |
| [0009](0009-read-only.md) | Read-only throughout the 0.x line |
| [0010](0010-authorized-state.md) | `AuthorizedQuery` and the `AllowDecision` token |
| [0011](0011-default-deny.md) | Default deny |
| [0012](0012-deterministic-policy.md) | Deterministic policy without an LLM |
| [0013](0013-no-async-trait.md) | No `async-trait`; boxed futures |
| [0014](0014-no-orm.md) | No ORM or query builder |
| [0015](0015-stdio-first.md) | stdio first, HTTP later |
| [0016](0016-db-permissions-mandatory.md) | Database privileges are mandatory |
| [0017](0017-no-explain-analyze.md) | Never expose `EXPLAIN ANALYZE` |
| [0018](0018-workspace-boundaries.md) | Crate boundaries as enforcement |
| [0019](0019-typed-secrets.md) | Typed, redacted secrets |
| [0020](0020-query-tool-select-only.md) | `query` accepts only `SELECT` |
| [0021](0021-no-non-exhaustive.md) | No `#[non_exhaustive]` on security enums |
| [0022](0022-two-phase-audit.md) | Two-phase auditing |
| [0023](0023-grant-is-read-boundary.md) | `GRANT` is the read-scope boundary |
| [0024](0024-server-side-deadlines.md) | Server-side deadlines, not only client timeouts |
| [0025](0025-two-pools-per-connection.md) | Two pools per named connection |
| [0026](0026-invariants-are-not-configurable.md) | Invariants have no configuration keys |
| [0027](0027-identifier-quoting.md) | Identifier quoting is part of the analysis model |
| [0028](0028-token-level-guard.md) | A token-level guard for constructs the parser rejects |

ADRs 0021–0026 are new in v0.3. ADR-0002 supersedes the v0.2 MSRV definition;
ADR-0022 supersedes the single-event audit model; ADR-0023 resolves v0.2 open
question 13; and ADR-0024 closes the MySQL timeout gap.
