# Milestones

Implement one milestone at a time. At the end of each, run `cargo fmt --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, and
`cargo test --workspace`, then report deviations.

---

## M0 — Workspace bootstrap

Create the workspace and root binary; establish the toolchain baseline, Edition 2024,
`rust-toolchain.toml`, workspace lints **with `[lints] workspace = true` in every
member crate**, `clippy.toml` with `disallowed-methods`, `deny.toml`, formatting,
Clippy, initial CI, and `warden version`.

Do not add database or MCP dependencies yet.

**Required verification:** confirm every crate actually inherits workspace lints. A
crate without `[lints] workspace = true` inherits nothing, and the silence resembles
success.

---

## M0.5 — Disposable tracer bullet

**This exists to retire risk, not to last.** Mark its code as disposable.

- An MCP stdio server with one tool that returns a constant.
- `SELECT 1` through `MySqlPool` and `PgPool` using exactly the feature set from
  `docs/operations.md` section 2.2.
- One Testcontainers container for each engine.
- A validated TLS handshake.

**Why:** the project's largest integration risk is rmcp 3.x plus SQLx 0.9 on this
toolchain. In the natural milestone order, it would remain untouched until M6 and
M12, twelve steps after architectural decisions built on assumptions. One day of work
validates Cargo features, API shape, TLS, and Testcontainers early.

This does not change the requirement that M4/M5 precede M7/M8; see "Why analyzers come
first." It only moves the unknown out of the end of the queue.

---

## M1 — Core types

Implement `Dialect`, `ConnectionName`, `Environment`, query requests,
`ParameterValue`, `QueryAnalysis`, `StatementKind`, `RiskFlag`, `ObjectRef`,
`FunctionRef`, result, schema, and explain models, and base typed errors.

Newtypes implement `TryFrom<String>`, `FromStr`, `Display`, and `AsRef<str>`, never
`Deref`, and deserialize through `#[serde(try_from = "String")]`.

No SQLx, rmcp, or sqlparser.

---

## M2 — Policy engine and authorized state

Implement `AnalyzedQuery`; `AllowDecision` **without a public constructor**;
`AuthorizedQuery`; the `Policy` trait; `DenyCode`; `DenyReason` with separate internal
detail; an engine that evaluates **every** policy and aggregates every denial; default
policies; denial precedence; and synthetic unit tests.

Establish security-state transitions before any database execution exists.

---

## M3 — Ports

Add dyn-compatible capability ports for analyzer, executor with `deadline` and
`CancellationToken`, inspector, explainer, two-phase audit sink, and registry. Use
explicit `BoxFuture`.

No `async-trait`, SQLx, rmcp, or sqlparser.

---

## M4 — MySQL analyzer

Use `sqlparser-rs` with `MySqlDialect` and an explicit recursion limit. Classify root
statements; analyze nested statements recursively; extract tables while excluding CTE
names and aliases; extract functions; classify risks; apply MySQL identifier folding;
build a corpus; and default-deny unknowns.

No MySQL server yet.

---

## M5 — PostgreSQL analyzer

Use `PostgreSqlDialect`; recursively analyze PostgreSQL syntax; detect data-modifying
CTEs, locking clauses, and `SELECT INTO`; classify functions; apply PostgreSQL
identifier folding; and build a corpus.

No PostgreSQL server yet.

---

## M6 — SQLx connection foundations

Add SQLx 0.9 with the defined features, Tokio integration, rustls TLS, MySQL and
PostgreSQL pool factories, and **two pools per connection**. On agent pools, configure
`statement_cache_capacity(0)` plus `.persistent(false)` for PostgreSQL; MySQL does not
need the latter. See `docs/operations.md` section 4. Add PostgreSQL connect options for
`statement_timeout`, `default_transaction_read_only`, and `search_path`; MySQL
`after_connect` for `MAX_EXECUTION_TIME`; secret DSN handling; connection health
tests; and integration/load tests for exact pool defaults (`max 5 / min 0 / acquire
3s`). M0.5 measured statement-cache behavior only, not those numeric defaults.

---

## M7 — MySQL execution

Implement read-only transactions; runtime parameter binding; ordered server and client
deadlines; a semaphore with `max_queue_wait`; bounded row scanning; per-value and total
byte accounting; common-type normalization; Testcontainers; and **database-privilege
tests**.

At this point, MySQL read queries work without MCP.

---

## M8 — PostgreSQL execution

Match M7 and add `SET LOCAL statement_timeout` as reinforcement, `UUID`, `JSONB`,
precision-preserving `NUMERIC`, digit-preserving `JSON`/`JSONB` decoding,
depth-limited arrays, and safe failures with cast suggestions for custom types.

---

## M9 — Schema inspection

For both adapters, implement schema search and description, indexes, primary- and
foreign-key metadata, a short-TTL cache, bounded responses, and **object policy at the
source**.

---

## M10 — Explain

For both adapters, implement non-executing EXPLAIN, structured plans, generic summaries
where meaningful, **reparse verification of the prefixed string**, and explicit tests
that prohibit `ANALYZE`.

---

## M11 — Application services

Complete orchestration: resolve -> analyze -> authorize -> audit attempt -> acquire ->
execute -> normalize -> redact -> audit outcome.

No MCP yet. Service tests use fake ports.

---

## M12 — MCP over stdio

Use rmcp for all five tools, populated `ToolAnnotations`, derived `output_schema`,
`structured_content`, descriptions from `docs/mcp.md` section 1.3, subprocess E2E
tests, and tool-schema snapshots.

**First developer-usable release.**

---

## M13 — Auditing and tracing

Implement two-phase audit events, a versioned fingerprint, spans, raw SQL disabled by
default, safe error mapping, request IDs, a panic hook without payloads, and per-task
panic containment.

---

## M14 — Streamable HTTP

Use rmcp's HTTP transport with `2026-07-28` semantics, authentication integration,
principal-bearing `RequestContext`, HTTP deployment documentation, and a remote
production example.

---

## M15 — Security hardening

Expand the adversarial corpus, fuzz targets, load and concurrency tests, dependency
scanning, threat-model documentation, a security checklist, and connection-reuse tests
after failure, cancellation, and timeout.

---

## Why analyzers come before execution

The generic core model is the project's largest architectural risk. Implementing both
analyzers before execution validates that `QueryAnalysis`, `RiskFlag`,
`StatementKind`, and `FunctionClassification` actually represent both dialects.

Otherwise, after hundreds of lines of MySQL execution code, the team may discover
that the supposedly generic core was secretly shaped around MySQL.

---

## Definition of done — first usable release

- [x] Workspace compiles on the declared toolchain
- [x] Every crate forbids `unsafe` and inherits workspace lints
- [x] MySQL and PostgreSQL analyzers exist
- [x] Both adapters execute safe read-only queries
- [x] SQLx's `any` feature is disabled and `AnyPool` is unreachable (`tests/architecture.rs`)
- [x] Both adapters use concrete pools
- [x] `sqlparser` appears only inside adapter crates
- [x] Multiple statements are denied
- [x] Nested writes are denied
- [x] Locking reads are denied
- [x] Known dangerous functions have regression tests
- [x] Unknown functions are denied by default
- [x] MySQL file access and output are denied
- [x] PostgreSQL sequence mutation is denied
- [x] Dedicated test roles demonstrably cannot write
- [x] Read-only transactions are verified
- [x] Every query has client-side **and** server-side deadlines
- [x] Rows, bytes per value, and total bytes are bounded
- [x] Queue wait is bounded with `server_busy`
- [x] Concurrency per connection is bounded
- [x] Schema search and description work on both engines with object policy
- [x] Non-executing `EXPLAIN` works on both engines with reparse verification
- [ ] MCP over stdio exposes generic tools with annotations and output schemas
- [ ] Tool schemas do not vary by database and are snapshotted in CI
- [ ] DSNs never appear in tool responses
- [ ] Raw SQL and parameters are disabled in logs and audits by default
- [ ] Two-phase auditing uses fail-closed attempts
- [ ] SQLx errors are sanitized at the MCP boundary
- [ ] Integration tests use real containers
- [ ] MCP E2E tests exist
- [x] A security corpus exists
- [ ] README documents secure deployment and the SPEC section 7 guarantee boundaries
- [ ] Security documentation states that database privileges are mandatory
