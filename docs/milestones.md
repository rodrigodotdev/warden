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

Delivered here: `warden-service` structurally orders the fail-closed audit attempt
before permit acquisition and adapter dispatch, and pairs the permit with that
runtime. The persistent sink remains Milestone 13 work, so the definition-of-done
checkbox for two-phase auditing does not flip in M11.

---

## M12 — MCP over stdio

**First developer-usable release.** Eleven milestones of libraries became a program.

Built here: `warden-config` parses the documented TOML, resolves DSNs from environment
variables and files straight into `warden_core::secret::Dsn` without ever holding one in
a struct that derives `Serialize`, and refuses a deployment it cannot serve.
`warden-mcp` exposes the five generic tools over rmcp 3.1.4 with populated
`ToolAnnotations`, an `output_schema` on every tool, and the section 1.3 descriptions,
each written as a doc comment the `#[tool]` macro lifts. A successful result carries its
data in `structured_content` and one counting line in `content` rather than a second copy
of the rows (ADR-0040). `initialize` advertises `2025-11-25` and `2026-07-28` and refuses
anything else instead of substituting silently (ADR-0041). `src/startup.rs` assembles
configuration, adapters, policy, and services in the composition root, and `warden serve
--transport stdio` and `warden check` are the CLI over it.

Measured, not asserted: `crates/warden-mcp/tests/protocol.rs` drives the handshake and
all five tools over a real duplex transport with fake ports;
`crates/warden-mcp/tests/snapshots/tools.json` pins the tool contract and
`crates/warden-mcp/tests/mcp_rules.rs` pins the boundary that sanitizes it;
`tests/mcp_database.rs` drives the real binary over stdio against MySQL and PostgreSQL
containers and, with every Warden layer removed, proves the database role itself refuses
the same write — the second barrier `AGENTS.md` requires. The disposable Milestone 0.5
tracer bullet was retired here, once those suites covered the same ground through the
real SPEC boundaries.

Deliberately left: the audit sink writes structured `tracing` events to stderr and
therefore cannot fail, so ADR-0022's fail-closed attempt has nothing to fail on and the
two audit-related boxes below stay unticked for Milestone 13. Per-request task
containment shipped (ADR-0038, `docs/security.md` section 14); the payload-free panic
hook did not. Policy profiles may differ in capacity but not in policy (ADR-0039).
`InputLimits` stay at their documented defaults with no configuration key, and a client
cancellation does not reach a running query — open questions 22, 23, and 24.

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
- [x] MCP over stdio exposes generic tools with annotations and output schemas
- [x] Tool schemas do not vary by database and are snapshotted in CI
- [x] DSNs never appear in tool responses
- [ ] Raw SQL and parameters are disabled in logs and audits by default
- [ ] Two-phase auditing uses fail-closed attempts
- [x] SQLx errors are sanitized at the MCP boundary
- [x] Integration tests use real containers
- [x] MCP E2E tests exist
- [x] A security corpus exists
- [x] README documents secure deployment and the SPEC section 7 guarantee boundaries
- [x] Security documentation states that database privileges are mandatory

The two unticked boxes are both about a sink Milestone 13 owns, not about a control that
is missing.

"Raw SQL and parameters are disabled in logs and audits by default" is structurally true
today: `warden_ports::AuditAttempt` has no field a statement or a bound parameter could
occupy, and `src/audit.rs` emits none. It stays unticked because a claim about what an
audit record does *not* contain is only reviewable against a record format, and Milestone
13 owns the sink that has one.

"Two-phase auditing uses fail-closed attempts" is ordered structurally — `warden-service`
records the attempt before it acquires a permit or dispatches, and
`crates/warden-service/tests/service_rules.rs` keeps that the only call path (ADR-0038).
It stays unticked because `src/audit.rs` writes `tracing` events and a `tracing` macro
returns unit: a sink that cannot fail cannot demonstrate failing closed. Milestone 13's
persistent sink can.
