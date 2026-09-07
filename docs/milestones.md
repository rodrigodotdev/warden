# Milestones

Implement one milestone at a time. At the end of each, run `cargo fmt --check`,
`cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`, and
`mise run check:standalone`, then report deviations. The last one builds each crate on
its own: the others are workspace-wide, and a workspace build unifies features across
the graph, so a crate that uses a feature it never declared still compiles.

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

**The audit trail became a durable, inspectable control.** The widened audit port now
names `query`, `explain`, `search_schema`, and `describe_schema`, so catalog reads join
statements in two-phase auditing; `list_connections` remains intentionally outside it
because it never reaches a database. An `OutcomeGuard` completes an opened record as
`abandoned` when the request is dropped or panics. The one versioned JSON Lines record
format gives attempts and outcomes a field allowlist, including the non-reversible
`v1:` fingerprint, request identity, and public error codes, with no field for a raw
statement or parameter. The append-only file sink can fail; its configured
`audit.destination` and `audit.path` keys are validated and proved writable by
`warden check` before any database pool opens. Non-regular special destinations such
as `/dev/full` are refused at open time rather than accepted as audit files.

Tracing now follows the documented service and database phase tree. Request identity
fields flow into the allowed span fields, while the architecture guard derives the
span-name set from both section 10.1 of `docs/operations.md` and production macros.
Per-request task containment was delivered in M12; this milestone closes its audit
half with the drop guard and installs the process panic hook after tracing. That hook
keeps location, thread name, payload shape, and an available backtrace, but never reads
or emits a panic payload.

Measured, not asserted: the file-sink test
`a_regular_file_write_failure_is_reported_so_the_caller_can_fail_closed` injects a
read-only regular-file handle and observes a real write map to `AuditError::Unavailable`;
separately, the pipeline test
`a_broken_attempt_write_takes_no_permit_and_reaches_no_executor` uses a failing sink and
proves an attempt-write failure takes neither a permit nor an executor. The
capturing-subscriber test `one_query_creates_the_documented_span_tree_and_leaks_no_statement`
observes the real phase order, parentage, fields, and absence of its statement literal;
the span-tree guard parses the operations documentation and production macros; and
`a_panicking_adapter_still_completes_the_audit_record_it_opened` and
`a_dropped_request_completes_its_audit_record_too` observe the `abandoned` outcome.

Deliberately left: OpenTelemetry metrics from `docs/operations.md` section 10.3;
rmcp's deserialization framing (open question 25, deferred to M14's tool-signature
work); and client cancellation reaching a running query (open question 23, also M14).

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
- [x] Raw SQL and parameters are disabled in logs and audits by default
- [x] Two-phase auditing uses fail-closed attempts
- [x] SQLx errors are sanitized at the MCP boundary
- [x] Integration tests use real containers
- [x] MCP E2E tests exist
- [x] A security corpus exists
- [x] README documents secure deployment and the SPEC section 7 guarantee boundaries
- [x] Security documentation states that database privileges are mandatory

Both claims are now reviewable against the versioned audit-record format and its field
allowlist, not only against structure. The persistent file sink's read-only
regular-file fixture proves that an actual attempt write reports `AuditError::Unavailable`.
Separately, the execution-gate fixture uses a failing sink and proves that this attempt
error takes no permit and reaches no executor, so a query cannot dispatch without its
fail-closed attempt.
