# Operations

## 1. Toolchain

```toml
edition = "2024"
rust-version = "1.94"    # See the note below.
```

**MSRV note.** The dependencies require SQLx 1.94 and rmcp 1.88. Pinning the MSRV to
the newest stable release would add CI and distribution friction without an identified
benefit. The floor is 1.94, the highest dependency MSRV, unless Warden needs a specific
1.95–1.97 feature; in that case ADR-0002 must name the feature.

This does not prevent development on current stable. `rust-toolchain.toml` pins the
development toolchain, while `rust-version` declares the supported floor.

`rust-toolchain.toml` is also the only hand-written source for the Rust version and
components. mise reads it to provision the toolchain but manages only auxiliary tools
and shortcuts; `mise.toml` does not repeat those values. The Cargo commands below
remain canonical even when a task groups them.

The project raises the MSRV intentionally, never silently.

## 2. Dependencies

### 2.1 Before adding a crate

1. Can `std` solve the problem adequately?
2. Is the crate maintained?
3. Is it security-sensitive?
4. Does it add substantial transitive code?
5. Does it introduce a native build requirement?
6. Can it be isolated behind a crate boundary?
7. Does Tokio, SQLx, or rmcp already provide the capability?

### 2.2 SQLx features—`default-features = false` is mandatory

SQLx 0.9 uses `default = ["any", "macros", "migrate", "json"]`. Those defaults
contradict project decisions:

- **`any`** enables `sqlx::any` and `AnyPool`, prohibited by ADR-0005. Disabling the
  feature makes violations **compile errors** instead of written rules.
- **`migrate`** compiles a DDL migration executor into a declared read-only gateway,
  adding dead and contradictory surface.
- **`macros`** adds procedural macros that do not apply to runtime agent SQL.

```toml
sqlx = { version = "0.9", default-features = false, features = [
  "runtime-tokio",
  "tls-rustls-ring-webpki",
  "mysql",
  "postgres",
  "json",
  "time",
  "uuid",
  "bigdecimal",
] }
```

`bigdecimal` is mandatory and **must not** be replaced with `rust_decimal`. The latter
is 96-bit and loses precision for large `NUMERIC` values, violating normalization rule
1 (`docs/data-model.md` section 8.1).

**Keep `mysql-rsa` disabled.** It is opt-in in 0.9. Disabling it prevents
`caching_sha2_password` from exchanging RSA keys over an insecure channel, effectively
pushing deployments toward TLS. **Milestone 0.5 confirmed this empirically on
2026-08-20:** connecting in cleartext with `MySqlSslMode::Disabled` rejected
authentication with `error with configuration: RSA auth backend disabled; enable
feature \`mysql-rsa\` (or \`rsa\` if using sqlx-mysql directly) or use TLS.`

### 2.3 rmcp features

```toml
rmcp = { version = "3", default-features = false, features = [
  "server",
  "macros",
  "schemars",
  "transport-io",                    # stdio
  "transport-streamable-http-server",
  "auth",                            # Milestone 14
] }
```

**The last two features are not enabled today.** `Cargo.toml` declares only `server`,
`macros`, `schemars`, and `transport-io`, with a comment recording the omission.
Enabling `auth` needs extra care because its manifest pulls in `dep:async-trait`, which
`deny.toml` bans under ADR-0013 except through the `testcontainers`/`tonic` wrappers.
Milestone 14 must explicitly revisit ADR-0013 before enabling `auth`; this is not a
routine feature addition.

### 2.4 sqlparser features

**Keep `recursive-protection`**, which is enabled by default. It prevents stack
overflow on deeply nested SQL and makes the fuzzing invariant achievable. It uses
`stacker`, which contains `unsafe`; this does not violate Warden's first-party
`unsafe` policy and is recorded in `deny.toml`.

**Enable `visitor`** (Milestone 4). It derives `Visit`/`VisitMut` on every AST node,
so an adapter's traversal reaches every `Statement`, `Query`, `TableFactor`,
`ObjectName`, `Expr`, and `Value` without a handwritten recursion that could forget
one. `docs/security.md` section 7.1 asks for exactly that property; the cost is the
`sqlparser_derive` proc macro at build time.

### 2.5 Expected production dependencies

```text
tokio  tokio-util  rmcp  sqlx  sqlparser  sha2  serde  serde_json
thiserror  tracing  tracing-subscriber  secrecy  time  base64  bigdecimal  uuid
```

`tokio-util` provides `CancellationToken` for explicit query cancellation.

`sha2` computes the `v1:<sha256-hex>` query fingerprint of `docs/security.md`
section 11.4, which `std` cannot provide. It is used behind one function per
adapter. The RustCrypto chain it sits in — `sha2`, `digest`, `hybrid-array`,
`typenum` — is already in the graph via `sqlx`'s MySQL authentication; the only
crate this dependency newly introduces is `const-oid`.

### 2.6 Do not add by default

An ORM; Axum merely because MCP supports HTTP; Actix; Rocket; a DI framework;
`async-trait`; a generic query builder; an OPA/Rego runtime; Redis; a distributed
cache; a dynamic plugin framework; or a generic repository abstraction.

If rmcp's HTTP transport uses HTTP-ecosystem types internally, follow the SDK instead
of wrapping an unrelated web framework around it.

### 2.7 Supply chain

Use `cargo-deny` for advisories, licenses, sources, and bans. Commit `Cargo.lock`
because Warden is an application.

> **PENDING:** the project license is not selected, which blocks the `deny.toml`
> license allowlist. This is a product choice between Apache-2.0, with its patent
> grant and common use in security infrastructure, and AGPL, which prevents
> closed-source SaaS resale.

## 3. Configuration

```toml
version = 1

[[connections]]
name = "production-mysql"
dialect = "mysql"
environment = "production"
database = "app"
dsn_env = "WARDEN_PRODUCTION_MYSQL_DSN"
policy = "production"

[[connections]]
name = "production-postgres"
dialect = "postgresql"
environment = "production"
database = "analytics"
dsn_file = "/run/secrets/warden-pg-dsn"
policy = "production"
search_path = ["app", "public"]

[policies.production]
query_timeout = "5s"
max_queue_wait = "2s"
max_rows = 200
max_value_bytes = 65536
max_result_bytes = 262144
max_concurrent_queries = 3
allow_locking_reads = false
allow_unknown_functions = false

[policies.production.agent_pool]
max_connections = 5
min_connections = 0
acquire_timeout = "3s"
statement_cache_capacity = 0
# Only PostgreSQL needs `persistent_statements`; the MySQL driver closes each
# statement after execution. The adapters diverge; see section 4.
persistent_statements = false

[policies.production.control_pool]
max_connections = 2
min_connections = 1
acquire_timeout = "3s"

[redaction]
columns = ["*.password", "*.password_hash", "*.access_token", "*.refresh_token", "*.secret"]

[audit]
mode = "fingerprint"
```

### 3.1 Structural rules

**`allow_multiple_statements` does not exist.** One statement is an invariant (SPEC
section 6, invariant 2), and invariants have no configuration keys. A boolean that can
become `true` would be exactly the bypass flag prohibited by SPEC section 9.

`allow_locking_reads` and `allow_unknown_functions` remain configurable because they
represent legitimate tradeoffs, but `warden check` warns when a `production` profile
enables either.

**Every configuration struct uses `#[serde(deny_unknown_fields)]`.** Without it, a
misspelled `allow_locking_read` is silently ignored and falls back to the default. The
operator believes the configuration is hardened when it is not. With this rule,
startup fails and identifies the field.

Support **`dsn_file` as well as `dsn_env`**. Docker and Kubernetes mount secrets as
files; forcing environment variables pushes operators toward the worse pattern.

### 3.2 Startup validation

Fail startup on duplicate connection names, unsupported dialects, missing DSN
environment variables or files, empty DSNs, invalid durations, zero or invalid hard
limits, pool maxima below required concurrency, unknown policy profiles, malformed
schema or table rules, unknown fields, and explicitly prohibited configuration.

**Error messages never contain secret values.**

### 3.3 Secrets

In v0.1, read DSNs from environment variables or files and immediately wrap them in
`secrecy`. Secret-bearing structs do **not** derive `Serialize` and **redact** `Debug`.

Possible future providers are Vault, AWS Secrets Manager, GCP Secret Manager, Azure
Key Vault, and OS keychains. A `SecretResolver` trait is optional and must not be
implemented before it is needed.

## 4. Pools

Each named connection owns two pools (`docs/architecture.md` section 6.1).

```text
agent_pool    max 5, min 0, acquire 3s
              PostgreSQL: statement_cache_capacity(0) + persistent(false)
              MySQL:      statement_cache_capacity(0)
control_pool  max 2, min 1, acquire 3s, default cache
idle_timeout and max_lifetime are configurable on both
```

**The adapters diverge here, and measurement—not assumption—establishes the
difference.** Warden receives an unlimited variety of SQL. Without care, every new
query becomes a prepared statement retained by the server-side connection. PostgreSQL
requires two controls, and disabling only the first worsens the problem; MySQL needs
one. Read the complete explanation before configuring either adapter.

Version 0.3 originally claimed that `statement_cache_capacity(0)` was sufficient.
**Milestone 0.5 measured it and proved the claim wrong.** In `sqlx-postgres` 0.9
(`src/connection/executor.rs`):

```rust
let id = if persistent { /* named id */ } else { StatementId::UNNAMED };
// ...
if persistent && self.inner.cache_statement.is_enabled() {
    // Only cache eviction emits Close::Statement.
}
```

`query()` and `query_scalar()` default to `persistent: true`. With persistence
enabled, PARSE creates a **named** statement. With the cache disabled, the second
condition is false, the statement never enters the cache, and `Close::Statement` is
**never emitted**. Capacity zero alone creates the worst case: named statements that
leak for the connection lifetime. M0.5 measured 21 rows in
`pg_prepared_statements` after 20 distinct queries.

`.persistent(false)` forces `StatementId::UNNAMED`, which PostgreSQL does not retain
or list in `pg_prepared_statements`. **Both settings are mandatory on PostgreSQL's
`agent_pool`**, and the second one actually prevents the leak.

**MySQL behaves differently for a structural reason.** In `sqlx-mysql` 0.9
(`src/connection/executor.rs:171`), the uncached path sends `StmtClose`
**unconditionally** after `StatementExecute`:

```rust
self.inner.stream.send_packet(StatementExecute { statement: id, arguments: &arguments }).await?;
self.inner.stream.send_packet(StmtClose { statement: id }).await?;
```

PostgreSQL sends `Close` only on cache eviction, which never occurs with the cache
disabled; MySQL sends it every time. M0.5 measured `Prepared_stmt_count` as **0** with
both `statement_cache_capacity(0)` alone and with `.persistent(false)` added. **On
MySQL, `capacity(0)` is sufficient and `.persistent(false)` is redundant.**

Do not generalize from one adapter to another. Each needs its own measurement, and
this section has already been wrong once after assuming symmetry.

`statement_cache_capacity` belongs to `PgConnectOptions` / `MySqlConnectOptions`, not
`PoolOptions`, even though the example groups it under a pool key. `persistent` is
selected per query through the `sqlx::query` builder.

Static, finite SQL makes the default cache and persistence appropriate for
`control_pool`.

M0.5's MySQL measurement covers only statement-cache behavior. It does not validate
numeric pool defaults (`max 5 / min 0 / acquire 3s`), which remain owned by M6 and
must be verified under integration and load tests (`docs/milestones.md`).

## 5. Timeouts and cancellation

Dropping a client future **does not** guarantee server-side termination. Without
server termination, Warden's concurrency limit bounds the load Warden observes, not
database load; repeated timeouts accumulate orphaned queries.

The solution **does not rewrite agent SQL**.

### 5.1 PostgreSQL

Apply these settings at connect time, outside any agent-controlled path:

```rust
PgConnectOptions::new()
    .options([
        ("statement_timeout", "5000"),
        ("idle_in_transaction_session_timeout", "10000"),
        ("lock_timeout", "1000"),
        ("default_transaction_read_only", "on"),
        ("search_path", "app,public"),
    ])
```

This is stronger than `SET LOCAL` inside a transaction because it applies to every
statement and does not depend on the transaction opening correctly.
`default_transaction_read_only = on` becomes a **fourth** independent write barrier,
and a fixed `search_path` removes name-resolution ambiguity (`docs/security.md`
section 5.1).

Keep `SET LOCAL statement_timeout` inside the transaction as reinforcement. The value
comes from validated configuration, **never** untrusted SQL.

**Deployment caveat:** these values travel through the protocol's startup `options`
parameter. Some managed pools and proxies, including PgBouncer in transaction mode
and certain cloud proxies, reject or discard it. In those deployments, `SET LOCAL`
becomes the primary control rather than reinforcement, and `warden check` must detect
the difference by querying `current_setting('statement_timeout')` after connecting.

### 5.2 MySQL

```sql
SET SESSION MAX_EXECUTION_TIME = 5000
```

Apply this through `PoolOptions::after_connect`. It covers read-only `SELECT`, exactly
Warden's profile, without touching agent SQL. It closes the v0.2 gap created by concern
over injecting an optimizer hint.

**Measured in Milestone 0.5.** With `after_connect` setting
`MAX_EXECUTION_TIME = 5000`, `@@SESSION.MAX_EXECUTION_TIME` read back as `5000`, and a
heavy read without `LIMIT` was aborted after **5.06 seconds** with server error 3024
(`ER_QUERY_TIMEOUT`, SQLSTATE `HY000`), compared with about 18.9 seconds without the
limit.

### 5.3 Deadline ordering

```text
server timeout < client timeout
      5s              6s
```

With this order, the normal path receives a clean server error and returns an intact
connection to the pool. `tokio::time::timeout` is a safety net rather than the primary
path.

This matters because a client timeout during row streaming forces SQLx to discard the
connection; repeated slow queries can drain a pool of five.

### 5.4 Explicit cancellation

`QueryExecutor::execute_read_only` accepts `deadline` and `CancellationToken` so the
adapter can issue real cancellation—a PostgreSQL cancel request or MySQL `KILL QUERY`—
instead of merely being dropped.

## 6. Execution

### 6.1 Read-only transactions

Every user query runs in a read-only transaction when the engine supports it.

```sql
-- MySQL
START TRANSACTION READ ONLY;
-- PostgreSQL
BEGIN READ ONLY;
```

Verify behavior in integration tests instead of assuming a driver option behaves the
same on both backends. MySQL's read-only transaction is weaker than commonly assumed:
it prevents table writes, not `SELECT ... INTO OUTFILE`, `GET_LOCK`, or `SLEEP`, which
is why other layers remain necessary.

### 6.2 Finalization

Choose a consistent per-adapter strategy: rollback after a read, or commit if driver
semantics require it. There must be no semantic write.

Test the strategy for pool reuse, cancellation, timeout, partial row consumption,
normalization failure, and database errors.

### 6.3 Parameter binding

**Never** interpolate strings:

```rust
// FORBIDDEN
format!("SELECT ... WHERE id = '{}'", user_value)
```

Use SQLx bind APIs. Adapters map `ParameterValue` variants to driver binds.

### 6.4 Dynamic queries

Agent SQL arrives at runtime, so `query!` / `query_as!` do not apply. Use runtime
prepared-statement APIs.

`sqlx::raw_sql` is **forbidden** because it is the multi-statement API.
`clippy.toml`, not prose, enforces the ban. Internal static SQL may use compile-time
macros when that improves correctness without complicating CI.

### 6.5 Row limit

Do not depend on the agent adding `LIMIT`. Read at most `max_rows + 1` rows to detect
truncation and return `truncated: true`. **Do not rewrite arbitrary SQL merely to append
`LIMIT`.**

The row limit does not bound database work: a heavy aggregate with `ORDER BY` can do
all its work first. Server timeouts and read replicas address that risk.

### 6.6 Byte limit

Count bytes during normalization. When the budget is reached, stop collecting, mark
truncation where safe, close the stream correctly, and discard or return the connection
as driver correctness requires.

**Never build an unbounded in-memory response and truncate afterward.** Consume SQLx
rows incrementally. Version 0.x may return a bounded, buffered `ResultSet` through MCP;
streaming and export are separate work.

## 7. Session hardening

Security-relevant session state must not leak between requests on pooled connections.

**PostgreSQL:** prefer transactional configuration. If an adapter changes session
state, make the change transactional where possible; otherwise restore it. Test pool
reuse after errors and timeouts.

**MySQL:** session and user variables persist on pooled connections. Deny agent session
mutation and user-variable assignment by default, avoid settings that cannot be safely
reset, and test reuse after cancellation and errors.

## 8. TLS

Production connections use TLS. `tls-rustls-ring-webpki`, with embedded Mozilla roots,
fits the minimal section 12 image better than `tls-rustls-ring-native-roots`, which
depends on the often-empty OS trust store of a distroless image.

Provide private CAs through `ssl_root_cert` on `PgConnectOptions` and
`MySqlConnectOptions`.

**Do not disable certificate verification to simplify setup.**

Avoid optional driver behavior that permits arbitrary local-file loading. Do not
expose unsafe driver-specific capabilities through generic configuration without a
documented need.

**Milestone 0.5 confirmed a real handshake.** With `MySqlSslMode::Required` against
MySQL 8.4 in Testcontainers, `SHOW STATUS LIKE 'Ssl_cipher'` returned
`TLS_AES_256_GCM_SHA384`; the connection truly negotiated TLS rather than silently
accepting a flag.

## 9. Read replicas

```text
agent -> Warden -> dedicated read-only role -> production replica
```

A replica does **not** remove the need for timeouts, row and byte limits, concurrency
limits, policy, and auditing. Read-only load can also exhaust infrastructure.

## 10. Observability

### 10.1 Spans

```text
mcp.tool.query
└── warden.query
    ├── connection.resolve
    ├── sql.analyze
    ├── policy.evaluate
    ├── audit.attempt
    ├── concurrency.acquire
    ├── db.transaction.begin_read_only
    ├── db.execute
    ├── result.normalize
    ├── result.redact
    └── audit.outcome
```

### 10.2 Fields

Allowed: `request_id`, `principal_id`, `connection`, `dialect`, `environment`,
`operation`, `statement_kind`, `policy_outcome`, `rows`, `result_bytes`,
`duration_ms`, and `queue_wait_ms`.

Forbidden by default: `raw_sql`, `raw_parameters`, `password`, and `dsn`.

### 10.3 Metrics

```text
warden_queries_total              warden_queries_denied_total
warden_queries_failed_total       warden_query_duration_seconds
warden_query_timeouts_total       warden_query_queue_wait_seconds
warden_queries_rejected_busy_total
warden_result_rows                warden_result_bytes
warden_active_queries             warden_pool_acquire_duration_seconds
warden_audit_write_failures_total
```

Avoid high-cardinality labels. Use `tracing` plus `tracing-subscriber`; add
OpenTelemetry after the first vertical slice. Do not mix logging ecosystems.

### 10.4 Health

Provide liveness, readiness, and connection health. HTTP deployments can expose health
endpoints separately from MCP. **Readiness must not execute an agent query**; use a
fixed, safe adapter query through `control_pool`.

## 11. CLI

```text
warden serve --transport stdio
warden serve --transport http
warden check
warden version
```

`warden check` validates configuration, secret references, connectivity, safely
testable read-only expectations, and server settings. It **never executes arbitrary
user SQL**. It warns when stdio serves a `production` profile (`docs/mcp.md` section 7).

Avoid a heavyweight CLI framework until argument complexity justifies one.

## 12. Build, CI, and distribution

### 12.1 Lints

```toml
# Root Cargo.toml
[workspace.lints.rust]
unsafe_code = "forbid"
unreachable_pub = "warn"
missing_debug_implementations = "warn"

[workspace.lints.clippy]
print_stdout = "deny"
print_stderr = "allow"       # stderr is the log destination
unwrap_used = "deny"
expect_used = "deny"
dbg_macro = "deny"
todo = "deny"
unimplemented = "deny"
disallowed_methods = "deny"
```

**Cargo pitfall:** `[workspace.lints]` does not apply automatically. Every member crate
must declare:

```toml
[lints]
workspace = true
```

Without that declaration, a crate inherits nothing and the silence resembles success.
The Milestone 0 checklist verifies this.

`print_stdout = "deny"` mechanically enforces protocol-only stdout. Test modules may
use `#![allow(clippy::unwrap_used)]` and `#![allow(clippy::expect_used)]`, which also
makes every production-code use visible in a diff.

```toml
# clippy.toml
disallowed-methods = [
  { path = "sqlx::raw_sql", reason = "multi-statement; use sqlx::query with binds" },
]
```

Use Clippy intentionally. Do not enable every pedantic lint in bulk when it would
produce noise and cargo-cult suppressions.

### 12.2 Minimum CI

```text
cargo fmt --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo deny --workspace check
```

Database integration tests run in a dedicated Docker job. CI denies warnings; do not
force developers to deny warnings in every exploratory local command.

**`cargo deny check` needs `--workspace` before the subcommand.** Without it,
cargo-deny 0.20 inspects only the nearly empty root package graph, missing SQLx, rmcp,
and their dependencies, then reports success because it did not look. M0.5 proved that
every earlier recorded "deny ok" was green for this reason. `deny.toml` declares no
directory or package scope, so nothing makes the flag redundant. Do not remove it.

### 12.3 Release profile

Start with normal optimized settings. Do not tune `lto`, `codegen-units`, `panic`, or
`strip` before measuring build or distribution needs.

**Keep `panic = "unwind"`**. Process resilience matters in a long-running gateway, and
per-task panic containment (`docs/security.md` section 14) depends on unwinding.

### 12.4 Targets

Linux x86_64, Linux aarch64, macOS aarch64, macOS x86_64 where worthwhile, Windows
x86_64, and an OCI image. The selected SQL stack requires neither `libmysqlclient` nor
`libpq`.

### 12.5 Container

Run as non-root; embed no secrets; use a read-only root filesystem where practical; a
minimal image; explicit CA certificates; minimal egress; no shell in the final image
where practical; and database access restricted to configured endpoints.

### 12.6 Network

```text
MCP clients -> authentication layer -> Warden -> MySQL/PostgreSQL replicas
```

Do not expose database ports directly to developer machines merely to enable the AI
workflow.
