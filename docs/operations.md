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

**Disabling `any` and `migrate` removes the API, not the code.** `sqlx` 0.9.0
declares `sqlx-core` with `features = ["migrate"]` unconditionally and inherits its
defaults, which include `any`, so both modules compile whatever the facade's feature
list says. `sqlx::AnyPool` and `sqlx::migrate!` are still unreachable, which is the
guarantee ADR-0005 and ADR-0009 need; ADR-0004 records the limitation and
`tests/architecture.rs` pins both facts so an upstream change is noticed here.

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
thiserror  tracing  tracing-subscriber  secrecy  url  percent-encoding
time  base64  bigdecimal  uuid
```

`tokio-util` provides `CancellationToken` for explicit query cancellation.

`url` and `percent-encoding` parse the DSN in `warden-core`, once, so that neither
adapter has to trust a driver's URL parser with a connection string (ADR-0031). Both
are already in the graph through `sqlx`, which parses URLs with the same two crates.

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

`deny.toml` has one deliberately narrow license exception:
`webpki-roots@1.0.9` is allowed to use `CDLA-Permissive-2.0`, and no other crate or
version inherits that allowance. SQLx 0.9 reaches this root store through `sqlx-core`'s
rustls webpki configuration. The crate packages Mozilla CCADB-derived root data under
that license; its [SPDX text](https://spdx.org/licenses/CDLA-Permissive-2.0.html)
permits use, modification, and sharing while requiring the license text to accompany
shared data. Any redistribution that includes this root store must preserve that
notice. A `webpki-roots` update requires a fresh provenance and license review before
its version-pinned exception can change.

`LICENSES/webpki-roots-1.0.9-CDLA-Permissive-2.0.txt` is the unmodified text
distributed by that crate. It is a third-party redistribution notice, **not**
Warden's project license. Today's distributable artifact is the source repository;
there is no Dockerfile, Containerfile, or release archive yet. The architecture test
compares its SHA-256 against the canonical crate text and parses future Dockerfile or
Containerfile `COPY` instructions. A file passes only when the **final** build stage —
the one a release artifact is built from, so a notice copied into a builder stage and
discarded with it does not count — copies either `LICENSES` or that exact notice path
to `/opt/warden/LICENSES`. A destination merely named `LICENSES`, an unrelated file
under `LICENSES/`, and a non-normalized source such as `./LICENSES` all fail.
Milestone 12 added no packaging, so no build file exercises that rule yet; section 12.5
carries the obligation for whichever milestone adds the first one.

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
schemas = ["app"]
allow_tables = ["app.orders", "app.customers", "app.invoices"]
deny_tables = ["app.audit_log"]

[policies.production.agent_pool]
max_connections = 5
min_connections = 0
acquire_timeout = "3s"

[policies.production.control_pool]
max_connections = 2
min_connections = 1
acquire_timeout = "3s"

[redaction]
columns = ["*.password", "*.password_hash", "*.access_token", "*.refresh_token", "*.secret"]

[audit]
mode = "fingerprint"
```

This is the file Warden parses. `crates/warden-config/tests/fixtures/example.toml` is a
near-copy of it that the crate's own tests read back, and a separate test asserts that the
two keys named below are refused. Two things about the example are worth stating rather
than inferring.

**`statement_cache_capacity` and `persistent_statements` are not configuration keys.**
Earlier revisions of this example showed both under `agent_pool`. ADR-0025 owns both
values — the agent pool disables statement caching, and PostgreSQL additionally marks
agent statements non-persistent — and ADR-0026 says an invariant has no configuration key,
so `deny_unknown_fields` refuses them and startup names the field. Section 4 is where the
adapters' divergence is described; it is not something an operator sets.

**Object rules live in the policy profile.** `schemas`, `allow_tables`, and `deny_tables`
sit beside the relaxations they belong with. All three are optional: an absent `schemas`
or `allow_tables` restricts nothing, and `deny_tables` wins over `allow_tables`. They
reduce attack surface and improve error messages; they are **not** the read-scope
boundary, which is the role's `SELECT` privilege alone (`docs/security.md` section 5,
ADR-0023).

### 3.1 Structural rules

**`allow_multiple_statements` does not exist.** One statement is an invariant (SPEC
section 6, invariant 2), and invariants have no configuration keys. A boolean that can
become `true` would be exactly the bypass flag prohibited by SPEC section 9.

`allow_locking_reads` and `allow_unknown_functions` remain configurable because they
represent legitimate tradeoffs, but `warden check` warns when either is enabled while a
`production` connection is served.

**Profiles may differ in capacity; they may not differ in policy (ADR-0039).** A profile
carries both halves an operator thinks of together, but only the first is per connection.
Limits and pool capacity — `query_timeout`, `max_rows`, `max_concurrent_queries`, the two
pool tables — are taken from each connection's own profile. The relaxations and the object
rules are process-wide, because `warden_service::Services` holds one `Arc<PolicyEngine>`.
Startup therefore **fails**, naming both profiles, when two referenced profiles disagree
about `allow_locking_reads`, `allow_unknown_functions`, or any object rule. Silently
applying one profile's policy to a connection that asked for another would be the worst
available outcome. A deployment that genuinely needs a policy per connection is open
question 22, not a configuration this build can express.

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

**A DSN names only the connection target** (ADR-0031). It must carry a supported
scheme, a TCP host, a user and a database; it may carry a port and a password; and it
may carry no query string and no fragment. `?sslmode=`, `?options=`, `?ssl-ca=`,
`?socket=` and every other driver parameter are startup errors rather than settings,
because each of them is a decision Warden makes from its own configuration, and a DSN
that carried one would be a second, unreviewed source of it. Unix-domain socket paths
are not addressable: TLS needs a TCP peer to authenticate.

**PostgreSQL connections refuse an ambient environment.** `PgConnectOptions` reads
`PGHOST`, `PGHOSTADDR`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`, `PGSSLMODE`,
`PGSSLROOTCERT`, `PGSSLCERT`, `PGSSLKEY`, `PGAPPNAME` and `PGOPTIONS` for itself, and
offers no way to clear the three certificate fields afterwards. Warden refuses to
build a connection while any of them — or `PGPASSFILE` — is set, and names the
variable. Unset them; put the value in Warden's configuration instead.

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
              (only the authorized parameter-bound agent query built by
               `bind::statement` is temporarily named; static Warden queries,
               including `set_config`, remain unnamed/non-persistent; the named query
               is deallocated on its pinned connection or that connection is retired)
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
or list in `pg_prepared_statements`. **Both settings are mandatory for generic
PostgreSQL `agent_pool` statements**, and the second one actually prevents the leak.
Milestone 8's only exception is the authorized parameter-bound agent query built by
`bind::statement`, which is deliberately temporary and named: SQLx may issue a simple
query while resolving custom result metadata, which destroys an unnamed prepared
statement. Static Warden queries, including `set_config`, remain unnamed and
non-persistent. After rollback, the executor sends `DEALLOCATE ALL` on that same pinned
connection before it returns to `agent_pool`. The connection is armed for retirement
before that named query can exist and is disarmed only after both operations confirm.
If rollback/deallocation is unconfirmed, or the request future is dropped mid-stream,
it retires the connection instead, so the statement cannot survive the request or reach
another agent query.

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

**Milestone 6 closed that gap.** `PoolSettings::agent()` and `PoolSettings::control()`
in `warden-core` carry the numbers, and each adapter asserts them twice: once against
`PoolOptions`'s own getters with no database, because SQLx defaults to `max 10` and a
30-second acquire timeout and an unset field is invisible in review; and once against a
real server, where five held connections make the sixth caller fail with
`PoolTimedOut` after three seconds rather than queue indefinitely. The same tests show
that a saturated `agent_pool` leaves `health_check` on `control_pool` unaffected, which
is the property ADR-0025 exists for.

M6 also measured what M0.5 could not: with `statement_cache_capacity(0)`, twenty
distinct agent-pool queries left `Prepared_stmt_count` unchanged on MySQL 8.4, and with
`statement_cache_capacity(0)` plus `.persistent(false)` through
`warden_postgres::query::agent_query`, twenty distinct agent-pool queries left
`pg_prepared_statements` empty on PostgreSQL 17.

## 5. Timeouts and cancellation

Dropping a client future **does not** guarantee server-side termination. Without
server termination, Warden's concurrency limit bounds the load Warden observes, not
database load; repeated timeouts accumulate orphaned queries.

The solution **does not rewrite agent SQL**.

### 5.1 PostgreSQL

Apply these settings at connect time, outside any agent-controlled path:

```rust
// `new_without_pgpass`, never `new` or `from_str`: every constructor seeds itself
// from `PG*` variables, and the parsing ones also read `~/.pgpass` and log what they
// cannot parse — password included — before hardening can run (ADR-0031).
PgConnectOptions::new_without_pgpass()
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
the difference after connecting.

**Milestone 6 provides that detection.**
`PostgreSqlConnectionPools::verify_session_settings` reads every pinned setting back
from `pg_settings` on **both** pools and reports
`ConnectError::SessionSettingRejected` naming the setting, the configured value and
the server's. It reads `pg_settings.setting` rather than `current_setting`, because
the former reports a time value in the row's own unit — milliseconds here — while the
latter normalizes `5000ms` to `5s` and would make the comparison depend on formatting.
`MySqlConnectionPools::verify_session_settings` does the same for
`@@SESSION.MAX_EXECUTION_TIME`. Neither is part of readiness, which stays a single
`SELECT 1` on `control_pool`.

**Milestone 8 implemented that reinforcement and made it one-directional.** `SET`
is a utility statement and cannot take a bound parameter, so
`PostgreSqlQueryExecutor` sends `SELECT set_config('statement_timeout', $1, true)`
instead: `is_local = true` is exactly `SET LOCAL`, and the value travels as a bind,
which keeps the whole executor inside section 6.3's bind-only rule with no
exception. The value is the **smaller** of the request's own
`ExecutionLimits::server_timeout` and the connection's pinned startup value, so a
request can only tighten the server-side deadline, never relax the one the deployment
configured.

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

**Milestone 7 measured the MySQL side of this ordering, and corrected a plan
assumption in the process.** `SELECT SLEEP(n)` does not prove the server deadline: a
real MySQL 8.4 server does not abort `SLEEP` when `MAX_EXECUTION_TIME` fires—`SLEEP`
catches the interrupt internally and returns `1`. The container tests instead run a
cross join with real per-row work under a two-second server deadline; it aborted at
**2.05 seconds**, arriving at `MySqlQueryExecutor` as `ExecuteError::Timeout` with the
connection returned to the pool intact. `SLEEP` is kept only where cancellation, not a
deadline, is under test: a `KILL QUERY` (section 5.4) does terminate it.

`deadline` bounds the query, not the call. On the truncation path, `MySqlQueryExecutor`
issues a `KILL QUERY` under its own budget and then a `ROLLBACK` under its own budget,
both after the query itself has already resolved (section 6.2), so total call latency
can exceed the configured `deadline` by up to `KILL_TIMEOUT + ROLLBACK_TIMEOUT`—2s + 2s
at today's constants. A caller enforcing its own aggregate request timeout should use
`warden_service::RequestBudget::total`, which adds queue wait, the client timeout,
`MAX_ADAPTER_CLEANUP`, and two `AUDIT_WRITE_TIMEOUT` writes; `MAX_ADAPTER_CLEANUP` is
pinned to PostgreSQL's larger three-step bound rather than this engine's own 2s + 2s
figure, because one shared constant must hold for both adapters.

**Milestone 8 measured PostgreSQL's server deadline with real work.** A
`SELECT count(*) FROM generate_series(1, 2000000000)` under a two-second server
deadline ran on the same pinned backend PID used before and after the request. Its
`pg_stat_activity` marker left the active state before the longer client deadline,
and PostgreSQL's `57014 query_canceled` reached the executor's SQLSTATE mapping as
`ExecuteError::Timeout`. Rollback and statement deallocation were then awaited under
their separate aggregate cleanup budget before the same physical session answered the
next query. `pg_sleep` instead belongs to explicit-cancellation tests; those tests
construct a synthetic `AuthorizedQuery` because the analyzer and policy rightly deny
the delay function (section 5.4).

`deadline` bounds the query, not the call, on this adapter too. On a truncated or error
path, cancellation, `ROLLBACK`, and — only after a confirmed rollback — `DEALLOCATE
ALL` run sequentially under their own two-second budgets. Those paths can therefore add
up to six seconds after `deadline`; a caller enforcing an aggregate request timeout must
budget for that maximum. `warden_service::RequestBudget::total` is the shipped
aggregate envelope: it adds queue wait, the client timeout,
`MAX_ADAPTER_CLEANUP`, and two `AUDIT_WRITE_TIMEOUT` writes.

### 5.4 Explicit cancellation

`QueryExecutor::execute_read_only` accepts `deadline` and `CancellationToken` so the
adapter can issue real cancellation—a PostgreSQL cancel request or MySQL `KILL QUERY`—
instead of merely being dropped.

**Milestone 7 measured MySQL's cancellation path.** It is `KILL QUERY <id>`, sent on
`control_pool` rather than `agent_pool` because the connection running the target
statement is busy and cannot be asked for its own id—`<id>` therefore costs one
`SELECT CONNECTION_ID()` round trip at the start of every call, before the agent's
statement begins (ADR-0025).

`KILL` does **not** accept a bound parameter, which the plan left open. Against a real
MySQL 8.4 container, `KILL QUERY ?` (and the `KILL ?` / `KILL CONNECTION ?` forms)
never kill the target at all: `Com_kill` stays at zero and the statement runs to
completion. sqlx 0.9.0 always sends a bound argument through the binary protocol, and
its `protocol/text/column.rs` has no arm for the server's prepared-statement response
column type (`0xf3`), so the client call fails to decode the response rather than
merely failing to kill anything. `MySqlQueryExecutor::kill` therefore sends
`KILL QUERY <id>` as an interpolated literal—the one audited exception to section
6.3's bind-only rule, recorded there.

**Milestone 8 measured PostgreSQL's cancellation path, and it is simpler than
MySQL's in the one way that matters.** `sqlx-postgres` 0.9.0 exposes no cancel handle
and never sends the protocol's `CancelRequest`, so the mechanism is
`SELECT pg_cancel_backend($1)` from another session — `control_pool`, for the same
reason MySQL uses it: the connection running the target statement is busy and cannot
be asked for its own identity, which costs one `SELECT pg_backend_pid()` round trip at
the start of every call (ADR-0025).

Unlike `KILL QUERY`, it **does** take a bound parameter: `pg_cancel_backend` is an
ordinary function call inside a `SELECT`, so no interpolation is involved and
PostgreSQL needs no exception to section 6.3.
`crates/warden-postgres/tests/adapter_rules.rs` pins the strict form — `format!`
anywhere in `execute.rs` fails the build.

`pg_cancel_backend`, never `pg_terminate_backend`: cancelling ends the statement and
leaves a reusable pooled session when cleanup is confirmed, while terminating discards
a connection Warden had already paid to open. Both pools authenticate as the same role,
which is what makes the call permitted without membership in `pg_signal_backend`.

The cancellation tests execute synthetic authorized `SELECT pg_sleep(...)` statements
only below the policy boundary. PostgreSQL corpus fixtures and Task 5's exhaustive
analyzer/policy table separately prove that `pg_sleep` is classified as a dangerous
delay function and denied before execution; the cancellation test proves neither that
classification nor the server statement-timeout behavior.

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

**Milestone 7 measured this on MySQL 8.4.** With the connecting account as **root**—
every privilege granted—an `INSERT` inside `START TRANSACTION READ ONLY` was still
refused, with `ER_CANT_EXECUTE_IN_READ_ONLY_TRANSACTION` (1792). The barrier is the
session's own state, not the connecting role's grants: the dedicated `warden_ro`
role's own refusal (`docs/security.md` section 3) is a second, independent barrier,
not a restatement of this one.

**Milestone 8 measured this on PostgreSQL 17.** With the connecting account as the
superuser — every privilege granted — `INSERT`, `UPDATE`, `DELETE`, `CREATE TABLE`,
`SELECT INTO`, a data-modifying CTE, and both `nextval` and `setval` were all refused
inside `BEGIN READ ONLY`, with SQLSTATE `25006` `read_only_sql_transaction`. The
barrier is the session's own state, not the connecting role's grants: the dedicated
`warden_ro` role's own refusal (`docs/security.md` section 4.2) is a second,
independent barrier, and Milestone 8's privilege tests have to switch the session
default off before they can observe it at all.

### 6.2 Finalization

Choose a consistent per-adapter strategy: rollback after a read, or commit if driver
semantics require it. There must be no semantic write.

Test the strategy for pool reuse, cancellation, timeout, partial row consumption,
normalization failure, and database errors.

**MySQL's strategy, measured in Milestone 7.** MySQL streams a result with no cursor:
once a query starts sending rows, sqlx will not send another command on that
connection until every remaining row packet has been drained, whether or not Warden is
still reading them. `MySqlQueryExecutor::run` treats "stopped reading early" as its
own event, separate from success or failure:

- On **success**, `ROLLBACK` runs under its own fresh budget, and its outcome—success,
  timeout, or error—is discarded. A slow or failed rollback must never overwrite a
  result that is already collected and already correct.
- On **failure**, the transaction is dropped rather than rolled back explicitly:
  dropping queues a `ROLLBACK` without awaiting it, because awaiting one on a
  connection whose statement may still be running would hang.
- A `KILL QUERY` (section 5.4) is issued whenever Warden stops reading a stream the
  server may still be writing. That is not limited to timeouts and cancellations: a
  **successful but truncated** result also has rows still in flight, and every
  `ExecuteError` variant on the failure path does too. Container tests measure
  `Com_kill` increasing on both truncation paths—the row bound and the byte bound—and
  confirm that a complete, undrained result issues no kill at all.

**PostgreSQL's strategy, measured in Milestone 8, is the same shape.** sqlx executes
the portal with no row limit (`limit: 0` in its own `Execute` message), so the server
writes the whole result whether or not Warden keeps reading, and the next use of that
connection would otherwise block draining it.

- On **success**, `ROLLBACK` runs under its own fresh budget. Only a confirmed rollback
  followed by confirmed `DEALLOCATE ALL` disarms the connection's retirement guard;
  otherwise the already determined result is preserved but the physical connection is
  retired rather than reused. Only the authorized parameter-bound agent query built by
  `bind::statement` is temporarily named, because SQLx resolves custom enum metadata
  through a simple query that destroys an unnamed statement; static Warden statements,
  including `set_config`, remain unnamed and non-persistent.
- On **failure**, Warden first requests cancellation and then attempts `ROLLBACK`
  under its own fresh two-second budget. The armed RAII owner retires the physical
  connection unless that rollback and the subsequent `DEALLOCATE ALL` both confirm,
  rather than returning a session that may still be in `25P02 in_failed_sql_transaction`
  or retain a named statement. A container test pins that the next query on the same
  pool succeeds, whether that means confirmed cleanup reused the session or retirement
  supplied a replacement.
- A **cancel request** is issued whenever Warden stops reading a stream the server may
  still be writing — a truncated-but-successful result included, not only the failure
  path. PostgreSQL offers no `Com_kill` equivalent to count, so the tests measure the
  backend instead: a statement that would otherwise run for minutes is first observed
  active and then leaves `pg_stat_activity`'s `active` state within the trigger's
  absolute two-second deadline. Those activity polls run concurrently with executor
  cleanup, so rollback and deallocation cannot be mistaken for cancellation latency;
  the executor future is awaited separately under the six-second aggregate cleanup
  budget. The observation deadline is far below the connection's own five-second
  `statement_timeout`, so nothing but the cancel could have cleared the marker.

### 6.3 Parameter binding

**Never** interpolate strings:

```rust
// FORBIDDEN
format!("SELECT ... WHERE id = '{}'", user_value)
```

Use SQLx bind APIs. Adapters map `ParameterValue` variants to driver binds.

The one audited exception is MySQL's cancellation path (section 5.4): `KILL QUERY`
cannot be sent as a prepared statement, so `MySqlQueryExecutor::kill` interpolates a
`u64` connection id read back from Warden's own `SELECT CONNECTION_ID()`. Its formatted
form is always `[0-9]+`, so there is no injection surface by construction, whatever the
value. `tests/adapter_rules.rs` pins `execute.rs` to exactly this one interpolation—a
second `format!` there fails the test unless it also names `KILL QUERY`.

**The second audited exception is the `explain` prefix, and it is a different kind of
exception.** `crates/warden-mysql/src/plan.rs` interpolates the analyzed statement
after `EXPLAIN FORMAT=JSON `. That is not an injection risk defused by a type — it is
SPEC section 6, invariant 19's own carve-out, the one design point where the string
sent differs from the string analyzed. Its compensating control is the reparse in the
same file (`docs/mcp.md` section 3.2, ADR-0037), not the interpolation's shape.
`tests/adapter_rules.rs` pins `plan.rs` to that single `format!` and pins the prefix
constant's exact text, and pins `explain.rs` to the same `KILL QUERY` exemption
`execute.rs` has and nothing more.

**PostgreSQL has no such exception, and its guard says so.** Its cancellation binds a
pid (`SELECT pg_cancel_backend($1)`) and its per-request deadline binds a value
(`SELECT set_config('statement_timeout', $1, true)`), so
`crates/warden-postgres/tests/adapter_rules.rs` enforces the strict rule: **no**
`format!` at all in `execute.rs`. A future change that needs one needs its own review
and its own ADR rather than an exemption inherited from the other adapter.

PostgreSQL's `plan.rs` carries the same single `format!` for the same reason and
under the same pinned constant, while its `explain.rs` carries none at all: the
cancellation binds a pid, the deadline binds a value, and the plan binds its
parameters, so `crates/warden-postgres/tests/adapter_rules.rs` keeps the strict rule
there that it already keeps for `execute.rs`.

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

**`warden_core::result::ResultBuilder` is the single place the row, per-value, and
total-byte budgets are enforced, applied as each row arrives rather than after the
fact** (section 6.6). `push_row` resolves to one of four outcomes: the row is stored
and reading continues (`RowOutcome::Accepted`); the row-count bound is reached and the
call returns `Ok` with `truncated: true`, storing nothing further
(`RowOutcome::Truncated`); the byte bound is reached after at least one row is already
stored, the same `Ok`/`truncated: true`/`Truncated`; or a single value exceeds
`max_value_bytes`, or the first row alone exceeds `max_result_bytes`, and the call
returns `Err` rather than truncate to a result the agent never actually received any
of.

Adapters ask the same builder to admit a fetched row **before** normalizing it. Once
`max_rows` valid rows are stored, the next row is only a sentinel proving truncation;
its unsupported, unrepresentable, or oversized values cannot replace those valid rows
with an error. `push_row` repeats the row-count check defensively, so the builder
remains authoritative even if a future adapter omits the pre-normalization check.

### 6.6 Byte limit

Count bytes during normalization. When the budget is reached, stop collecting, mark
truncation where safe, close the stream correctly, and discard or return the connection
as driver correctness requires.

**Never build an unbounded in-memory response and truncate afterward.** Consume SQLx
rows incrementally. Version 0.x may return a bounded, buffered `ResultSet` through MCP;
streaming and export are separate work.

**On MySQL, "close the stream correctly" is `KILL QUERY`** (section 5.4), not merely
dropping the connection: MySQL's no-cursor protocol keeps sending rows Warden has
stopped reading, and section 6.2 records exactly when the kill fires.

**On PostgreSQL it is `pg_cancel_backend`** (section 5.4), for the same reason and at
the same moments section 6.2 lists.

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

Warden makes this a connection-policy invariant: `Disabled` and the driver mapping of
`Required` (TLS without peer verification) are legal only for a `development`
connection. Staging, production, and every operator-defined environment must use
`VerifyCa` or `VerifyIdentity`; the default is `VerifyIdentity`.

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

The child labels are code paths, and `mcp.tool.query`'s entry point exists as of
Milestone 12: `warden-mcp`'s five `#[tool]` methods, four of which run in their own
spawned task (`docs/security.md` section 14).
Connection resolution, analysis, policy, attempt and outcome writes, permit acquisition,
the adapter's read-only transaction and execution/normalization, and service-layer
redaction all exist too. **None of them is a tracing span yet.** Milestone 13 adds the
instrumentation; do not read this tree as claiming any span already exists.

### 10.2 Fields

Reconciled with `src/audit.rs` in Milestone 12: the list below is what the code emits,
not a wish. The added names were reviewed and carry nothing sensitive.

The Milestone 12 audit sink emits, per attempt: `attempt_id`, `request_id`,
`principal_id`, `client`, `connection`, `dialect`, `environment`, `statement_kind`,
`fingerprint`, and `deny_codes`. Per outcome: `attempt_id`, `outcome`, `duration_ms`,
`rows`, `result_bytes`, and `error_code`. `src/audit.rs` declares both lists as constants
and its own test asserts the emitted field names against them, so a renamed field fails
the build rather than silently drifting from this section.

Four of those are new since the list this section first carried, and each is safe by
construction: `attempt_id` is a generated identifier and the only thing that makes the two
lines readable as one record; `client` is a validated `ClientName` of printable ASCII;
`fingerprint` is `v1:<sha256>` and not reversible; and `deny_codes` is a comma-joined list
of `&'static str` codes — never `DenyReason::internal_detail`, which names the object or
function that tripped a rule and stays off every surface but a durable audit record
(`docs/security.md` section 6). `error_code` is a `PublicErrorCode`, the same closed set
section 10 of `docs/security.md` fixes. `outcome` is this section's former
`policy_outcome` under the name `warden_ports::AuditOutcome` actually uses.

`operation` and `queue_wait_ms` remain allowed and are not emitted yet: nothing carries
them into `AuditAttempt` or `AuditOutcomeEvent`.

Forbidden by default: `raw_sql`, `raw_parameters`, `password`, and `dsn`. `AuditAttempt`
has no field any of them could occupy, which is the structural half of the guarantee; the
constants above are the half a rename could break.

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
warden serve --transport stdio    # shipped in Milestone 12
warden serve --transport http     # Milestone 14; parsed and refused by name today
warden check                      # shipped in Milestone 12
warden version
warden help
```

`--config <path>` selects the configuration file for `serve` and `check`, and defaults to
`warden.toml` in the working directory. `--transport http` is not silently ignored: it
parses and exits with the usage code, naming the transport this build does not serve.

`warden check` is everything `warden serve` would do, minus serving. It loads and
validates the configuration, resolves every secret reference, opens every connection with
the same eager connect `serve` performs, runs each adapter's fixed readiness probe on
`control_pool` (section 10.4), reads the session settings back on **both** pools to catch
a pooler or proxy that discarded the connection-time options (section 5.2), and closes
every pool it opened before it returns. It **never executes arbitrary user SQL**: it takes
no query permit and dispatches no query, so the only statements it causes are those two
fixed adapter ones.

One failing connection does not stop the others — an operator fixing a deployment wants
every broken connection named in one run — and the count of failures decides the exit
code.

It also warns, without failing, about two deployment choices: a connection whose
`environment` is `production` served over stdio (`docs/mcp.md` section 7), and
`allow_locking_reads` or `allow_unknown_functions` enabled while such a connection is
served (section 3.1). A warning describes a deployment an operator may have chosen, so the
exit code stays 0 and the last line says so.

**The report goes to stderr, not stdout.** `warden check`'s answer is its exit code and
the lines explain it; stdout carries MCP and nothing else (`docs/mcp.md` section 5.1), and
a command whose output habit differs from `serve`'s is a command that eventually prints
into a protocol stream. `version` and `help`, which serve nothing, write to stdout.

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

**Milestone 12 ships no `Dockerfile`, `Containerfile`, or release archive.** The
distributable artifact is still the source repository. This section is therefore a
checklist for the day a container image appears, not a description of one that exists;
read every requirement below as binding on that future image.

Run as non-root; embed no secrets; use a read-only root filesystem where practical; a
minimal image; explicit CA certificates; minimal egress; no shell in the final image
where practical; and database access restricted to configured endpoints.

**Copy `LICENSES` to `/opt/warden/LICENSES` in the final build stage.** The
`webpki-roots` root store Warden redistributes carries a notice that must accompany it
(section 2.7). `tests/architecture.rs` already enforces this: it parses any `Dockerfile`
or `Containerfile` that appears and fails unless the **final** stage copies either
`LICENSES` or that exact notice path to that destination — a notice copied into a builder
stage and discarded with it does not count, and neither does a destination merely named
`LICENSES`, an unrelated file under `LICENSES/`, or a non-normalized source such as
`./LICENSES`. The rule is live today against a file that does not yet exist, which is why
adding one cannot forget it.

### 12.6 Network

```text
MCP clients -> authentication layer -> Warden -> MySQL/PostgreSQL replicas
```

Do not expose database ports directly to developer machines merely to enable the AI
workflow.
