# Architecture

## 1. Layers

```text
┌──────────────────────────────────────────────────┐
│                     AI Agent                     │
└───────────────────────┬──────────────────────────┘
                        │ MCP
                        ▼
┌──────────────────────────────────────────────────┐
│                   MCP Adapter                    │
│  list_connections  search_schema  describe_schema│
│  query             explain                       │
└───────────────────────┬──────────────────────────┘
                        ▼
┌──────────────────────────────────────────────────┐
│              Application Services                │
│  QueryService   SchemaService   ExplainService   │
│  ConnectionRegistry  PolicyEngine  AuditSink     │
└───────────────────────┬──────────────────────────┘
             ┌──────────┴───────────┐
             ▼                      ▼
┌─────────────────────────┐ ┌─────────────────────────┐
│      MySQL Adapter      │ │   PostgreSQL Adapter    │
│  MySqlPool              │ │  PgPool                 │
│  MySqlDialect           │ │  PostgreSqlDialect      │
│  information_schema     │ │  pg_catalog             │
│  EXPLAIN FORMAT=JSON    │ │  EXPLAIN (FORMAT JSON)  │
└────────────┬────────────┘ └────────────┬────────────┘
             ▼                           ▼
           MySQL                     PostgreSQL
```

## 2. Workspace structure

Warden uses a Cargo workspace from the beginning because crate boundaries are the
only way for the compiler to enforce dependency direction.

```text
warden/
├── Cargo.toml            workspace, lints, and shared dependencies
├── Cargo.lock            committed because this is an application
├── rust-toolchain.toml   development toolchain
├── mise.toml             auxiliary tools and development shortcuts
├── mise.lock             auxiliary-tool versions and checksums
├── clippy.toml           disallowed methods
├── deny.toml             cargo-deny configuration
│
├── crates/
│   ├── warden-core/      domain: dialect, connection, query, result, schema, errors
│   ├── warden-policy/    engine, decisions, AllowDecision, AuthorizedQuery, policies
│   ├── warden-ports/     analyzer, executor, inspector, explainer, audit, registry traits
│   ├── warden-mysql/     analyzer, executor, inspector, explainer, normalize, connection
│   ├── warden-postgres/  same responsibilities for PostgreSQL
│   ├── warden-service/   query, schema, explain, registry, limits, redaction
│   ├── warden-mcp/       server, tools, mappings, stdio, HTTP
│   └── warden-config/    model, loading, validation, secrets
│
├── src/main.rs           composition root
├── tests/e2e/
├── fuzz/
└── docs/
```

The root package is the executable and composition root. Do not add crates without a
concrete boundary reason.

## 3. Dependency direction

```text
core        -> minimal foundational dependencies
policy      -> core
ports       -> core + policy
mysql       -> core + policy + ports + sqlx + sqlparser
postgres    -> core + policy + ports + sqlx + sqlparser
service     -> core + policy + ports
mcp         -> core + service + rmcp
config      -> serde/toml/secrecy + core metadata
binary      -> config + service + mcp + mysql + postgres
```

Forbidden and verifiable through `Cargo.toml` inspection:

```text
core -> sqlx        core -> rmcp
policy -> sqlx      policy -> rmcp
service -> sqlx     mysql -> rmcp        postgres -> rmcp
```

## 4. Security state as a type

```text
QueryRequest          raw input with validated size
   │ analyze          (adapter, synchronous, no I/O)
AnalyzedQuery
   │ authorize        (policy, synchronous, no I/O)
AuthorizedQuery
   │ execute_read_only
ResultSet
```

### 4.1 `AllowDecision` is a capability token

This mechanism enforces the transition and must be implemented exactly as shown.

```rust
// warden-policy
pub struct AllowDecision {
    // Private fields and no public constructor.
    evaluated_policies: u16,
    fingerprint: Option<QueryFingerprint>,
}

impl PolicyEngine {
    pub fn authorize(
        &self,
        context: &RequestContext,
        connection: &ConnectionMetadata,
        query: AnalyzedQuery,
        limits: ExecutionLimits,
    ) -> Result<AuthorizedQuery, PolicyRejection>;
}
```

`AuthorizedQuery::new` can safely be public because it requires an `AllowDecision`,
which only `warden-policy` can produce. The capability cannot be forged outside that
crate.

### 4.2 What this design does not protect

It prevents **accidental** bypasses within Warden. It does not protect against a
malicious adapter crate; adapters are trusted by construction, and no type system
can solve that.

### 4.3 Known dead end: feature gates

Restricting `AnalyzedQuery::new` to adapter crates through
`#[cfg(feature = "analyzer-internals")]` **does not work**. Cargo feature unification
enables the feature for the entire build as soon as any workspace member requests it,
making the constructor visible to `warden-mcp`. This is documented to prevent future
time being spent on the same attempt.

## 5. Ports

Parsing is local, synchronous CPU work:

```rust
pub trait QueryAnalyzer: Send + Sync {
    fn analyze(&self, request: QueryRequest) -> Result<AnalyzedQuery, AnalyzeError>;
}
```

Asynchronous ports require dynamic dispatch because the connection is selected at
runtime. `async fn` in traits is not dyn-compatible, so boxing is explicit:

```rust
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
```

This keeps allocation and dispatch visible. Do not add `async-trait` merely to hide
the representation (ADR-0013).

```rust
pub trait QueryExecutor: Send + Sync {
    fn execute_read_only<'a>(
        &'a self,
        query: &'a AuthorizedQuery,
        deadline: Instant,
        cancel: CancellationToken,
    ) -> BoxFuture<'a, Result<ResultSet, ExecuteError>>;
}

pub trait SchemaInspector: Send + Sync {
    fn search_schema<'a>(&'a self, r: &'a SchemaSearchRequest)
        -> BoxFuture<'a, Result<SchemaSearchResult, SchemaError>>;
    fn describe_schema<'a>(&'a self, r: &'a SchemaDescribeRequest)
        -> BoxFuture<'a, Result<SchemaDescription, SchemaError>>;
}

pub trait Explainer: Send + Sync {
    fn explain<'a>(&'a self, r: &'a ExplainRequest)
        -> BoxFuture<'a, Result<QueryPlan, ExplainError>>;
}

pub trait AuditSink: Send + Sync {
    fn record_attempt<'a>(&'a self, e: &'a AuditAttempt)
        -> BoxFuture<'a, Result<(), AuditError>>;
    fn record_outcome<'a>(&'a self, e: &'a AuditOutcomeEvent)
        -> BoxFuture<'a, Result<(), AuditError>>;
}
```

Dropping a future does not guarantee server-side query termination. Passing the
deadline and cancellation token explicitly lets adapters issue real cancellation—a
PostgreSQL cancel request or MySQL `KILL QUERY`—instead of merely being dropped. See
`docs/operations.md` section 5.

No port exposes an `execute(sql: &str)` API that accepts untrusted SQL.

## 6. Connection runtime

```rust
pub struct ConnectionRuntime {
    metadata: ConnectionMetadata,
    analyzer: Arc<dyn QueryAnalyzer>,
    executor: Arc<dyn QueryExecutor>,
    inspector: Arc<dyn SchemaInspector>,
    explainer: Arc<dyn Explainer>,
    capabilities: Capabilities,
    query_semaphore: Arc<Semaphore>,
}

pub trait ConnectionRegistry: Send + Sync {
    fn get(&self, name: &ConnectionName) -> Result<Arc<ConnectionRuntime>, ConnectionError>;
    fn list(&self) -> Vec<ConnectionMetadata>;
}
```

Fields are private. The concrete implementation uses a `HashMap` that becomes
immutable after startup. Dynamic configuration reload is future work.

A connection encapsulates its concrete pools and dialect behavior.

### 6.1 Two pools per connection

Each `ConnectionRuntime` owns **two** pools:

| Pool | Use | Statement cache |
|---|---|---|
| `agent_pool` | agent queries and EXPLAIN | PostgreSQL: `capacity(0)` **plus `.persistent(false)`**; MySQL: `capacity(0)` is sufficient |
| `control_pool` | health checks and schema introspection | default for static SQL |

On PostgreSQL, `capacity(0)` alone is the worst case. `sqlx::query()` defaults to
`persistent: true`, which creates a *named* prepared statement during PARSE. With the
cache disabled, that name is never released and `Close::Statement` is never emitted.
`.persistent(false)` forces `StatementId::UNNAMED` and actually prevents the leak.
The MySQL driver has no such distinction: it unconditionally sends `StmtClose` after
execution, so `capacity(0)` alone is sufficient. See `docs/operations.md` section 4
for the measurements.

A timeout during row streaming forces SQLx to discard the connection. Under repeated
slow queries, a single pool drains and also takes down health checks and schema
discovery. Separate pools are simpler and more robust than reserving capacity in one
pool.

## 7. Capabilities

```rust
pub struct Capabilities {
    pub read_only_transactions: bool,
    pub structured_explain: bool,
    pub server_statement_timeout: bool,
    pub schema_search: bool,
}
```

Services inspect capabilities rather than matching on `Dialect`, except where
user-visible behavior is inherently dialect-specific, such as placeholders.

## 8. `QueryService` flow

```rust
pub async fn execute(
    &self,
    context: &RequestContext,
    request: QueryRequest,
) -> Result<ResultSet, QueryServiceError> {
    // 1. Validate input size before parsing.
    // 2. Resolve the connection.
    // 3. Analyze SQL.                         -> AnalyzedQuery
    // 4. Evaluate every policy.               -> AuthorizedQuery or PolicyRejection
    // 5. Record the audit attempt.             -> fail closed
    // 6. Acquire a permit within max_queue_wait.
    // 7. Execute with client and server deadlines.
    // 8. Normalize under row, value, and byte limits.
    // 9. Redact.
    // 10. Record the audit outcome.            -> fail open with an alarm
}
```

Exact APIs may differ. Dependency flow and ordering may not.

The attempt is recorded **before** permit acquisition and execution. If the sink
fails, deny the query. If the process dies during execution, the attempt is already
recorded.

## 9. Why adapters remain separate crates

Even though SQLx and sqlparser-rs support both engines, separate crates provide
independent compile features, parser evolution, dialect tests, clearer security
review, and fewer accidental cross-dialect assumptions.

Do not create a single `warden-sql` crate.

## 10. Parser replacement seam

Because ASTs do not cross adapter boundaries, a future implementation can replace
`sqlparser-rs` with a specific parser such as `libpg_query` without changing MCP,
core, policy, query service, or audit models. This seam is intentional (ADR-0007).

## 11. MySQL/PostgreSQL parity rule

Fixing or adding adapter behavior does not require artificial parity. If PostgreSQL
exposes a planner field that MySQL lacks, the generic MySQL summary omits it. **Do not
invent values.**

Uniformity belongs at semantic boundaries—`analyze`, `authorize`,
`execute_read_only`, `inspect_schema`, and `explain`—not in driver APIs.

## 12. Startup sequence

```text
install tracing subscriber
    ↓ load configuration
    ↓ validate configuration
    ↓ resolve secrets
    ↓ create audit sink
    ↓ build MySQL connections (agent_pool + control_pool)
    ↓ build PostgreSQL connections
    ↓ build ConnectionRegistry
    ↓ build PolicyEngine
    ↓ build application services
    ↓ build MCP adapter
    ↓ serve selected transport
```

Use one root Tokio cancellation token.

## 13. Graceful shutdown

Stop accepting requests; signal cancellation to in-flight operations; bound the wait;
close pools; and drain audit and telemetry where practical. Never wait indefinitely.
