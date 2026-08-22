# Data model

General rule: use enums for closed sets, newtypes for identifiers, private fields for
security-sensitive state, and validation in both constructors and deserialization.

## 1. Base types

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Dialect { MySql, PostgreSql }

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[serde(try_from = "String")]
pub struct ConnectionName(String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Environment { Development, Staging, Production, Other(String) }
```

Internally, `Dialect` is never an arbitrary user string; configuration converts text
to the enum.

`ConnectionName` rejects empty values, values above its maximum length, and values
outside `[a-zA-Z0-9._-]+`. It implements `TryFrom<String>`, `FromStr`, `Display`, and
`AsRef<str>`—but not `Deref`, which would expose the entire `String` API and erase the
newtype's purpose.

**`#[serde(try_from = "String")]` is mandatory.** Deriving `Deserialize` directly
bypasses the constructor and can materialize an invalid `ConnectionName` from TOML.

`Environment` is metadata and policy input, not authorization by itself.

### 1.1 No `#[non_exhaustive]` on security enums

`StatementKind`, `RiskFlag`, `DenyCode`, `FunctionClassification`, and similar enums
**do not** use `#[non_exhaustive]`.

The attribute only affects downstream crates, and `warden-policy` is downstream of
`warden-core`. It would force a `_ =>` arm in policy, allowing new variants to compile
silently through the wildcard. The desired property is the opposite: the compiler
must force policy review for every new variant.

Crate APIs are internal before 1.0, so there is no stability cost. See ADR-0021.

## 2. Query input

```rust
pub struct QueryRequest {
    connection: ConnectionName,
    sql: String,
    parameters: Vec<ParameterValue>,
}
```

The public constructor validates hard, configurable size limits **before parsing**:

```text
maximum SQL bytes:  64 KiB
maximum parameters: 100
```

## 3. Parameters

The core does not expose SQLx driver argument types.

```rust
pub enum ParameterValue {
    Null, Bool(bool), I64(i64), U64(u64), F64(f64), String(String),
}
```

The set is deliberately small for v0.1. PostgreSQL callers use explicit casts when
needed, such as `WHERE id = $1::uuid`.

Possible future variants include `Decimal(String)`, `Uuid(String)`,
`Json(serde_json::Value)`, `Date/Time/DateTime(String)`, and `Bytes(Vec<u8>)`.

**Do not infer complex SQL types from arbitrary strings.**

### 3.1 Validating numbers from JSON

MCP input is JSON. Conversion to `ParameterValue` **rejects** values that cannot be
represented exactly by the chosen variant, including integers above `i64`/`u64` and
values such as `1e400`. Never silently wrap or truncate; a silently wrong answer is
worse than an error in an investigation tool.

## 4. Dialect-native placeholders

Warden does not invent a universal placeholder language.

```sql
-- MySQL
WHERE customer_id = ?
-- PostgreSQL
WHERE customer_id = $1
```

The active connection determines the dialect. SQL remains copyable and understandable
in ordinary database tools.

## 5. Query analysis

```rust
pub struct QueryAnalysis {
    dialect: Dialect,
    statement_count: usize,
    root_kind: StatementKind,
    nested_kinds: Vec<StatementKind>,
    objects: Vec<ObjectRef>,
    functions: Vec<FunctionRef>,
    risks: Vec<RiskFlag>,
    has_locking_clause: bool,
    has_side_effects: bool,
    fingerprint: Option<QueryFingerprint>,
}
```

**Fields are private with read-only accessors.** `QueryAnalysis` is the evidence used
for authorization. Public fields would let any crate construct
`QueryAnalysis { risks: vec![], .. }` and defeat the pipeline. Construction belongs
to adapter crates.

The representation may evolve but remains parser-library independent.

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementKind {
    Select, Explain, Show, Insert, Update, Delete, Merge, Call, Copy,
    Ddl, TransactionControl, SessionControl, Utility, Unknown,
}
```

The policy engine matches exhaustively. Adding a variant must force compiler-driven
review.

```rust
pub struct ObjectRef {
    pub catalog: Option<SqlIdentifier>,
    pub schema: Option<SqlIdentifier>,
    pub name: SqlIdentifier,
    pub kind: ObjectKind,
}

pub enum ObjectKind { Table, View, MaterializedView, Sequence, Function, Unknown }
```

Do not assume a two-part name means the same thing across engines. Policy comparison
applies dialect-specific folding (`docs/security.md` section 5.1). CTE names and
subquery aliases are **not** `ObjectRef` values.

```rust
pub struct FunctionRef {
    pub name: SqlIdentifier,
    pub schema: Option<SqlIdentifier>,
    pub classification: FunctionClassification,
}

pub enum FunctionClassification { KnownSafe, KnownDangerous, Unknown }
```

Each name part is a `SqlIdentifier { value, quoting }`: the value without quote
characters, plus whether the statement quoted it. Policy comparison needs that bit
(`docs/security.md` section 5.1, ADR-0027).

```text
KnownSafe      -> eligible
KnownDangerous -> deny
Unknown        -> deny
```

Functions are security-relevant because a `SELECT` can still have side effects.

```rust
pub enum RiskFlag {
    MultipleStatements, WriteStatement, Ddl, LockingRead, DataModifyingCte,
    FileAccess, FileOutput, DelayFunction, AdvisoryLock, SessionMutation,
    SequenceMutation, StoredRoutine, UserDefinedFunction, ExplainAnalyze,
    SelectInto, UnknownConstruct,
}
```

Risk flags are **evidence**. Policies make authorization decisions; no isolated
boolean does.

## 6. Security states

```rust
pub struct AnalyzedQuery { request: QueryRequest, analysis: QueryAnalysis }

pub struct AuthorizedQuery {
    analyzed: AnalyzedQuery,
    decision: AllowDecision,     // Capability token; see architecture.md section 4.1.
    limits: ExecutionLimits,
}
```

Fields are private. `warden-policy` is the only legitimate producer of
`AuthorizedQuery` because only it can create `AllowDecision`. Adapters use read-only
accessors. There is **no public `AuthorizedQuery::new_unchecked`**.

Bad API: `executor.execute(sql: &str)`.

Correct API: `executor.execute_read_only(&authorized_query, deadline, cancel)`.

This reduces accidental internal bypasses; it does not replace database privileges.

## 7. Execution limits

```rust
pub struct ExecutionLimits {
    pub timeout: Duration,
    pub max_queue_wait: Duration,
    pub max_rows: usize,
    pub max_value_bytes: usize,
    pub max_result_bytes: usize,
    pub max_concurrent_queries: usize,
}
```

Initial production defaults:

```text
timeout:                 5s
max_queue_wait:          2s
max_rows:                200
max_value_bytes:         64 KiB
max_result_bytes:        256 KiB
max_concurrent_queries:  3
```

**`max_result_bytes` is 256 KiB, not 1 MiB.** The consumer is model context: 1 MiB of
JSON is roughly 250,000 tokens, so an MCP client exhausts context before Warden
truncates it. One MiB remains the maximum configurable ceiling.

**`max_value_bytes` is necessary** because a single row with a 500 MB `TEXT` or `BLOB`
is not constrained by `max_rows` or incremental result-byte accounting. This limit
only bounds what **leaves** Warden; the driver still materializes the incoming value.
Database `GRANT`s or views are the real mitigation for giant values.

**`max_queue_wait` is necessary** because `timeout` measures execution, not waiting.
Without it, 50 concurrent calls with `max_concurrent_queries = 3` leave 47 tasks
waiting indefinitely, so client-perceived latency includes an unbounded queue.
Exhaustion returns `server_busy`.

Profiles can configure these limits. Startup validation rejects zero and invalid
values.

## 8. Result model

One JSON object per row is not a suitable canonical model because duplicate column
names are legal SQL. Use positional rows plus metadata.

```rust
pub struct ResultSet {
    pub columns: Vec<ResultColumn>,
    pub rows: Vec<Vec<ResultValue>>,
    pub truncated: bool,
    pub stats: QueryStats,
}

pub struct ResultColumn {
    pub name: String,
    pub database_type: String,
    pub nullable: Option<bool>,
}

pub struct QueryStats {
    pub rows_returned: usize,
    pub bytes: usize,
    pub duration: Duration,
}
```

```rust
pub enum ResultValue {
    Null, Bool(bool), I64(i64), U64(u64), F64(f64),
    Decimal(String), String(String), Json(serde_json::Value),
    BytesBase64(String), Date(String), Time(String), DateTime(String),
    Uuid(String), Array(Vec<ResultValue>),
}
```

### 8.1 Normalization rules

1. Never convert arbitrary-precision decimal/numeric values to `f64`.
2. Emit dates and times in a standard, deterministic string format.
3. Emit binary values as base64 or redact them.
4. Unsupported types produce a safe normalization error containing the **type name**,
   never driver internals or memory data.
5. The error may suggest an explicit cast.
6. **Emit integers outside ±2^53 as strings.** Most MCP clients use JavaScript and
   lose precision above that bound; silently returning a wrong `bigint` is unacceptable.
7. **Bound `Array` depth**, initially at 8. This recursive type could otherwise allow a
   deeply nested PostgreSQL array to overflow the stack during normalization or
   serialization, violating the fuzzing invariant.

Example error:

```text
Column "custom_state" uses unsupported PostgreSQL type "order_state".
Cast it explicitly, for example: custom_state::text
```

### 8.2 Types by adapter

**MySQL:** NULL; signed and unsigned integers; floating point; `DECIMAL` preserved as
a string; `CHAR`/`VARCHAR`/`TEXT`; binary/blob; `DATE`; `TIME`;
`DATETIME`/`TIMESTAMP`; `JSON`; and semantically identifiable boolean types.

**PostgreSQL:** NULL; `bool`; `int2`/`int4`/`int8`; `float4`/`float8`; `NUMERIC`
with preserved precision; `text`/`varchar`; `bytea`; `date`; `time`;
`timestamp`/`timestamptz`; `UUID`; `JSON`/`JSONB`; and common arrays when they can be
decoded safely.

Extension and custom types fail safely with a cast suggestion.

**Do not build a universal database type system.** The core needs only a safe,
JSON-compatible result representation. Metadata preserves the original type name.

### 8.3 SQLx feature consequences

Precision-preserving `NUMERIC`/`DECIMAL` requires the `bigdecimal` feature. Without it,
SQLx has no `Decode` implementation and every such column follows the unsupported-type
path. Use `bigdecimal`, **not** `rust_decimal`: the latter is 96-bit and would lose
precision for large `NUMERIC` values, violating rule 1. The `uuid`, `time`, and `json`
features are also mandatory. See `docs/operations.md` section 2.2.

## 9. Schema model

```rust
pub struct SchemaDescription { pub schemas: Vec<Schema> }
pub struct Schema { pub name: String, pub tables: Vec<Table> }

pub struct Table {
    pub schema: String,
    pub name: String,
    pub kind: TableKind,
    pub columns: Vec<ColumnDescription>,
    pub primary_key: Vec<String>,
    pub foreign_keys: Vec<ForeignKey>,
    pub indexes: Vec<IndexDescription>,
}
```

Never include connection data. Redaction from `docs/security.md` section 8 also
applies here because column defaults and comments may contain secrets.

Schema discovery is a product capability, not an implementation detail. The agent
must learn tables, columns, primary and foreign keys, indexes, relation and view
names, and column types.

**Metadata comes from adapter-owned static SQL**: `information_schema` on MySQL, and
`pg_catalog` plus `information_schema` on PostgreSQL. Use `SHOW` only when necessary
and map its output intentionally. Arbitrary agent `SHOW` never passes through `query`.

### 9.1 Schema search

`search_schema` accepts text terms. Initial deterministic ranking: exact table match,
table prefix, table substring, column match, schema match, and configured human
description. Embeddings are unnecessary in v0.x.

### 9.2 Cache

```text
RwLock<HashMap<CacheKey, CacheEntry>>   suggested TTL: 5 minutes
```

The key includes connection identity. Do not add Redis or a cache framework in the
first release.
