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

MCP input is JSON. With serde_json's arbitrary-precision feature, conversion to
`ParameterValue` classifies the exact number token before choosing a bind type:
negative integers through `i64` and non-negative integers through `u64` remain exact;
integer syntax outside those ranges is rejected rather than rounded through `f64`.
Decimal and exponent syntax follows the existing finite-`f64` parameter contract,
including rejection of non-finite or out-of-range forms such as `1e400` and integral
magnitudes at or above 2^53. Never silently wrap or truncate an integer; a silently
wrong answer is worse than an error in an investigation tool.

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
    statement_count: NonZeroUsize,
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

**`max_result_bytes` bounds `rows` only, not the total response.** `ResultBuilder`
(section 8.1) accounts only for the stored rows' JSON encoding; `columns` metadata is
not part of what it counts (`ResultBuilder::finish`'s own doc comment says so). What
actually reaches model context is `rows + columns` together, so the real upper bound
on one response is `max_result_bytes` plus whatever `columns` costs, uncapped. Worst
case on MySQL: a `SELECT *` against a table wide enough to fit the 64 KiB SQL
statement-size cap can carry roughly 4096 columns, and each contributes its name (up
to 64 bytes), its `database_type` string, and JSON object overhead — on the order of
0.5 MiB, against a 256 KiB row budget. This is deliberate, not a bug: bounding
`columns` too would require truncating schema information rows have already made
visible. Milestone 12 must design the MCP tool contract against this real combined
bound, not against `max_result_bytes` alone.

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
   **Exception:** `ResultValue::Json` serializes the driver's own `serde_json::Value`
   document as-is. Warden enables serde_json's `arbitrary_precision` feature so its
   decoder and serializer preserve the server's exact digits, including integers
   above `u64` and high-precision decimals; real PostgreSQL `JSON` and `JSONB`
   regressions pin both cases. The value still reaches the MCP client as a raw JSON
   number, so a JavaScript client can round it. Rule 6 is enforced for `I64`/`U64`,
   the columnar integer types; it is not applied recursively inside a document value
   (`docs/open-questions.md` section 2).
7. **Bound `Array` depth**, initially at 8. This recursive type could otherwise allow a
   deeply nested PostgreSQL array to overflow the stack during normalization or
   serialization, violating the fuzzing invariant.

Rules 4 and 5 cover a value whose **type** has no representation.
`NormalizationError::UnrepresentableValue` covers the other case, which PostgreSQL
produces and MySQL does not: a supported type holding a value the model cannot carry.
`'infinity'::timestamptz`, any `date` or `timestamp` beyond the year 9999, and
`'NaN'::numeric` are the reachable cases. The error names the column and the type and
suggests the same `::text` cast, but it says the *value* has no JSON representation,
because every other row of that column normalizes fine and telling an agent the
column's type is unsupported would make it stop querying the column entirely.

`QueryStats.bytes` is the exact length of the stored rows' JSON encoding, escaping
included—not the driver's wire size, not an in-memory decoded size.
`ResultValue::json_bytes` computes this figure directly, without producing the JSON
text, so it always matches what `serde_json::to_string` would have written. This is
the same quantity `max_result_bytes` and `max_value_bytes` bound, because what the
budget protects is model context, and model context is spent on the JSON an agent
actually receives, not on how the database or the driver represented the value
internally.

Example error:

```text
Column "custom_state" uses unsupported PostgreSQL type "order_state".
Cast it explicitly, for example: custom_state::text
```

### 8.2 Types by adapter

**MySQL:** NULL; signed and unsigned integers, including `YEAR` (signed) and `BIT`
(unsigned); floating point; `DECIMAL` preserved as a string; `CHAR`/`VARCHAR`/`TEXT`;
binary/blob; `DATE`; `TIME`; `DATETIME`/`TIMESTAMP`; `JSON`; and semantically
identifiable boolean types. `GEOMETRY` is not representable and fails safely with a
cast suggestion, the same as an unrecognized PostgreSQL type. `ResultColumn::nullable`
is always `None` on MySQL—the driver's column metadata does not report it—and a
zero-row MySQL result carries no columns at all, because the driver exposes column
definitions only through a row (section 8.1's normalization rules still apply; nothing
about a column is invented to fill the gap).

**PostgreSQL:** NULL; `bool`; `int2`/`int4`/`int8`, all widened to a signed 64-bit
integer; `float4` and `float8`, decoded at their own widths; `NUMERIC` with preserved
precision, rendered from `BigDecimal::to_plain_string` so a large or small value keeps
positional digits rather than becoming exponential notation; `text`/`varchar`/`char`/
`name`; `bytea`; `date`; `time`; `timestamp`; `timestamptz`, emitted with an explicit
`+00:00` because PostgreSQL stores it in UTC and the offset is therefore known rather
than invented; `UUID`; `JSON` and `JSONB`; and one-dimensional arrays of any of those
**except** `date`, `timestamp` and `timestamptz`.

Those three array types fail safely with a cast suggestion rather than being decoded.
`sqlx` decodes array elements internally, so the range check that keeps a `timestamp`
beyond year 9999 or an `'infinity'` from reaching `time`'s panicking arithmetic cannot
be applied per element, and `col::text` renders such an array correctly.
Multi-dimensional arrays fail the same way: `sqlx` decodes one dimension only, and
Warden reports the failure rather than flattening it. Extension types, user-defined
enums and composites, `interval`, `timetz`, `money`, ranges and geometry all reach the
same safe error with the `::text` cast the message names.

The PostgreSQL 17 round-trip fixture rendered its tested `numeric[]` elements as
`1.5000` and `2.2500`; Warden preserves that measured scale rather than shortening
them to `1.50` and `2.25`.

`ResultColumn::nullable` is always `None` on PostgreSQL for the same reason it is on
MySQL — row-level column metadata does not report it — and a zero-row PostgreSQL result
carries no columns either, because column metadata is read from the first row. Nothing
about a column is invented to fill either gap.

**Do not build a universal database type system.** The core needs only a safe,
JSON-compatible result representation. Metadata preserves the original type name.

### 8.3 SQLx feature consequences

Precision-preserving `NUMERIC`/`DECIMAL` requires the `bigdecimal` feature. Without it,
SQLx has no `Decode` implementation and every such column follows the unsupported-type
path. Use `bigdecimal`, **not** `rust_decimal`: the latter is 96-bit and would lose
precision for large `NUMERIC` values, violating rule 1. The `uuid`, `time`, and `json`
features are also mandatory. serde_json's `arbitrary_precision` feature is mandatory
too: without it, decoding a JSON document can silently pass an integer above `u64` or
a high-precision decimal through `f64` before Warden serializes the result. See
`docs/operations.md` section 2.2.

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
    pub truncated: bool,
}
```

`Table.truncated` says that some of the relation's metadata was left out: a bound cut
a list or catalog text value; the engine reported a key part with no column name (a
MySQL functional index or PostgreSQL expression index); or a foreign-key target was
not visible under the request's object rules or PostgreSQL privileges. A refused FK
target is omitted silently rather than turned into a rejection that confirms its
existence. Response bounds are `MAX_DESCRIBED_COLUMNS` 512,
`MAX_DESCRIBED_INDEXES` 128 and `MAX_DESCRIBED_FOREIGN_KEYS` 128 per relation, on top
of the 20-table cap per call.

Column defaults and comments are bounded, not redacted in Milestone 9. Each retains
at most `MAX_SCHEMA_VALUE_BYTES` (64 KiB) at a valid UTF-8 boundary, and their
accumulated retained payload is at most `MAX_SCHEMA_DESCRIPTION_BYTES` (256 KiB)
per cached table and again per complete `describe_schema` response. Exhausting
either budget sets the affected `Table.truncated`; identifiers and serialization
overhead are not part of this text-byte count. Both adapters ask static catalog SQL
for one sentinel character beyond the byte limit before decoding, then enforce the
exact byte bound in core. The sentinel distinguishes an ASCII value cut at exactly
64 KiB from a complete value of that length. Never include connection data. The
Milestone 11 redaction matcher
will also apply here because defaults and comments may contain secrets.

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

Ranking is dialect-independent and lives in `warden_core::schema::search`:
`CatalogIndex::search` filters through the request's object rules, sorts by
`MatchReason` — whose declaration order **is** the ranking — then by schema and name,
and truncates at the request's `limit`, itself capped at `MAX_SEARCH_RESULTS` (50).
The index behind it is a bounded projection of the catalog: at most
`MAX_CATALOG_ROWS` (20 000) catalog rows and `MAX_INDEXED_COLUMNS` (64) column names
per relation. Hitting the global row cap marks every search partial. A relation's
column cap marks only that `IndexedRelation`; it contributes `truncated: true` after
the request's object policy permits that relation. A denied wide relation therefore
cannot reveal its existence through the truncation bit, while a permitted relation
reports partiality even when the response limit was not reached or a term matched
only an omitted column.

`MatchReason::Description` has no producer in v0.x: it ranks a configured human
description, and configured descriptions are future schema-intelligence work.

### 9.2 Cache

`warden_core::schema::cache::SchemaCache` is that map: `RwLock<HashMap<CacheKey,
Expiring>>`, a five-minute TTL, a 512-entry ceiling, and keys that name the
connection — `Catalog(connection)` for the search index, `Table { connection,
schema, table }` for a description. It takes the current time as a parameter rather
than reading a clock, so expiry is testable without sleeping and `warden-core` needs
no runtime dependency. A full cache first drops expired entries and then refuses to
grow; serving from the database is slower, and unbounded growth is worse. Expiry is
computed with `Instant::checked_add`; an unrepresentable TTL refuses the insertion
instead of panicking on the request path.

**Cached metadata is unfiltered.** Object rules are per-request (ADR-0036), so
caching a filtered answer would freeze one request's identity into another's. The
adapter applies the filter after every read, hit or miss, including each foreign-key
target. A request-specific FK omission mutates only the response copy; a later
permitted request can still receive the raw cached constraint.
