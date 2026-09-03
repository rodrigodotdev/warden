# MCP interface

**SDK:** official `rmcp` 3.x

**`V_2026_07_28` is not "the newest version."** In the `rmcp` 3.1.x source,
`ProtocolVersion::LATEST` is `V_2025_11_25`; `V_2026_07_28` is
`ProtocolVersion::STANDARD_HEADERS`, the first protocol version that requires SEP-2243
standard HTTP headers. Both are in `KNOWN_VERSIONS` and both negotiate. Targeting
`2026-07-28` means requiring SEP-2243 HTTP headers, which matters only from Milestone
14 (Streamable HTTP); it is not a claim of using the protocol's leading edge.

**The client, not the server, determines the session's effective version.**
`negotiate_protocol_version` echoes a requested version whenever it appears in
`KNOWN_VERSIONS`, while the SDK's default `supported_protocol_versions` contains all
five known versions from `2024-11-05` through `2026-07-28`. Milestone 0.5 confirmed
this with a real handshake: requesting `2026-07-28` returned `2026-07-28`.

**For an unsupported version, the SDK silently substitutes instead of rejecting.**
Milestone 0.5 requested `1999-01-01`; the server returned `2025-11-25` (`LATEST`) and
no error, only a `tracing::warn!` on stderr that the client cannot see. The client
must notice by comparing the `initialize` response's `protocolVersion` with its
request.

**Decided in Milestone 12: Warden advertises only what it implements (ADR-0041).**
`supported_protocol_versions` returns exactly two revisions — `V_2025_11_25` and
`V_2026_07_28` — rather than the five the SDK knows, because advertising a revision
Warden has neither implemented nor tested is a claim it cannot keep. Silent substitution
is closed the only way the SDK allows: `negotiate_protocol_version` has no error hook, so
`ServerHandler::initialize` is overridden instead, and a request naming any other revision
returns `ErrorData::unsupported_protocol_version` carrying the supported list in its
`data`, so the client can retry with a version both sides actually implement. A refusal
returned from a handler's `initialize` is written to the transport before the session
ends, so it reaches the client rather than only stderr.

Do not hand-roll framing or Streamable HTTP semantics supplied by the official SDK.

## 1. Tools

```text
list_connections   search_schema   describe_schema   query   explain
```

The names are deliberately generic. Do **not** add `mysql_query` or
`postgres_query`; the selected connection chooses the backend, while the tool schema
remains identical across adapters.

### 1.1 Annotations are mandatory

Populate `rmcp::model::ToolAnnotations`. All five tools are read-only by construction,
and some clients use these hints to decide whether to request user confirmation.

| Tool | `read_only_hint` | `destructive_hint` | `idempotent_hint` |
|---|---|---|---|
| `list_connections` | `true` | `false` | `true` |
| `search_schema` | `true` | `false` | `true` |
| `describe_schema` | `true` | `false` | `true` |
| `query` | `true` | `false` | `false` |
| `explain` | `true` | `false` | `true` |

These five lines declare read-only behavior in the protocol instead of only in prose.

### 1.2 Output schemas and structured content

Use `Tool::output_schema` and `CallToolResult::structured_content` from `rmcp` 3.x.

- Derive `output_schema` from response types with the `schemars` feature, creating a
  verifiable contract instead of a prose example.
- `structured_content` separates data from text at the protocol level. This materially
  reduces injection through data (`docs/security.md` section 9) because database
  contents are no longer free text indistinguishable from instructions.
- Snapshot-test schemas in CI. Without verification, the evolution rules in section 4
  are ineffective; snapshots make every contract change visible in the diff.

**Shipped in Milestone 12.** All five tools carry an `output_schema` derived from their
response type, and the whole advertised contract — every tool's name, description,
annotations, input schema, and output schema — is snapshotted in
`crates/warden-mcp/tests/snapshots/tools.json`. Renaming a field, relaxing an annotation,
or adding a tool changes that file, so section 4's rules are reviewable in a diff rather
than remembered. One schema is hand-written: a result cell's, because no Rust type
expresses "an integer outside ±2^53 arrives as a decimal string" and a derived schema
would claim `integer` alone (`docs/data-model.md` section 8.1, rule 6). **ADR-0040
governs the response shape**: `structured_content` is the data, and `content` is not a
second copy of it — see the note at the top of section 2.

### 1.3 Descriptions

Descriptions are product and security surface: they shape agent behavior. Poor
descriptions cause more denied queries than any policy.

Each description must communicate:

- **`query`** accepts **only `SELECT`**, including read-only CTEs; placeholders are
  dialect-native (`?` on MySQL, `$1` on PostgreSQL); results can be truncated, and the
  correct response to `truncated: true` is refining the query rather than repeating
  it; `SHOW`, `EXPLAIN`, and `SET` use dedicated tools.
- **`search_schema`** should run **before** `query` to discover table names and accepts
  multiple terms.
- **`describe_schema`** follows `search_schema` and accepts at most 20 tables per call.
- **`explain`** inspects a plan **without executing** the query.
- **`list_connections`** explains that the connection determines the dialect and
  placeholder syntax.

## 2. Contracts

Each document below is what `structured_content` carries. **A successful result puts the
data there and nothing else**: `content` holds one short line that states counts and flags
— rows returned, matches found, whether the result was truncated, and for `explain` the
plan's own row estimate — and never a value the database returned.
rmcp's own `Json<T>` return type would set `structured_content` *and* push the whole
document into a text block; Warden builds the result by hand instead, because
`structured_content` is adopted in `docs/security.md` section 9 precisely so database
contents stop being free text indistinguishable from instructions, and duplicating them
into `content` would forfeit that and double what reaches model context. ADR-0040 records
the decision, including that it is a deliberate deviation from MCP's
backward-compatibility SHOULD.

**A failed result is the one asymmetry.** Its payload is a fixed code and a fixed
sentence from `docs/security.md` section 10 — no database content at all — so it appears
in both `structured_content` and `content`, which costs nothing and still serves a client
that reads only text.

### `list_connections`

Return only safe public metadata.

```json
{
  "connections": [
    { "name": "production-mysql",    "dialect": "mysql",      "environment": "production", "database": "app" },
    { "name": "production-postgres", "dialect": "postgresql", "environment": "production", "database": "analytics" }
  ]
}
```

Never return passwords, DSNs, TLS private keys, secret-reference values, database
users unless intentionally public, or internal hostnames by default.

### `search_schema`

```json
{ "connection": "production-mysql", "query": "customer invoice subscription" }
```

Bound the output; a broad search never returns the entire catalog. Object policy
(`docs/security.md` section 5.2) filters at the source.

### `describe_schema`

```json
{ "connection": "production-postgres", "tables": ["app.orders", "app.customers"] }
```

Initial limit: **20 tables per call**. Object policy applies.

### `query`

```json
{
  "connection": "production-mysql",
  "sql": "SELECT id, status FROM orders WHERE customer_id = ? ORDER BY created_at DESC LIMIT 20",
  "parameters": ["customer_123"]
}
```

```json
{
  "connection": "production-postgres",
  "sql": "SELECT id, status FROM orders WHERE customer_id = $1 ORDER BY created_at DESC LIMIT 20",
  "parameters": ["customer_123"]
}
```

The tool schema is generic; SQL is dialect-native.

### `explain`

```json
{ "connection": "production-postgres", "sql": "SELECT ...", "parameters": [] }
```

```json
{ "dialect": "postgresql", "summary": { "estimated_rows": 1200 }, "plan": {} }
```

**Do not invent a universal cost metric.** MySQL and PostgreSQL cost units are not
comparable.

## 3. EXPLAIN semantics

1. Resolve the connection.
2. Analyze the target query.
3. Apply **all the same security policies**, without a subset.
4. Execute a non-running EXPLAIN variant.

Never run `EXPLAIN ANALYZE`; it executes the underlying query.

- **MySQL:** `EXPLAIN FORMAT=JSON`, never `EXPLAIN ANALYZE`.
- **PostgreSQL:** `EXPLAIN (FORMAT JSON)`, never `ANALYZE TRUE`.

**Shipped in Milestone 10.** Both prefixes are declared verbatim as a constant that
`tests/adapter_rules.rs` pins, both adapters run the plan on `agent_pool` under the
connection's `QueryPermit`, inside the same read-only transaction and under the same
deadline and cancellation token as `query`, and the response is bounded by
`MAX_PLAN_BYTES` before it reaches model context (`docs/data-model.md` section 10).
`summary.estimated_rows` is PostgreSQL's root-node `Plan Rows`; MySQL's summary is
empty because MySQL states no statement-level estimate, and Warden does not invent
one.

### 3.1 Why all policies still apply

`EXPLAIN` plans the query, and PostgreSQL's planner constant-folds functions marked
`IMMUTABLE`. A malicious immutable UDF can run during planning, so function policy
must apply exactly as it does in `query`.

### 3.2 Prefix verification

`explain` is the **only** design point where the string sent to the database differs
from the analyzed string (SPEC section 6, invariant 19).

After adding the prefix, **reparse the resulting string** and verify that it is an
`Statement::Explain` containing a statement equivalent to the analyzed one. This is
cheap and closes the entire class of comment- or quoting-based context breaks.

**Shipped in Milestone 10 as a type, not a step (ADR-0037).** Each adapter's private
`plan.rs` declares `VerifiedExplain`, whose only constructor prefixes the analyzed
SQL and then reparses the result. The check asserts the shape it requires — exactly
one statement, an `EXPLAIN` with every executing and decorating flag false, the
dialect's exact JSON-format spelling, and an inner statement equal to a standalone
parse of the analyzed SQL — rather than enumerating forbidden spellings. Both of
PostgreSQL's `ANALYZE` spellings fail it, and so does a prefix followed by a second
statement, which `sqlparser` really does accept as two statements. The only failure
is `explain_error`, and it names no part of the agent's statement.

## 4. Tool-schema evolution

- Prefer additive optional fields.
- Removing or renaming a field requires version consideration.
- Adding PostgreSQL must **not** create a second set of tool names.
- Database-specific detail belongs in clearly scoped result metadata.
- Snapshot tests enforce every rule above (section 1.2).

## 5. Transports

### 5.1 stdio

The first transport and shortest path to a local vertical slice.

- **stdout contains only MCP protocol data.** `clippy::print_stdout = "deny"`
  enforces this mechanically because one stray `println!` corrupts the stream.
- Tracing and logging go to stderr.
- Do not print a startup banner to stdout.
- Handle signals during shutdown.
- Malformed messages do not expose internal errors.

### 5.2 Streamable HTTP

The second transport and recommended production architecture. Use rmcp's transport
implementation with `2026-07-28` semantics. Do not hand-roll session or version
negotiation.

## 6. Remote deployment model

```text
developer / agent
       │ authenticated MCP HTTP
       ▼
   Warden
       │ private network
       ▼
  read replica
```

The agent receives no database network access.

## 7. Local stdio threat model

A local coding agent with unrestricted shell access can read environment variables
and files available to its process. **MCP over stdio alone does not protect a
production DSN stored in the same environment available to the agent.**

Do not store production secrets in a committed or agent-readable `.env`, repository
configuration, `AGENTS.md`, `CLAUDE.md`, prompt files, or MCP tool output.

Prefer remote Warden for production. `warden check` prints a warning for every connection
whose `environment` is `production`, naming it, and `warden serve` logs the same sentence
on stderr before it opens anything. Neither is a failure: an operator may have chosen this
deployment, so the exit code stays 0.

## 8. HTTP authorization

Remote mode follows the MCP authorization specification and OAuth/OIDC standards. Do
not invent a proprietary bearer-token protocol when standard integration is practical.

An authorized identity becomes a trusted `RequestContext`:

```rust
pub struct RequestContext {
    pub request_id: RequestId,
    pub principal: PrincipalId,
    pub client: ClientIdentity,
}
```

Transport and authentication layers construct it. **The agent cannot provide its own
principal identifier through tool input.**
