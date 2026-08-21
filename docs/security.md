# Security

Read this document before changing the parser, policy, executor, or error model.

## 1. Assets

Production data; database credentials; database availability and integrity; sensitive
table and column contents; infrastructure hostnames and topology; audit integrity;
principal identity; and Warden configuration.

## 2. Adversarial input

**Assume all input SQL is malicious.** Sources include prompt injection, repository
content read by an agent, a compromised MCP client, SQL generated incorrectly by the
model, a malicious human with MCP access, and schema names or stored values designed
to influence the agent.

**The model is not a trusted security component.**

## 3. Threat-to-control matrix

Every row needs an identified control and a corresponding test. A row without a
control is accepted risk and must say so explicitly.

| Threat | Controls | Test |
|---|---|---|
| Root DML | root-statement policy; read-only transaction; `default_transaction_read_only`; no-write `GRANT` | corpus + integration + privilege test |
| DDL | same | same |
| Write in a CTE (`DELETE ... RETURNING`) | recursive nested-statement analysis; read-only transaction; `GRANT` | PostgreSQL corpus |
| `SELECT INTO` creating a table | `SELECT INTO` detection; no `CREATE` privilege | PostgreSQL corpus |
| `INTO OUTFILE` / `DUMPFILE` | MySQL analyzer detection; no `FILE` privilege | MySQL corpus + privilege test |
| Function with side effects | function classification and default deny; restricted `GRANT EXECUTE` | corpus + integration |
| Sequence mutation | `nextval`/`setval` detection; read-only transaction, which PostgreSQL rejects | corpus + PostgreSQL integration |
| Session or user-variable mutation | session-mutation policy; pool hooks restore state | corpus + connection-reuse test |
| Advisory lock | function classification | corpus |
| Multiple statements | analyzer requires exactly one; prepared-statement path | corpus + integration |
| Giant join or Cartesian product | server and client timeouts; row and byte limits; replica | integration + load |
| `SLEEP` / `pg_sleep` / `BENCHMARK` | function classification; server timeout | corpus + integration |
| Expensive regex | server timeout; concurrency limit | load |
| Recursive query | server timeout; row limit | integration |
| Excessive concurrency | per-connection semaphore; `max_queue_wait`; pool limit | concurrency test |
| Massive result | `max_rows`, `max_value_bytes`, `max_result_bytes`; incremental streaming | integration |
| Deeply nested SQL causing stack overflow | sqlparser `recursive-protection`; explicit `with_recursion_limit`; input-size limit | fuzz |
| Read from a forbidden table | role's **`GRANT SELECT`** is the real boundary; allowlist reduces attack surface | privilege test |
| Read through a view that bypasses the allowlist | role `GRANT`; allowlist explicitly is not a boundary | privilege test + documentation |
| Ambiguous name resolution (`search_path`, default database) | set `search_path` and database at connect time | integration |
| File-reading function | function classification; no `FILE` privilege | corpus + privilege test |
| Broad schema enumeration | bounded response; object policy on schema tools | E2E |
| DSN in a tool response | non-serializable secret types; MCP models have no DSN field | unit + E2E |
| Credential in log, trace, or error | sanitized error mapping; trace-field allowlist; panic hook without payload | unit + E2E |
| Malformed MCP payload | rmcp SDK; input-size limit; sanitized error | E2E |
| Unauthorized transport access | OAuth/OIDC under the MCP specification; trusted `RequestContext` | HTTP E2E |
| **Injection through returned data** | section 9; partial mitigation and partially accepted risk | — |

## 4. Real write boundary

SQL policy and parsing **reduce attack surface**. Database privileges are the write
boundary. Every production connection uses a dedicated Warden account. Never reuse
the application owner, migration user, DBA, MySQL `root`, or PostgreSQL superuser.

### 4.1 MySQL

Grant only `SELECT` on required tables and schemas. Do not grant:

```text
INSERT UPDATE DELETE CREATE DROP ALTER FILE EXECUTE LOCK TABLES
administrative privileges
```

If the agent must never see a table, **do not grant `SELECT` on it**. Do not trust a
deny policy for that boundary.

### 4.2 PostgreSQL

```text
CONNECT on the database
USAGE on approved schemas
SELECT on approved tables and views
```

Avoid schema `CREATE`, table writes, sequence mutation, `EXECUTE` on unsafe functions,
administrative roles, and superuser. Row Level Security can provide an additional
layer.

## 5. Real read-scope boundary

**The table allowlist does not bound what the agent can read.** It operates on AST
names, but names do not determine what a relation reads.

Four structural bypasses exist:

1. **Views.** `SELECT * FROM public_report` passes the allowlist while the view reads
   `users.password_hash`; the parser sees only the view name.
2. **`search_path` on PostgreSQL.** The session resolves unqualified names.
3. **Default database on MySQL.** The same problem.
4. **Identifier folding.** PostgreSQL folds unquoted identifiers to lowercase, so a
   deny-list entry named `Users` would never match. MySQL case sensitivity depends on
   `lower_case_table_names` and the file system.

**Design consequence:** the dedicated role's `GRANT SELECT` bounds read scope. The
allowlist remains useful for reducing attack surface and improving error messages,
but public material does not present it as a security boundary.

### 5.1 Mandatory supporting controls

- **Fix name resolution at connect time**, not query time, through
  `PgConnectOptions::options("-c search_path=app,public")` and an explicit database in
  the MySQL DSN. This removes bypasses 2 and 3 without touching agent SQL.
- **Define dialect-specific folding** for policy comparison:
  - PostgreSQL: unquoted identifiers become lowercase; quoted identifiers remain
    literal.
  - MySQL: compare case-insensitively by default and document the dependency on
    `lower_case_table_names`.
  Without this rule, policy has silent false negatives.
- **CTE names and subquery aliases are not `ObjectRef`.** The analyzer must distinguish
  `WITH x AS (SELECT * FROM secrets) SELECT * FROM x`; `secrets` is the relation, and
  `x` is not an object.

### 5.2 Object policy applies to every tool

`SchemaAllowListPolicy` and `TableAllowDenyPolicy` operate on `ObjectRef`, not
`QueryAnalysis`, through a separate contract:

```rust
pub trait ObjectAccessPolicy: Send + Sync {
    fn name(&self) -> &'static str;
    fn check(&self, object: &ObjectRef, ctx: &PolicyContext) -> PolicyDecision;
}
```

Apply it to **every** object-touching tool: `query`, `explain`, `search_schema`, and
`describe_schema`. `SchemaInspector` receives the allowed set and filters at the
source; it never returns the entire catalog for the service to filter later.

Otherwise, a denied table remains describable and the agent can learn the entire data
model.

## 6. Policy engine

```rust
pub trait Policy: Send + Sync {
    fn name(&self) -> &'static str;
    fn evaluate(&self, input: &PolicyInput) -> PolicyDecision;
}

pub enum PolicyDecision {
    Allow,
    Deny(DenyReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DenyCode {
    MultipleStatements,
    ParserRecursionLimit,
    WriteStatement,
    NestedWrite,
    Ddl,
    StatementNotAllowed,
    SessionMutation,
    ObjectNotAllowed,
    DangerousFunction,
    UnknownFunction,
    LockingRead,
    UnknownConstruct,
}

pub struct DenyReason {
    code: DenyCode,
    /// Which policy produced it. Stamped by the engine, not by the policy.
    policy: Option<&'static str>,
    /// Internal detail for auditing and tracing. Never crosses the MCP boundary.
    internal_detail: Option<String>,
}
```

Evaluation is synchronous and deterministic, without network, database, or LLM calls.

**Evaluate every policy; do not stop at the first denial.** If a query violates three
rules but the log records one, fixing the first reveals the next. The agent gains an
iterative oracle and the auditor loses the full picture. Aggregate every `DenyReason`
in the audit event.

**The agent receives one `DenyCode` and curated fixed-table text.** The text never
includes query identifiers or policy configuration.

**Declaration order is precedence order.** A query that breaks four rules produces
four `DenyReason` values, and the agent receives exactly one code, so the winner must
be deterministic. `DenyCode` derives `Ord`; the engine sorts the aggregated reasons by
it and reports the first. The order runs from the most categorical violation to the
least specific, with `UnknownConstruct` last as the residual code. Reordering the enum
changes what agents are told and requires the same review as adding a variant.

`StatementNotAllowed` covers a statement the analyzer recognized and this tool does
not accept, such as `SHOW`, `EXPLAIN`, `CALL`, or `BEGIN` (ADR-0020). It exists so
that denying a `SHOW` does not have to be recorded as a write.

```text
LockingRead     -> "locking reads are not allowed"
UnknownFunction -> "the query uses a function not classified as safe"
```

`DenyCode` is an enum rather than `&'static str`: exhaustive, match-testable, immune
to typos and duplicate codes.

### 6.1 Initial policies

1. `AnalysisIntegrityPolicy` — the analysis must describe this connection's dialect
2. `SingleStatementPolicy`
3. `ReadOnlyRootStatementPolicy`
4. `NestedWritePolicy`
5. `SessionMutationPolicy`
6. `LockingReadPolicy`
7. `FunctionSafetyPolicy`
8. `RiskEvidencePolicy` — every `RiskFlag` is a denial by default, plus a side effect
   the analyzer reported without naming. This replaces v0.3's `UnknownConstructPolicy`,
   which covered one of the sixteen flags; matching all of them in one exhaustive
   `match` is what makes adding a flag break the build.
9. `ObjectAccessPolicy`, a separate contract described in section 5.2

Resource limits are **not parser policies**. They belong to execution configuration.

### 6.2 `query` statement policy

The default permitted root statement is **`SELECT`**, including a CTE-based `SELECT`
only when every nested statement is read-only.

Do not allow `SHOW`, `EXPLAIN`, `SET`, `BEGIN`, `COMMIT`, or `ROLLBACK` through
`query`. Metadata and EXPLAIN use dedicated, controlled tools. This is deliberately
narrower than "anything resembling a read."

### 6.3 Nested-statement analysis

Classifying only the root is insufficient:

```sql
WITH changed AS (DELETE FROM orders RETURNING *)
SELECT * FROM changed;
```

The analyzer inspects recursively. Any nested statement that modifies data causes
rejection.

## 7. Dialect analysis

### 7.1 Common rules

- Use `sqlparser-rs` with the corresponding dialect and confine ASTs to adapter crates
  (ADR-0007).
- Keep the default `recursive-protection` feature. It prevents stack overflow for
  deeply nested SQL and makes the fuzzing invariant "arbitrary bytes do not terminate
  the process" achievable. The feature uses `stacker`, which contains `unsafe`; this
  does not violate Warden's first-party `unsafe` policy and is recorded in `deny.toml`.
- Set `Parser::with_recursion_limit` explicitly as an auditable bound.
- **Map wildcard arms to `Unknown` (denied), never to "ignore."**
- Evaluate sqlparser's `visitor` feature for traversal. Handwritten recursive traversal
  is where bypasses hide because forgetting one `Expr` variant is enough; a derived
  visitor is exhaustive by construction.
- **Upgrading `sqlparser` requires running the entire corpus and reviewing new AST
  variants.** This is a mandatory process step.

### 7.2 MySQL

At minimum, detect multiple statements; non-`SELECT` roots; writes in nested
constructs; `SELECT ... INTO OUTFILE`; `SELECT ... INTO DUMPFILE`; locking reads;
stored-routine calls; file-reading functions; advisory locks; delay and benchmark
functions; user- or session-variable mutation; unknown function categories; and
constructs that cannot be classified safely.

Initially dangerous concepts:

```text
SLEEP  BENCHMARK  GET_LOCK  RELEASE_LOCK  LOAD_FILE
INTO OUTFILE  INTO DUMPFILE
locking SELECT forms
session/user variable assignment
```

The list is not assumed complete. The database account remains the boundary.

### 7.3 PostgreSQL

At minimum, detect multiple statements; DML and DDL; data-modifying CTEs; `CALL`;
`COPY`; table-creating `SELECT INTO`; row-locking clauses; `EXPLAIN ANALYZE`; advisory
locks; delay functions; sequence mutation; session mutation; unknown or user-defined
functions; and unknown utility statements.

Initially dangerous concepts:

```text
pg_sleep  pg_advisory_lock  pg_advisory_xact_lock
nextval  setval  pg_notify
unverified user-defined functions
```

Function classification is conservative by definition.

### 7.4 Parser limitations

`sqlparser-rs` is a multi-dialect parser, not the server parser:

```text
valid in the database but rejected by the parser -> query_parse_error, no execution
```

This is acceptable for a security gateway. **Never fall back to unparsed execution.**

## 8. Result redaction

Redaction occurs after normalization and before MCP serialization.

```toml
[redaction]
columns = ["*.password", "*.password_hash", "*.access_token", "*.refresh_token", "*.secret"]
```

```rust
pub enum RedactionStrategy { Replace, Null }
```

**Redaction is not authorization.** It matches **output** column names, so
`SELECT password AS p` produces `p` and bypasses the rule. Aliases and expressions
defeat it by construction.

Redaction protects against accidental exposure and minimizes output. If an agent must
never access a secret column, use database privileges or a view that omits it. Public
material does **not** present redaction as an exfiltration control.

Redaction also applies to `describe_schema` output because column defaults and comments
can contain secrets.

## 9. Injection through returned data

This is a real threat listed in section 2 with only partial mitigation: database
contents and schema names enter model context and can attempt to influence the agent.

**Adopted mitigations:**

- Use MCP `structured_content` instead of free text. Separating data from instructions
  at the protocol level is the most important available structural improvement.
- Row and byte limits reduce untrusted content volume per call.
- Auditing records every read, making abuse detectable after the fact.

**Accepted residual risk:** Warden does not inspect or sanitize database contents. A
hostile stored value can influence the agent. This appears in the SPEC section 7
guarantee boundaries and must appear in the README. Heuristic content sanitization
would be security theater and create false confidence.

## 10. Public error model

Internal errors are typed and sanitized at the MCP boundary. Raw SQLx errors can
contain hostnames, users, database names, SQL, and server details; never return them to
the model.

Canonical public codes:

```text
connection_not_found        query_timeout
connection_unavailable      query_cancelled
query_too_large             query_result_too_large
query_parse_error           query_normalization_error
query_rejected              query_execution_error
server_busy                 schema_lookup_error
explain_error               internal_error
```

## 11. Auditing

### 11.1 Two phases

```text
attempt -> written BEFORE execution. Sink failure => deny the query.
outcome -> written AFTER execution.  Sink failure => alarm without rollback.
```

This guarantees a trace for every attempt even if the process dies during execution,
and prevents an unavailable sink from creating an unaudited operation window. A
single-event model loses the attempt in exactly the most important case.

### 11.2 Events

```rust
pub struct AuditAttempt {
    pub id: AuditEventId,
    pub timestamp: OffsetDateTime,
    pub request_id: RequestId,
    pub principal: PrincipalId,
    pub client: ClientName,
    pub connection: ConnectionName,
    pub dialect: Dialect,
    pub environment: Environment,
    pub fingerprint: Option<QueryFingerprint>,
    pub statement_kind: StatementKind,
    pub deny_reasons: Vec<DenyReason>,   // Every denial, not only the first.
}

pub struct AuditOutcomeEvent {
    pub attempt_id: AuditEventId,
    pub outcome: AuditOutcome,
    pub duration: Option<Duration>,
    pub rows_returned: Option<usize>,
    pub result_bytes: Option<usize>,
    pub error_code: Option<&'static str>,
}

pub enum AuditOutcome { Denied, Succeeded, Failed, TimedOut, Cancelled }
```

Identifiers are newtypes, not `String`; swapping two `String` fields in an audit event
would otherwise compile.

### 11.3 SQL in audits

```text
raw SQL:     OFF by default
parameters:  OFF by default
fingerprint: ON when available
```

SQL can contain emails, tokens, names, search strings, private messages, and literal
secrets. A security product must not accidentally create a second sensitive-data
store.

Normalized SQL may be added after literal redaction is thoroughly fuzz-tested.

### 11.4 Fingerprints

Each adapter computes fingerprints from a normalized AST with literals replaced.
Algorithms need not match across dialects. Use a stable, versioned format such as
`v1:<sha256-hex>` so audits remain comparable over time.

## 12. Preventing internal bypasses

No public API can permit `MCP -> executor.execute(raw_sql)`. The executable wires
concrete adapter objects during composition, but query executors consume authorized
state. Internal SQL APIs remain private to adapters.

### 12.1 Trusted internal SQL

Warden needs its own queries for schema introspection, health checks, EXPLAIN setup,
and transaction configuration. These are not agent queries: they are adapter-owned
static SQL, do not pass through the policy pipeline, and are not exposed to MCP
handlers through a generic internal-SQL executor.

## 13. `unsafe` policy

Every Warden crate declares `#![forbid(unsafe_code)]` and inherits
`unsafe_code = "forbid"` from the workspace. Dependencies may contain `unsafe`; Warden
does not introduce it without an explicit decision.

Any future need requires an ADR, an isolated crate or module, documented safety
invariants, and dedicated tests.

## 14. Panic policy

Request-path code must not rely on panics. Except for provable structural
unreachability, prohibit `unwrap()`, `expect()`, `unreachable!()`, and `todo!()`.

Two complementary controls are mandatory:

- **Containment:** run each request in its own task so a panic becomes
  `JoinError -> internal_error` instead of terminating the process. This is critical
  for the single-process stdio transport.
- **Panic hook:** panic messages can contain data, such as an `expect` formatting a row
  value, and stderr is the log destination. Record location and type, **not payload**.

Do not globally catch every panic and continue as if nothing happened. Add parser
panic containment only if fuzzing demonstrates a dependency panic that can be safely
isolated.

## 15. Pre-release security review checklist

- [ ] Review the threat model and complete the section 3 matrix
- [ ] Document database privileges; example roles use least privilege
- [ ] No DSNs in logs; no raw SQL or parameters by default
- [ ] Parser corpus includes adversarial SQL; fuzz both analyzers
- [ ] Nested-write bypass tests exist
- [ ] Function side-effect tests exist
- [ ] MySQL file operations are tested
- [ ] MySQL session mutation is tested
- [ ] PostgreSQL sequence mutation is tested
- [ ] PostgreSQL locking tests exist
- [ ] `EXPLAIN` cannot select `ANALYZE`
- [ ] Real-database timeouts cover client and server
- [ ] Semaphore and `max_queue_wait` are tested
- [ ] Per-value and total-byte limits are tested
- [ ] Pool reuse after cancellation is tested
- [ ] Database-role write rejection is tested
- [ ] MCP error sanitization is tested
- [ ] Fail-closed audit attempts are tested
- [ ] HTTP authorization is tested before publishing remote-production guidance
- [ ] `cargo deny check` is clean
- [ ] No first-party `unsafe`
- [ ] No reachable `unwrap`/`expect` without explicit proof
- [ ] Container runs as a non-root user
- [ ] Production guide recommends a read replica
