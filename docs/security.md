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
| Root DML | root-statement policy; read-only transaction; `default_transaction_read_only`; no-write `GRANT` | corpus + integration + privilege test (MySQL tested: `the_transaction_refuses_a_write_even_as_root`, `the_role_refuses_every_write_warden_never_sends`; PostgreSQL tested: `the_transaction_refuses_every_write_even_as_a_superuser`, `the_role_refuses_every_write_warden_never_sends`) |
| DDL | same | same (PostgreSQL tested: `the_transaction_refuses_every_write_even_as_a_superuser`, `the_role_refuses_every_write_warden_never_sends`) |
| Write in a CTE (`DELETE ... RETURNING`) | recursive nested-statement analysis; read-only transaction; `GRANT` | PostgreSQL corpus + integration (PostgreSQL tested: `the_transaction_refuses_every_write_even_as_a_superuser`) |
| `SELECT INTO` creating a table | `SELECT INTO` detection; no `CREATE` privilege | PostgreSQL corpus + integration (PostgreSQL tested: `the_transaction_refuses_every_write_even_as_a_superuser`) |
| `INTO OUTFILE` / `DUMPFILE` | MySQL analyzer detection; no `FILE` privilege | MySQL corpus + privilege test (MySQL tested: `file_access_is_refused_by_privileges_as_well_as_by_policy`) |
| Function with side effects | function classification and default deny; restricted `GRANT EXECUTE` | corpus + integration |
| Sequence mutation | `nextval`/`setval` detection; read-only transaction, which PostgreSQL rejects | corpus + PostgreSQL integration (PostgreSQL tested: `the_transaction_refuses_every_write_even_as_a_superuser`, `the_role_refuses_every_write_warden_never_sends`) |
| Session or user-variable mutation | session-mutation policy; pool hooks restore state | corpus + connection-reuse test (PostgreSQL tested: `no_session_state_leaks_between_requests`) |
| Advisory lock | function classification | corpus |
| Multiple statements | analyzer requires exactly one; prepared-statement path | corpus + integration |
| Giant join or Cartesian product | server and client timeouts; row and byte limits; replica | integration + load |
| `SLEEP` / `pg_sleep` / `BENCHMARK` | function classification and default deny; server timeout | corpus + integration (PostgreSQL classification/denial tested: `the_analyzer_and_policy_engine_deny_every_statement_before_it_is_ever_sent`; synthetic-authorized `cancellation_reaches_the_server` tests cancellation below policy, not classification or the server deadline) |
| Expensive regex | server timeout; concurrency limit | load |
| Recursive query | server timeout; row limit | integration |
| Excessive concurrency | per-connection semaphore; `max_queue_wait`; pool limit | concurrency test (PostgreSQL tested: `concurrency_is_bounded_on_a_real_executor`) |
| Massive result | `max_rows`, `max_value_bytes`, `max_result_bytes`; incremental streaming | integration (MySQL tested: `a_row_truncated_result_is_ok_and_kills_the_orphaned_query`, `a_byte_truncated_result_is_ok_and_kills_the_orphaned_query`, `a_complete_result_fires_no_kill`; PostgreSQL tested: `an_unrepresentable_row_sentinel_cannot_replace_valid_rows_with_an_error`, `a_truncated_result_is_ok_and_cancels_the_orphaned_query`, `a_byte_truncated_result_cancels_the_orphaned_query_too`, `a_mid_stream_value_too_large_cancels_the_orphaned_query`, `a_complete_result_leaves_the_connection_immediately_reusable`) |
| Deeply nested SQL causing stack overflow | sqlparser `recursive-protection`; explicit `with_recursion_limit`; input-size limit | fuzz |
| Read from a forbidden table | role's **`GRANT SELECT`** is the real boundary; allowlist reduces attack surface | privilege test (PostgreSQL tested: `the_grant_is_the_read_boundary_and_the_allowlist_is_not`) |
| Read through a view that bypasses the allowlist | role `GRANT`; allowlist explicitly is not a boundary | privilege test + documentation (PostgreSQL tested: `the_grant_is_the_read_boundary_and_the_allowlist_is_not`, whose second half reads the denied table through a granted view) |
| Ambiguous name resolution (`search_path`, default database) | set `search_path` and database at connect time | integration |
| File-reading function | function classification; no `FILE` privilege | corpus + privilege test |
| Broad schema enumeration | bounded response; object policy on schema tools at the source (ADR-0036); per-relation partiality is applied only after policy | integration (both engines: `search_never_returns_more_than_the_requested_limit`, `a_denied_table_is_invisible_to_search_and_refused_by_describe`, `wide_relation_truncation_is_filtered_on_cold_and_warm_cache_reads`; PostgreSQL also: `an_unqualified_selector_cannot_reach_a_denied_schema`) |
| Describing a relation or FK target the role cannot read | catalog queries filter on `has_table_privilege`/`has_schema_privilege`; MySQL's `information_schema` hides unprivileged objects itself; FK targets also pass per-request object rules | integration (MySQL tested: `foreign_key_target_policy_is_reapplied_on_cold_and_warm_cache_reads`; PostgreSQL tested: the same plus `a_relation_the_role_cannot_select_is_invisible`, `a_foreign_key_to_a_target_without_select_is_omitted_as_truncated`) |
| Oversized catalog default or comment | 64 KiB per UTF-8 value and 256 KiB accumulated per cached table and description response; static SQL fetches one sentinel character; `Table.truncated` | core/adapter unit tests, PostgreSQL Docker at 64 KiB + 1, and MySQL real `LEFT` boundary plus supported catalog/cache path |
| DSN in a tool response | non-serializable secret types; MCP models have no DSN field | unit + E2E |
| Credential in log, trace, or error | sanitized error mapping; trace-field allowlist; panic hook without payload | unit + E2E |
| Raw SQL in an operator log through the driver | `ConnectOptions::disable_statement_logging` on every connect options value | unit |
| Connection setting smuggled through a DSN parameter or a `PG*` variable | `Dsn` rejects query strings and fragments; adapters build options field by field; PostgreSQL refuses an ambient environment (ADR-0031) | unit + AST guard |
| Password logged by the driver's own URL or `.pgpass` parser | neither is ever called; `PgConnectOptions::new_without_pgpass` only (ADR-0031) | AST guard |
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

PostgreSQL grants `CONNECT` and `TEMPORARY` to `PUBLIC` by default. Revoke both, then
grant only the configured role its explicit `CONNECT`; do not leave temporary-table
creation as a write escape outside schema grants. Milestone 8 measured `42501`
`insufficient_privilege` for a temporary-table create after that revoke. The fixture
also proves `42501` for `nextval`, `setval`, and its explicitly revoked
`pg_sleep(double precision)` privilege. That is deliberately **not** a claim that all
unsafe PostgreSQL functions have been revoked: deployments must audit and revoke their
own unsafe-function set while preserving safe reporting functions. RLS restricts rows
within a granted table; grants remain the boundary for whether the role can read that
table or a granted view at all.

## 5. Real read-scope boundary

**The table allowlist does not bound what the agent can read.** It operates on AST
names, but names do not determine what a relation reads.

Seven structural bypasses exist:

1. **Views.** `SELECT * FROM public_report` passes the allowlist while the view reads
   `users.password_hash`; the parser sees only the view name.
2. **`search_path` on PostgreSQL.** The session resolves unqualified names.
3. **Default database on MySQL.** The same problem.
4. **Identifier folding.** PostgreSQL folds unquoted identifiers to lowercase, so a
   deny-list entry named `Users` would never match. MySQL case sensitivity depends on
   `lower_case_table_names` and the file system.
5. **CTE-name shadowing (both analyzers).** `visit::collect` subtracts every
   unqualified relation whose name matches a declared CTE alias anywhere in the
   statement, not only within that alias's own scope. `WITH orders AS (SELECT * FROM
   orders) SELECT * FROM orders` self-references the real base table — MySQL resolves
   a non-`RECURSIVE` CTE's own body to a table of that name — but the analyzer drops
   it along with the alias, so `TableAllowDenyPolicy` never evaluates it.

   The PostgreSQL analyzer folds each side by its own quoting rather than comparing
   case-insensitively, which is accurate for that dialect, but it is equally
   scope-blind: `WITH orders AS (SELECT * FROM orders) SELECT * FROM orders` loses
   the real base table there too.

6. **`INSERT`, `COPY`, and DDL target relations (both analyzers).** `INSERT INTO t`,
   `COPY t FROM/TO`, and every DDL target (`CREATE TABLE`, `ALTER TABLE`, `DROP`,
   ...) do not appear in `QueryAnalysis`'s object list. sqlparser routes each of
   these through `Visitor::pre_visit_relation` — and `COPY`'s table through no
   visitor hook at all — rather than through `TableFactor`, which is the hook both
   analyzers implement. This is not an authorization gap under a read-only
   profile: each such statement independently carries `RiskFlag::WriteStatement`
   or `RiskFlag::Ddl`, and policy denies it on that evidence alone. It becomes
   load-bearing the moment a write-permitting profile exists, at which point
   `TableAllowDenyPolicy` would not see the relation being written.
7. **User-defined casts on PostgreSQL.** `'x'::evil_type` and
   `CAST('x' AS evil_type)` reach `Expr::Cast`, never `Expr::Function`, so the
   function classification in section 7.3 never sees them. `CREATE CAST ... WITH
   FUNCTION` and a type's input function both run arbitrary code. This does not
   need a wildcard-to-`Unknown` `Expr` arm to close: creating the cast, or the type
   it casts to, is DDL, and DDL is denied outright.

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

  **Shipped in Milestone 4 (ADR-0027).** `warden_core::analysis::SqlIdentifier`
  carries each name part together with the quoting the statement used, and
  `warden_policy::folding::rule_matches` applies the rule above: PostgreSQL folds an
  unquoted identifier and compares a quoted one exactly, MySQL compares
  case-insensitively regardless of backticks. An analyzer that cannot report quoting
  cannot build an `ObjectRef`.

  **Shipped in Milestone 5.** `warden-postgres` applies the same rule to its own CTE
  subtraction: an unquoted alias folds to lowercase, a quoted one does not, so
  `WITH "Report" AS (…) SELECT * FROM report` correctly reports `report` as a base
  table. It also refuses to describe `SELECT * FROM ONLY t`, which sqlparser 0.62
  parses as a relation named `ONLY`; recording that name would make the object rules
  evaluate a relation that does not exist.
- **CTE names and subquery aliases are not `ObjectRef`.** The shipped MySQL analyzer
  does not track scope to distinguish them precisely; it approximates by dropping any
  unqualified relation whose name matches a declared CTE alias anywhere in the
  statement. That correctly removes the alias from `WITH x AS (SELECT * FROM secrets)
  SELECT * FROM x`, but it also removes a real relation that happens to share a CTE's
  name (bypass 5, above). Precise scope resolution needs a name resolver the analyzer
  does not have.

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
`describe_schema`.

**Shipped in Milestone 9 (ADR-0036).** `SchemaInspector::search_schema` and
`describe_schema` take `filter: ObjectFilter<'a>`, a `Copy` view over
`PolicyEngine::check_object` and one request's `PolicyContext`. `search_schema`
drops a refused relation before the response limit is applied, so a denied table
cannot displace an allowed one or be counted; `describe_schema` returns
`SchemaError::Rejected`, and checks twice — once on the name the agent wrote and once
on the name the default database or `search_path` resolved it to, which is what stops
an unqualified selector from reaching a denied schema. Each returned foreign key is
also checked against its referenced relation on every response, including cache
hits. A refused target is omitted silently and sets `Table.truncated`; rejecting the
source would confirm that the hidden target exists. PostgreSQL additionally requires
`USAGE` on the referenced schema and `SELECT` on the referenced table in its static
foreign-key catalog SQL.

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
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

**How each one is detected (Milestone 4).** Locking clauses, `SELECT INTO`,
`EXPLAIN ANALYZE`, `:=` assignment, stored-routine calls, and every function above
come from the AST. `INTO OUTFILE` and `INTO DUMPFILE` do **not**: sqlparser 0.62
rejects both, so they are detected by a token-level guard that reports
`RiskFlag::FileOutput`, keeping the audit record accurate and the denial independent
of a parser limitation (ADR-0028). `LOCK IN SHARE MODE` is likewise unparseable
today and is denied as a parse error; the corpus records that, so an upgrade that
changes it fails a test rather than passing silently.

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

**How each one is detected (Milestone 5).** Data-modifying CTEs, locking clauses,
`SELECT INTO`, `COPY`, `CALL`, and every function above come from the AST.
`EXPLAIN ANALYZE` needs both of sqlparser's spellings: the bare form sets
`Statement::Explain::analyze`, while the idiomatic `EXPLAIN (ANALYZE, BUFFERS)` form
leaves that flag false and records the option list in `Statement::Explain::options`,
so the analyzer reads both (ADR-0017). A user-defined operator invoked as
`OPERATOR(schema.name)` produces no function node at all and is reported as
`unknown_construct`. Unlike MySQL, no construct on this list needs a token-level
guard: every one of them has an AST path (ADR-0028's bar).

`FOR NO KEY UPDATE` and `FOR KEY SHARE` do **not** parse under sqlparser 0.62, so
they are denied as parse errors rather than as locking reads. `FOR UPDATE` and
`FOR SHARE` do parse into `Query::locks`, so `RiskFlag::LockingRead` has a real
producer; the corpus records the two unparseable forms so that an upgrade which
starts parsing one fails a test instead of passing silently.

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

Redaction must also apply to `describe_schema` output because column defaults and
comments can contain secrets.

Milestone 11 ships one `warden_service::Redactor`, parsed once and shared by all three
response paths: `redact_result` for normalized rows, `redact_description` for column
defaults and comments, and `redact_plan` for structured plan documents. A rule is
`*.column` or `table.column`, and matching is ASCII case-insensitive. Result columns
and plan members carry no table provenance, so only `*.column` can match them;
described columns can match either form.

The limits remain intentional. Aliasing a result column or selecting an expression
changes the output name and can bypass a rule. Plan redaction matches JSON member keys
but does not scan free text such as a node's `Filter` string. These are consequences
of column-name matching, not defects that turn redaction into authorization. Schema
text remains bounded independently: 64 KiB per value and 256 KiB accumulated across
one description response, with UTF-8-safe truncation.

## 9. Injection through returned data

This is a real threat listed in section 2 with only partial mitigation: database
contents and schema names enter model context and can attempt to influence the agent.

**Adopted mitigations:**

- Use MCP `structured_content` instead of free text. Separating data from instructions
  at the protocol level is the most important available structural improvement.
- Row and byte limits reduce untrusted content volume per call.
- Auditing records every read, making abuse detectable after the fact.

**Shipped in Milestone 12 (ADR-0040).** Structured content is not merely used, it is the
whole response: a successful tool result carries its data in `structured_content` and one
line in `content` that states counts and flags and never a value the database returned.
rmcp's own `Json<T>` return type would have set `structured_content` *and* pushed the
serialized document into a text block, which is what MCP's backward-compatibility SHOULD
asks for; Warden builds the result by hand instead, because a free-text copy of every row
would forfeit exactly the mitigation this section adopts and double what reaches model
context. `crates/warden-mcp/src/output.rs` has one place that builds a successful result,
so no tool can reintroduce the copy on its own, and
`crates/warden-mcp/tests/protocol.rs` asserts over the wire that the rows arrive in
`structuredContent` and that the fixture's own cell value appears in no text block.

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

**Shipped in Milestone 12.** `crates/warden-mcp/src/error.rs` is the single boundary:
every failed tool call in `warden-mcp` leaves through its `failure` function, and so does
the one path in `output.rs` where a response cannot be serialized. It takes a
`PublicErrorCode` and **never a message** — there is no parameter a driver string could be
threaded through — and pairs each code with a fixed sentence chosen by an exhaustive match
with no wildcard arm, so a new code does not compile until someone has written what an
agent will read.

`crates/warden-mcp/tests/mcp_rules.rs` keeps it that way, and two of its rules exist
because the first versions did not. One is an AST guard: any path ending in
`CallToolResult::error` — rmcp's own constructor, which yields `is_error: true` with
free-form text — fails the build in every file but `error.rs`. The other scans `server.rs`
and `stdio.rs` for `format!`, for `.to_string()` on a binding *named* like an error, and
for `{error}`-style interpolation; it is a name-based heuristic backstop and its own
comment says so, because the structural guarantee is `failure`'s signature rather than
anything a syntactic scan can prove.

One documented gap: an argument that fails `serde` deserialization is refused by rmcp
before Warden sees it, and the agent reads rmcp's own wording ("failed to deserialize
parameters: missing field `sql`") rather than a `PublicErrorCode`. That text is limited to
Warden's own schema field names, which are already public in the tool-schema snapshot — no
user data, no driver message, no DSN — so this section's prohibitions hold. Intercepting
it would mean every tool taking a raw `Value` and hand-rolling deserialization;
`crates/warden-mcp/tests/protocol.rs` pins the current framing with a comment saying it
pins the SDK's behaviour, not a Warden invariant.

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
    pub error_code: Option<PublicErrorCode>,
}

pub enum AuditOutcome {
    Denied, Succeeded, Failed, TimedOut, Cancelled, NotStarted,
}
```

`NotStarted` means an authorized statement had an attempt on record but never reached
the database, such as when permit acquisition ended at `server_busy`.

Identifiers are newtypes, not `String`; swapping two `String` fields in an audit event
would otherwise compile. `error_code` is the `PublicErrorCode` enum rather than a
string, so an outcome cannot record a code outside the closed set of section 10.

Both types live in `warden-ports`, not `warden-core`: `AuditAttempt` carries
`DenyReason`, which belongs to `warden-policy`, downstream of the core. Neither
derives `Serialize` — a record carrying internal denial detail must not be attachable
to a tool response by accident, and Milestone 13's sink decides its own format for the
fields it may write.

### 11.3 SQL in audits

```text
raw SQL:     OFF by default
parameters:  OFF by default
fingerprint: ON when available
```

**The driver is a second source, and its default is on.** SQLx 0.9's
`LogSettings::default()` logs every statement at `DEBUG` and every statement slower
than one second at `WARN`, emitted through `tracing` with the statement in a
`db.statement` field. A deployment that never writes a log line itself would still
publish agent SQL at `WARN`. Both adapters call
`ConnectOptions::disable_statement_logging` on every connect options value they build,
for both pools. Each adapter's tests parse its own `options.rs` and fail if the call
is missing, duplicated, or moved out of the one chain that builds those values, so the
control cannot be deleted by an edit that still compiles.

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

**Containment shipped in Milestone 12; the panic hook did not.** Every `#[tool]` method in
`crates/warden-mcp/src/server.rs` that reaches an adapter runs through
`WardenServer::run_in_task`, which `tokio::spawn`s the call, awaits the handle, and maps a
`JoinError` to `internal_error` while logging no payload. `list_connections` is the one
exception, and deliberately so: it reads an in-memory map and awaits nothing, so a task
would add a hop and a failure mode without containing anything.
`docs/architecture.md` section 8 and ADR-0038 both assign this to Milestone 12 by name,
because a recorded audit attempt receives its terminal outcome only if the request future
is polled to completion. Containment is all it buys: a task that panics still leaves its
attempt without an outcome, which ADR-0038 states and Milestone 13's audit work owns. The
payload-free panic hook is Milestone 13's too, so until it exists a panic message reaches
stderr with whatever the panicking expression formatted into it.

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
- [x] `EXPLAIN` cannot select `ANALYZE`
- [x] Real-database timeouts cover client and server
- [x] Semaphore and `max_queue_wait` are tested
- [x] Per-value and total-byte limits are tested
- [x] Pool reuse after cancellation is tested
- [x] Database-role write rejection is tested
- [x] MCP error sanitization is tested
- [ ] Fail-closed audit attempts are tested
- [ ] HTTP authorization is tested before publishing remote-production guidance
- [ ] `cargo deny check` is clean
- [ ] No first-party `unsafe`
- [ ] No reachable `unwrap`/`expect` without explicit proof
- [ ] Container runs as a non-root user
- [ ] Production guide recommends a read replica
