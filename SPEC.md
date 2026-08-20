# Warden — Product Specification

**Status:** v0.3
**Date:** 2026-08-19
**Language:** Rust (Edition 2024)
**Primary interface:** Model Context Protocol
**Initial adapters:** MySQL and PostgreSQL

> **Warden lets AI agents investigate production databases through a narrow,
> deterministic, least-privilege, read-only interface without exposing database
> credentials to the model.**

---

## How this specification is organized

This file defines **the product and its invariants**. It is deliberately short:
it is the document everyone rereads. Technical detail lives in dedicated documents,
each written for a specific audience and point in time.

| Document | Contents |
|---|---|
| `AGENTS.md` | Contract for implementation agents. Loaded automatically. |
| `docs/architecture.md` | Layers, crates, ports, dependency direction, composition |
| `docs/security.md` | Threat model, threat-to-control matrix, dialect analysis, database privileges |
| `docs/data-model.md` | Domain types, query analysis, result model, normalization |
| `docs/mcp.md` | MCP tools, schemas, annotations, transports, authorization |
| `docs/operations.md` | Configuration, pools, TLS, observability, CLI, deployment, CI |
| `docs/testing.md` | Test strategy, corpus, fuzzing, privilege tests |
| `docs/milestones.md` | Implementation sequence and definition of done |
| `docs/open-questions.md` | Unresolved questions and future work |
| `docs/adr/` | Architectural decisions, one per file |
| `docs/spec-review-v0.2.md` | Technical review that produced this version |
| `docs/archive/SPEC-v0.2.md` | Preserved previous version |

---

## 1. The problem

The common "AI + database" workflow is manual and unsafe:

```text
agent generates SQL -> human copies it -> database client -> production
                    -> human copies rows -> agent continues
```

This interrupts the agent's reasoning, wastes developer time, encourages
copy-and-paste against production, leaves no useful audit trail, and makes the
human responsible for evaluating every query.

The naive alternative—giving the connection string to an agent through a generic
MCP server—replaces the problem with a worse one.

## 2. What Warden is

A database-agnostic **secure query gateway** with dialect-native SQL analysis and
defense-in-depth execution controls.

```text
agent -> MCP -> Warden -> resolve connection
                     -> parse in the target dialect
                     -> analyze semantics
                     -> evaluate policy
                     -> acquire permit
                     -> read-only transaction with a deadline
                     -> bounded, normalized, redacted result
                     -> audit
             -> safe response
```

The agent can repeat `search schema -> describe tables -> query -> refine hypothesis
-> query again -> diagnose` without ever receiving the production password.

## 3. What Warden is not

It **is not** an MCP wrapper around a connection string. This distinction governs
the entire architecture.

```text
right: Protocol -> Application -> Security model -> Dialect adapter -> Database privileges
wrong: MCP tool -> Raw SQL -> Production
```

## 4. Principles

**Defense in depth.** No mechanism is trusted in isolation. A bug in any layer must
still encounter independent barriers after it:

```text
parser -> dialect analyzer -> policy engine -> resource limits
       -> read-only transaction -> hardened session on connect
       -> least-privilege database account -> restricted schemas/tables
       -> read replica
```

**Default deny.** Unknown or unsupported syntax, parse failures, multiple statements,
unclassified functions, and ambiguous side effects are all denied. Rejecting a safe
query is acceptable; authorizing an unsafe one is not.

**Generic core, dialect-native edges.** The core operates on a deliberately lossy
`QueryAnalysis`. MySQL and PostgreSQL do not pretend to share a grammar or runtime
behavior.

**Types encode security state.** The pipeline is not `String -> execute`. It is
`RawQuery -> AnalyzedQuery -> AuthorizedQuery -> ResultSet`, and the executor does
not accept arbitrary MCP input.

**MCP is an inbound adapter.** The core, policy, and database adapters do not depend
on `rmcp`. Crate boundaries, not discipline, enforce dependency direction.

**Explicit paths.** No magic DI containers, reflection-based registration, runtime
code generation, mutable global registries, "execute anything" helpers, or middleware
that silently mutates queries.

**No premature plugin system.** Extensibility happens in source code. Adding a
database may require adding a crate and wiring it into the composition root. That is
acceptable.

**Invariants are not configurable.** If a rule appears in section 6, there is no
corresponding configuration key. A security gateway with an easy bypass flag is not
a security gateway.

## 5. Scope

### 5.1 The product must

1. Let agents inspect configured MySQL and PostgreSQL databases.
2. Expose the same MCP tools regardless of the selected database.
3. Be read-only by construction throughout the 0.x line.
4. Make deterministic security decisions; no LLM decides whether SQL is safe.
5. Keep credentials out of any data visible to the model.
6. Parse SQL before authorization.
7. Reject unknown, unsupported, ambiguous, or unclassifiable SQL.
8. Keep parser ASTs out of the core security model.
9. Rely on least-privilege controls in the database itself.
10. Run every query under an effective deadline, both client-side and server-side.
11. Limit rows, bytes per value, total bytes, concurrency, queue wait, and pool use.
12. Audit attempts, denials, failures, and successes.
13. Do not log raw SQL or parameters by default.
14. Expose schema discovery optimized for an agent's workflow.
15. Support stdio for local use and Streamable HTTP for remote use.
16. Distribute as a single native executable.
17. Forbid `unsafe` in first-party crates.
18. Treat MySQL and PostgreSQL as first-class implementations.

### 5.2 The product should

Support multiple named connections; policy profiles per connection; concurrency
limits per connection; a schema metadata cache; query fingerprints; OpenTelemetry
traces and metrics; deterministic column redaction; internal capability metadata;
future adapters without changing policy concepts; replaceable parsers per adapter;
distribution without native client libraries; and first-class security regression
testing.

### 5.3 The product does not provide

`INSERT`, `UPDATE`, `DELETE`, `MERGE`, `COPY`, DDL, migrations, stored procedure
execution, administrative commands, session mutation, credential provisioning, a
network-protocol proxy, cross-database joins, SQL rewriting as a primary security
mechanism, automatic query optimization, ETL, bulk export, an ORM, a query builder
for agent SQL, an MCP-specific domain model, generic support for every SQL engine,
a plugin ABI, LLM policy decisions, automatic LLM-based PII classification, or
write access behind a configuration flag.

If writes are ever introduced, they will be a separate capability with a separate
authorization model and explicit design review.

## 6. Security invariants

These are non-negotiable throughout the 0.x line. **None has a configuration key.**
Changing any one requires an ADR.

1. No unparsed agent SQL executes.
2. Exactly one agent statement is accepted per `query` call.
3. Root write statements are denied.
4. Nested write statements are denied.
5. Unknown SQL categories are denied.
6. Locking reads are denied by default.
7. Dangerous and unclassified functions are denied by default.
8. Session mutation is denied.
9. MySQL file access and output are denied.
10. PostgreSQL sequence mutation is denied.
11. `EXPLAIN ANALYZE` is not exposed to the agent.
12. Execution requires an `AuthorizedQuery`.
13. Every query has both client-side and server-side deadlines.
14. Rows are bounded.
15. Bytes per value and total result bytes are bounded.
16. Queue wait is bounded.
17. Concurrency per connection is bounded.
18. Connection pools are bounded.
19. **Executed SQL is byte-for-byte identical to analyzed SQL.** The only exception
    is `explain`, which reparses and verifies the prefixed result.
20. Credentials are not exposed through MCP.
21. Credentials are not logged.
22. Raw SQL is not logged by default.
23. Parameters are not audited by default.
24. Every query attempt creates an audit record before execution.
25. Database accounts have no write privileges, independently of policy.
26. MCP handlers never access SQLx pools directly.
27. MCP crates contain no database-driver logic.
28. Parser AST types never leave adapter crates.
29. Policy decisions never depend on an LLM.
30. First-party Warden crates forbid `unsafe`.
31. Unsupported result types do not cause a panic.
32. Security regression cases remain tested forever.

## 7. Guarantee boundaries

A security product must state precisely what it guarantees and what it does not.
These statements bind the README and all public material.

**Warden prevents** write SQL, multiple statements, locking reads, unknown side
effects, and unparseable SQL from reaching the database. It limits time, volume,
and concurrency. It keeps credentials out of model context. It produces an audit
trail for every attempt.

**Warden is not the final write boundary.** That boundary is the dedicated role's
`GRANT`. SQL analysis reduces attack surface.

**The table allowlist is not a read-scope boundary.** It operates on names extracted
from the AST, but names do not determine what a relation reads: an allowed view can
read a denied table. **The dedicated role's `SELECT` privilege is the only read-scope
boundary.** The allowlist reduces attack surface and improves error messages.

**Column redaction is not access control.** It matches output column names and can be
bypassed with an alias or expression. It protects against accidental exposure, not
an adversarial agent.

**Warden does not sanitize database contents.** Returned data enters model context.
A hostile stored value may try to influence the agent. See `docs/security.md`,
"Injection through data."

Suggested README wording:

> Warden provides defense-in-depth controls, but production security still requires
> least-privilege database credentials and appropriate infrastructure isolation.

## 8. Priority during architectural conflicts

1. Database-level security
2. Correctness
3. Explicit security invariants
4. Auditability
5. Predictable resource use
6. Code clarity
7. Extensibility
8. Development convenience
9. Micro-performance

Do not choose an abstraction merely because it is "more Rust." Use the type system
where it eliminates invalid states or makes security boundaries explicit. Avoid type
cleverness where it only makes maintenance harder.

The goal is not the most sophisticated Rust codebase. It is a small, understandable,
auditable security gateway that an experienced engineer can review and trust.

## 9. What Warden must never become

```text
"the LLM requested it, so execute it"
```

Do not add `--unsafe`, `--skip-policy`, or `--allow-write`. Development bypasses, if
ever needed, must not be accidentally usable against a production profile.

## 10. Versioning

The initial line is `0.x`. Before `1.0`: stabilize MCP tool contracts and the
configuration schema, document adapter compatibility, and clearly delimit security
guarantees.

Rust crate APIs are internal implementation details before 1.0. MCP tool schemas are
user-facing contracts from the first release and change cautiously. The configuration
format is versioned from the beginning.
