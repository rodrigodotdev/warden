# ADR-0006 — `sqlparser-rs` as the initial parser

**Status:** Accepted · 2026-08-19

## Context

Warden must parse SQL in both dialects before authorization. A custom parser would
be prohibitively expensive and more prone to security bugs.

## Decision

Use `sqlparser-rs` (Apache DataFusion) with `MySqlDialect` and
`PostgreSqlDialect`.

Keep the default `recursive-protection` feature and set
`Parser::with_recursion_limit` explicitly.

## Consequences

`sqlparser-rs` is a multi-dialect parser, not the database server's parser. SQL that
the database accepts but the parser rejects yields `query_parse_error` and is never
executed. This is acceptable for a security gateway; there is no fallback to
unparsed SQL.

Even though both adapters use the same library, do not create a shared parser
abstraction merely because the dependency is common (ADR-0007).

Dependency upgrades require running the complete corpus and reviewing new AST
variants.
