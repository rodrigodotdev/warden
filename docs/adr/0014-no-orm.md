# ADR-0014 — No ORM or query builder for agent SQL

**Status:** Accepted · 2026-08-19

## Context

The product receives SQL from the agent and must analyze it. An abstraction over SQL
does not help and obstructs analysis.

## Decision

SQL is a first-class value. Do not use an ORM or a generic query builder for agent
SQL.

## Consequences

The SQL the agent writes is the SQL Warden analyzes and executes (SPEC section 6,
invariant 19), a central auditability property. The SQL remains copyable and
verifiable in ordinary database tools.

Internal adapter queries remain adapter-owned static SQL.
