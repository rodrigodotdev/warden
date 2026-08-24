# ADR-0029 — `pg_catalog` is the only trusted function schema

**Status:** Accepted · 2026-08-23

## Context

`warden-mysql` treats **any** schema-qualified function call as provably
user-defined, because MySQL cannot schema-qualify a built-in: writing
`schema.name(...)` is only legal for a stored routine. That rule closed a real
bypass, in which a stored routine sharing a name with a `SAFE` entry laundered
itself into `KnownSafe`.

PostgreSQL inverts the premise. Built-in functions live in `pg_catalog`, and
`pg_catalog.count(1)` is both legal and idiomatic — schema-qualifying a built-in is
the standard way to write a call that does not depend on `search_path`. Applying
MySQL's rule here would deny ordinary PostgreSQL. Dropping the rule and classifying
every call by its bare name would restore the MySQL bypass: `public.count(1)` could
be a user-defined function shadowing a safe name.

## Decision

`warden-postgres` consults the function registry for a call that is unqualified, or
qualified by a schema that names `pg_catalog`. Every other qualified call is
`FunctionClassification::Unknown` with `RiskFlag::UserDefinedFunction`, decided
before the bare name is compared against anything.

"Names `pg_catalog`" is
`warden_policy::folding::rule_matches(Dialect::PostgreSql, "pg_catalog", schema)` —
the same asymmetric comparison the policy engine uses (ADR-0027) — so `pg_catalog`
and `"pg_catalog"` are trusted and `"PG_CATALOG"` is not.

This is sound because PostgreSQL reserves the `pg_` schema-name prefix: an
unprivileged role cannot create a schema whose name would be trusted here.

## Consequences

Ordinary qualified PostgreSQL reads are no longer false positives, and a
user-defined function in any other schema still cannot inherit a built-in's
classification.

The trusted set is exactly one schema and grows only by amending this ADR. In
particular `public` is **not** trusted, even though it is on the default
`search_path`: it is the one schema an ordinary role can usually write to.

This does not change the read-scope boundary. The dedicated role's `GRANT` remains
it (ADR-0023 and ADR-0016); classification reduces attack surface.
