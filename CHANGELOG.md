# Changelog

All notable changes to Warden are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Two contracts are versioned, and they are the ones a `0.x` bump is measured against:
the **MCP tool schemas** and the **configuration format**. Rust crate APIs are internal
implementation details before `1.0` and change without notice (`SPEC.md` section 10).

## [Unreleased]

### Added

- **npm distribution.** `npx -y warden-db-mcp` installs one prebuilt binary for the
  platform and runs it, so an MCP client configuration needs no path to a downloaded
  file. No package in the set declares an install script; npm resolves the platform
  through `os` and `cpu` fields. Every tarball is published with npm provenance from
  the same tag that publishes the release archives. `warden-sql-mcp` is published as a
  deprecated alias of the same server, so the neighbouring name resolves to Warden.
- **Onboarding subcommands.** `warden init` writes a starting configuration and
  refuses to overwrite one. `warden role` prints the least-privilege `CREATE ROLE` and
  `GRANT` statements for MySQL or PostgreSQL — the database role is the real write
  boundary, and until now nothing helped an operator create it; `--user` and
  `--database` take a plain SQL name and refuse the words SQL reads as grantees that
  already exist, `public` above all, so the script can never grant `SELECT` to every
  role in the database. `warden mcp-config` prints the MCP client block with the binary
  and configuration paths already resolved absolutely — including a `warden.toml` that
  does not exist yet — which is what an MCP client needs because it spawns servers with
  an arbitrary working directory.
- **Homebrew tap.** `brew install rodrigodotdev/tap/warden` installs Warden on macOS
  and Linux, on both x86_64 and arm64. Every tag renders the formula from the
  release's own `SHA256SUMS` and pushes it, so the tap cannot describe a version that
  was never published.

## [0.1.0] - 2026-09-08

The first developer-usable release. Warden runs as an MCP server over stdio and gives
an agent read-only, policy-checked access to MySQL and PostgreSQL without exposing
database credentials to the model.

### Added

- **MCP server over stdio.** `warden serve --transport stdio` exposes five generic
  tools — `list_connections`, `search_schema`, `describe_schema`, `query`, and
  `explain` — with populated annotations and an output schema on every tool. The
  schemas are identical for MySQL and PostgreSQL and are snapshotted in CI, so an
  agent needs no per-engine tooling. Warden speaks the `2025-11-25` and `2026-07-28`
  protocol revisions, over the `initialize` handshake and the inline lifecycle alike,
  and refuses anything else rather than substituting silently. A handshake is answered
  with `2025-11-25` whatever it requested, because sending `initialize` is itself the
  selection of legacy semantics.
- **`warden check`.** Validates the configuration, resolves every DSN, proves the
  audit destination writable, and reports what a deployment would do — before any
  database pool opens.
- **MySQL and PostgreSQL adapters.** Each brings its own dialect analyzer, executor,
  schema inspector, explainer, and value normalizer. Neither is forced into the
  other's semantics.
- **Schema discovery.** `search_schema` and `describe_schema` return relations,
  columns, indexes, and primary- and foreign-key metadata through a short-TTL cache,
  with object policy applied at the source rather than filtered afterward.
- **Non-executing query plans.** `explain` returns a structured plan with a generic
  summary where one is meaningful. The prefixed statement is reparsed and verified,
  and `EXPLAIN ANALYZE` is prohibited by construction.
- **Value normalization.** Precision-preserving `NUMERIC`, digit-preserving `JSON` and
  `JSONB`, `UUID`, depth-limited arrays, and cast suggestions instead of silent
  failure for custom types.
- **Configuration.** A versioned TOML format with multiple named connections, per
  connection policy profiles, limits, and TLS settings. DSNs resolve from environment
  variables or files straight into a redacting secret type and never reach a
  serializable struct.
- **Durable audit trail.** `query`, `explain`, `search_schema`, and `describe_schema`
  each record a two-phase, append-only JSON Lines record: an attempt before dispatch
  and an outcome after it. Records carry a non-reversible `v1:` fingerprint, request
  identity, and public error codes. A dropped or panicking request still completes its
  record, as `abandoned`.
- **Tracing.** A documented service and database phase tree, with request identity in
  span fields and a panic hook that reports location, thread, and payload shape.
- **Prebuilt binaries** for Linux (x86_64, aarch64), macOS (x86_64, aarch64), and
  Windows (x86_64), each with SHA-256 checksums and signed build provenance.

### Security

- **Read-only by construction.** Only a single `SELECT`, including read-only CTEs,
  can reach execution. Multiple statements, nested writes, data-modifying CTEs, and
  locking reads are denied. Unknown, unsupported, or unclassifiable SQL is denied by
  default, as is any function outside the reviewed registry.
- **SQL is parsed before it is authorized**, and parser ASTs never leave the adapter
  crates. Policy decisions are deterministic; no model decides whether SQL is safe.
- **The database role is the real boundary.** Warden is defense in depth over a
  dedicated `SELECT`-only role, and the container suite proves that role itself
  refuses a write with every Warden layer removed.
- **Every query is bounded** by a client-side *and* a server-side deadline, a row
  ceiling, per-value and total byte budgets, bounded queue wait, and bounded
  concurrency per connection.
- **Credentials never reach the model.** DSNs appear in no tool response, log, span,
  or audit record, and driver errors are sanitized to fourteen public codes at the
  MCP boundary.
- **Raw SQL and parameters are in no log and no audit record**, by default and with
  no configuration key to change it.
- `unsafe` is forbidden in every first-party crate.

### Known limitations

These are documented deliberately, not oversights; `SPEC.md` section 7 and
`docs/open-questions.md` carry the full list.

- **stdio only.** Streamable HTTP and its authorization model are Milestone 14. Remote
  production deployment is not supported yet.
- The table allowlist reduces attack surface but does not bound read scope — `GRANT`
  does. Column redaction is not access control. Database contents are not sanitized
  and may carry hostile instructions into model context.
- A client cancellation does not reach an already-running database query; the request
  budget bounds it instead.
- One policy engine is shared by every connection, so a deployment serving two
  unrelated databases shares its object rules between them.
- A JSON document's integers above 2^53 reach a JavaScript client unquoted, and a
  PostgreSQL `time` of `24:00:00` reads back as `00:00:00`.

[Unreleased]: https://github.com/rodrigodotdev/warden/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/rodrigodotdev/warden/releases/tag/v0.1.0
