# Warden

> Warden lets AI agents investigate production databases through a narrow,
> deterministic, least-privilege, read-only interface without exposing database
> credentials to the model.

A **Model Context Protocol** server written in Rust, for MySQL and PostgreSQL.

**Status:** first developer-usable release. Milestone 12 shipped the MCP server:
`warden serve --transport stdio` exposes the five tools — `list_connections`,
`search_schema`, `describe_schema`, `query`, `explain` — over MySQL and PostgreSQL, and
`warden check` validates a deployment before it serves one. Streamable HTTP, and the
authorization model that has to come with it, are Milestone 14; until then a remote
deployment is not yet supported. Build from source: there is no published binary, no
container image, and no selected license yet. See
[`docs/milestones.md`](docs/milestones.md).

## Quick start

Write `warden.toml`. Every optional key falls back to a hardened default, so this is a
complete file:

```toml
version = 1

[[connections]]
name = "orders-replica"
dialect = "postgresql"
environment = "production"
database = "app"
dsn_env = "WARDEN_ORDERS_REPLICA_DSN"
search_path = ["app", "public"]
policy = "default"

[policies.default]
query_timeout = "5s"
max_rows = 200

[redaction]
columns = ["*.password_hash", "*.access_token"]
```

Warden never reads a DSN from this file. `dsn_env` names the environment variable that
holds it, and `dsn_file` — which Docker and Kubernetes secret mounts make the better
choice — names a file to read it from. A DSN names only the connection target: a scheme,
a host, a user, a database, optionally a port and a password, and no query string
(ADR-0031). Everything else, TLS included, is Warden's own configuration.

```bash
export WARDEN_ORDERS_REPLICA_DSN='postgres://warden_ro:...@replica.internal:5432/app'

cargo build --release
target/release/warden check                  # report on stderr; exit 0 when it passes
target/release/warden serve --transport stdio
```

`warden check` does everything `warden serve` would do except serve: it loads and
validates the configuration, resolves every secret reference, opens every connection,
runs each adapter's fixed readiness probe on the control pool, reads the session
settings back to catch a proxy that discarded them, and warns about a production
connection reached over stdio or a relaxed policy profile serving one. It never executes
agent SQL. Its report goes to **stderr**, because stdout carries MCP and nothing else;
its answer is the exit code, and a warning is not a failure.

An MCP client runs the same command. The entry carries no secret:

```json
{
  "mcpServers": {
    "warden": {
      "command": "/usr/local/bin/warden",
      "args": ["serve", "--transport", "stdio", "--config", "/etc/warden/warden.toml"]
    }
  }
}
```

`--config` defaults to `warden.toml` in the working directory. The client's own
environment supplies `WARDEN_ORDERS_REPLICA_DSN`, which is exactly the exposure the next
section is about.

## Secure deployment

### Database privileges are mandatory

Warden is not a substitute for a least-privilege role, and configuring one is not
optional. Give Warden a dedicated database role with `SELECT` and nothing else, on the
smallest set of relations the work needs, and prefer a read replica.

**That role's `GRANT` is the write boundary** (ADR-0016), and **its `SELECT` privilege is
the only read-scope boundary** (ADR-0023). Warden's SQL analysis and table allowlist
reduce attack surface and improve error messages; they do not bound what a query can
read, because an allowed view can read a denied table. A deployment whose role can write,
or can read everything, has no boundary at all — only Warden's opinion of one.
[`docs/security.md`](docs/security.md) sections 4 and 5 name, per engine, the privileges
to grant and the ones never to grant.

### The local stdio threat model

A local coding agent with unrestricted shell access can read environment variables and
files available to its own process. **MCP over stdio alone does not protect a production
DSN stored in the same environment available to the agent.**

Do not store production secrets in a committed or agent-readable `.env`, repository
configuration, `AGENTS.md`, `CLAUDE.md`, or prompt files.

Prefer a remote Warden for production, reached over an authenticated transport, with the
database on a private network the agent has no route to. `warden check` warns whenever
stdio serves a connection whose `environment` is `production`; the warning is a statement
about the deployment, not about the configuration being wrong.

The boundaries this deployment advice exists to keep are stated in the next section.

## What Warden does and does not guarantee

A security product must state both. These are
[`SPEC.md` section 7](SPEC.md)'s statements, which bind this README and all public
material:

**Warden prevents** write SQL, multiple statements, locking reads, unknown side effects,
and unparseable SQL from reaching the database. It limits time, volume, and concurrency.
It keeps credentials out of model context. It produces an audit trail for every attempt.

**The audit trail covers query attempts, not every tool call.** SPEC section 6's
invariant 24 — "every query attempt" — is what Warden implements today: `query` and
`explain` record an attempt and its outcome. Schema reads (`search_schema`,
`describe_schema`) and `list_connections` record neither, so a denied catalog read leaves
no audit record. See [`docs/open-questions.md`](docs/open-questions.md) item 21.

**Warden is not the final write boundary.** That boundary is the dedicated role's
`GRANT`. SQL analysis reduces attack surface.

**The table allowlist is not a read-scope boundary.** It operates on names extracted from
the AST, but names do not determine what a relation reads: an allowed view can read a
denied table. **The dedicated role's `SELECT` privilege is the only read-scope boundary.**
The allowlist reduces attack surface and improves error messages.

**Column redaction is not access control.** It matches output column names and can be
bypassed with an alias or expression. It protects against accidental exposure, not an
adversarial agent.

**Warden does not sanitize database contents.** Returned data enters model context. A
hostile stored value may try to influence the agent. See
[`docs/security.md`](docs/security.md) section 9, "Injection through returned data."

> Warden provides defense-in-depth controls, but production security still requires
> least-privilege database credentials and appropriate infrastructure isolation.

## Documentation

| Document | Contents |
|---|---|
| [`SPEC.md`](SPEC.md) | Product, 32 security invariants, guarantee boundaries |
| [`AGENTS.md`](AGENTS.md) | Contract for implementation agents |
| [`docs/architecture.md`](docs/architecture.md) | Layers, crates, ports, dependency direction |
| [`docs/mcp.md`](docs/mcp.md) | Tools, contracts, transports, local stdio threat model |
| [`docs/security.md`](docs/security.md) | Threat model, threat-to-control matrix, privileges |
| [`docs/operations.md`](docs/operations.md) | Configuration, pools, TLS, observability, CLI, CI |
| [`docs/testing.md`](docs/testing.md) | Test strategy, corpus, fuzzing |
| [`docs/adr/`](docs/adr/) | Architectural decisions, one per file |

## Development

The Rust toolchain is declared in `rust-toolchain.toml` and provisioned by
rustup. [mise](https://mise.jdx.dev) reads that file and manages only auxiliary
tools and development shortcuts.

```bash
mise trust
mise install          # Rust from rust-toolchain.toml plus tools from mise.lock
mise run ci           # the same gate run by CI
mise run test:docker  # integration tests; requires a Docker daemon
mise run coverage     # coverage report in coverage/
```

`mise tasks` lists the shortcuts. They are conveniences; the Cargo commands in
`AGENTS.md` and `docs/operations.md` remain the canonical gate interface.

`rust-version = "1.94"` in `Cargo.toml` is the supported floor (MSRV), verified
by a dedicated job. The development toolchain comes from `rust-toolchain.toml`,
the only hand-written source for its version and components. These are distinct;
see [ADR-0002](docs/adr/0002-edition-2024-msrv.md).

## License

Not yet selected; see [`docs/open-questions.md`](docs/open-questions.md), item 12.
Until then, all rights reserved.
