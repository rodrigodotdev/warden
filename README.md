<div align="center">
  <img src="assets/warden.png" width="220" alt="Warden, a pixel-art guardian" />

  <h1>Warden</h1>

  <p><strong>Safe database access for AI agents.</strong></p>
  <p>
    Let agents explore MySQL and PostgreSQL through a narrow, deterministic,
    least-privilege MCP interface—without handing database credentials to the model.
  </p>

  <p>
    <a href="https://github.com/rodrigodotdev/warden/releases/latest"><img src="https://img.shields.io/github/v/release/rodrigodotdev/warden?style=flat-square&amp;label=release&amp;color=8A63D2" alt="Latest release" /></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-3DA639?style=flat-square" alt="MIT license" /></a>
    <a href="https://github.com/rodrigodotdev/warden/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/rodrigodotdev/warden/ci.yml?branch=main&amp;style=flat-square&amp;label=CI" alt="CI status" /></a>
    <img src="https://img.shields.io/badge/Rust-1.94%2B-000000?style=flat-square&amp;logo=rust&amp;logoColor=white" alt="Rust 1.94 or newer" />
    <img src="https://img.shields.io/badge/MCP-stdio-008B8B?style=flat-square" alt="Model Context Protocol over stdio" />
    <img src="https://img.shields.io/badge/MySQL-supported-4479A1?style=flat-square&amp;logo=mysql&amp;logoColor=white" alt="MySQL supported" />
    <img src="https://img.shields.io/badge/PostgreSQL-supported-4169E1?style=flat-square&amp;logo=postgresql&amp;logoColor=white" alt="PostgreSQL supported" />
  </p>

  <p>
    <a href="#quick-start">Quick start</a> ·
    <a href="#a-natural-workflow-for-agents">MCP workflow</a> ·
    <a href="#security-model">Security</a> ·
    <a href="#development">Development</a> ·
    <a href="#documentation">Documentation</a>
  </p>
</div>

---

Warden is a [Model Context Protocol](https://modelcontextprotocol.io/) server for
controlled, read-only investigation of MySQL and PostgreSQL databases. It gives an
agent five focused tools for discovering a schema, inspecting relations, running a
bounded `SELECT`, and examining a query plan—while the database credentials stay in
the Warden process.

| Read-only by construction | Bounded by default | Built for agent workflows |
|---|---|---|
| Only a single `SELECT`, including read-only CTEs, can reach execution. | Time, rows, bytes, queue wait, and concurrency all have limits. | Structured results, descriptive tools, safe errors, and a discover-before-query flow. |

> [!IMPORTANT]
> Warden is defense in depth, not a replacement for database permissions. Its final
> write boundary is a dedicated database role that has `SELECT` and nothing else.

## How it works

```text
AI agent / MCP client
        │
        │ stdio (MCP)
        ▼
     Warden
        ├── discovers and describes allowed relations
        ├── parses SQL and applies every policy
        ├── enforces deadlines, size limits, and concurrency
        └── returns bounded, structured content
        │
        │ dedicated read-only role
        ▼
MySQL or PostgreSQL
```

The selected connection determines the SQL dialect. The MCP contract stays the same
for both databases, so agents do not need separate MySQL and PostgreSQL tools.

## Quick start

### 1. Install Warden

On macOS or Linux with [Homebrew](https://brew.sh):

```bash
brew install rodrigodotdev/tap/warden
```

Download the archive for your platform from the
[latest release](https://github.com/rodrigodotdev/warden/releases/latest): Linux and
macOS on x86_64 and arm64, Windows on x86_64. Each archive holds a single
self-contained executable — no `libmysqlclient`, no `libpq`.

Verify it before you run it. Every published file carries signed build provenance, and
`SHA256SUMS` is signed alongside the archives it lists:

```bash
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify warden-v0.1.0-x86_64-unknown-linux-gnu.tar.gz \
  --repo rodrigodotdev/warden
tar -xzf warden-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
```

There is no container image yet.

<details>
<summary>Or build from source</summary>

The repository pins its development toolchain in `rust-toolchain.toml`.

```bash
git clone https://github.com/rodrigodotdev/warden.git
cd warden
cargo build --locked --release
```

</details>

### 2. Create `warden.toml`

```bash
warden init
```

That writes a starting configuration and refuses to touch one that already exists.
Open it and set `name`, `dialect`, `database`, and the environment variable name in
`dsn_env`.

Warden never reads a DSN from this file. `dsn_env` names the environment variable that
holds it; `dsn_file` names a secret file instead.

**Prefer `dsn_file` where the deployment allows it.** The two are not equally strong. A
DSN read from a file exists only in a buffer Warden zeroes as soon as it is parsed. One
read from the environment cannot be: the value stays in the process environment block
for the process lifetime, readable through `/proc/self/environ` by anything that can
read the process — which is exactly the local agent the threat model below describes.
`dsn_file` also fits Docker and Kubernetes secret mounts.

A DSN describes only the connection target: scheme, host, user, database, and optionally
a port and password. It cannot contain a query string. TLS and every other behavior are
configured explicitly by Warden.

### 3. Create the read-only database role

This role, not Warden, is the write boundary. Print the statements, **read them**, set a
real password, and run them as an administrator:

```bash
warden role --dialect postgresql --user warden_ro --database app
```

The output grants `SELECT` and nothing else, and on PostgreSQL also sets
`default_transaction_read_only` on the role, so the session refuses a write even with
every Warden layer removed.

### 4. Validate the deployment

```bash
export WARDEN_LOCAL_DSN='postgres://warden_ro:...@localhost:5432/app'

warden check
```

`warden check` follows the same startup path as `warden serve`, without accepting MCP
requests. It validates the configuration, resolves secret references, opens every
connection, verifies session settings, and runs fixed readiness probes. It never runs
agent SQL.

The report goes to stderr because stdout is reserved for MCP. Exit code `0` means the
deployment is ready; warnings remain warnings and do not change that exit code.

TLS is `verify-identity` unless the configuration says otherwise, so a local server with
SSL off fails here. The generated file carries the two commented lines that relax it for
a development machine; a real database keeps the default.

### 5. Connect your MCP client

```bash
warden mcp-config
```

That prints the block below with the real absolute paths already filled in — copy it
into your client's MCP configuration:

```json
{
  "mcpServers": {
    "warden": {
      "args": [
        "serve",
        "--transport",
        "stdio",
        "--config",
        "/absolute/path/to/warden.toml"
      ],
      "command": "/absolute/path/to/warden"
    }
  }
}
```

Both paths are absolute on purpose: a client spawns its servers with an arbitrary
working directory, so a relative `warden.toml` will not resolve — the `--config` path is
made absolute even when that file does not exist yet, and the missing file is noted on
stderr. The keys come back in that order because the block is serialized sorted; the
order does not matter to a client.

The client process must inherit the environment variable named by `dsn_env`, or be able
to read the file named by `dsn_file`. Do not paste a DSN into the MCP configuration.

> [!CAUTION]
> Use local stdio with development data. A local coding agent with unrestricted shell
> access may be able to read the same environment variables and files as Warden. The
> authenticated remote transport required for a production deployment arrives in
> Milestone 14 and is not available yet.

### 6. Give your agent a useful first task

This prompt demonstrates the intended discovery flow without encouraging the agent to
guess schema details:

```text
Use Warden to investigate recent orders. First list the available connections, then
search the selected connection for order and customer relations. Describe the relevant
tables before writing a bounded SELECT. If the result is truncated, refine the query
instead of repeating it unchanged.
```

## A natural workflow for agents

Warden's tools are deliberately small and generic. A well-behaved agent moves from
discovery to execution:

```text
list_connections
        │
        ▼
search_schema ──► describe_schema
                         │
                         ├──► query
                         └──► explain
```

| Tool | When to use it | What the agent should remember |
|---|---|---|
| `list_connections` | Start of an investigation | The connection selects the dialect and placeholder syntax. |
| `search_schema` | Before inventing a table name | Search accepts several terms and returns bounded, ranked matches. |
| `describe_schema` | After choosing relevant relations | Inspect columns, keys, and indexes for at most 20 tables per call. |
| `query` | After the schema is understood | Send one `SELECT`; use `?` for MySQL and `$1` for PostgreSQL parameters. |
| `explain` | Before a potentially expensive query | Inspect the database plan without executing the statement. |

When `query` reports `truncated: true`, the right next step is a narrower projection,
a stronger filter, or a smaller `LIMIT`—not the same query again.

Successful tool results place database data in MCP `structuredContent`. Their text
content contains only a short summary, never a second copy of returned values. This keeps
data distinct from instructions and avoids wasting model context.

See [`docs/mcp.md`](docs/mcp.md) for complete inputs, outputs, annotations, and protocol
semantics.

## Secure deployment

### Database privileges are mandatory

Give Warden a dedicated database role with `SELECT` and nothing else, scoped to the
smallest set of relations the investigation needs. Prefer a read replica.

The role's `GRANT` is the write boundary (ADR-0016), and its `SELECT` privilege is the
only read-scope boundary (ADR-0023). Warden's SQL analysis and table allowlist reduce
attack surface and improve error messages; they cannot prove what an allowed view reads.

[`docs/security.md`](docs/security.md) sections 4 and 5 list the privileges to grant—and
the privileges never to grant—for each supported engine.

### The local stdio threat model

A local coding agent with unrestricted shell access can read environment variables and
files available to its own process. MCP over stdio alone does not protect a production
DSN stored in the same environment available to the agent.

Do not store production secrets in a committed or agent-readable `.env`, repository
configuration, `AGENTS.md`, `CLAUDE.md`, or prompt file.

The recommended production shape is a remote Warden, reached over an authenticated
transport, with the database on a private network the agent cannot reach directly.
`warden check` warns when stdio serves a connection marked as `production`.

## Security model

A security tool should be explicit about both its guarantees and its boundaries. The
statements below are governed by [`SPEC.md` section 7](SPEC.md).

### What Warden prevents

Warden prevents write SQL, multiple statements, locking reads, unknown side effects,
and unparseable SQL from reaching the database. It limits time, volume, and concurrency,
keeps credentials out of model context, and produces an audit trail for every query
attempt.

### What Warden does not claim

- **The audit trail does not cover every tool call.** `query`, `explain`,
  `search_schema`, and `describe_schema` each record an attempt and its outcome.
  `list_connections` does not: it reads an in-memory map, reaches no database, and
  returns configuration metadata the agent must already have to call anything else
  (ADR-0042).
- **Warden is not the final write boundary.** The dedicated role's database privileges
  are. SQL analysis is an additional barrier.
- **The table allowlist is not a read-scope boundary.** An allowed view can read a denied
  table. The dedicated role's `SELECT` privileges define what can actually be read.
- **Column redaction is not access control.** Matching output column names protects
  against accidental exposure, but aliases and expressions can bypass it.
- **Database contents are not sanitized.** Returned values enter model context and may
  contain hostile instructions. See [`docs/security.md`](docs/security.md) section 9.

> [!NOTE]
> Warden provides defense-in-depth controls. Production security still requires
> least-privilege database credentials and appropriate infrastructure isolation.

## Project status

Warden has reached its first developer-usable release. Milestone 12 ships
`warden serve --transport stdio`, `warden check`, all five MCP tools for MySQL and
PostgreSQL, and an audit trail written through the process's stderr subscriber.

Milestone 13 makes that audit trail durable and reviewable: `query`, `explain`, and both
catalog reads record two phases to a versioned, append-only audit file; raw SQL and
parameters have no record or span field; a read-only regular-file fixture proves a real
attempt write maps to `AuditError::Unavailable`, and the execution gate separately proves
a failing attempt takes neither permit nor executor; the documented tracing tree and
payload-free panic reporting give operators safe diagnostics. `/dev/full` is rejected at
open time as a special-file destination rather than used as the write-failure fixture.

v0.1.0 is the first tagged release: MIT-licensed, with signed, checksummed binaries
for Linux, macOS, and Windows. [`CHANGELOG.md`](CHANGELOG.md) records what it contains
and what it deliberately does not.

Streamable HTTP and its authorization model are planned for Milestone 14. Until then,
remote production deployment is not supported, and there is no container image. Follow
progress in [`docs/milestones.md`](docs/milestones.md).

## Development

Rust comes from `rust-toolchain.toml`. [mise](https://mise.jdx.dev/) provisions the
auxiliary tools and gives the repository memorable development commands:

```bash
mise trust
mise install
mise tasks
```

### Everyday checks

| Command | Purpose | Requires Docker? |
|---|---|:---:|
| `mise run fmt:check` | Check Rust and TOML formatting | No |
| `mise run check` | Type-check every workspace target | No |
| `mise run check:standalone` | Check that every crate builds on its own | No |
| `mise run lint` | Run Clippy with warnings denied | No |
| `mise run test` | Run the fast workspace test suite | No |
| `RUST_TEST_THREADS=4 mise run test:docker` | Verify both adapters and the MCP server against real databases at the documented container-capacity limit | Yes |
| `mise run coverage` | Build the HTML report and enforce 95% line coverage | Yes |
| `mise run ci` | Run the complete local CI-equivalent gate | No |

The canonical milestone gate remains:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
for manifest in Cargo.toml crates/*/Cargo.toml; do
  cargo check --manifest-path "$manifest" || exit 1
done
```

The last one is not redundant with `cargo check --workspace`. A workspace build unifies
features across the dependency graph, so a crate that uses a feature it never declared
still compiles — and every other command here is workspace-wide, which is why this class
of error went unnoticed until a crate was built on its own. `mise run ci` includes it.

Before changing implementation or architecture, read [`SPEC.md`](SPEC.md) and
[`AGENTS.md`](AGENTS.md). Work proceeds one milestone at a time, and architectural
decisions live in [`docs/adr/`](docs/adr/).

## Documentation

| Document | Start here when you need to understand… |
|---|---|
| [`SPEC.md`](SPEC.md) | The product, its 32 security invariants, and guarantee boundaries |
| [`CHANGELOG.md`](CHANGELOG.md) | What a release contains, and what it deliberately does not |
| [`AGENTS.md`](AGENTS.md) | The implementation contract for contributors and coding agents |
| [`docs/architecture.md`](docs/architecture.md) | Layers, crates, ports, and dependency direction |
| [`docs/mcp.md`](docs/mcp.md) | Tool contracts, protocol behavior, and transports |
| [`docs/security.md`](docs/security.md) | Threats, controls, database privileges, and safe failures |
| [`docs/operations.md`](docs/operations.md) | Configuration, pools, TLS, observability, CLI, and CI |
| [`docs/testing.md`](docs/testing.md) | Test strategy, regression corpus, and fuzzing |
| [`docs/adr/`](docs/adr/) | One architectural decision per file |

## License

[MIT](LICENSE), for the reasoning in
[ADR-0050](docs/adr/0050-mit-license.md). Contributions arrive under the same terms;
there is no CLA.

Warden redistributes the Mozilla CCADB root store through `webpki-roots`, which carries
a separate CDLA-Permissive-2.0 notice in [`LICENSES/`](LICENSES/). Both files ship
inside every release archive.
