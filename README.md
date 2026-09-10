<div align="center">
  <img src="assets/warden.png" width="220" alt="Warden, a pixel-art guardian" />

  <h1>Warden</h1>

  <p><strong>Safe database access for AI agents.</strong></p>
  <p>Explore MySQL and PostgreSQL from your MCP client, with built-in query limits and SQL policy checks.</p>

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
    <a href="#installation">Installation</a> ·
    <a href="#quick-start">Quick start</a> ·
    <a href="#tools">Tools</a> ·
    <a href="#security">Security</a> ·
    <a href="#documentation">Documentation</a>
  </p>
</div>

Warden is a [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server
that lets AI agents discover tables, understand schemas, query data, and inspect
query plans. Database credentials are never included in MCP responses.

- **MySQL and PostgreSQL:** the same five tools work with either database.
- **Read-only queries:** SQL is parsed and checked against deterministic policies
  before execution. Writes, locking reads, multiple statements, unparseable SQL,
  and unknown side effects are denied.
- **Bounded results:** limits on execution time, rows, bytes, and concurrency keep
  investigations manageable.
- **Audit logging:** database operations record an attempt and its outcome, with
  optional persistent file storage.

Warden currently runs over **local stdio**. Authenticated remote access is not yet
available. See [Security](#security) for deployment requirements and limitations.

## Installation

With Node.js and npm installed, run Warden through `npx`:

```bash
npx -y warden-db-mcp version
```

Prebuilt binaries are available for Linux and macOS on x64 and arm64, and Windows
on x64. No Rust toolchain is needed to use them.

<details>
<summary>Other installation options</summary>

**Homebrew (macOS and Linux)**

```bash
brew install rodrigodotdev/tap/warden
```

**Release archive**

Download your platform's archive from the
[latest release](https://github.com/rodrigodotdev/warden/releases/latest), extract
it, and place the executable on your `PATH`. Releases include checksums and signed
build provenance; see [release artifacts](docs/operations.md#127-release-artifacts).

**Build from source**

Install [Rust](https://www.rust-lang.org/tools/install); the repository pins its
toolchain in [`rust-toolchain.toml`](rust-toolchain.toml).

```bash
git clone https://github.com/rodrigodotdev/warden.git
cd warden
cargo build --locked --release
```

The executable is `target/release/warden` (`warden.exe` on Windows). Use that path
directly or place the binary on your `PATH`.

The prebuilt Linux binaries require glibc. On Alpine or another musl distribution,
build from source.

</details>

The examples below use `npx`. If you installed a binary, replace
`npx -y warden-db-mcp` with `warden`.

## Quick start

This example connects to an existing **local PostgreSQL development database**
named `app`. You will need administrator access to create its read-only role and
an MCP client that supports stdio servers.

### 1. Create the configuration

```bash
npx -y warden-db-mcp init
```

This creates `warden.toml` without overwriting an existing file. The template uses
PostgreSQL, the `app` database, and the `public` schema. Adjust these values to match
your database.

TLS verifies the server's identity by default. If your local development database
has no TLS, uncomment the `[connections.tls]` and `mode = "disabled"` lines in the
generated file. Keep identity verification enabled outside local development.

### 2. Set up database access

Generate SQL for a dedicated read-only role:

```bash
npx -y warden-db-mcp role --dialect postgresql --user warden_ro --database app
```

This command **prints SQL; it does not execute it**. Review the grants, replace
`CHANGE_ME` with a real password, and run the SQL as an administrator connected to
`app`. Grant access only to the data the agent should be able to read.

Set the connection string in the environment variable named by `dsn_env` in your
configuration. For Bash or Zsh:

```bash
export WARDEN_LOCAL_DSN='postgres://warden_ro:YOUR_PASSWORD@localhost:5432/app'
```

Replace `YOUR_PASSWORD` with the role's password, URL-encoding special characters.
Keep the connection string out of `warden.toml` and your MCP client configuration.
Configure TLS in `warden.toml`; connection strings must not contain query parameters.

If you use a secret file, replace `dsn_env` with `dsn_file = "/absolute/path/to/dsn"`.
Prefer a secret file where possible to avoid keeping credentials in the process
environment. See [configuration and secrets](docs/operations.md#3-configuration).

<details>
<summary>Using MySQL instead</summary>

Set `dialect = "mysql"` in `warden.toml` and remove `search_path`, which is specific
to PostgreSQL. Generate the role SQL with `--dialect mysql` and use a connection
string such as `mysql://warden_ro:YOUR_PASSWORD@localhost:3306/app`.

</details>

### 3. Check the connection

```bash
npx -y warden-db-mcp check
```

This validates the configuration and checks database connectivity and session
settings before an agent connects. Diagnostics go to stderr; exit code `0` means
the check passed.

### 4. Connect your MCP client

Add this server entry to your client's MCP configuration, replacing the path with
the **absolute path** to your `warden.toml`:

```json
{
  "mcpServers": {
    "warden": {
      "command": "npx",
      "args": ["-y", "warden-db-mcp", "serve", "--config", "/absolute/path/to/warden.toml"]
    }
  }
}
```

Your client must inherit `WARDEN_LOCAL_DSN` or have access to the configured secret
file. Restart or reload the client after updating its configuration.

For a binary installed on your `PATH`, run `warden mcp-config` from the directory
containing `warden.toml` to generate the entry with absolute paths. Use the `npx`
entry above for npm installations, since npm may remove cached binary paths.

Try asking your agent:

> Use Warden to list my connections and find tables related to orders. Describe
> the relevant tables, then show the 10 most recent orders using the actual column
> names. If the result is truncated, narrow the query.

## Tools

| Tool | Purpose |
|---|---|
| `list_connections` | List available connections and their SQL dialects. |
| `search_schema` | Find tables and views by search terms. |
| `describe_schema` | Inspect columns, keys, and indexes. |
| `query` | Run a single bounded `SELECT`, including read-only CTEs. |
| `explain` | Inspect a query plan without executing the query (`EXPLAIN ANALYZE` is disabled). |

Start with discovery, describe the relevant tables, then query or explain. Use `?`
for MySQL parameters and `$1`, `$2`, … for PostgreSQL. When a result reports
`truncated: true`, narrow the columns, filters, or row limit before trying again.

See the [MCP reference](docs/mcp.md) for tool inputs, structured results, and errors.

## Security

Warden adds SQL policy checks, query limits, and auditing. A **dedicated database
role with read-only privileges** is required: its grants determine what the agent
can read and prevent writes independently of Warden. Scope those grants narrowly
and prefer a read replica.

Keep these boundaries in mind:

- **Local access:** an agent with unrestricted shell access may read the same
  environment variables and files as Warden. Use local stdio with development data;
  authenticated remote production deployment is not supported yet.
- **Table allowlists:** an allowed view can read other tables. Database `SELECT`
  privileges define the read boundary.
- **Column redaction:** it reduces accidental exposure, but aliases and expressions
  can bypass it. It is not access control.
- **Returned data:** database values are not sanitized and may contain instructions
  intended to influence an agent.

`query`, `explain`, `search_schema`, and `describe_schema` are audited.
`list_connections` reads configuration metadata and does not create an audit record.

Read the [security guide](docs/security.md) for database grants, the threat model,
and deployment guidance.

## Documentation

| Guide | What you'll find |
|---|---|
| [Configuration and operations](docs/operations.md) | Connections, secrets, TLS, query limits, audit logging, and CLI options. |
| [MCP reference](docs/mcp.md) | Tool inputs, outputs, and protocol behavior. |
| [Security](docs/security.md) | Database permissions, protections, and limitations. |
| [Architecture](docs/architecture.md) | Crate responsibilities and how the system fits together. |
| [Testing](docs/testing.md) | Test suites, database integration tests, and coverage. |
| [Changelog](CHANGELOG.md) | Changes in each release. |

## Contributing

Bug reports and feature requests are welcome through
[GitHub Issues](https://github.com/rodrigodotdev/warden/issues). Include your Warden
version and steps to reproduce a problem, without credentials or sensitive data.

Before contributing code, read the [specification](SPEC.md) and
[contributor guidelines](AGENTS.md). The Rust toolchain is pinned in
`rust-toolchain.toml`; [mise](https://mise.jdx.dev/) installs the auxiliary tools:

```bash
mise trust
mise install
mise run ci
```

`mise run ci` runs the local checks, including formatting, Clippy, workspace tests,
and independent crate builds. To run database integration tests with Docker:

```bash
mise run test:docker
```

Use `mise tasks` to list individual checks. See the [testing guide](docs/testing.md)
for the full workflow.

## License

Licensed under the [MIT License](LICENSE).
Third-party license notices are included in [LICENSES/](LICENSES/).
