# warden-db-mcp

Safe, read-only database access for AI agents, over the Model Context Protocol.

Warden gives an agent five focused tools for exploring MySQL and PostgreSQL — discover a
schema, inspect relations, run a bounded `SELECT`, examine a query plan — while the
database credentials stay in the Warden process. Every statement is parsed and
policy-checked before it runs, and only a single `SELECT` can reach execution.

## Use it

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

Before an agent points at it, check the configuration:

```bash
npx -y warden-db-mcp check --config /absolute/path/to/warden.toml
```

`check` validates the file and probes every connection, so a bad DSN or a missing
read-only grant surfaces as an error you can read rather than as a failing tool call.
`npx -y warden-db-mcp version` reports which build is installed, and
`npx -y warden-db-mcp help` lists the whole command surface: `serve`, `check`,
`version`, `help`.

## What this package contains

A launcher with no binary of its own. npm installs one prebuilt platform package —
Linux and macOS on x64 and arm64, Windows on x64 — and this launcher runs it. **There is
no install script**: nothing is downloaded or executed at install time.

The Linux builds link glibc. On Alpine or another musl distribution, build from source.

## Documentation and source

<https://github.com/rodrigodotdev/warden>

MIT licensed.
