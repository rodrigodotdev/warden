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

That `warden.toml` is yours to write, and two commands write most of it:

```bash
npx -y warden-db-mcp init --config /absolute/path/to/warden.toml
npx -y warden-db-mcp role --dialect postgresql --user warden_ro --database app
```

`init` writes a starting configuration and refuses to overwrite one that already
exists. `role` prints the `CREATE ROLE` and `GRANT` statements for Warden's dedicated
read-only role — read them, set a real password, and run them as an administrator. That
role, not Warden, is the write boundary.

Before an agent points at it, check the configuration:

```bash
npx -y warden-db-mcp check --config /absolute/path/to/warden.toml
```

`check` validates the file and probes every connection, so a bad DSN or a missing
read-only grant surfaces as an error you can read rather than as a failing tool call.
`npx -y warden-db-mcp version` reports which build is installed, and
`npx -y warden-db-mcp help` lists the whole command surface: `serve`, `check`, `init`,
`role`, `mcp-config`, `version`, `help`.

`mcp-config` prints the client block above with real absolute paths in it, but it
resolves the path of the running executable — under `npx` that is a file inside a cache
npm is free to evict. Use it from a binary installed by Homebrew or the release archive;
through npm, the `"command": "npx"` block above is the stable one.

## What this package contains

A launcher with no binary of its own. npm installs one prebuilt platform package —
Linux and macOS on x64 and arm64, Windows on x64 — and this launcher runs it. **There is
no install script**: nothing is downloaded or executed at install time.

The Linux builds link glibc. On Alpine or another musl distribution, build from source.

## Documentation and source

<https://github.com/rodrigodotdev/warden>

MIT licensed.
