# warden-sql-mcp

An alias for [`warden-db-mcp`](https://www.npmjs.com/package/warden-db-mcp), which is
the package to install.

It runs the same server: this one depends on it and calls it. It is published so the
name resolves to Warden rather than to something else, because an MCP server sits next
to database credentials.

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

<https://github.com/rodrigodotdev/warden> — MIT licensed.
