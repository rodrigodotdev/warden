#!/usr/bin/env node
"use strict";

// The `warden-sql-mcp` alias.
//
// This package exists so the neighbouring name cannot become someone else's MCP
// server installing itself next to database credentials. It is a working alias rather
// than a placeholder: npm's name-dispute policy protects a name that is used, not one
// that is merely held.
//
// `main` runs in this process rather than spawning a second one, so stdio stays the
// process's own descriptors and the MCP stream is untouched. The deep require works
// because the launcher declares no `exports` map — and must not start declaring one.

require("warden-db-mcp/bin/warden.js").main();
