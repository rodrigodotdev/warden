# Warden platform binary

This package carries one prebuilt `warden` binary and nothing else. It is not the
package to install.

Install [`warden-db-mcp`](https://www.npmjs.com/package/warden-db-mcp) — safe,
read-only database access for AI agents over the Model Context Protocol. npm picks
exactly one of these platform packages through its `os` and `cpu` fields and the
launcher runs it. There is no install script anywhere in the set: nothing is downloaded
or executed while installing.

<https://github.com/rodrigodotdev/warden> — MIT licensed.
