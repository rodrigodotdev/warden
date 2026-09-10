// The one place the platform map lives. The build script reads it to assemble the
// packages and the tests read it to check the shim agrees, so a new target is added
// here and nowhere else.
//
// `rustTarget` is the triple in the release archive's file name; `platform` and `arch`
// are the values Node reports at runtime. `package` is the npm name and `directory` is
// where the build script writes it: a scoped name carries a `/`, which is a path
// separator and not a directory name, so the two cannot be the same string.
//
// The platform packages are scoped and the launcher is not. Five unscoped names
// differing only by suffix are what npm's anti-squatting heuristic is built to catch,
// and it caught them: `warden-db-mcp-win32-x64` was refused with "Package name
// triggered spam detection" after four siblings went through. Under a scope the
// namespace is already the publisher's, so the heuristic has nothing to decide. Nobody
// types these names — `optionalDependencies` and `require.resolve` are the only things
// that read them — so scoping costs the reader nothing.
export const TARGETS = [
  {
    rustTarget: "x86_64-unknown-linux-gnu",
    platform: "linux",
    arch: "x64",
    package: "@rodrigodotdev/warden-db-mcp-linux-x64",
    directory: "warden-db-mcp-linux-x64",
    binary: "warden",
  },
  {
    rustTarget: "aarch64-unknown-linux-gnu",
    platform: "linux",
    arch: "arm64",
    package: "@rodrigodotdev/warden-db-mcp-linux-arm64",
    directory: "warden-db-mcp-linux-arm64",
    binary: "warden",
  },
  {
    rustTarget: "x86_64-apple-darwin",
    platform: "darwin",
    arch: "x64",
    package: "@rodrigodotdev/warden-db-mcp-darwin-x64",
    directory: "warden-db-mcp-darwin-x64",
    binary: "warden",
  },
  {
    rustTarget: "aarch64-apple-darwin",
    platform: "darwin",
    arch: "arm64",
    package: "@rodrigodotdev/warden-db-mcp-darwin-arm64",
    directory: "warden-db-mcp-darwin-arm64",
    binary: "warden",
  },
  {
    rustTarget: "x86_64-pc-windows-msvc",
    platform: "win32",
    arch: "x64",
    package: "@rodrigodotdev/warden-db-mcp-win32-x64",
    directory: "warden-db-mcp-win32-x64",
    binary: "warden.exe",
  },
];

// Unscoped on purpose: this is the name a human types and an MCP client spawns.
// `npx -y warden-db-mcp` is the whole point, and a scope would put a namespace in
// front of it for no gain. One distinctive name trips no heuristic.
export const LAUNCHER_PACKAGE = "warden-db-mcp";

// The neighbouring name, published as a working alias rather than left for someone
// else. An MCP server that installs itself next to database credentials is a name
// worth holding, and npm's dispute policy only protects a name that is actually used.
export const ALIAS_PACKAGE = "warden-sql-mcp";
