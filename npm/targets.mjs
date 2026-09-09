// The one place the platform map lives. The build script reads it to assemble the
// packages and the tests read it to check the shim agrees, so a new target is added
// here and nowhere else.
//
// `rustTarget` is the triple in the release archive's file name; `platform` and `arch`
// are the values Node reports at runtime.
export const TARGETS = [
  {
    rustTarget: "x86_64-unknown-linux-gnu",
    platform: "linux",
    arch: "x64",
    package: "warden-db-mcp-linux-x64",
    binary: "warden",
  },
  {
    rustTarget: "aarch64-unknown-linux-gnu",
    platform: "linux",
    arch: "arm64",
    package: "warden-db-mcp-linux-arm64",
    binary: "warden",
  },
  {
    rustTarget: "x86_64-apple-darwin",
    platform: "darwin",
    arch: "x64",
    package: "warden-db-mcp-darwin-x64",
    binary: "warden",
  },
  {
    rustTarget: "aarch64-apple-darwin",
    platform: "darwin",
    arch: "arm64",
    package: "warden-db-mcp-darwin-arm64",
    binary: "warden",
  },
  {
    rustTarget: "x86_64-pc-windows-msvc",
    platform: "win32",
    arch: "x64",
    package: "warden-db-mcp-win32-x64",
    binary: "warden.exe",
  },
];

export const LAUNCHER_PACKAGE = "warden-db-mcp";
