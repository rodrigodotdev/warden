#!/usr/bin/env node
"use strict";

// Warden's npm launcher.
//
// This package carries no binary. npm installs exactly one of the platform packages
// below through `optionalDependencies` and its `os`/`cpu` fields, and this file finds
// it and runs it.
//
// There is no install script anywhere in this distribution. Nothing is downloaded and
// nothing is executed at install time: npm resolves the platform itself, which is the
// property that makes a security gateway safe to ship this way.
//
// Nothing here may write to stdout. stdout is the MCP protocol stream
// (`docs/mcp.md` section 5.1), and one stray line makes the server unusable. Every
// diagnostic goes to stderr.

const { spawnSync } = require("node:child_process");
const path = require("node:path");

// Kept in sync with `npm/targets.mjs` by a test, because the two files cannot import
// each other: this one is CommonJS so `require.resolve` is available.
const SUPPORTED = [
  { platform: "linux", arch: "x64", package: "@rodrigodotdev/warden-db-mcp-linux-x64", binary: "warden" },
  { platform: "linux", arch: "arm64", package: "@rodrigodotdev/warden-db-mcp-linux-arm64", binary: "warden" },
  { platform: "darwin", arch: "x64", package: "@rodrigodotdev/warden-db-mcp-darwin-x64", binary: "warden" },
  { platform: "darwin", arch: "arm64", package: "@rodrigodotdev/warden-db-mcp-darwin-arm64", binary: "warden" },
  { platform: "win32", arch: "x64", package: "@rodrigodotdev/warden-db-mcp-win32-x64", binary: "warden.exe" },
];

/** The platform package for a `process.platform`/`process.arch` pair, or null. */
function packageFor(platform, arch) {
  const match = SUPPORTED.find((entry) => entry.platform === platform && entry.arch === arch);
  return match ? match.package : null;
}

/** The absolute path of the installed binary, or null when nothing is installed. */
function binaryPath(platform, arch) {
  const match = SUPPORTED.find((entry) => entry.platform === platform && entry.arch === arch);
  if (!match) {
    return null;
  }
  try {
    return require.resolve(`${match.package}/bin/${match.binary}`);
  } catch (_notInstalled) {
    return null;
  }
}

function main() {
  const { platform, arch } = process;
  const wanted = packageFor(platform, arch);

  if (wanted === null) {
    process.stderr.write(
      `warden: no prebuilt binary for ${platform}-${arch}.\n` +
        "warden: supported: " +
        SUPPORTED.map((entry) => `${entry.platform}-${entry.arch}`).join(", ") +
        "\n" +
        "warden: the Linux builds link glibc, so Alpine and other musl distributions\n" +
        "warden: are not covered. Build from source: https://github.com/rodrigodotdev/warden\n",
    );
    process.exit(1);
  }

  const binary = binaryPath(platform, arch);
  if (binary === null) {
    process.stderr.write(
      `warden: ${wanted} is not installed.\n` +
        "warden: it is an optional dependency, so an install run with --no-optional or\n" +
        "warden: --omit=optional skips it. Reinstall without that flag.\n",
    );
    // The platform packages declare `libc: ["glibc"]`, so a musl distribution is a
    // second way to reach this branch: npm skipped the optional dependency on purpose
    // rather than being told to.
    if (platform === "linux") {
      process.stderr.write(
        "warden: on Alpine or another musl distribution it is skipped by design — the\n" +
          "warden: Linux builds link glibc. Build from source:\n" +
          "warden: https://github.com/rodrigodotdev/warden\n",
      );
    }
    process.exit(1);
  }

  // `stdio: "inherit"` hands the real descriptors to the child, so the MCP stream is
  // the process's own stdin and stdout with nothing in between — no buffering, no
  // encoding, no chance of this file appearing in the protocol.
  const result = spawnSync(binary, process.argv.slice(2), { stdio: "inherit" });

  if (result.error) {
    process.stderr.write(`warden: ${path.basename(binary)} could not be started: ${result.error.message}\n`);
    // A binary that resolved but will not start is, on Linux, almost always a glibc
    // build on a musl distribution: the kernel reports the missing loader as ENOENT
    // for the executable itself, which reads as "the file is not there" when the file
    // plainly is. Say so here rather than leaving the operator to decode it.
    if (platform === "linux") {
      process.stderr.write(
        "warden: on Alpine or another musl distribution this is expected — the Linux\n" +
          "warden: builds link glibc. Build from source: https://github.com/rodrigodotdev/warden\n",
      );
    }
    process.exit(1);
  }
  // A child killed by a signal reports a null status. Exit non-zero rather than
  // reporting success for a process that never finished.
  process.exit(result.status === null ? 1 : result.status);
}

// `main` is exported for the `warden-sql-mcp` alias package, which calls it in this
// process rather than spawning a second one. Nothing else should call it.
module.exports = { packageFor, binaryPath, main, SUPPORTED };

if (require.main === module) {
  main();
}
