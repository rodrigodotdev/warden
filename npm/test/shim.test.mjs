import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { TARGETS } from "../targets.mjs";

// The shim is CommonJS so it can use `require.resolve` to find the platform package.
const require = createRequire(import.meta.url);
const shim = require("../launcher/bin/warden.js");

test("every target in the map resolves to its own package", () => {
  for (const target of TARGETS) {
    assert.equal(shim.packageFor(target.platform, target.arch), target.package);
  }
});

test("an unsupported platform resolves to nothing rather than guessing", () => {
  assert.equal(shim.packageFor("linux", "ppc64"), null);
  assert.equal(shim.packageFor("freebsd", "x64"), null);
  assert.equal(shim.packageFor("win32", "arm64"), null);
});

test("the shim declares the same targets as the build map", () => {
  // Drift between the two is the failure this catches: a target added to the build
  // but not to the shim installs a package the launcher can never find.
  const fromShim = shim.SUPPORTED.map((entry) => `${entry.platform}-${entry.arch}`).sort();
  const fromMap = TARGETS.map((entry) => `${entry.platform}-${entry.arch}`).sort();
  assert.deepEqual(fromShim, fromMap);
});

test("the build assembles one launcher and one package per target", () => {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "warden-npm-"));
  const archives = path.join(work, "archives");
  const out = path.join(work, "out");

  // A stand-in for each unpacked release archive: the build script only needs the
  // binary at the path the archive puts it at.
  for (const target of TARGETS) {
    const staged = path.join(archives, `warden-v9.9.9-${target.rustTarget}`);
    fs.mkdirSync(staged, { recursive: true });
    fs.writeFileSync(path.join(staged, target.binary), "#!/bin/sh\nexit 0\n");
    fs.writeFileSync(path.join(staged, "LICENSE"), "MIT\n");
    fs.mkdirSync(path.join(staged, "LICENSES"), { recursive: true });
    fs.writeFileSync(path.join(staged, "LICENSES", "notice.txt"), "notice\n");
  }

  execFileSync(process.execPath, [
    path.join(import.meta.dirname, "..", "build.mjs"),
    "--version", "9.9.9",
    "--archives", archives,
    "--out", out,
  ]);

  const launcher = JSON.parse(fs.readFileSync(path.join(out, "warden-db-mcp", "package.json"), "utf8"));
  assert.equal(launcher.version, "9.9.9");
  assert.equal(launcher.bin.warden, "bin/warden.js");
  assert.equal(launcher.scripts, undefined, "the launcher must declare no scripts at all");
  for (const target of TARGETS) {
    assert.equal(launcher.optionalDependencies[target.package], "9.9.9");

    const platform = JSON.parse(
      fs.readFileSync(path.join(out, target.package, "package.json"), "utf8"),
    );
    assert.deepEqual(platform.os, [target.platform]);
    assert.deepEqual(platform.cpu, [target.arch]);
    assert.equal(platform.scripts, undefined, "a platform package must declare no scripts");
    assert.ok(fs.existsSync(path.join(out, target.package, "bin", target.binary)));
    // MIT requires the notice to travel with the software, and CDLA-Permissive-2.0
    // requires the webpki-roots notice to accompany the redistributed root data.
    assert.ok(fs.existsSync(path.join(out, target.package, "LICENSE")));
    assert.ok(fs.existsSync(path.join(out, target.package, "LICENSES", "notice.txt")));
  }

  fs.rmSync(work, { recursive: true, force: true });
});

test("a unix binary is assembled executable", { skip: process.platform === "win32" }, () => {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "warden-npm-mode-"));
  const archives = path.join(work, "archives");
  const out = path.join(work, "out");
  const target = TARGETS.find((entry) => entry.platform === "linux" && entry.arch === "x64");
  const staged = path.join(archives, `warden-v9.9.9-${target.rustTarget}`);
  fs.mkdirSync(staged, { recursive: true });
  fs.writeFileSync(path.join(staged, target.binary), "#!/bin/sh\nexit 0\n", { mode: 0o644 });
  fs.writeFileSync(path.join(staged, "LICENSE"), "MIT\n");
  fs.mkdirSync(path.join(staged, "LICENSES"), { recursive: true });
  fs.writeFileSync(path.join(staged, "LICENSES", "notice.txt"), "notice\n");

  execFileSync(process.execPath, [
    path.join(import.meta.dirname, "..", "build.mjs"),
    "--version", "9.9.9",
    "--archives", archives,
    "--out", out,
    "--only", target.rustTarget,
  ]);

  // npm preserves the mode from the tarball. A binary published 0644 cannot be run.
  const mode = fs.statSync(path.join(out, target.package, "bin", target.binary)).mode;
  assert.equal(mode & 0o111, 0o111, "the binary must be executable");

  fs.rmSync(work, { recursive: true, force: true });
});
