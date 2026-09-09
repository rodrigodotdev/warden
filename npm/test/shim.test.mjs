import assert from "node:assert/strict";
import { createRequire } from "node:module";
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
