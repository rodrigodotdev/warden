import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { ALIAS_PACKAGE, LAUNCHER_PACKAGE, TARGETS } from "../targets.mjs";

// The shim is CommonJS so it can use `require.resolve` to find the platform package.
const require = createRequire(import.meta.url);
const SHIM = path.join(import.meta.dirname, "..", "launcher", "bin", "warden.js");
const shim = require(SHIM);

const BUILD = path.join(import.meta.dirname, "..", "build.mjs");
const RELEASE_WORKFLOW = path.join(
  import.meta.dirname,
  "..",
  "..",
  ".github",
  "workflows",
  "release.yml",
);

/** A stand-in for the unpacked release archives, one directory per target. */
function stageArchives(archives, { targets = TARGETS, script = "#!/bin/sh\nexit 0\n", mode } = {}) {
  for (const target of targets) {
    const staged = path.join(archives, `warden-v9.9.9-${target.rustTarget}`);
    fs.mkdirSync(staged, { recursive: true });
    fs.writeFileSync(path.join(staged, target.binary), script, mode === undefined ? {} : { mode });
    fs.writeFileSync(path.join(staged, "LICENSE"), "MIT\n");
    fs.mkdirSync(path.join(staged, "LICENSES"), { recursive: true });
    fs.writeFileSync(path.join(staged, "LICENSES", "notice.txt"), "notice\n");
  }
}

function assemble(archives, out, only) {
  const flags = only === undefined ? [] : ["--only", only];
  execFileSync(process.execPath, [BUILD, "--version", "9.9.9", "--archives", archives, "--out", out, ...flags]);
}

/** Runs `body` against a fresh temporary workspace and removes it afterwards. */
function inWorkspace(prefix, body) {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  try {
    body({ work, archives: path.join(work, "archives"), out: path.join(work, "out") });
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}

/**
 * Runs the shim in a child process with `process.platform`/`process.arch` forced, so
 * `main`'s error paths can be reached from any machine.
 *
 * The forcing lives in a generated entry file rather than in the shim: the shim must
 * carry nothing whose only purpose is to be testable.
 */
function runShimAs(platform, arch) {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "warden-npm-stdout-"));
  try {
    const entry = path.join(work, "entry.cjs");
    fs.writeFileSync(
      entry,
      '"use strict";\n' +
        `Object.defineProperty(process, "platform", { value: ${JSON.stringify(platform)} });\n` +
        `Object.defineProperty(process, "arch", { value: ${JSON.stringify(arch)} });\n` +
        `require(${JSON.stringify(SHIM)}).main();\n`,
    );
    return spawnSync(process.execPath, [entry], { encoding: "utf8" });
  } finally {
    fs.rmSync(work, { recursive: true, force: true });
  }
}

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
  // but not to the shim installs a package the launcher can never find. The whole
  // tuple is compared, not just the platform pair — a shim that said `warden` where
  // the map says `warden.exe` would resolve to nothing on every Windows machine and
  // no other test in this suite would notice.
  const tuple = (entry) => `${entry.platform}-${entry.arch} ${entry.package} ${entry.binary}`;
  assert.deepEqual(shim.SUPPORTED.map(tuple).sort(), TARGETS.map(tuple).sort());
});

test("the release workflow builds exactly the targets the map declares", () => {
  // A target in the matrix but not in the map builds, uploads, and is attested, and
  // then `build.mjs` silently never packages it. A target in the map but not in the
  // matrix makes the npm job fail on a missing archive. Both directions are drift.
  const workflow = fs.readFileSync(RELEASE_WORKFLOW, "utf8");
  const start = workflow.indexOf("        include:");
  const end = workflow.indexOf("\n    steps:", start);
  assert.ok(start !== -1 && end > start, "release.yml no longer has a build matrix to read");

  const matrix = [...workflow.slice(start, end).matchAll(/^ +- target: (\S+)$/gm)].map((m) => m[1]);
  assert.deepEqual(matrix.sort(), TARGETS.map((target) => target.rustTarget).sort());
});

test("the platform packages are scoped and the two public names are not", () => {
  // Five unscoped names differing only by suffix are what npm's anti-squatting
  // heuristic exists to catch, and it caught them: the fifth was refused with
  // "Package name triggered spam detection" after four siblings published. Under a
  // scope the namespace is already the publisher's and there is nothing to decide.
  for (const target of TARGETS) {
    assert.ok(
      target.package.startsWith("@"),
      `${target.package} is unscoped; five sibling names trip npm spam detection`,
    );
    assert.ok(!target.directory.includes("/"), "a directory name cannot carry a scope");
  }

  // The launcher is what a human types and an MCP client spawns, and the alias only
  // holds the neighbouring name if it occupies it. Neither may grow a scope.
  assert.ok(!LAUNCHER_PACKAGE.startsWith("@"), "npx -y warden-db-mcp is the whole point");
  assert.ok(!ALIAS_PACKAGE.startsWith("@"), "a scoped alias holds no unscoped name");
});

test("every npm publish in the release workflow names a directory, not a repo", () => {
  // npm parses a bare `a/b` argument as a GitHub `owner/repo` shorthand before it
  // looks at the filesystem, so `npm publish packages/warden-db-mcp-darwin-arm64`
  // clones over SSH and exits 128 rather than publishing the directory that is
  // plainly there. It cost one tag to learn; the `./` is what makes it a path.
  const workflow = fs.readFileSync(RELEASE_WORKFLOW, "utf8");
  // Comment lines are skipped: the one above this call site quotes the broken form
  // on purpose, and a guard that its own explanation trips is a guard nobody keeps.
  const args = workflow
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("#"))
    .flatMap((line) => [...line.matchAll(/npm publish (\S+)/g)].map((m) => m[1]));

  assert.ok(args.length > 0, "release.yml no longer runs npm publish");
  for (const arg of args) {
    assert.ok(
      arg.startsWith('"./') || arg.startsWith("./"),
      `npm publish ${arg} is a git spec to npm, not a directory`,
    );
  }
});

test("binaryPath returns nothing when there is no package to find", () => {
  assert.equal(shim.binaryPath("freebsd", "x64"), null, "an unsupported pair has no package");
  // Supported, but no platform package is installed beside this checkout, which is the
  // `--omit=optional` and musl-skip case. `require.resolve` throws and the shim must
  // report the absence rather than propagate it.
  assert.equal(shim.binaryPath(TARGETS[0].platform, TARGETS[0].arch), null);
});

test("the shim writes nothing to stdout when it has no binary to run", () => {
  // stdout is the MCP protocol stream. One stray line makes the server unusable, so
  // both of `main`'s failure paths are checked, not just the one this machine takes.
  const unsupported = runShimAs("sunos", "ppc64");
  assert.equal(unsupported.status, 1);
  assert.equal(unsupported.stdout, "", "a diagnostic on stdout would corrupt the MCP stream");
  assert.match(unsupported.stderr, /sunos-ppc64/);

  const notInstalled = runShimAs(TARGETS[0].platform, TARGETS[0].arch);
  assert.equal(notInstalled.status, 1);
  assert.equal(notInstalled.stdout, "", "a diagnostic on stdout would corrupt the MCP stream");
  assert.match(notInstalled.stderr, new RegExp(TARGETS[0].package));
});

test("the assembled alias finds and runs the assembled platform binary", { skip: skipEndToEnd() }, () => {
  // The one test that exercises `binaryPath` against a real installation: the three
  // assembled packages are laid out the way npm lays them out, and the alias's own
  // `bin/warden.js` is run. It covers the deep require, the platform resolution, the
  // argument pass-through, and the stdout rule on the success path at once.
  const target = hostTarget();
  inWorkspace("warden-npm-e2e-", ({ work, archives, out }) => {
    stageArchives(archives, { script: '#!/bin/sh\necho "ran $*" >&2\nexit 0\n' });
    assemble(archives, out);

    // node_modules is laid out by npm name, so the scoped platform package lands
    // under its scope directory — which is exactly what `require.resolve` walks.
    // The build output it comes from is addressed by directory instead.
    const modules = path.join(work, "node_modules");
    for (const [from, to] of [
      [LAUNCHER_PACKAGE, LAUNCHER_PACKAGE],
      [ALIAS_PACKAGE, ALIAS_PACKAGE],
      [target.directory, target.package],
    ]) {
      fs.cpSync(path.join(out, from), path.join(modules, to), { recursive: true });
    }

    const result = spawnSync(
      process.execPath,
      [path.join(modules, ALIAS_PACKAGE, "bin", "warden.js"), "check", "--config", "warden.toml"],
      { encoding: "utf8" },
    );

    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, "", "the launcher must add nothing to the MCP stream");
    assert.match(result.stderr, /ran check --config warden\.toml/);
  });
});

/** The target for the machine running the suite, or undefined when there is none. */
function hostTarget() {
  return TARGETS.find(
    (target) => target.platform === process.platform && target.arch === process.arch,
  );
}

function skipEndToEnd() {
  if (process.platform === "win32") {
    return "the stand-in binary is a shell script";
  }
  return hostTarget() === undefined ? "no prebuilt target for this machine" : false;
}

test("the build assembles one launcher and one package per target", () => {
  inWorkspace("warden-npm-", ({ archives, out }) => {
    stageArchives(archives);
    assemble(archives, out);

    const launcher = JSON.parse(
      fs.readFileSync(path.join(out, LAUNCHER_PACKAGE, "package.json"), "utf8"),
    );
    assert.equal(launcher.version, "9.9.9");
    assert.equal(launcher.bin.warden, "bin/warden.js");
    assert.equal(launcher.scripts, undefined, "the launcher must declare no scripts at all");
    assert.equal(launcher.exports, undefined, "an exports map makes the alias's deep require unresolvable");

    for (const target of TARGETS) {
      assert.equal(launcher.optionalDependencies[target.package], "9.9.9");

      const platform = JSON.parse(
        fs.readFileSync(path.join(out, target.directory, "package.json"), "utf8"),
      );
      assert.deepEqual(platform.os, [target.platform]);
      assert.deepEqual(platform.cpu, [target.arch]);
      // `os` and `cpu` both match on Alpine, so only `libc` keeps npm from installing
      // a glibc binary there and leaving the operator with an ENOENT for a file that
      // exists. It belongs on the Linux packages and nowhere else.
      assert.deepEqual(
        platform.libc,
        target.platform === "linux" ? ["glibc"] : undefined,
        `libc is wrong on ${target.package}`,
      );
      assert.equal(platform.scripts, undefined, "a platform package must declare no scripts");
      // Five blank pages on npmjs.com for a security product is a bad first look.
      assert.equal(platform.homepage, launcher.homepage);
      assert.deepEqual(platform.bugs, launcher.bugs);
      assert.ok(fs.existsSync(path.join(out, target.directory, "README.md")));
      assert.ok(fs.existsSync(path.join(out, target.directory, "bin", target.binary)));
      // MIT requires the notice to travel with the software, and CDLA-Permissive-2.0
      // requires the webpki-roots notice to accompany the redistributed root data.
      assert.ok(fs.existsSync(path.join(out, target.directory, "LICENSE")));
      assert.ok(fs.existsSync(path.join(out, target.directory, "LICENSES", "notice.txt")));
    }
  });
});

test("a unix binary is assembled executable", { skip: process.platform === "win32" }, () => {
  inWorkspace("warden-npm-mode-", ({ archives, out }) => {
    const target = TARGETS.find((entry) => entry.platform === "linux" && entry.arch === "x64");
    stageArchives(archives, { targets: [target], mode: 0o644 });
    assemble(archives, out, target.rustTarget);

    // npm preserves the mode from the tarball. A binary published 0644 cannot be run.
    const mode = fs.statSync(path.join(out, target.directory, "bin", target.binary)).mode;
    assert.equal(mode & 0o111, 0o111, "the binary must be executable");
  });
});

test("the alias pins the launcher exactly and carries no logic", () => {
  inWorkspace("warden-npm-alias-", ({ archives, out }) => {
    stageArchives(archives);
    assemble(archives, out);

    const alias = JSON.parse(fs.readFileSync(path.join(out, ALIAS_PACKAGE, "package.json"), "utf8"));

    assert.equal(alias.name, ALIAS_PACKAGE);
    assert.equal(alias.version, "9.9.9");
    // Exact, not a range: an alias that resolves to "whatever is newest" contradicts a
    // repository that pins action SHAs and builds with `--locked`.
    assert.equal(alias.dependencies[LAUNCHER_PACKAGE], "9.9.9");
    assert.equal(alias.scripts, undefined, "the alias must declare no scripts");
    assert.equal(alias.optionalDependencies, undefined, "the launcher owns the binaries");
    assert.equal(alias.bin.warden, "bin/warden.js");

    // It carries no binary of its own — that is the whole point of an alias.
    assert.ok(!fs.existsSync(path.join(out, ALIAS_PACKAGE, "bin", "warden")));
  });
});
