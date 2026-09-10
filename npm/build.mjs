// Assembles the publishable npm packages from unpacked release archives.
//
// Input is a directory holding one unpacked archive per target, named exactly as
// `release.yml` names it: `warden-v<version>-<rust target>/`. Output is a directory
// holding one publishable package per target plus the launcher.
//
// No package this script writes declares any lifecycle script. That is asserted by the
// test suite, not merely intended: an install script is the thing this distribution
// exists to avoid.

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { ALIAS_PACKAGE, LAUNCHER_PACKAGE, TARGETS } from "./targets.mjs";

const REPOSITORY = "https://github.com/rodrigodotdev/warden";

// Every source path is resolved against this file, never against the working
// directory: CI runs `node npm/build.mjs` from the repository root and `npm test` runs
// it from `npm/`, and a relative literal cannot be right in both.
const HERE = path.dirname(fileURLToPath(import.meta.url));

function argument(name) {
  const index = process.argv.indexOf(`--${name}`);
  if (index === -1 || index + 1 >= process.argv.length) {
    return null;
  }
  return process.argv[index + 1];
}

function required(name) {
  const value = argument(name);
  if (value === null) {
    process.stderr.write(`build: --${name} is required\n`);
    process.exit(2);
  }
  return value;
}

const version = required("version");
const archives = required("archives");
const out = required("out");
const only = argument("only");

const selected = only === null ? TARGETS : TARGETS.filter((t) => t.rustTarget === only);
if (selected.length === 0) {
  process.stderr.write(`build: --only ${only} matches no target\n`);
  process.exit(2);
}

/** Copies the license files every package must carry. */
function copyLicenses(from, to) {
  fs.copyFileSync(path.join(from, "LICENSE"), path.join(to, "LICENSE"));
  fs.cpSync(path.join(from, "LICENSES"), path.join(to, "LICENSES"), { recursive: true });
}

for (const target of selected) {
  const staged = path.join(archives, `warden-v${version}-${target.rustTarget}`);
  const destination = path.join(out, target.package);
  fs.mkdirSync(path.join(destination, "bin"), { recursive: true });

  const binary = path.join(destination, "bin", target.binary);
  fs.copyFileSync(path.join(staged, target.binary), binary);
  // npm publishes the mode it finds. A binary that arrives 0644 cannot be executed,
  // and the failure surfaces as EACCES from the launcher rather than as a bad package.
  fs.chmodSync(binary, 0o755);
  copyLicenses(staged, destination);
  // One shared page for all five, so npmjs.com does not render a blank listing for a
  // security product. It says what the package is and points at the one to install.
  fs.copyFileSync(path.join(HERE, "platform", "README.md"), path.join(destination, "README.md"));

  fs.writeFileSync(
    path.join(destination, "package.json"),
    `${JSON.stringify(
      {
        name: target.package,
        version,
        description: `Warden binary for ${target.platform} ${target.arch}. Installed automatically by ${LAUNCHER_PACKAGE}.`,
        license: "MIT",
        repository: { type: "git", url: `git+${REPOSITORY}.git` },
        homepage: REPOSITORY,
        bugs: { url: `${REPOSITORY}/issues` },
        os: [target.platform],
        cpu: [target.arch],
        // The Linux binaries link glibc. Without this, npm installs the package on
        // Alpine — `os` and `cpu` both match — and `spawnSync` then fails with ENOENT
        // for the missing loader, which reads as a missing file. npm 10.4 and later,
        // pnpm, and Yarn all honour `libc`, so the optional dependency is skipped
        // instead and the launcher's own "is not installed" message is what appears.
        ...(target.platform === "linux" ? { libc: ["glibc"] } : {}),
        files: ["bin/", "README.md", "LICENSE", "LICENSES/"],
        preferUnplugged: true,
      },
      null,
      2,
    )}\n`,
  );
}

// The launcher, only when the whole set was built: a partial run would publish a
// launcher whose optional dependencies do not all exist.
if (only === null) {
  const destination = path.join(out, LAUNCHER_PACKAGE);
  fs.mkdirSync(path.join(destination, "bin"), { recursive: true });
  fs.copyFileSync(
    path.join(HERE, "launcher", "bin", "warden.js"),
    path.join(destination, "bin", "warden.js"),
  );
  fs.chmodSync(path.join(destination, "bin", "warden.js"), 0o755);
  fs.copyFileSync(path.join(HERE, "launcher", "README.md"), path.join(destination, "README.md"));
  copyLicenses(path.join(archives, `warden-v${version}-${TARGETS[0].rustTarget}`), destination);

  const optionalDependencies = {};
  for (const target of TARGETS) {
    optionalDependencies[target.package] = version;
  }

  fs.writeFileSync(
    path.join(destination, "package.json"),
    `${JSON.stringify(
      {
        name: LAUNCHER_PACKAGE,
        version,
        description:
          "Safe, read-only MCP access to MySQL and PostgreSQL for AI agents. Parses and policy-checks every statement.",
        license: "MIT",
        repository: { type: "git", url: `git+${REPOSITORY}.git` },
        homepage: REPOSITORY,
        bugs: { url: `${REPOSITORY}/issues` },
        keywords: [
          "mcp",
          "model-context-protocol",
          "mysql",
          "postgresql",
          "sql",
          "read-only",
          "database",
          "agent",
        ],
        bin: { warden: "bin/warden.js" },
        engines: { node: ">=18" },
        files: ["bin/", "README.md", "LICENSE", "LICENSES/"],
        optionalDependencies,
      },
      null,
      2,
    )}\n`,
  );

  // The alias. It is written from the same run as the launcher, and only from a full
  // run, because it pins the launcher's exact version and that version must exist.
  const aliasDestination = path.join(out, ALIAS_PACKAGE);
  fs.mkdirSync(path.join(aliasDestination, "bin"), { recursive: true });
  fs.copyFileSync(
    path.join(HERE, "alias", "bin", "warden.js"),
    path.join(aliasDestination, "bin", "warden.js"),
  );
  fs.chmodSync(path.join(aliasDestination, "bin", "warden.js"), 0o755);
  fs.copyFileSync(path.join(HERE, "alias", "README.md"), path.join(aliasDestination, "README.md"));
  copyLicenses(path.join(archives, `warden-v${version}-${TARGETS[0].rustTarget}`), aliasDestination);

  fs.writeFileSync(
    path.join(aliasDestination, "package.json"),
    `${JSON.stringify(
      {
        name: ALIAS_PACKAGE,
        version,
        description: `Alias for ${LAUNCHER_PACKAGE}, which is the package to install.`,
        license: "MIT",
        repository: { type: "git", url: `git+${REPOSITORY}.git` },
        homepage: REPOSITORY,
        bin: { warden: "bin/warden.js" },
        engines: { node: ">=18" },
        files: ["bin/", "README.md", "LICENSE", "LICENSES/"],
        dependencies: { [LAUNCHER_PACKAGE]: version },
      },
      null,
      2,
    )}\n`,
  );
}

process.stderr.write(
  `build: wrote ${selected.length} platform package(s)${only === null ? " plus the launcher and its alias" : ""} to ${out}\n`,
);
