import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { log } from "node:console";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import process from "node:process";

const npmCli = process.env.npm_execpath;
assert.ok(npmCli, "Run through npm run smoke:package");

// npm-shrinkwrap.json is the single lockfile: it pins the native runtime tree for
// consumers, so the published manifest must match it exactly.
const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
const workspaceManifest = readJson(resolve("package.json"));
const shrinkwrap = readJson(resolve("npm-shrinkwrap.json"));
const pinnedRuntime = {
  "fs-ext-extra-prebuilt": shrinkwrap.packages["node_modules/fs-ext-extra-prebuilt"]?.version,
  nan: shrinkwrap.packages["node_modules/nan"]?.version,
};
for (const [name, version] of Object.entries(pinnedRuntime)) {
  assert.match(version ?? "", /^\d+\.\d+\.\d+$/, `npm-shrinkwrap.json must pin ${name}`);
}
assert.deepEqual(
  workspaceManifest.dependencies,
  { "fs-ext-extra-prebuilt": pinnedRuntime["fs-ext-extra-prebuilt"] },
  "The native runtime dependency must be an exact version equal to npm-shrinkwrap.json",
);
assert.deepEqual(
  shrinkwrap.packages[""].dependencies,
  workspaceManifest.dependencies,
  "npm-shrinkwrap.json must be regenerated after changing runtime dependencies",
);

const directory = mkdtempSync(join(tmpdir(), "codex-unlock-package-smoke-"));
const npm = (args, cwd = process.cwd()) =>
  execFileSync(process.execPath, [npmCli, ...args], {
    cwd,
    encoding: "utf8",
    timeout: 120_000,
    stdio: ["ignore", "pipe", "pipe"],
  });

try {
  const [packed] = JSON.parse(
    npm(["pack", "--json", "--ignore-scripts", "--pack-destination", directory]),
  );
  const expectedFiles = [
    "CHANGELOG.md",
    "LICENSE",
    "README.md",
    "dist/cli.js",
    "dist/coordination.js",
    "dist/doctor.js",
    "dist/inspection.js",
    "dist/json-types.d.ts",
    "dist/lock.js",
    "dist/options.js",
    "dist/policy.js",
    "dist/process.js",
    "dist/transcript.js",
    "dist/types.js",
    "dist/types.d.ts",
    "dist/unlock.js",
    "dist/update.js",
    "dist/util.js",
    "docs/cli-reference.md",
    "docs/json-v1.md",
    "docs/platform-support.md",
    "docs/safety-race-matrix.md",
    "docs/update-security.md",
    "docs/upstream-handoff-proposal.md",
    "docs/v0.2-migration.md",
    "npm-shrinkwrap.json",
    "package.json",
    "schemas/codex-unlock-v1.schema.json",
  ].sort();
  assert.deepEqual(
    packed.files.map(({ path }) => path).sort(),
    expectedFiles,
    "Package contents must match the explicit public artifact allowlist",
  );

  const cacheDirectory = join(directory, "npm-cache");
  const primeDirectory = join(directory, "cache-prime");
  mkdirSync(primeDirectory);
  npm(
    [
      "install",
      "--prefix",
      primeDirectory,
      "--cache",
      cacheDirectory,
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      join(directory, packed.filename),
    ],
    primeDirectory,
  );
  rmSync(primeDirectory, { recursive: true, force: true });

  const installDirectory = join(directory, "installation");
  mkdirSync(installDirectory);
  npm(
    [
      "install",
      "--prefix",
      installDirectory,
      "--cache",
      cacheDirectory,
      "--offline",
      "--omit=dev",
      "--no-audit",
      "--no-fund",
      join(directory, packed.filename),
    ],
    installDirectory,
  );

  const packageRoot = join(installDirectory, "node_modules", "codex-unlock");
  const manifest = readJson(join(packageRoot, "package.json"));

  // Resolve the way the installed CLI does, so a hoisted or nested copy is checked.
  const installedVersion = (name, fromPackageRoot) => {
    const manifestPath = createRequire(join(fromPackageRoot, "package.json"))
      .resolve(`${name}/package.json`);
    assert.ok(
      !relative(realpathSync(installDirectory), manifestPath).startsWith(".."),
      `${name} must resolve inside the clean installation`,
    );
    return { root: dirname(manifestPath), version: readJson(manifestPath).version };
  };
  const nativeDependency = installedVersion("fs-ext-extra-prebuilt", packageRoot);
  assert.deepEqual(
    {
      "fs-ext-extra-prebuilt": nativeDependency.version,
      nan: installedVersion("nan", nativeDependency.root).version,
    },
    pinnedRuntime,
    "Installed runtime dependencies must equal the published npm-shrinkwrap.json pins",
  );
  assert.equal(manifest.bin["codex-unlock"], "dist/cli.js");
  assert.deepEqual(manifest.exports, {
    "./types": { types: "./dist/json-types.d.ts" },
    "./package.json": "./package.json",
  });
  assert.equal(manifest.main, undefined);
  assert.equal(manifest.types, "dist/json-types.d.ts");
  assert.match(readFileSync(resolve(packageRoot, manifest.types), "utf8"), /export type/);
  assert.equal(manifest.scripts.prepare, "npm run build");
  assert.equal(manifest.scripts.prepack, undefined);
  assert.match(
    readFileSync(resolve(packageRoot, manifest.bin["codex-unlock"]), "utf8"),
    /^#!\/usr\/bin\/env node/,
  );
  assert.equal(
    npm(["exec", "--offline", "--", "codex-unlock", "--version"], installDirectory).trim(),
    manifest.version,
  );
  assert.match(
    npm(["exec", "--offline", "--", "codex-unlock", "--help"], installDirectory),
    /codex-unlock/,
  );
  const jsonOutput = npm(
    ["exec", "--offline", "--", "codex-unlock", "list", "--json", "--codex-home", join(directory, "empty-home")],
    installDirectory,
  );
  assert.equal(JSON.parse(jsonOutput).schemaVersion, 1);

  assert.throws(
    () => execFileSync(
      process.execPath,
      ["--input-type=module", "--eval", "await import('codex-unlock')"],
      { cwd: installDirectory, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    ),
    (error) => error?.stderr?.includes("ERR_PACKAGE_PATH_NOT_EXPORTED"),
  );
  assert.throws(
    () => execFileSync(
      process.execPath,
      ["--input-type=module", "--eval", "await import('codex-unlock/dist/doctor.js')"],
      { cwd: installDirectory, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    ),
    (error) => error?.stderr?.includes("ERR_PACKAGE_PATH_NOT_EXPORTED"),
  );
  for (const subpath of ["types", "dist/types.js", "dist/types.d.ts"]) {
    assert.throws(
      () => execFileSync(
        process.execPath,
        ["--input-type=module", "--eval", `await import('codex-unlock/${subpath}')`],
        { cwd: installDirectory, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
      ),
      (error) => error?.stderr?.includes("ERR_PACKAGE_PATH_NOT_EXPORTED"),
    );
  }

  // Compile against the installed tarball, not workspace source or declarations.
  const consumer = join(installDirectory, "json-types-consumer.mts");
  copyFileSync(resolve("scripts/fixtures/json-types-consumer.mts"), consumer);
  const emptyTypeRoots = join(installDirectory, "empty-types");
  mkdirSync(emptyTypeRoots);
  for (const [module, moduleResolution] of [["NodeNext", "NodeNext"], ["ESNext", "Bundler"]]) {
    execFileSync(
      process.execPath,
      [
        resolve("node_modules/typescript/bin/tsc"), "--noEmit", "--strict",
        "--target", "ES2022", "--lib", "ES2022", "--module", module,
        "--moduleResolution", moduleResolution, "--typeRoots", emptyTypeRoots,
        "--verbatimModuleSyntax", consumer,
      ],
      { cwd: installDirectory, encoding: "utf8", timeout: 30_000, stdio: ["ignore", "pipe", "pipe"] },
    );
  }
  log("Packed artifact passes pinned-dependency, offline CLI/JSON, and type-only consumer boundary checks.");
} finally {
  rmSync(directory, { recursive: true, force: true });
}
