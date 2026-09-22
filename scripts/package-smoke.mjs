import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { log } from "node:console";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import process from "node:process";

const npmCli = process.env.npm_execpath;
assert.ok(npmCli, "Run through npm run smoke:package");

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
    "dist/lock.js",
    "dist/options.js",
    "dist/policy.js",
    "dist/process.js",
    "dist/transcript.js",
    "dist/types.js",
    "dist/unlock.js",
    "dist/util.js",
    "docs/json-v1.md",
    "docs/platform-support.md",
    "docs/safety-race-matrix.md",
    "docs/upstream-handoff-proposal.md",
    "docs/v0.2-migration.md",
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
  const manifest = JSON.parse(readFileSync(join(packageRoot, "package.json"), "utf8"));
  assert.equal(manifest.bin["codex-unlock"], "dist/cli.js");
  assert.deepEqual(manifest.exports, { "./package.json": "./package.json" });
  assert.equal(manifest.main, undefined);
  assert.equal(manifest.types, undefined);
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
  log("Packed artifact matches the allowlist and passes offline CLI/JSON boundary checks.");
} finally {
  rmSync(directory, { recursive: true, force: true });
}
