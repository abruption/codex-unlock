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
  const publicFile = /^(dist\/.+\.(?:js|d\.ts)|package\.json|README\.md|CHANGELOG\.md|LICENSE|docs\/upstream-handoff-proposal\.md)$/;
  assert.ok(
    packed.files.every(({ path }) => publicFile.test(path)),
    "Package must contain only runtime JS/types and public documentation",
  );
  for (const path of [
    "dist/cli.js",
    "dist/doctor.js",
    "dist/doctor.d.ts",
    "docs/upstream-handoff-proposal.md",
  ]) {
    assert.ok(
      packed.files.some((file) => file.path === path),
      `Missing ${path}`,
    );
  }

  const installDirectory = join(directory, "installation");
  mkdirSync(installDirectory);
  npm(
    [
      "install",
      "--prefix",
      installDirectory,
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
  log("Packed artifact installs and passes help/version checks.");
} finally {
  rmSync(directory, { recursive: true, force: true });
}
