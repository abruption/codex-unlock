import assert from "node:assert/strict";
import { execFile, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { createRequire } from "node:module";
import { join } from "node:path";
import process from "node:process";
import test from "node:test";
import { promisify } from "node:util";

import { artifactRegistry } from "../scripts/package-registry.mjs";

test("registry metadata applies shrinkwrap to exact artifact bytes, unlike file installs", { timeout: 120_000 }, async () => {
  const root = mkdtempSync(join(tmpdir(), "codex-registry-test-"));
  const npmCli = process.env.npm_execpath;
  assert.ok(npmCli, "Run this test through npm test");
  const env = Object.fromEntries(Object.entries(process.env)
    .filter(([key]) => !/^npm_config_/i.test(key) && key !== "NODE_ENV"));
  const config = join(root, "empty-npmrc");
  const globalConfig = join(root, "empty-global-npmrc");
  writeFileSync(config, "");
  writeFileSync(globalConfig, "");
  const npmArgs = [npmCli, "--userconfig", config, "--globalconfig", globalConfig, "--update-notifier=false"];
  const pack = (name, version, extra = {}, shrinkwrap) => {
    const directory = join(root, `${name}-${version}`);
    mkdirSync(directory);
    const manifest = { name, version, ...extra };
    writeFileSync(join(directory, "package.json"), JSON.stringify(manifest));
    if (shrinkwrap) writeFileSync(join(directory, "npm-shrinkwrap.json"), JSON.stringify(shrinkwrap));
    const [result] = JSON.parse(execFileSync(process.execPath,
      [...npmArgs, "pack", "--json", "--ignore-scripts", "--cache", join(root, "pack-cache")],
      { cwd: directory, env, encoding: "utf8", timeout: 20_000 }));
    const path = join(directory, result.filename);
    return { manifest, tarball: readFileSync(path), path, hasShrinkwrap: Boolean(shrinkwrap) };
  };
  let registry;
  try {
    const oldDependency = pack("smoke-dependency", "1.0.0");
    const newDependency = pack("smoke-dependency", "1.1.0");
    const artifact = pack("smoke-artifact", "1.0.0", { dependencies: { "smoke-dependency": "^1.0.0" } }, {
      name: "smoke-artifact", version: "1.0.0", lockfileVersion: 3, requires: true,
      packages: {
        "": { name: "smoke-artifact", version: "1.0.0", dependencies: { "smoke-dependency": "^1.0.0" } },
        "node_modules/smoke-dependency": { version: "1.0.0" },
      },
    });
    const install = async (label, spec) => {
      const directory = join(root, label);
      mkdirSync(directory);
      await promisify(execFile)(process.execPath, [...npmArgs, "install", "--prefix", directory,
        "--cache", join(root, `${label}-cache`), "--registry", registry.url,
        "--ignore-scripts", "--no-audit", "--no-fund", spec],
      { cwd: directory, env, encoding: "utf8", timeout: 30_000 });
      const require = createRequire(join(directory, "node_modules/smoke-artifact/package.json"));
      return JSON.parse(readFileSync(require.resolve("smoke-dependency/package.json"), "utf8")).version;
    };
    registry = await artifactRegistry([artifact, oldDependency, newDependency]);
    const metadata = await (await globalThis.fetch(`${registry.url}/smoke-artifact`)).json();
    const published = metadata.versions["1.0.0"];
    assert.equal(published._hasShrinkwrap, true);
    assert.equal(published.dist.integrity,
      `sha512-${createHash("sha512").update(artifact.tarball).digest("base64")}`);
    const served = new Uint8Array(await (await globalThis.fetch(published.dist.tarball)).arrayBuffer());
    assert.deepEqual(served, new Uint8Array(artifact.tarball));
    assert.equal((await globalThis.fetch(`${registry.url}/unlisted`)).status, 404);
    assert.equal((await globalThis.fetch(`${registry.url}/smoke-artifact`, { method: "POST" })).status, 404);
    assert.equal(await install("registry-pinned", "smoke-artifact@1.0.0"), "1.0.0");
    assert.equal(await install("file-unpinned", artifact.path), "1.1.0");
    await registry.close();
    registry = await artifactRegistry([{ ...artifact, hasShrinkwrap: false }, oldDependency, newDependency]);
    assert.equal(await install("registry-without-flag", "smoke-artifact@1.0.0"), "1.1.0");
  } finally {
    try {
      if (registry) await registry.close();
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }
});
