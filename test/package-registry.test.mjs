import assert from "node:assert/strict";
import { execFile, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { createRequire } from "node:module";
import { join } from "node:path";
import process from "node:process";
import test from "node:test";
import { promisify } from "node:util";

import { artifactRegistry, packageNpmEnvironment } from "../scripts/package-registry.mjs";

test("package npm environment bypasses loopback with absent or conflicting proxy exclusions", () => {
  for (const exclusions of [{}, { NO_PROXY: "example.org" },
    { NO_PROXY: "example.org", no_proxy: "other.example.org" }]) {
    const input = { HTTP_PROXY: "http://proxy.example:8080", https_proxy: "http://proxy.example:8443",
      npm_config_proxy: "http://other.example:8080", NODE_ENV: "production", ...exclusions };
    const snapshot = { ...input };
    const env = packageNpmEnvironment(input);
    assert.deepEqual(input, snapshot);
    assert.equal(env.HTTP_PROXY, input.HTTP_PROXY);
    assert.equal(env.https_proxy, input.https_proxy);
    assert.equal(env.npm_config_proxy, undefined);
    assert.equal(env.NODE_ENV, undefined);
    assert.equal(env.NO_PROXY, env.no_proxy);
    for (const host of ["127.0.0.1", "localhost", "::1",
      ...Object.values(exclusions)]) assert.ok(env.NO_PROXY.split(",").includes(host));
  }
});

test("registry metadata applies shrinkwrap to exact artifact bytes, unlike file installs", { timeout: 120_000 }, async () => {
  const root = mkdtempSync(join(tmpdir(), "codex-registry-test-"));
  const npmCli = process.env.npm_execpath;
  assert.ok(npmCli, "Run this test through npm test");
  const config = join(root, "empty-npmrc");
  const globalConfig = join(root, "empty-global-npmrc");
  writeFileSync(config, "");
  writeFileSync(globalConfig, "");
  let proxyRequests = 0;
  const proxy = createServer((_request, response) => {
    proxyRequests += 1;
    response.writeHead(403).end("Loopback requests must not reach the proxy");
  });
  await new Promise((resolve, reject) => {
    proxy.once("error", reject);
    proxy.listen(0, "127.0.0.1", resolve);
  });
  const proxyUrl = `http://127.0.0.1:${proxy.address().port}`;
  const env = packageNpmEnvironment({ ...process.env,
    HTTP_PROXY: proxyUrl, HTTPS_PROXY: proxyUrl, ALL_PROXY: proxyUrl,
    http_proxy: proxyUrl, https_proxy: proxyUrl, all_proxy: proxyUrl,
    NO_PROXY: "example.org", no_proxy: "other.example.org" });
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
    assert.equal(proxyRequests, 0, "Local npm registry requests must bypass inherited proxies");
  } finally {
    try {
      if (registry) await registry.close();
    } finally {
      proxy.closeAllConnections();
      await new Promise((resolve) => proxy.close(resolve));
      rmSync(root, { recursive: true, force: true });
    }
  }
});
