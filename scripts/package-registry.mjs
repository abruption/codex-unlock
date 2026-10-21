import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { createServer } from "node:http";

// A fixed, read-only registry fixture. It never forwards client headers or
// proxies arbitrary URLs, and never looks up the project on the public registry.
export async function artifactRegistry(packages) {
  const requests = [];
  const routes = new Map();
  const server = createServer((request, response) => {
    requests.push({ method: request.method, path: request.url });
    const route = routes.get(request.url);
    if (request.method !== "GET" || !route) {
      response.writeHead(404).end();
      return;
    }
    response.writeHead(200, { "content-type": route.type, "content-length": route.body.length });
    response.end(route.body);
  });
  server.requestTimeout = 10_000;
  server.headersTimeout = 10_000;
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const url = `http://127.0.0.1:${server.address().port}`;
  try {
    for (const entry of packages) {
      if (entry.metadata) {
        routes.set(`/${entry.metadata.name}`, {
          type: "application/json", body: Buffer.from(JSON.stringify(entry.metadata)),
        });
        continue;
      }
      const { manifest, tarball, hasShrinkwrap = true } = entry;
      assert.match(manifest.name, /^[a-z0-9][a-z0-9.-]*$/);
      assert.match(manifest.version, /^\d+\.\d+\.\d+$/);
      const path = `/${manifest.name}/-/${manifest.name}-${manifest.version}.tgz`;
      const integrity = `sha512-${createHash("sha512").update(tarball).digest("base64")}`;
      const version = { ...manifest, _hasShrinkwrap: hasShrinkwrap,
        dist: { tarball: `${url}${path}`, integrity } };
      const metadata = { name: manifest.name, "dist-tags": { latest: manifest.version },
        versions: { [manifest.version]: version } };
      const existing = routes.get(`/${manifest.name}`);
      if (existing) Object.assign(metadata.versions, JSON.parse(existing.body).versions);
      routes.set(`/${manifest.name}`, { type: "application/json", body: Buffer.from(JSON.stringify(metadata)) });
      routes.set(path, { type: "application/octet-stream", body: tarball });
    }
  } catch (error) {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
    throw error;
  }
  return { url, requests, close: async () => {
    server.closeAllConnections();
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  } };
}

// Fetch only the two runtime dependency packuments, with no caller credentials.
// Their tarballs retain the official URLs (replace-registry-host=never).
export async function runtimeMetadata(name) {
  assert.ok(["fs-ext-extra-prebuilt", "nan"].includes(name));
  const response = await globalThis.fetch(`https://registry.npmjs.org/${name}`, {
    redirect: "error", signal: globalThis.AbortSignal.timeout(20_000),
  });
  assert.equal(response.status, 200, `Registry metadata HTTP status for ${name}`);
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    assert.ok(size <= 2 * 1024 * 1024, "Dependency packument exceeds 2 MiB");
    chunks.push(chunk);
  }
  const metadata = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  assert.equal(metadata.name, name);
  return { metadata };
}
