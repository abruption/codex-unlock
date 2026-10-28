import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { URL } from "node:url";
import test from "node:test";

const read = (path) => readFile(new URL(`../${path}`, import.meta.url), "utf8");

test("supported Node security minimums match lock metadata and CI", async () => {
  const manifest = JSON.parse(await read("package.json"));
  const lock = JSON.parse(await read("package-lock.json"));
  assert.equal(manifest.engines.node, "^22.23.4 || ^24.22.1");
  assert.equal(lock.packages[""].engines.node, manifest.engines.node);
  const ci = await read(".github/workflows/ci.yml");
  for (const version of ["22.23.4", "24.22.1", "22", "24"]) {
    assert.equal(ci.split(`node: "${version}"`).length - 1, 4,
      `all four OS/architecture combinations must test Node ${version}`);
  }
  assert.doesNotMatch(ci, /22\.13\.0/);
  const release = await read(".github/workflows/release-please.yml");
  assert.equal(release.split("node-version: 24.22.1").length - 1, 2);
});
