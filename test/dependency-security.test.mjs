import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { URL } from "node:url";
import { minimatch } from "minimatch";

const readJson = async (path) => JSON.parse(await readFile(new URL(`../${path}`, import.meta.url), "utf8"));

test("the minimatch security override resolves to the first patched release", async () => {
  const [manifest, lock] = await Promise.all([
    readJson("package.json"),
    readJson("package-lock.json"),
  ]);

  assert.equal(manifest.overrides?.minimatch, "11.0.1");
  assert.equal(lock.packages["node_modules/minimatch"]?.version, "11.0.1");
  assert.equal(
    minimatch("src/process.ts", "src/**/*.ts", { optimizationLevel: 2 }),
    true,
  );
});
