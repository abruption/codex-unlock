// Generates the published npm-shrinkwrap.json from package-lock.json.
//
// package-lock.json is the repository lockfile and includes development
// dependencies. npm installs every entry of a dependency's shrinkwrap, so the
// published shrinkwrap must contain only the runtime tree. Run without
// arguments to write npm-shrinkwrap.json, or with --check to verify an
// existing one before publishing.
import assert from "node:assert/strict";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import process from "node:process";

const lockPath = resolve("package-lock.json");
const shrinkwrapPath = resolve("npm-shrinkwrap.json");
const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));

export function consumerShrinkwrap(lock) {
  assert.equal(lock.lockfileVersion, 3, "package-lock.json must use lockfileVersion 3");
  const packages = {};
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (path === "") {
      const { devDependencies: _devDependencies, ...root } = entry;
      packages[path] = root;
    } else if (entry.dev !== true && entry.devOptional !== true) {
      packages[path] = entry;
    }
  }
  return { ...lock, packages };
}

function runtimeEntries(shrinkwrap) {
  return Object.entries(shrinkwrap.packages).filter(([path]) => path !== "");
}

export function assertConsumerShrinkwrap(shrinkwrap, manifest) {
  assert.equal(shrinkwrap.name, manifest.name, "npm-shrinkwrap.json names another package");
  assert.equal(shrinkwrap.version, manifest.version, "npm-shrinkwrap.json version is stale");
  const root = shrinkwrap.packages[""];
  assert.equal(root.version, manifest.version, "npm-shrinkwrap.json root version is stale");
  assert.equal(root.devDependencies, undefined, "npm-shrinkwrap.json lists devDependencies");
  assert.deepEqual(root.dependencies, manifest.dependencies,
    "npm-shrinkwrap.json root dependencies differ from package.json");
  for (const [path, entry] of runtimeEntries(shrinkwrap)) {
    assert.ok(entry.dev !== true && entry.devOptional !== true,
      `npm-shrinkwrap.json includes the development entry ${path}`);
  }
}

const invokedDirectly = process.argv[1] && resolve(process.argv[1]) === resolve(import.meta.filename);
if (invokedDirectly) {
  const manifest = readJson(resolve("package.json"));
  const expected = consumerShrinkwrap(readJson(lockPath));
  if (process.argv.includes("--check")) {
    assert.ok(existsSync(shrinkwrapPath),
      "npm-shrinkwrap.json is missing; run node scripts/consumer-shrinkwrap.mjs before publishing");
    const actual = readJson(shrinkwrapPath);
    assertConsumerShrinkwrap(actual, manifest);
    assert.deepEqual(actual, expected,
      "npm-shrinkwrap.json is out of date with package-lock.json; regenerate it");
  } else {
    assertConsumerShrinkwrap(expected, manifest);
    writeFileSync(shrinkwrapPath, `${JSON.stringify(expected, null, 2)}\n`);
  }
}
