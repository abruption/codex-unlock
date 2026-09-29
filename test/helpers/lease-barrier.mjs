// Test-only preload: hold the actual operation lease until the competing CLI
// finishes. Do not rely on a stability sleep or runner scheduling for overlap.
import fs from "node:fs";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { basename, dirname } from "node:path";
import { performance } from "node:perf_hooks";
import process from "node:process";

const addon = createRequire(import.meta.url)("fs-ext-extra-prebuilt");
const open = fs.openSync;
const close = fs.closeSync;
const flock = addon.flockSync;
const leases = new Set();
const release = process.env.CODEX_UNLOCK_TEST_LEASE_RELEASE;
fs.openSync = (path, ...args) => {
  const fd = open(path, ...args);
  if (typeof path === "string" && basename(dirname(path)) === "codex-unlock" &&
    /^[a-f0-9]{64}\.lock$/.test(basename(path))) {
    leases.add(fd);
  }
  return fd;
};
fs.closeSync = (fd) => {
  leases.delete(fd);
  return close(fd);
};
syncBuiltinESMExports();
addon.flockSync = (fd, operation) => {
  const result = flock(fd, operation);
  if (operation === "exnb" && leases.delete(fd)) {
    const deadline = performance.now() + 30_000;
    while (!fs.existsSync(release)) {
      if (performance.now() >= deadline) throw new Error("lease barrier timed out");
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
    }
  }
  return result;
};
