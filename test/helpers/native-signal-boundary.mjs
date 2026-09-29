// Test-only preload; production code never reads these variables.
import assert from "node:assert/strict";
import fs from "node:fs";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { basename } from "node:path";
import process from "node:process";

const addon = createRequire(import.meta.url)("fs-ext-extra-prebuilt");
const open = fs.openSync;
const close = fs.closeSync;
const flock = addon.flockSync;
const kill = process.kill.bind(process);
const guards = new Set();
let attempts = 0;
let finalDescriptor;
let finalClosed = false;
let microtaskRan = false;
const held = new Set();

fs.openSync = (path, ...args) => {
  const fd = open(path, ...args);
  if (typeof path === "string" && basename(path) === ".coordination.lock") guards.add(fd);
  return fd;
};
fs.closeSync = (fd) => {
  const result = close(fd);
  guards.delete(fd);
  held.delete(fd);
  if (fd === finalDescriptor) finalClosed = true;
  return result;
};
syncBuiltinESMExports();
addon.flockSync = (fd, operation) => {
  if (guards.has(fd) && operation === "exnb") {
    attempts += 1;
    if (attempts === 5) {
      finalDescriptor = fd;
      if (process.env.CODEX_UNLOCK_TEST_NATIVE_SIGNAL === "busy") {
        throw Object.assign(new Error("injected native guard contention"), { code: "EAGAIN" });
      }
    }
  }
  const result = flock(fd, operation);
  if (guards.has(fd)) {
    if (operation === "exnb") held.add(fd);
    if (operation === "un") {
      held.delete(fd);
      if (fd === finalDescriptor) Promise.resolve().then(() => { microtaskRan = true; });
    }
  }
  return result;
};
process.kill = (pid, signal) => {
  if (signal === "SIGTERM") {
    assert.equal(attempts, 5);
    assert.equal(held.size, 0);
    assert.equal(finalClosed, true);
    assert.equal(microtaskRan, false);
    fs.writeFileSync(process.env.CODEX_UNLOCK_TEST_NATIVE_SIGNAL_MARKER,
      JSON.stringify({ attempts, guardReleased: true, guardClosed: true, microtaskRan }));
  }
  return kill(pid, signal);
};
