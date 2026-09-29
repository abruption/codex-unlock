// Guarantee that the first post-signal probe observes an owner's drop guard.
import fs from "node:fs";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { basename } from "node:path";
import { performance } from "node:perf_hooks";
import process from "node:process";

const addon = createRequire(import.meta.url)("fs-ext-extra-prebuilt");
const open = fs.openSync;
const close = fs.closeSync;
const flock = addon.flockSync;
const kill = process.kill.bind(process);
const guards = new Set();
let signaled = false;
fs.openSync = (path, ...args) => {
  const fd = open(path, ...args);
  if (basename(path) === ".coordination.lock") guards.add(fd);
  return fd;
};
fs.closeSync = (fd) => { guards.delete(fd); return close(fd); };
syncBuiltinESMExports();
addon.flockSync = (fd, operation) => {
  try {
    return flock(fd, operation);
  } catch (error) {
    if (signaled && guards.has(fd) && operation === "exnb" &&
      ["EAGAIN", "EWOULDBLOCK", "EACCES"].includes(error.code)) {
      fs.appendFileSync(process.env.CODEX_UNLOCK_TEST_DROP_BUSY, "busy\n");
    }
    throw error;
  }
};
process.kill = (pid, signal) => {
  const result = kill(pid, signal);
  if (signal === "SIGTERM") {
    signaled = true;
    const deadline = performance.now() + 3_000;
    while (!fs.existsSync(process.env.CODEX_UNLOCK_TEST_DROP_READY)) {
      if (performance.now() >= deadline) throw new Error("drop guard barrier timed out");
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1);
    }
  }
  return result;
};
