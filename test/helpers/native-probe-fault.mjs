import fs from "node:fs";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { basename } from "node:path";
import process from "node:process";

const addon = createRequire(import.meta.url)("fs-ext-extra-prebuilt");
const open = fs.openSync;
const close = fs.closeSync;
const flock = addon.flockSync;
const descriptors = new Map();
const mode = process.env.CODEX_UNLOCK_TEST_NATIVE_FAULT;
fs.openSync = (path, ...args) => {
  const fd = open(path, ...args);
  if (typeof path === "string" && path.endsWith(".lock")) {
    descriptors.set(fd, basename(path) === ".coordination.lock" ? "guard" : "thread");
  }
  return fd;
};
fs.closeSync = (fd) => {
  const kind = descriptors.get(fd);
  descriptors.delete(fd);
  close(fd);
  if (mode === `close-${kind}`) throw new Error("injected close failure");
};
syncBuiltinESMExports();
addon.flockSync = (fd, operation) => {
  if (operation === "un" && mode === `release-${descriptors.get(fd)}`) {
    throw new Error("injected unlock failure");
  }
  return flock(fd, operation);
};
