// CLI-only instrumentation: real directory handles/traversals and native lock
// probes are retained. Synthetic ps/lsof output avoids hundreds of unrelated
// process-table scans while testing list's filesystem resource bound.
import fs from "node:fs";
import promises from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { join, resolve } from "node:path";
import process from "node:process";

import { overrideDiagnosticExecutableForTesting } from "../../dist/process.js";

overrideDiagnosticExecutableForTesting("ps", "/usr/bin/true");
overrideDiagnosticExecutableForTesting("lsof", "/usr/bin/true");

const home = process.env.CODEX_UNLOCK_TEST_LIST_HOME;
const roots = new Set([join(home, "sessions"), join(home, "archived_sessions")]);
const metrics = {
  roots: 0, maxRoots: 0, rootCalls: 0,
  directories: 0, maxDirectories: 0,
  errorEmissionRoots: null,
};
const originalOpendir = promises.opendir;
let injected = false;
promises.opendir = async function (path, ...args) {
  const root = roots.has(resolve(path));
  if (root) {
    metrics.rootCalls += 1;
    if (process.env.CODEX_UNLOCK_TEST_LIST_FAIL === "1" && !injected) {
      injected = true;
      throw new Error("injected transcript traversal failure");
    }
    metrics.roots += 1;
    metrics.maxRoots = Math.max(metrics.maxRoots, metrics.roots);
  }
  metrics.directories += 1;
  metrics.maxDirectories = Math.max(metrics.maxDirectories, metrics.directories);
  const finished = () => {
    metrics.directories -= 1;
    if (root) metrics.roots -= 1;
  };
  let directory;
  try {
    directory = await originalOpendir(path, ...args);
  } catch (error) {
    finished();
    throw error;
  }
  const iterator = directory[Symbol.asyncIterator]();
  directory[Symbol.asyncIterator] = async function* () {
    try {
      yield* iterator;
    } finally {
      finished();
    }
  };
  return directory;
};
syncBuiltinESMExports();

const originalWrite = process.stdout.write;
process.stdout.write = function (chunk, ...args) {
  if (String(chunk).includes('"command_failed"')) {
    metrics.errorEmissionRoots = metrics.roots;
  }
  return originalWrite.call(this, chunk, ...args);
};
process.on("exit", () => {
  fs.writeFileSync(process.env.CODEX_UNLOCK_TEST_LIST_METRICS, JSON.stringify(metrics), {
    mode: 0o600,
  });
});
