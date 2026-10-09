// Benchmark-only preload. Native probes and independent transcript walks remain
// real; the optional system-true mode removes ps/lsof process-table work only.
import fs from "node:fs";
import { spawn } from "node:child_process";
import promises from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { basename, join, resolve } from "node:path";
import process from "node:process";
import { clearInterval, setInterval } from "node:timers";
import { overrideDiagnosticExecutableForTesting } from "../../dist/process.js";
import { overrideSpawnForTesting } from "../../dist/util.js";

const home = process.env.CODEX_UNLOCK_BENCHMARK_HOME;
const metricsFile = process.env.CODEX_UNLOCK_BENCHMARK_METRICS;
if (!home || !metricsFile) throw new Error("Benchmark preload requires private fixture paths");
if (process.env.CODEX_UNLOCK_BENCHMARK_DIAGNOSTICS === "system-true") {
  overrideDiagnosticExecutableForTesting("ps", "/usr/bin/true");
  overrideDiagnosticExecutableForTesting("lsof", "/usr/bin/true");
}
const roots = new Set([join(home, "sessions"), join(home, "archived_sessions")]);
const metrics = {
  rootTraversals: 0, directoryOpens: 0, entriesVisited: 0,
  activeRootWalks: 0, peakRootWalks: 0,
  activeDirectoryHandles: 0, peakDirectoryHandles: 0,
  transcriptReadCalls: 0, transcriptReadBytes: 0,
  diagnosticSpawnCalls: {}, activeDiagnosticChildren: 0, peakDiagnosticChildren: 0,
  fdMetric: process.platform === "linux" ? "sampled_proc_self_fd" : "tracked_directory_handles_only",
  sampledPeakTotalFds: null, fdSamples: 0, injectedDiscoveryFailure: false,
};
const originalOpendir = promises.opendir;
const originalOpen = promises.open;
const startUsage = process.resourceUsage();

overrideSpawnForTesting((executable, args, options) => {
  const tool = basename(executable);
  metrics.diagnosticSpawnCalls[tool] = (metrics.diagnosticSpawnCalls[tool] ?? 0) + 1;
  const child = spawn(executable, args, options);
  metrics.activeDiagnosticChildren += 1;
  metrics.peakDiagnosticChildren = Math.max(metrics.peakDiagnosticChildren, metrics.activeDiagnosticChildren);
  child.once("close", () => { metrics.activeDiagnosticChildren -= 1; });
  return child;
});

function sampleFds() {
  if (process.platform !== "linux") return;
  try {
    const count = fs.readdirSync("/proc/self/fd").length;
    metrics.sampledPeakTotalFds = Math.max(metrics.sampledPeakTotalFds ?? 0, count);
    metrics.fdSamples += 1;
  } catch {
    // A unavailable /proc mount is recorded explicitly, never estimated as zero.
    metrics.fdMetric = "proc_unavailable_tracked_directory_handles_only";
  }
}

promises.opendir = async function (path, ...args) {
  const root = roots.has(resolve(path));
  if (root) {
    metrics.rootTraversals += 1;
    if (process.env.CODEX_UNLOCK_BENCHMARK_FAIL_DISCOVERY === "1"
      && !metrics.injectedDiscoveryFailure) {
      metrics.injectedDiscoveryFailure = true;
      throw new Error("injected benchmark transcript discovery failure");
    }
    metrics.activeRootWalks += 1;
    metrics.peakRootWalks = Math.max(metrics.peakRootWalks, metrics.activeRootWalks);
  }
  let directory;
  try {
    directory = await originalOpendir(path, ...args);
  } catch (error) {
    if (root) metrics.activeRootWalks -= 1;
    throw error;
  }
  metrics.directoryOpens += 1;
  metrics.activeDirectoryHandles += 1;
  metrics.peakDirectoryHandles = Math.max(metrics.peakDirectoryHandles, metrics.activeDirectoryHandles);
  sampleFds();
  const iterator = directory[Symbol.asyncIterator]();
  directory[Symbol.asyncIterator] = async function* () {
    try {
      for await (const entry of iterator) {
        metrics.entriesVisited += 1;
        yield entry;
      }
    } finally {
      metrics.activeDirectoryHandles -= 1;
      if (root) metrics.activeRootWalks -= 1;
    }
  };
  return directory;
};

promises.open = async function (path, ...args) {
  const handle = await originalOpen(path, ...args);
  if (String(path).endsWith(".jsonl")) {
    const originalRead = handle.read.bind(handle);
    handle.read = async (...readArgs) => {
      const result = await originalRead(...readArgs);
      metrics.transcriptReadCalls += 1;
      metrics.transcriptReadBytes += result.bytesRead;
      sampleFds();
      return result;
    };
  }
  return handle;
};
syncBuiltinESMExports();
sampleFds();
const sampler = setInterval(sampleFds, 5);
sampler.unref();
process.once("exit", () => {
  clearInterval(sampler);
  sampleFds();
  const usage = process.resourceUsage();
  fs.writeFileSync(metricsFile, JSON.stringify({ ...metrics,
    cpuUserMicroseconds: usage.userCPUTime - startUsage.userCPUTime,
    cpuSystemMicroseconds: usage.systemCPUTime - startUsage.systemCPUTime,
    maxRssKiB: usage.maxRSS,
  }), { mode: 0o600 });
});
