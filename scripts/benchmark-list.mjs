// Controlled measurement of today's list implementation. No cache or scan
// sharing is introduced: every thread retains both independent observations.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import console from "node:console";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { performance } from "node:perf_hooks";
import process from "node:process";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const repository = dirname(dirname(scriptPath));
const metricsPreload = join(repository, "scripts/fixtures/list-benchmark-metrics.mjs");
const threadId = index => `00000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}`;

if (process.argv[2] === "--worker") {
  const config = JSON.parse(await readFile(process.argv[3], "utf8"));
  const { listThreads } = await import("../dist/inspection.js");
  const { defaultOptions } = await import("../dist/options.js");
  const started = performance.now();
  try {
    const result = await listThreads({ ...defaultOptions(), codexHome: config.home,
      ...(config.stabilityMs === null ? {} : { stabilityMs: config.stabilityMs }) });
    const expectedIds = Array.from({ length: config.n }, (_, index) => threadId(index));
    assert.deepEqual(result.sessions.map(value => value.threadId), expectedIds);
    assert.equal(result.count, config.n);
    for (const value of result.sessions) {
      assert.equal(value.classification, config.coordinatorAbsent ? "unknown" : "stale_residue");
      assert.equal(value.safeToUnlock, false);
      assert.equal(value.lock.probe.status, config.coordinatorAbsent ? "unknown" : "free");
      assert.equal(value.lock.probe.guard.status, config.coordinatorAbsent ? "absent" : "acquired");
      if (config.coordinatorAbsent) assert.equal(value.lock.probe.error, "native_coordination_absent");
      assert.equal(value.lock.stable, true);
      assert.equal(value.transcript.status, "found");
      assert.equal(value.transcript.stable, true);
      assert.equal(value.transcript.lastRecord.eventType, "task_complete");
    }
    console.log(JSON.stringify({ status: "ok", count: result.count, sortedComplete: true,
      guardedNativeProbes: !config.coordinatorAbsent, independentStableObservations: true,
      ...(config.coordinatorAbsent ? { classification: "unknown", safeToUnlock: false, failClosed: true } : {}),
      elapsedMs: performance.now() - started }));
  } catch (error) {
    if (config.fail && error.message === "injected benchmark transcript discovery failure") {
      console.log(JSON.stringify({ status: "command_failed", failClosed: true,
        errorCode: "command_failed", elapsedMs: performance.now() - started }));
      process.exitCode = 3;
    } else throw error;
  }
} else {
  assert.ok(process.argv.slice(2).every(value => value === "--quick"),
    "Usage: node scripts/benchmark-list.mjs [--quick] (run npm run build first)");
  const quick = process.argv.includes("--quick");
  const totalBudgetMs = quick ? 15_000 : 60_000;
  const started = performance.now();
  const scratch = await mkdtemp(join(tmpdir(), "codex-list-benchmark-"));
  const record = `${JSON.stringify({ type: "event_msg", payload: { type: "task_complete" } })}\n`;
  const base = { n: 4, t: quick ? 64 : 512, depth: 0, transcriptBytes: 128,
    diagnostics: "system-true", stabilityMs: 0 };
  const configurations = quick ? [
    { ...base, id: "baseline" },
    { ...base, id: "n-8", n: 8 },
    { ...base, id: "t-256", t: 256 },
    { ...base, id: "nested-large-transcript", depth: 4, transcriptBytes: 65_536 },
    { ...base, id: "real-diagnostics", diagnostics: "system" },
    { ...base, id: "default-window", stabilityMs: null },
  ] : [
    { ...base, id: "baseline" },
    { ...base, id: "n-16", n: 16 },
    { ...base, id: "n-32", n: 32 },
    { ...base, id: "t-64", t: 64 },
    { ...base, id: "t-2048", t: 2048 },
    { ...base, id: "depth-4", depth: 4 },
    { ...base, id: "transcript-64k", transcriptBytes: 65_536 },
    { ...base, id: "real-diagnostics", diagnostics: "system" },
    { ...base, id: "default-window", stabilityMs: null },
  ];

  async function fixture(config, index) {
    const root = join(scratch, `case-${index}`);
    const home = join(root, "home");
    const files = [];
    async function put(relative, content) {
      const path = join(home, relative);
      await mkdir(dirname(path), { recursive: true, mode: 0o700 });
      await writeFile(path, content, { mode: 0o600 });
      files.push(relative);
    }
    if (!config.coordinatorAbsent) await put("thread-writer-locks/.coordination.lock", "");
    for (let index = config.n - 1; index >= 0; index -= 1) {
      await put(`thread-writer-locks/${threadId(index)}.lock`, "");
    }
    // T counts transcript files independently of N. Only N match listed locks;
    // all other files are realistic traversal noise, split across both roots.
    const paddingRecord = padding => `${JSON.stringify({ type: "benchmark_padding", payload: padding })}\n`;
    const overheadBytes = paddingRecord("").length + record.length;
    for (let index = 0; index < config.t; index += 1) {
      const tree = index < config.n || index % 2 === 0 ? "sessions" : "archived_sessions";
      const levels = Array.from({ length: config.depth }, (_, depth) => `level-${depth}`);
      const transcript = `${paddingRecord("x".repeat(Math.max(0, config.transcriptBytes - overheadBytes)))}${record}`;
      assert.equal(transcript.length, config.transcriptBytes);
      await put(join(tree, ...levels, `rollout-${threadId(index)}.jsonl`), transcript);
    }
    return { root, home, files };
  }

  async function snapshot(value) {
    const hash = createHash("sha256");
    for (const relative of value.files.sort()) {
      const path = join(value.home, relative);
      const [content, metadata] = await Promise.all([readFile(path), stat(path)]);
      // Reads may update atime. Content, inode, owner, mode, size, and mtime must
      // remain unchanged, including the native coordinator and thread files.
      hash.update(JSON.stringify({ relative, ino: metadata.ino, uid: metadata.uid,
        mode: metadata.mode, size: metadata.size, mtimeMs: metadata.mtimeMs }));
      hash.update(content);
    }
    return hash.digest("hex");
  }

  async function run(value, config, repetition, fail = false) {
    const remaining = totalBudgetMs - (performance.now() - started);
    assert.ok(remaining >= 100, "Benchmark time budget exhausted");
    const configPath = join(value.root, `config-${repetition}${fail ? "-failure" : ""}.json`);
    const metricsPath = join(value.root, `metrics-${repetition}${fail ? "-failure" : ""}.json`);
    await writeFile(configPath, JSON.stringify({ ...config, home: value.home, fail }), { mode: 0o600 });
    const child = spawnSync(process.execPath,
      ["--import", metricsPreload, scriptPath, "--worker", configPath], {
        cwd: repository, timeout: Math.floor(Math.min(remaining, 15_000)), maxBuffer: 1024 * 1024,
        env: { ...process.env, CODEX_HOME: value.home,
          CODEX_UNLOCK_BENCHMARK_HOME: value.home,
          CODEX_UNLOCK_BENCHMARK_METRICS: metricsPath,
          CODEX_UNLOCK_BENCHMARK_DIAGNOSTICS: config.diagnostics,
          CODEX_UNLOCK_BENCHMARK_FAIL_DISCOVERY: fail ? "1" : "0" },
        encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
      });
    assert.equal(child.error, undefined, child.error?.message);
    assert.equal(child.signal, null);
    assert.equal(child.status, fail ? 3 : 0, child.stderr);
    assert.equal(child.stderr, "");
    const result = JSON.parse(child.stdout);
    const metrics = JSON.parse(await readFile(metricsPath, "utf8"));
    assert.equal(metrics.activeDirectoryHandles, 0);
    assert.equal(metrics.activeRootWalks, 0);
    assert.equal(metrics.activeDiagnosticChildren, 0);
    assert.ok(metrics.peakRootWalks <= 4 * 2);
    assert.ok(metrics.peakDirectoryHandles <= 4 * 2 * (config.depth + 1));
    if (fail) {
      assert.equal(result.status, "command_failed");
      assert.equal(result.failClosed, true);
      assert.equal(metrics.injectedDiscoveryFailure, true);
    } else {
      assert.equal(metrics.rootTraversals, config.n * 2 * 2);
      assert.equal(metrics.transcriptReadCalls, config.n * 2);
    }
    return { repetition, cacheCondition: repetition === 0 ? "fresh_process_first_run" : "fresh_process_warm_fixture",
      ...result, ...metrics };
  }

  try {
    const cases = [];
    let firstFixture;
    for (const [index, config] of configurations.entries()) {
      const value = await fixture(config, index);
      if (index === 0) firstFixture = value;
      const before = await snapshot(value);
      const runs = [];
      for (let repetition = 0; repetition < 3; repetition += 1) {
        runs.push(await run(value, config, repetition));
      }
      assert.equal(await snapshot(value), before, "Fixture content or metadata changed");
      const elapsed = runs.map(value => value.elapsedMs).sort((a, b) => a - b);
      cases.push({ ...config, effectiveStabilityMs: config.stabilityMs ?? 1000,
        fixtureInvariant: true, medianElapsedMs: elapsed[1], minElapsedMs: elapsed[0],
        maxElapsedMs: elapsed[2], runs });
    }
    const beforeFailure = await snapshot(firstFixture);
    const discoveryFailure = await run(firstFixture, base, 3, true);
    assert.equal(await snapshot(firstFixture), beforeFailure);
    const unknownConfig = { ...base, coordinatorAbsent: true };
    const unknownFixture = await fixture(unknownConfig, configurations.length);
    const beforeUnknown = await snapshot(unknownFixture);
    const missingCoordinator = await run(unknownFixture, unknownConfig, 0);
    assert.equal(await snapshot(unknownFixture), beforeUnknown);
    await assert.rejects(stat(join(unknownFixture.home, "thread-writer-locks/.coordination.lock")),
      { code: "ENOENT" }, "Diagnostics must not create a native coordinator");
    console.log(JSON.stringify({ schemaVersion: 1, mode: quick ? "quick" : "standard",
      nodeVersion: process.version, platform: process.platform, architecture: process.arch,
      elapsedMs: performance.now() - started, timeBudgetMs: totalBudgetMs,
      concurrencyLimit: 4, cases, discoveryFailure, missingCoordinator,
      limitations: ["Fresh processes and repeated fixtures; files are hashed before timing and OS caches are not flushed, so first run is not a cold-cache claim.",
        "system-true still spawns fixed /usr/bin/true children; it removes ps/lsof scanning, not all diagnostic overhead.",
        "System diagnostic outputs differ from empty system-true outputs; spawned command counts are reported, not assumed equal.",
        "CPU and maxRSS describe the measured Node process, excluding resource usage of spawned diagnostic programs.",
        "Linux FD counts are sampled (/proc/self/fd), including the sampling descriptor; short peaks can be missed.",
        "Other platforms report exact tracked directory handles only, not total process descriptors.",
        "The zero window is an internal listThreads control; the default 1000 ms window remains unmodified.",
        "Discovery failure rejects the whole list as command_failed; it does not return successful or partial sessions."],
    }, null, 2));
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}
