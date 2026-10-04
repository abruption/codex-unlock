import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import process from "node:process";
import test from "node:test";
import { clearTimeout, setTimeout } from "node:timers";

const SESSION_COUNT = 120;
const DEPTH = 5;

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "codex-list-concurrency-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const home = join(root, "home");
  const locks = join(home, "thread-writer-locks");
  await mkdir(locks, { recursive: true });
  await writeFile(join(locks, ".coordination.lock"), "", { mode: 0o600 });
  let transcripts;
  for (const tree of ["sessions", "archived_sessions"]) {
    const leaf = join(home, tree, ...Array.from({ length: DEPTH }, (_, i) => `level-${i}`));
    await mkdir(leaf, { recursive: true });
    if (tree === "sessions") transcripts = leaf;
  }
  const ids = [];
  for (let i = SESSION_COUNT - 1; i >= 0; i -= 1) {
    const id = `00000000-0000-4000-8000-${i.toString(16).padStart(12, "0")}`;
    ids.push(id);
    await writeFile(join(locks, `${id}.lock`), "");
    await writeFile(join(transcripts, `rollout-${id}.jsonl`),
      `${JSON.stringify({ type: "event_msg", payload: { type: "task_complete" } })}\n`);
  }
  return { root, home, ids: ids.sort() };
}

async function runList(value, fail = false) {
  const metricsPath = join(value.root, fail ? "failed-metrics.json" : "metrics.json");
  // Only the child has the low soft descriptor limit. The actual CLI, native
  // guarded flock probes, recursive walks, and transcript reads run normally.
  const child = spawn("/bin/sh", [
    "-c", 'ulimit -n 256 || exit 99; exec "$@"', "codex-low-fd",
    process.execPath, "--import", resolve("test/helpers/list-filesystem-metrics.mjs"),
    resolve("dist/cli.js"), "list", "--codex-home", value.home,
    "--json", "--no-update-notice", "--stability-ms", "250",
  ], {
    env: {
      ...process.env,
      CODEX_UNLOCK_TEST_LIST_HOME: value.home,
      CODEX_UNLOCK_TEST_LIST_METRICS: metricsPath,
      CODEX_UNLOCK_TEST_LIST_FAIL: fail ? "1" : "0",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8").on("data", (chunk) => { stdout += chunk; });
  child.stderr.setEncoding("utf8").on("data", (chunk) => { stderr += chunk; });
  const timer = setTimeout(() => child.kill("SIGTERM"), 60_000);
  const status = await new Promise((resolveExit, reject) => {
    child.once("error", reject);
    child.once("close", resolveExit);
  }).finally(() => clearTimeout(timer));
  return { status, stdout, stderr, metrics: JSON.parse(await readFile(metricsPath, "utf8")) };
}

test("list fully inspects 120 sessions under a 256-descriptor limit with bounded independent walks", async (t) => {
  const value = await fixture(t);
  const result = await runList(value);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.equal(result.stderr, "");
  assert.doesNotMatch(result.stdout, /EMFILE/);
  const listing = JSON.parse(result.stdout);
  assert.equal(listing.command, "list");
  assert.equal(listing.count, SESSION_COUNT);
  assert.deepEqual(listing.sessions.map((session) => session.threadId), value.ids);
  for (const session of listing.sessions) {
    assert.equal(session.classification, "stale_residue");
    assert.equal(session.lock.probe.status, "free");
    assert.equal(session.lock.probe.guard.status, "acquired");
    assert.equal(session.transcript.status, "found");
    assert.equal(session.transcript.stable, true);
    assert.equal(session.transcript.lastRecord.eventType, "task_complete");
    assert.equal(session.safeToUnlock, false);
  }
  assert.equal(result.metrics.rootCalls, SESSION_COUNT * 2 * 2,
    "each thread traverses both roots independently before and after the window");
  assert.ok(result.metrics.maxRoots >= 2);
  assert.ok(result.metrics.maxRoots <= 4 * 2, JSON.stringify(result.metrics));
  assert.ok(result.metrics.maxDirectories <= 4 * 2 * (DEPTH + 1), JSON.stringify(result.metrics));
  assert.equal(result.metrics.roots, 0);
  assert.equal(result.metrics.directories, 0);
});

test("list stops dispatching and drains active inspections before emitting its original error", async (t) => {
  const value = await fixture(t);
  const result = await runList(value, true);
  assert.equal(result.status, 3, result.stdout + result.stderr);
  assert.equal(result.stderr, "");
  const failure = JSON.parse(result.stdout);
  assert.equal(failure.command, "list");
  assert.equal(failure.errorCode, "command_failed");
  assert.equal(failure.error, "injected transcript traversal failure");
  assert.ok(result.metrics.rootCalls <= 14, JSON.stringify(result.metrics));
  assert.ok(result.metrics.maxRoots <= 8, JSON.stringify(result.metrics));
  assert.equal(result.metrics.errorEmissionRoots, 0);
  assert.equal(result.metrics.roots, 0);
  assert.equal(result.metrics.directories, 0);
});
