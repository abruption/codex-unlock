import assert from "node:assert/strict";
import { once } from "node:events";
import { chmod, mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawn } from "node:child_process";
import test from "node:test";

import { inspectThread, unlockThread } from "../dist/doctor.js";
import { parseLsofProcesses } from "../dist/process.js";

const THREAD_ID = "01a089e8-3731-7202-ba68-0f4b0a3b2711";
const OWNER_FIXTURE = resolve("test/fixtures/codex");

async function fixture(lastEvent = "task_complete") {
  const codexHome = await mkdtemp(join(tmpdir(), "codex-unlock-test-"));
  const lockDirectory = join(codexHome, "thread-writer-locks");
  const sessionDirectory = join(codexHome, "sessions", "2026", "09", "15");
  await mkdir(lockDirectory, { recursive: true });
  await mkdir(sessionDirectory, { recursive: true });
  const lockPath = join(lockDirectory, `${THREAD_ID}.lock`);
  const transcriptPath = join(
    sessionDirectory,
    `rollout-2026-09-15T00-00-00-${THREAD_ID}.jsonl`,
  );
  await writeFile(lockPath, "");
  await writeFile(
    transcriptPath,
    `${JSON.stringify({
      timestamp: "2026-09-15T00:00:00.000Z",
      type: "event_msg",
      payload: { type: lastEvent },
    })}\n`,
  );
  await chmod(OWNER_FIXTURE, 0o755);
  const child = spawn(OWNER_FIXTURE, [lockPath], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.setEncoding("utf8");
  await new Promise((resolveReady, reject) => {
    child.stdout.once("data", (chunk) => {
      if (chunk.includes("ready")) resolveReady();
      else reject(new Error(`unexpected owner output: ${chunk}`));
    });
    child.once("error", reject);
    child.once("exit", (code) => reject(new Error(`owner exited early: ${code}`)));
  });
  return {
    codexHome,
    lockPath,
    transcriptPath,
    child,
    options: { codexHome, stabilityMs: 50, terminationTimeoutMs: 3_000 },
  };
}

async function stopChild(child) {
  if (child.exitCode === null && child.signalCode === null) {
    child.kill("SIGTERM");
    await once(child, "exit");
  }
}

test("parses null-delimited lsof process fields", () => {
  assert.deepEqual(parseLsofProcesses("p42\0ccodex\0u501\0\np7\0cnode\0u502\0"), [
    { pid: 7, command: "node", uid: 502 },
    { pid: 42, command: "codex", uid: 501 },
  ]);
});

test("classifies an unlocked lock file as stale residue", async () => {
  const value = await fixture();
  await stopChild(value.child);
  const inspection = await inspectThread(THREAD_ID, value.options);
  assert.equal(inspection.classification, "stale_residue");
  assert.equal(inspection.lock.probe.status, "free");
  assert.equal(inspection.safeToUnlock, false);
});

test("refuses a live owner when the transcript is not task_complete", async (t) => {
  const value = await fixture("task_started");
  t.after(async () => await stopChild(value.child));
  const inspection = await inspectThread(THREAD_ID, value.options);
  assert.equal(inspection.classification, "live_owner");
  assert.equal(inspection.safeToUnlock, false);
  assert.ok(inspection.blockers.includes("transcript_last_event_not_task_complete"));

  const result = await unlockThread(THREAD_ID, value.options);
  assert.equal(result.outcome, "refused");
  assert.equal(result.signalSent, null);
  assert.equal(value.child.exitCode, null);
});

test("terminates a completed idle owner and verifies transcript invariance", async (t) => {
  const value = await fixture();
  t.after(async () => await stopChild(value.child));
  const inspection = await inspectThread(THREAD_ID, value.options);
  assert.equal(inspection.classification, "live_owner");
  assert.equal(inspection.safeToUnlock, true);
  assert.equal(inspection.owner?.pid, value.child.pid);
  assert.deepEqual(inspection.ownerLockFiles, [value.lockPath]);

  const result = await unlockThread(THREAD_ID, value.options);
  assert.equal(result.outcome, "unlocked");
  assert.equal(result.signalSent, "SIGTERM");
  assert.equal(result.processExited, true);
  assert.equal(result.lockReleased, true);
  assert.equal(result.transcriptUnchanged, true);
  assert.equal(result.lockFileRemovedByTool, false);
});
