import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import fs from "node:fs";
import { mkdir, readFile, rename, symlink, writeFile } from "node:fs/promises";
import { syncBuiltinESMExports } from "node:module";
import { join, resolve } from "node:path";
import process from "node:process";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";

import { acquireUnlockLease } from "../dist/coordination.js";
import { inspectThread } from "../dist/inspection.js";
import { guardedProbeOnce } from "../dist/native-coordination.js";
import { processStartTime } from "../dist/process.js";
import { stableFileHash } from "../dist/transcript.js";
import { unlockInspectedThread } from "../dist/unlock.js";
import {
  THREAD_ID,
  commandOwner,
  fixture,
  otherLockPath,
  stopChild,
} from "./helpers/owner-fixture.mjs";

const schema = JSON.parse(await readFile(resolve("schemas/codex-unlock-v1.schema.json"), "utf8"));
const validate = new Ajv2020({ strict: true, allowUnionTypes: true }).compile(schema);

function barrier() {
  let arrive;
  let release;
  const arrived = new Promise((resolveArrived) => { arrive = resolveArrived; });
  const released = new Promise((resolveReleased) => { release = resolveReleased; });
  return {
    arrived,
    release,
    async pause() {
      arrive();
      await released;
    },
  };
}

async function signalFixture(t) {
  const value = await fixture();
  let attempts = 0;
  const originalKill = process.kill;
  process.kill = (pid, signal) => {
    if (pid === value.child.pid && signal === "SIGTERM") attempts += 1;
    return originalKill(pid, signal);
  };
  t.after(async () => {
    process.kill = originalKill;
    await stopChild(value.child);
  });
  const inspection = await inspectThread(THREAD_ID, value.options);
  assert.equal(inspection.safeToUnlock, true);
  assert.equal(guardedProbeOnce(value.lockPath).status, "held");
  return { ...value, inspection, attempts: () => attempts };
}

async function unlockWithLease(value, dependencies) {
  const attempt = acquireUnlockLease(value.codexHome, THREAD_ID);
  assert.equal(attempt.status, "acquired");
  try {
    return await unlockInspectedThread(value.inspection, value.options, dependencies);
  } finally {
    attempt.lease.release();
  }
}

function assertRefusedUntouched(value, result) {
  assert.equal(result.outcome, "refused");
  assert.equal(result.changed, false);
  assert.equal(result.signalSent, null);
  assert.equal(value.attempts(), 0);
  assert.equal(value.child.exitCode, null);
  assert.equal(value.child.signalCode, null);
  assert.equal(guardedProbeOnce(value.lockPath).status, "held");
  assert.equal(validate(result), true, JSON.stringify(validate.errors));
}

test("late evidence refuses an extra advisory lock acquired during the final hash", { timeout: 30_000 }, async (t) => {
  const value = await signalFixture(t);
  const extraLock = await otherLockPath(value.codexHome);
  const hashing = barrier();
  let hashes = 0;
  const pending = unlockWithLease(value, {
    stableFileHash: async (path) => {
      hashes += 1;
      // Suspend the second hashing operation until the synthetic owner has
      // acknowledged acquisition; this does not depend on transcript size.
      if (hashes === 2) await hashing.pause();
      return await stableFileHash(path);
    },
  });
  await Promise.race([
    hashing.arrived,
    pending.then(() => { throw new Error("unlock finished before the final hash barrier"); }),
  ]);
  try {
    await commandOwner(value.child, { action: "acquire", path: extraLock });
    assert.equal(guardedProbeOnce(extraLock).status, "held");
  } finally {
    hashing.release();
  }
  const result = await pending;
  assert.equal(hashes, 2);
  assertRefusedUntouched(value, result);
  assert.ok(result.reasons.includes("owner_lock_set_changed_before_signal"));
  assert.equal(guardedProbeOnce(extraLock).status, "held");
});

test("late evidence refuses an append after hashing during the final process sample", { timeout: 30_000 }, async (t) => {
  const value = await signalFixture(t);
  const sampling = barrier();
  let hashes = 0;
  const pending = unlockWithLease(value, {
    stableFileHash: async (path) => {
      hashes += 1;
      return await stableFileHash(path);
    },
    processStartTime: async (pid) => {
      assert.equal(hashes, 2);
      await sampling.pause();
      return await processStartTime(pid);
    },
  });
  await Promise.race([
    sampling.arrived,
    pending.then(() => { throw new Error("unlock finished before the process sample barrier"); }),
  ]);
  try {
    await writeFile(value.transcriptPath,
      `${JSON.stringify({ type: "event_msg", payload: { type: "task_started" } })}\n`,
      { flag: "a" });
  } finally {
    sampling.release();
  }
  const result = await pending;
  assertRefusedUntouched(value, result);
  assert.ok(result.reasons.includes("transcript_changed_before_signal"));
});

test("late evidence preserves an unchanged owner control", { timeout: 30_000 }, async (t) => {
  const value = await signalFixture(t);
  const before = await stableFileHash(value.transcriptPath);
  const result = await unlockWithLease(value);
  assert.equal(result.outcome, "unlocked");
  assert.equal(result.signalSent, "SIGTERM");
  assert.equal(result.changed, true);
  assert.equal(value.attempts(), 1);
  assert.equal(result.processExited, true);
  assert.equal(result.lockReleased, true);
  assert.equal(result.transcriptUnchanged, true);
  assert.equal((await stableFileHash(value.transcriptPath)).hash, before.hash);
  assert.equal(existsSync(value.lockPath), true);
  assert.equal(validate(result), true, JSON.stringify(validate.errors));
});

for (const [label, dependency, reason] of [
  ["an empty owner lock set", { lockFilesOpenedByProcess: async () => ({ paths: [] }) }, "owner_lock_set_changed_before_signal"],
  ["unknown owner lock set", { lockFilesOpenedByProcess: async () => ({ paths: [], error: "injected lsof failure" }) }, "owner_lock_set_unknown_before_signal:"],
  ["throwing owner lock lookup", { lockFilesOpenedByProcess: async () => { throw new Error("injected lookup failure"); } }, "owner_lock_set_unknown_before_signal:"],
  ["unavailable process sample", { processStartTime: async () => ({ status: "unknown", startTime: null, error: "injected ps failure" }) }, "owner_changed_before_signal"],
  ["throwing process sample", { processStartTime: async () => { throw new Error("injected ps failure"); } }, "owner_observation_failed_before_signal:"],
  ["failed synchronous transcript sample", { transcriptSnapshot: () => { throw new Error("injected lstat failure"); } }, "transcript_observation_failed_before_signal:"],
]) {
  test(`late evidence refuses ${label}`, { timeout: 30_000 }, async (t) => {
    const value = await signalFixture(t);
    const result = await unlockWithLease(value, dependency);
    assertRefusedUntouched(value, result);
    assert.ok(result.reasons.some((value) => value.startsWith(reason)));
  });
}

for (const type of ["symlink", "directory"]) {
  test(`late transcript sample refuses a ${type} replacement`, { timeout: 30_000 }, async (t) => {
    const value = await signalFixture(t);
    const result = await unlockWithLease(value, {
      processStartTime: async (pid) => {
        const original = join(value.codexHome, "original-transcript.jsonl");
        await rename(value.transcriptPath, original);
        if (type === "symlink") await symlink(original, value.transcriptPath);
        else await mkdir(value.transcriptPath);
        return await processStartTime(pid);
      },
    });
    assertRefusedUntouched(value, result);
    assert.ok(result.reasons.some((reason) => reason.startsWith("transcript_observation_failed_before_signal:")));
  });
}

test("late transcript descriptor close failure refuses without signaling", { timeout: 30_000 }, async (t) => {
  const value = await signalFixture(t);
  const originalOpen = fs.openSync;
  const originalClose = fs.closeSync;
  let transcriptFd = null;
  let injected = false;
  let result;
  try {
    result = await unlockWithLease(value, {
      processStartTime: async (pid) => {
        const observation = await processStartTime(pid);
        fs.openSync = (path, ...args) => {
          const fd = originalOpen(path, ...args);
          if (path === value.transcriptPath) transcriptFd = fd;
          return fd;
        };
        fs.closeSync = (fd) => {
          const closed = originalClose(fd);
          if (fd === transcriptFd) {
            // Actually close the descriptor so the injected error cannot
            // leak it or interfere with the following guarded lock probe.
            transcriptFd = null;
            injected = true;
            throw Object.assign(new Error("injected transcript close failure"), { code: "EIO" });
          }
          return closed;
        };
        syncBuiltinESMExports();
        return observation;
      },
    });
  } finally {
    fs.openSync = originalOpen;
    fs.closeSync = originalClose;
    syncBuiltinESMExports();
  }
  assert.equal(injected, true);
  assertRefusedUntouched(value, result);
  assert.ok(result.reasons.includes("transcript_observation_failed_before_signal:EIO: injected transcript close failure"));
});

for (const code of ["ESRCH", "EPERM"]) {
  test(`SIGTERM ${code} leaves process exit evidence unavailable`, { timeout: 30_000 }, async (t) => {
    const value = await signalFixture(t);
    const originalKill = process.kill;
    let attempts = 0;
    process.kill = (pid, signal) => {
      if (pid === value.child.pid && signal === "SIGTERM") {
        attempts += 1;
        throw Object.assign(new Error(`kill ${code}`), { code });
      }
      return originalKill(pid, signal);
    };
    const result = await unlockWithLease(value);
    assert.equal(result.outcome, "termination_failed");
    assert.equal(result.changed, false);
    assert.equal(result.signalSent, null);
    assert.equal(result.processExited, null);
    assert.equal(result.processObservation, null);
    assert.equal(result.lockReleased, false);
    assert.equal(result.transcriptUnchanged, null);
    assert.deepEqual(result.reasons, [`sigterm_failed:${code}: kill ${code}`]);
    assert.equal(attempts, 1);
    assert.equal(value.child.exitCode, null);
    assert.equal(value.child.signalCode, null);
    assert.equal(guardedProbeOnce(value.lockPath).status, "held");
    assert.equal(validate(result), true, JSON.stringify(validate.errors));
  });
}
