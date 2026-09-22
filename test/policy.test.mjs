import assert from "node:assert/strict";
import process from "node:process";
import test from "node:test";

import { evaluateSafety } from "../dist/policy.js";

const THREAD_ID = "01a089e8-3731-7202-ba68-0f4b0a3b2711";
const LOCK_PATH = `/tmp/codex-home/thread-writer-locks/${THREAD_ID}.lock`;

function evidence(overrides = {}) {
  const uid = process.getuid?.() ?? 501;
  const owner = {
    pid: 4242,
    ppid: 1,
    uid,
    startTime: "Sun Sep 20 12:34:56 2026",
    tty: "/dev/ttys001",
    command: "codex",
    arguments: "codex app-server",
    cwd: "/tmp/project",
    lsofCommand: "codex",
    identityComplete: true,
    isCodex: true,
    isSharedService: false,
    errors: [],
  };
  return {
    schemaVersion: 1,
    command: "inspect",
    inspectedAt: "2026-09-22T00:00:00.000Z",
    codexHome: "/tmp/codex-home",
    threadId: THREAD_ID,
    classification: "live_owner",
    lock: {
      path: LOCK_PATH,
      observation: "present",
      exists: true,
      regularFile: true,
      symlink: false,
      ownedByCurrentUser: true,
      snapshot: {
        device: "1",
        inode: "2",
        mode: 0o100600,
        uid,
        links: 1,
        size: 0,
        modifiedAt: "2026-09-22T00:00:00.000Z",
        modifiedMs: 0,
      },
      stable: true,
      probe: { status: "held", method: "flock_exclusive_nonblocking" },
    },
    owner,
    openers: [owner],
    ownerIdentityStable: true,
    ownerLockFiles: [LOCK_PATH],
    descendantPids: [],
    transcript: {
      status: "found",
      path: `/tmp/codex-home/sessions/rollout-${THREAD_ID}.jsonl`,
      candidates: [`/tmp/codex-home/sessions/rollout-${THREAD_ID}.jsonl`],
      snapshot: {
        device: "1",
        inode: "3",
        mode: 0o100600,
        uid,
        links: 1,
        size: 100,
        modifiedAt: "2026-09-22T00:00:00.000Z",
        modifiedMs: 0,
      },
      lastRecord: {
        recordType: "event_msg",
        eventType: "task_complete",
        timestamp: "2026-09-22T00:00:00.000Z",
        ordinal: null,
      },
      stable: true,
    },
    ...overrides,
  };
}

function context(overrides = {}) {
  return {
    currentProcessFamily: new Set([100, 101]),
    currentUid: process.getuid?.() ?? 501,
    ...overrides,
  };
}

test("authorizes complete deterministic evidence without process fixtures", () => {
  const decision = evaluateSafety(evidence(), context());
  assert.deepEqual(decision, {
    safeToUnlock: true,
    blockers: [],
    warnings: [],
  });
});

test("refuses shared owners and current-process-family owners", () => {
  const value = evidence();
  value.owner.isSharedService = true;
  const decision = evaluateSafety(value, context({
    currentProcessFamily: new Set([value.owner.pid]),
  }));
  assert.equal(decision.safeToUnlock, false);
  assert.ok(decision.blockers.includes("lock_owner_is_shared_service"));
  assert.ok(decision.blockers.includes("lock_owner_is_current_process_family"));
});

test("fails closed when owner lookup and current-family evidence are unavailable", () => {
  const decision = evaluateSafety(
    evidence({ ownerLockFiles: null }),
    context({
      currentProcessFamily: null,
      openerError: "lsof failed",
      ownerLockError: "open files unavailable",
    }),
  );
  assert.equal(decision.safeToUnlock, false);
  assert.ok(decision.blockers.includes("lock_opener_lookup_failed"));
  assert.ok(decision.blockers.includes("current_process_family_unavailable"));
  assert.ok(decision.blockers.includes("owner_lock_file_lookup_failed"));
  assert.ok(decision.blockers.includes("owner_lock_files_unavailable"));
});

test("refuses incomplete transcript evidence", () => {
  const value = evidence();
  value.transcript = {
    ...value.transcript,
    stable: false,
    lastRecord: {
      ...value.transcript.lastRecord,
      eventType: "task_started",
    },
  };
  const decision = evaluateSafety(value, context());
  assert.equal(decision.safeToUnlock, false);
  assert.ok(decision.blockers.includes("transcript_not_stable"));
  assert.ok(decision.blockers.includes("transcript_last_event_not_task_complete"));
});
