import assert from "node:assert/strict";
import { chmod, link, mkdir, mkdtemp, rename, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import { spawn } from "node:child_process";
import test from "node:test";

import {
  inspectThread,
  unlockInspectedThread,
  unlockThread,
} from "../dist/doctor.js";
import {
  OWNER_FIXTURE,
  OTHER_THREAD_ID,
  THREAD_ID,
  commandOwner,
  fixture,
  otherLockPath,
  runCli,
  stopChild,
  waitForUnlockLeaseContention,
} from "./helpers/owner-fixture.mjs";

test("classifies an unlocked lock file as stale residue", async () => {
  const value = await fixture();
  await stopChild(value.child);
  const inspection = await inspectThread(THREAD_ID, value.options);
  assert.equal(inspection.classification, "stale_residue");
  assert.equal(inspection.lock.probe.status, "free");
  assert.equal(inspection.safeToUnlock, false);
});

test("retains lock observation failure in inspection JSON", async () => {
  const codexHome = await mkdtemp(join(tmpdir(), "codex-unlock-enotdir-test-"));
  await writeFile(join(codexHome, "thread-writer-locks"), "not a directory");
  const inspection = await inspectThread(THREAD_ID, {
    codexHome,
    stabilityMs: 10,
    terminationTimeoutMs: 100,
  });
  assert.equal(inspection.classification, "unknown");
  assert.equal(inspection.lock.observation, "unknown");
  assert.match(inspection.lock.observationError, /ENOTDIR/);
  assert.equal(inspection.lock.probe.status, "unknown");
  assert.ok(inspection.blockers.includes("lock_file_observation_failed"));

  const unlock = await unlockThread(THREAD_ID, {
    codexHome,
    stabilityMs: 10,
    terminationTimeoutMs: 100,
  });
  assert.equal(unlock.outcome, "refused");
  assert.equal(unlock.signalSent, null);
  assert.ok(unlock.reasons.includes("lock_file_observation_failed"));
});

test("refuses a live owner when the transcript is not task_complete", async (t) => {
  const value = await fixture("task_started");
  t.after(async () => await stopChild(value.child));
  const inspection = await inspectThread(THREAD_ID, value.options);
  assert.equal(inspection.classification, "live_owner");
  assert.equal(inspection.safeToUnlock, false);
  assert.ok(inspection.blockers.includes("transcript_last_event_not_task_complete"));

  const result = await unlockThread(THREAD_ID, {
    ...value.options,
    terminationTimeoutMs: 500,
  });
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
  assert.equal(result.processObservation.status, "absent");
  assert.equal(result.lockReleased, true);
  assert.equal(result.transcriptUnchanged, true);
  assert.equal(result.lockFileRemovedByTool, false);
});

test("refuses an owner that holds native locks across Codex homes", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "codex-unlock-orca-test-"));
  const defaultHome = join(root, ".codex");
  const extraLock = await otherLockPath(
    root,
    join("Library", "Application Support", "orca", "codex-accounts", "account", "home"),
  );
  const value = await fixture("task_complete", {
    codexHome: defaultHome,
    additionalLockPaths: [extraLock],
  });
  t.after(async () => await stopChild(value.child));

  const inspection = await inspectThread(THREAD_ID, value.options);
  assert.equal(inspection.classification, "live_owner");
  assert.equal(inspection.safeToUnlock, false);
  assert.equal(inspection.ownerLockFiles.length, 2);
  assert.ok(inspection.ownerLockFiles.includes(value.lockPath));
  assert.ok(
    inspection.ownerLockFiles.some(
      (path) => path.includes("/orca/codex-accounts/") && path.endsWith(`${OTHER_THREAD_ID}.lock`),
    ),
  );
  assert.ok(inspection.blockers.includes("owner_holds_other_thread_locks"));
});

test("hard-linked rollout candidates do not count as owner thread locks", async (t) => {
  const value = await fixture();
  t.after(async () => await stopChild(value.child));
  const archived = join(value.codexHome, "archived_sessions");
  await mkdir(archived, { recursive: true });
  await link(
    value.transcriptPath,
    join(archived, `rollout-copy-${THREAD_ID}.jsonl`),
  );

  const inspection = await inspectThread(THREAD_ID, value.options);
  assert.deepEqual(inspection.ownerLockFiles, [value.lockPath]);
  assert.ok(inspection.blockers.includes("transcript_ambiguous"));
  assert.ok(!inspection.blockers.includes("owner_holds_other_thread_locks"));
});

test("fails closed when an open lock path cannot be resolved", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "codex-unlock-unresolved-test-"));
  const extraLock = await otherLockPath(root);
  const value = await fixture("task_complete", { additionalLockPaths: [extraLock] });
  t.after(async () => await stopChild(value.child));
  await unlink(extraLock);

  const inspection = await inspectThread(THREAD_ID, value.options);
  assert.equal(inspection.safeToUnlock, false);
  assert.ok(inspection.blockers.includes("owner_lock_file_lookup_failed"));
});

test("revalidation refuses a transcript record appended before SIGTERM", async (t) => {
  const value = await fixture();
  t.after(async () => await stopChild(value.child));
  const inspection = await inspectThread(THREAD_ID, value.options);
  await writeFile(
    value.transcriptPath,
    `${JSON.stringify({ type: "event_msg", payload: { type: "task_started" } })}\n`,
    { flag: "a" },
  );

  const result = await unlockInspectedThread(inspection, value.options);
  assert.equal(result.outcome, "refused");
  assert.equal(result.signalSent, null);
  assert.equal(value.child.exitCode, null);
  assert.ok(result.reasons.some((reason) => reason.includes("transcript")));
});

test("revalidation refuses a newly acquired lock in another home", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "codex-unlock-delayed-lock-test-"));
  const extraLock = await otherLockPath(root);
  const value = await fixture();
  t.after(async () => await stopChild(value.child));
  const inspection = await inspectThread(THREAD_ID, value.options);
  await commandOwner(value.child, { action: "acquire", path: extraLock });

  const result = await unlockInspectedThread(inspection, value.options);
  assert.equal(result.outcome, "refused");
  assert.equal(result.signalSent, null);
  assert.equal(value.child.exitCode, null);
  assert.ok(
    result.reasons.includes("revalidation_owner_holds_other_thread_locks") ||
      result.reasons.includes("owner_lock_set_changed"),
  );
});

test("revalidation refuses changed process arguments", async (t) => {
  const value = await fixture();
  t.after(async () => await stopChild(value.child));
  const inspection = await inspectThread(THREAD_ID, value.options);
  await commandOwner(value.child, {
    action: "title",
    value: "not-the-original-codex-owner",
  });

  const result = await unlockInspectedThread(inspection, value.options);
  assert.equal(result.outcome, "refused");
  assert.equal(result.signalSent, null);
  assert.equal(value.child.exitCode, null);
  assert.ok(result.reasons.includes("owner_identity_changed"));
});

test("revalidation refuses a replaced lock inode and owner", async (t) => {
  const value = await fixture();
  const replacementOwner = { child: null };
  t.after(async () => {
    if (replacementOwner.child) await stopChild(replacementOwner.child);
    await stopChild(value.child);
  });
  const inspection = await inspectThread(THREAD_ID, value.options);
  await rename(value.lockPath, `${value.lockPath}.old`);
  await writeFile(value.lockPath, "");
  const child = spawn(OWNER_FIXTURE, [value.lockPath], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  replacementOwner.child = child;
  child.stdout.setEncoding("utf8");
  await new Promise((resolveReady, reject) => {
    child.stdout.once("data", (chunk) => {
      if (chunk.includes("ready")) resolveReady();
      else reject(new Error(`unexpected replacement output: ${chunk}`));
    });
    child.once("error", reject);
    child.once("exit", (code) => reject(new Error(`replacement exited early: ${code}`)));
  });

  const result = await unlockInspectedThread(inspection, value.options);
  assert.equal(result.outcome, "refused");
  assert.equal(result.signalSent, null);
  assert.equal(value.child.exitCode, null);
  assert.equal(replacementOwner.child.exitCode, null);
  assert.ok(
    result.reasons.some(
      (reason) =>
        reason.includes("lock") ||
        reason.includes("owner") ||
        reason === "classification_unknown",
    ),
  );
});

test("concurrent CLI unlock attempts send at most one SIGTERM", async (t) => {
  const value = await fixture();
  t.after(async () => await stopChild(value.child));
  const firstArgs = [
    "unlock",
    THREAD_ID,
    "--json",
    "--codex-home",
    value.codexHome,
    "--stability-ms",
    "1000",
  ];
  const competingArgs = [...firstArgs.slice(0, -1), "250"];
  const first = runCli(firstArgs);
  await waitForUnlockLeaseContention(value.codexHome);
  const invocations = await Promise.all([first, runCli(competingArgs)]);
  const results = invocations.map((invocation) => JSON.parse(invocation.stdout));
  const signaled = results.filter((result) => result.signalSent === "SIGTERM");

  assert.equal(signaled.length, 1, JSON.stringify(results, null, 2));
  assert.equal(signaled[0].outcome, "unlocked", JSON.stringify(results, null, 2));
  const competing = results.find((result) => result.signalSent === null);
  assert.equal(competing?.outcome, "refused", JSON.stringify(results, null, 2));
  assert.deepEqual(competing?.reasons, ["concurrent_unlock_in_progress"]);
});

test("coordination failure refuses without signaling the safe owner", async (t) => {
  const value = await fixture();
  t.after(async () => await stopChild(value.child));
  const runtimeDirectory = await mkdtemp(join(tmpdir(), "codex-unlock-public-runtime-"));
  await chmod(runtimeDirectory, 0o755);

  const result = await runCli(
    [
      "unlock",
      THREAD_ID,
      "--json",
      "--codex-home",
      value.codexHome,
      "--stability-ms",
      "250",
    ],
    { ...process.env, XDG_RUNTIME_DIR: runtimeDirectory },
  );
  const parsed = JSON.parse(result.stdout);

  assert.equal(result.code, 2);
  assert.equal(parsed.outcome, "refused");
  assert.equal(parsed.signalSent, null);
  assert.ok(parsed.reasons[0].startsWith("unlock_coordination_failed:"));
  assert.equal(value.child.exitCode, null);
});

test("process inspection failure cannot produce a successful unlock", async (t) => {
  const value = await fixture();
  t.after(async () => await stopChild(value.child));
  const bin = await mkdtemp(join(tmpdir(), "codex-unlock-failing-ps-"));
  const fakePs = join(bin, "ps");
  await writeFile(fakePs, "#!/bin/sh\nexit 2\n", { mode: 0o755 });

  const result = await runCli(
    [
      "unlock",
      THREAD_ID,
      "--json",
      "--codex-home",
      value.codexHome,
      "--stability-ms",
      "250",
    ],
    { ...process.env, PATH: `${bin}:${process.env.PATH}` },
  );
  assert.equal(result.code, 2, result.stderr);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.outcome, "refused");
  assert.equal(parsed.signalSent, null);
  assert.equal(parsed.inspection.classification, "unknown");
  assert.ok(
    parsed.inspection.openers[0].errors.some((error) =>
      error.startsWith("start_time_unknown"),
    ),
  );
  assert.equal(value.child.exitCode, null);
});

test("post-signal process observation failure cannot report success", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "codex-unlock-post-signal-ps-"));
  const marker = join(root, "owner-terminated");
  const value = await fixture("task_complete", {
    ownerEnv: { CODEX_FIXTURE_SIGTERM_MARKER: marker },
  });
  t.after(async () => await stopChild(value.child));
  const bin = join(root, "bin");
  await mkdir(bin);
  const fakePs = join(bin, "ps");
  await writeFile(
    fakePs,
    `#!/bin/sh\nif [ -e '${marker}' ]; then exit 2; fi\nexec /bin/ps "$@"\n`,
    { mode: 0o755 },
  );

  const result = await runCli(
    [
      "unlock",
      THREAD_ID,
      "--json",
      "--codex-home",
      value.codexHome,
      "--stability-ms",
      "250",
      "--timeout-ms",
      "500",
    ],
    { ...process.env, PATH: `${bin}:${process.env.PATH}` },
  );
  assert.equal(result.code, 3, result.stderr);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.outcome, "termination_failed");
  assert.equal(parsed.signalSent, "SIGTERM");
  assert.equal(parsed.processExited, null);
  assert.equal(parsed.processObservation.status, "unknown");
  assert.ok(parsed.reasons.some((reason) => reason.startsWith("owner_exit_unknown:")));
});

test("post-signal lock observation failure cannot report release", async (t) => {
  const value = await fixture("task_complete", {
    ownerEnv: { CODEX_FIXTURE_SIGTERM_BREAK_LOCK_PATH: "1" },
  });
  t.after(async () => await stopChild(value.child));

  const result = await unlockThread(THREAD_ID, {
    ...value.options,
    terminationTimeoutMs: 500,
  });
  assert.equal(result.outcome, "termination_failed");
  assert.equal(result.signalSent, "SIGTERM");
  assert.equal(result.processExited, true);
  assert.equal(result.lockReleased, false);
  assert.ok(result.reasons.some((reason) => reason.startsWith("lock_release_unknown:")));
});
