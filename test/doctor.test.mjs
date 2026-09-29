import assert from "node:assert/strict";
import { once } from "node:events";
import { existsSync } from "node:fs";
import {
  access,
  chmod,
  link,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import process from "node:process";
import { URL } from "node:url";
import { spawn } from "node:child_process";
import test from "node:test";

import {
  inspectThread,
  listThreads,
  unlockInspectedThread,
  unlockThread,
} from "../dist/doctor.js";
import { LEASE_DIRECTORY_NAME, acquireUnlockLease } from "../dist/coordination.js";
import {
  DIAGNOSTIC_OVERRIDE,
  OWNER_FIXTURE,
  OTHER_THREAD_ID,
  POST_SIGNAL_FAULT,
  SUCCESSOR_FIXTURE,
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
  const invocations = await overlappingUnlocks(value.codexHome, firstArgs, competingArgs);
  const results = invocations.map((invocation) => JSON.parse(invocation.stdout));
  const signaled = results.filter((result) => result.signalSent === "SIGTERM");

  assert.equal(signaled.length, 1, JSON.stringify(results, null, 2));
  assert.equal(signaled[0].outcome, "unlocked", JSON.stringify(results, null, 2));
  const competing = results.find((result) => result.signalSent === null);
  assert.equal(competing?.outcome, "refused", JSON.stringify(results, null, 2));
  assert.deepEqual(competing?.reasons, ["concurrent_unlock_in_progress"]);
});

function unlockArgs(codexHome, stabilityMs = "250") {
  return [
    "unlock",
    THREAD_ID,
    "--json",
    "--codex-home",
    codexHome,
    "--stability-ms",
    stabilityMs,
  ];
}

function environmentWithout(names, additions = {}) {
  const environment = { ...process.env, ...additions };
  for (const name of names) delete environment[name];
  return environment;
}

async function overlappingUnlocks(codexHome, firstArgs, competingArgs,
  firstEnv = process.env, competingEnv = process.env) {
  const release = join(codexHome, "test-lease-release");
  const first = runCli(firstArgs, {
    ...firstEnv,
    CODEX_UNLOCK_TEST_LEASE_RELEASE: release,
  }, ["--import", new URL("./helpers/lease-barrier.mjs", import.meta.url).href]);
  let competing;
  try {
    await waitForUnlockLeaseContention(codexHome);
    competing = await runCli(competingArgs, competingEnv);
  } finally {
    await writeFile(release, "release");
    await first;
  }
  return [await first, competing];
}

test("concurrent CLI unlocks from different TMPDIR and XDG_RUNTIME_DIR send one SIGTERM", async (t) => {
  const value = await fixture();
  t.after(async () => await stopChild(value.child));
  const runtimeDirectory = await mkdtemp(join(tmpdir(), "codex-unlock-runtime-"));
  await chmod(runtimeDirectory, 0o700);
  const invocations = await overlappingUnlocks(
    value.codexHome,
    unlockArgs(value.codexHome, "1000"),
    unlockArgs(value.codexHome),
    environmentWithout(["XDG_RUNTIME_DIR"], { TMPDIR: runtimeDirectory }),
    environmentWithout(["TMPDIR"], { XDG_RUNTIME_DIR: runtimeDirectory }),
  );
  const results = invocations.map((invocation) => JSON.parse(invocation.stdout));
  const signaled = results.filter((result) => result.signalSent === "SIGTERM");

  assert.equal(signaled.length, 1, JSON.stringify(results, null, 2));
  const competing = results.find((result) => result.signalSent === null);
  assert.deepEqual(competing?.reasons, ["concurrent_unlock_in_progress"]);
});

test("aliased Codex homes share one unlock lease", async (t) => {
  const value = await fixture();
  t.after(async () => await stopChild(value.child));
  const linkedHome = await mkdtemp(join(tmpdir(), "codex-unlock-linked-home-"));
  await symlink(
    join(value.codexHome, "thread-writer-locks"),
    join(linkedHome, "thread-writer-locks"),
  );
  await symlink(join(value.codexHome, "sessions"), join(linkedHome, "sessions"));
  const aliases = [linkedHome, `${value.codexHome}-alias`];
  await symlink(value.codexHome, aliases[1]);
  const variant = join(
    dirname(value.codexHome),
    basename(value.codexHome).toUpperCase(),
  );
  if (variant !== value.codexHome && existsSync(variant)) aliases.push(variant);

  const lease = acquireUnlockLease(value.codexHome, THREAD_ID);
  assert.equal(lease.status, "acquired");
  if (lease.status !== "acquired") return;
  try {
    for (const alias of aliases) {
      const result = await runCli(unlockArgs(alias));
      const parsed = JSON.parse(result.stdout);
      assert.equal(parsed.outcome, "refused", alias);
      assert.equal(parsed.signalSent, null, alias);
      assert.deepEqual(parsed.reasons, ["concurrent_unlock_in_progress"], alias);
      assert.equal(value.child.exitCode, null);
    }
  } finally {
    lease.lease.release();
  }
});

test("a squatted shared temporary lease root does not deny unlock", async (t) => {
  const value = await fixture();
  t.after(async () => await stopChild(value.child));
  const temporary = await mkdtemp(join(tmpdir(), "codex-unlock-shared-tmp-"));
  const squatted = join(temporary, `codex-unlock-${process.getuid()}`);
  await mkdir(squatted);
  await chmod(squatted, 0o777);

  const result = await runCli(
    unlockArgs(value.codexHome),
    environmentWithout(["XDG_RUNTIME_DIR"], { TMPDIR: temporary }),
  );
  const parsed = JSON.parse(result.stdout);

  assert.equal(parsed.outcome, "unlocked", result.stdout);
  assert.equal(parsed.signalSent, "SIGTERM");
});

test("coordination failure refuses without signaling the safe owner", async (t) => {
  const value = await fixture();
  t.after(async () => await stopChild(value.child));
  const coordinationDirectory = join(value.codexHome, LEASE_DIRECTORY_NAME);
  await mkdir(coordinationDirectory);
  await chmod(coordinationDirectory, 0o755);

  const result = await runCli(unlockArgs(value.codexHome));
  const parsed = JSON.parse(result.stdout);

  assert.equal(result.code, 2);
  assert.equal(parsed.outcome, "refused");
  assert.equal(parsed.signalSent, null);
  assert.deepEqual(parsed.reasons, [
    "unlock_coordination_failed:coordination_directory_is_not_private",
  ]);
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
    { ...process.env, CODEX_UNLOCK_TEST_PS: fakePs },
    ["--import", DIAGNOSTIC_OVERRIDE],
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
    { ...process.env, CODEX_UNLOCK_TEST_PS: fakePs },
    ["--import", DIAGNOSTIC_OVERRIDE],
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

test("terminal width variables cannot hide a shared app-server owner", async (t) => {
  const value = await fixture();
  t.after(async () => await stopChild(value.child));
  const title = `codex --x${"x".repeat(48)} app-server`;
  await commandOwner(value.child, { action: "title", value: title });

  const result = await runCli(
    ["inspect", THREAD_ID, "--json", "--codex-home", value.codexHome, "--stability-ms", "250"],
    { ...process.env, COLUMNS: "40", LINES: "5", PS_FORMAT: "pid" },
  );
  assert.equal(result.stderr, "");
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.owner.pid, value.child.pid);
  assert.ok(parsed.owner.arguments === null || parsed.owner.arguments.includes("app-server"));
  assert.equal(parsed.owner.isSharedService, true);
  assert.equal(parsed.safeToUnlock, false);
  assert.ok(parsed.blockers.includes("lock_owner_is_shared_service"));
});

test("ps and lsof on PATH cannot supply process evidence", async (t) => {
  const value = await fixture();
  t.after(async () => await stopChild(value.child));
  const bin = await mkdtemp(join(tmpdir(), "codex-unlock-shadow-path-"));
  const marker = join(bin, "shadow-used");
  for (const tool of ["ps", "lsof"]) {
    await writeFile(
      join(bin, tool),
      `#!/bin/sh\necho ${tool} >> '${marker}'\nexit 2\n`,
      { mode: 0o755 },
    );
  }

  const result = await runCli(
    ["inspect", THREAD_ID, "--json", "--codex-home", value.codexHome, "--stability-ms", "250"],
    { ...process.env, PATH: `${bin}:${process.env.PATH}` },
  );
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.classification, "live_owner", result.stdout);
  assert.equal(parsed.owner.pid, value.child.pid);
  assert.equal(parsed.safeToUnlock, true);
  await assert.rejects(access(marker), { code: "ENOENT" });
});

test("matches owner locks by device and inode under a non-ASCII Codex home", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "codex-unlock-non-ascii-"));
  const value = await fixture("task_complete", {
    codexHome: join(root, "홈 코덱스", ".codex"),
  });
  t.after(async () => await stopChild(value.child));

  const inspection = await inspectThread(THREAD_ID, value.options);
  assert.equal(inspection.classification, "live_owner");
  assert.deepEqual(inspection.ownerLockFiles, [value.lockPath]);
  assert.ok(!inspection.blockers.includes("owner_lock_file_lookup_failed"));
  assert.equal(inspection.safeToUnlock, true, inspection.blockers.join(","));

  const result = await unlockThread(THREAD_ID, value.options);
  assert.equal(result.outcome, "unlocked");
  assert.equal(result.lockReleased, true);
});

test("an unresolvable second lock under a non-ASCII home still fails closed", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "codex-unlock-non-ascii-other-"));
  const extraLock = await otherLockPath(join(root, "다른 홈"));
  const value = await fixture("task_complete", {
    codexHome: join(root, "홈 코덱스", ".codex"),
    additionalLockPaths: [extraLock],
  });
  t.after(async () => await stopChild(value.child));

  const inspection = await inspectThread(THREAD_ID, value.options);
  assert.equal(inspection.safeToUnlock, false);
  assert.ok(
    inspection.blockers.includes("owner_lock_file_lookup_failed") ||
      inspection.blockers.includes("owner_holds_other_thread_locks"),
  );
});

test("matches owner locks when lsof omits file descriptor fields (Linux format)", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "codex-unlock-lsof-no-f-"));
  const value = await fixture("task_complete", {
    codexHome: join(root, "홈 코덱스", ".codex"),
  });
  t.after(async () => await stopChild(value.child));
  const fakeLsof = join(root, "lsof");
  await writeFile(
    fakeLsof,
    [
      "#!/bin/sh",
      "for real in /usr/sbin/lsof /usr/bin/lsof; do [ -x \"$real\" ] && break; done",
      "\"$real\" \"$@\" | tr '\\000' '\\n' | grep -v '^f' | tr '\\n' '\\000'",
      "",
    ].join("\n"),
    { mode: 0o755 },
  );

  const result = await runCli(
    ["inspect", THREAD_ID, "--json", "--codex-home", value.codexHome, "--stability-ms", "250"],
    { ...process.env, CODEX_UNLOCK_TEST_LSOF: fakeLsof },
    ["--import", DIAGNOSTIC_OVERRIDE],
  );
  assert.equal(result.stderr, "");
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.classification, "live_owner", result.stdout);
  assert.deepEqual(parsed.ownerLockFiles, [value.lockPath]);
  assert.equal(parsed.safeToUnlock, true, parsed.blockers.join(","));
});

async function unlockResultValidator() {
  const { default: Ajv2020 } = await import("ajv/dist/2020.js");
  const schema = JSON.parse(
    await readFile(resolve("schemas/codex-unlock-v1.schema.json"), "utf8"),
  );
  return new Ajv2020({ strict: true, allowUnionTypes: true }).compile(schema);
}

function killQuietly(pid) {
  if (!pid) return;
  try {
    process.kill(pid, "SIGKILL");
  } catch {
    // Already gone.
  }
}

test("an unreaped zombie owner counts as exited", async (t) => {
  const value = await fixture("task_complete", { unreapedParent: true });
  t.after(async () => await stopChild(value.child));
  const inspection = await inspectThread(THREAD_ID, value.options);
  assert.equal(inspection.safeToUnlock, true, inspection.blockers.join(","));
  const ownerPid = inspection.owner.pid;
  assert.notEqual(ownerPid, value.child.pid);
  t.after(() => killQuietly(ownerPid));

  const result = await runCli(
    ["unlock", THREAD_ID, "--json", "--codex-home", value.codexHome, "--stability-ms", "250"],
    { ...process.env, CODEX_UNLOCK_NO_UPDATE_NOTICE: "yes" },
  );
  assert.equal(result.stderr, "");
  const parsed = JSON.parse(result.stdout);
  assert.equal(result.code, 0, result.stdout);
  assert.equal(parsed.outcome, "unlocked");
  assert.equal(parsed.pid, ownerPid);
  assert.equal(parsed.processExited, true);
  assert.equal(parsed.processObservation.zombie, true);
  assert.equal(parsed.lockReleased, true);
  assert.deepEqual(parsed.reasons, []);
  const validate = await unlockResultValidator();
  assert.equal(validate(parsed), true, JSON.stringify(validate.errors));
});

test("an immediate successor is reported as a reacquisition, not an unreleased lock", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "codex-unlock-successor-"));
  const marker = join(root, "owner-terminated");
  const acquiredMarker = join(root, "successor-acquired");
  const value = await fixture("task_complete", {
    ownerEnv: { CODEX_FIXTURE_SIGTERM_MARKER: marker },
  });
  t.after(async () => await stopChild(value.child));
  const successor = spawn(process.execPath, [SUCCESSOR_FIXTURE, marker, value.lockPath, acquiredMarker], {
    stdio: ["ignore", "pipe", "inherit"],
  });
  t.after(async () => await stopChild(successor));
  successor.stdout.setEncoding("utf8");
  let successorOutput = "";
  successor.stdout.on("data", (chunk) => {
    successorOutput += chunk;
  });
  await once(successor.stdout, "data");

  const result = await runCli(
    ["unlock", THREAD_ID, "--json", "--codex-home", value.codexHome, "--stability-ms", "250"],
    { ...process.env, CODEX_UNLOCK_NO_UPDATE_NOTICE: "yes",
      CODEX_UNLOCK_TEST_SUCCESSOR_ACQUIRED: acquiredMarker },
    ["--import", resolve("test/helpers/successor-barrier.mjs")],
  );
  assert.equal(result.stderr, "");
  const parsed = JSON.parse(result.stdout);
  assert.equal(result.code, 3, result.stdout);
  assert.equal(parsed.outcome, "verification_failed");
  assert.equal(parsed.pid, value.child.pid);
  assert.equal(parsed.signalSent, "SIGTERM");
  assert.equal(parsed.processExited, true);
  assert.equal(parsed.lockReleased, false);
  assert.deepEqual(parsed.lockReacquiredBy.map((holder) => holder.pid), [successor.pid]);
  assert.ok(parsed.reasons.includes(`lock_reacquired_by_other_owner:${successor.pid}`));
  assert.ok(!parsed.reasons.includes("lock_was_not_released"));
  assert.match(successorOutput, /acquired/);
  assert.equal(successor.exitCode, null);
  assert.equal(successor.signalCode, null);
  const validate = await unlockResultValidator();
  assert.equal(validate(parsed), true, JSON.stringify(validate.errors));
});

for (const mode of ["emfile", "throw"]) {
  test(`post-signal ${mode} failure preserves the signal in the unlock result`, async (t) => {
    const value = await fixture();
    t.after(async () => await stopChild(value.child));

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
      {
        ...process.env,
        CODEX_UNLOCK_NO_UPDATE_NOTICE: "yes",
        CODEX_UNLOCK_TEST_POST_SIGNAL_FAULT: mode,
      },
      ["--import", POST_SIGNAL_FAULT],
    );
    assert.equal(result.stderr, "");
    assert.equal(result.code, 3, result.stdout);
    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.command, "unlock");
    assert.equal(parsed.outcome, "termination_failed");
    assert.equal(parsed.pid, value.child.pid);
    assert.equal(parsed.signalSent, "SIGTERM");
    assert.equal(parsed.changed, true);
    const expectedReason =
      mode === "throw" ? "post_signal_verification_failed:" : "owner_exit_unknown:";
    assert.ok(
      parsed.reasons.some((reason) => reason.startsWith(expectedReason)),
      parsed.reasons.join(","),
    );
    assert.equal(parsed.processExited, null);
    const validate = await unlockResultValidator();
    assert.equal(validate(parsed), true, JSON.stringify(validate.errors));
  });
}
test("a missing Codex home is a command failure, not a confirmed-absent lock", async () => {
  const codexHome = join(await mkdtemp(join(tmpdir(), "codex-unlock-missing-home-")), "typo");
  const options = { codexHome, stabilityMs: 10, terminationTimeoutMs: 100 };
  await assert.rejects(inspectThread(THREAD_ID, options), /Codex home does not exist/);
  await assert.rejects(unlockThread(THREAD_ID, options), /Codex home does not exist/);
  await assert.rejects(listThreads(options), /Codex home does not exist/);

  const fileHome = join(await mkdtemp(join(tmpdir(), "codex-unlock-file-home-")), "home");
  await writeFile(fileHome, "not a directory");
  await assert.rejects(
    inspectThread(THREAD_ID, { ...options, codexHome: fileHome }),
    /Codex home is not a directory/,
  );

  for (const args of [
    ["list", "--json", "--codex-home", codexHome],
    ["inspect", THREAD_ID, "--json", "--codex-home", codexHome],
    ["unlock", THREAD_ID, "--json", "--codex-home", codexHome],
  ]) {
    const result = await runCli([...args, "--no-update-notice"]);
    assert.equal(result.code, 3, result.stdout);
    assert.equal(result.stderr, "");
    const value = JSON.parse(result.stdout);
    assert.equal(value.command, args[0]);
    assert.equal(value.errorCode, "command_failed");
    assert.match(value.error, /Codex home does not exist/);
    assert.equal(value.lockReleased, undefined);
  }
});

test("a dangling thread-writer-locks symlink is unknown, not absent", async () => {
  const codexHome = await mkdtemp(join(tmpdir(), "codex-unlock-dangling-locks-"));
  await symlink(join(codexHome, "unmounted-volume"), join(codexHome, "thread-writer-locks"));
  const options = { codexHome, stabilityMs: 10, terminationTimeoutMs: 100 };

  const inspection = await inspectThread(THREAD_ID, options);
  assert.equal(inspection.classification, "unknown");
  assert.equal(inspection.lock.observation, "unknown");
  assert.match(inspection.lock.observationError, /dangling symlink/);
  assert.equal(inspection.safeToUnlock, false);

  const unlock = await unlockThread(THREAD_ID, options);
  assert.equal(unlock.outcome, "refused");
  assert.equal(unlock.lockReleased, false);
  assert.equal(unlock.signalSent, null);

  await assert.rejects(listThreads(options), /dangling symlink/);
  const list = await runCli(["list", "--json", "--no-update-notice", "--codex-home", codexHome]);
  assert.equal(list.code, 3);
  assert.equal(JSON.parse(list.stdout).errorCode, "command_failed");

  const cli = await runCli(["unlock", THREAD_ID, "--json", "--no-update-notice", "--codex-home", codexHome]);
  assert.equal(cli.code, 2);
  assert.equal(JSON.parse(cli.stdout).outcome, "refused");
});

test("an existing Codex home without thread-writer-locks remains a confirmed absence", async () => {
  const codexHome = await mkdtemp(join(tmpdir(), "codex-unlock-no-locks-yet-"));
  const options = { codexHome, stabilityMs: 10, terminationTimeoutMs: 100 };
  const inspection = await inspectThread(THREAD_ID, options);
  assert.equal(inspection.classification, "absent");
  const list = await listThreads(options);
  assert.equal(list.count, 0);
  const unlock = await unlockThread(THREAD_ID, options);
  assert.equal(unlock.outcome, "not_locked");
});
