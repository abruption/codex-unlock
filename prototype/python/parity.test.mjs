import assert from "node:assert/strict";
import { once } from "node:events";
import { access, link, mkdir, mkdtemp, readFile, rename, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import process from "node:process";
import { spawn } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";

import Ajv2020 from "ajv/dist/2020.js";
import { inspectThread, listThreads, unlockInspectedThread, unlockThread } from "../../dist/doctor.js";
import { acquireUnlockLease } from "../../dist/coordination.js";
import {
  THREAD_ID, commandOwner, fixture, otherLockPath, runCli, stopChild,
} from "../../test/helpers/owner-fixture.mjs";

const python = process.env.CODEX_UNLOCK_TEST_PYTHON ?? "python3";
const pythonPath = resolve("prototype/python");
const schema = JSON.parse(await readFile("schemas/codex-unlock-v1.schema.json", "utf8"));
const validate = new Ajv2020({ strict: true, allowUnionTypes: true }).compile(schema);

async function testFixture(t, event = "task_complete", settings = {}) {
  const root = process.env.CODEX_UNLOCK_TEST_TMP ?? tmpdir();
  const codexHome = await mkdtemp(join(root, "codex-python-parity-"));
  let value;
  try {
    value = await fixture(event, { ...settings, codexHome });
  } catch (error) {
    await rm(codexHome, { recursive: true, force: true });
    throw error;
  }
  value.extraOwners = [];
  t.after(async () => {
    for (const owner of value.extraOwners) await stopChild(owner);
    await stopChild(value.child);
    await rm(codexHome, { recursive: true, force: true });
  });
  return value;
}

async function runPython(command, home, extra = []) {
  const args = ["-m", "codex_unlock_prototype", command];
  if (command !== "list") args.push(THREAD_ID);
  args.push("--json", "--codex-home", home, "--stability-ms", "250", ...extra);
  const child = spawn(python, args, {
    env: { ...process.env, PYTHONPATH: pythonPath, CODEX_UNLOCK_NO_UPDATE_NOTICE: "1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (data) => { stdout += data; });
  child.stderr.on("data", (data) => { stderr += data; });
  const [code] = await once(child, "exit");
  assert.equal(stderr, "", stderr);
  const value = JSON.parse(stdout);
  assert.equal(validate(value), true, JSON.stringify(validate.errors));
  return { code, value };
}

async function gatedPython(value, stage, onReady) {
  const gate = join(value.codexHome, "python-test-gate");
  await mkdir(gate);
  const args = ["-m", "codex_unlock_prototype", "unlock", THREAD_ID, "--json",
    "--codex-home", value.codexHome, "--stability-ms", "250",
    "--test-gate", gate, "--test-gate-stage", stage];
  const child = spawn(python, args, {
    env: { ...process.env, PYTHONPATH: pythonPath, CODEX_UNLOCK_NO_UPDATE_NOTICE: "1" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (data) => { stdout += data; });
  child.stderr.on("data", (data) => { stderr += data; });
  const deadline = Date.now() + 8_000;
  while (Date.now() < deadline) {
    try {
      await access(join(gate, "ready"));
      break;
    } catch {
      if (child.exitCode !== null) throw new Error(`Python gate exited: ${stderr} ${stdout}`);
      await delay(25);
    }
  }
  await access(join(gate, "ready"));
  try {
    await onReady();
  } finally {
    await writeFile(join(gate, "go"), "");
  }
  const [code] = await once(child, "exit");
  assert.equal(stderr, "", stderr);
  const parsed = JSON.parse(stdout);
  assert.equal(validate(parsed), true, JSON.stringify(validate.errors));
  return { code, value: parsed };
}

function comparable(value) {
  return {
    classification: value.classification,
    safeToUnlock: value.safeToUnlock,
    blockers: value.blockers,
    lockObservation: value.lock.observation,
    probe: value.lock.probe.status,
    ownerPid: value.owner?.pid ?? null,
    ownerStable: value.ownerIdentityStable,
    ownerLocks: value.ownerLockFiles,
    transcriptStatus: value.transcript.status,
    lastEvent: value.transcript.lastRecord?.eventType ?? null,
    transcriptStable: value.transcript.stable,
  };
}

async function compareInspect(value) {
  const node = await inspectThread(THREAD_ID, { ...value.options, stabilityMs: 250 });
  const py = await runPython("inspect", value.codexHome);
  assert.equal(py.code, 0);
  assert.deepEqual(comparable(py.value), comparable(node));
  return { node, py: py.value };
}

test("Python and Node agree on live, completed and active owners", async (t) => {
  for (const event of ["task_complete", "task_started"]) {
    const value = await testFixture(t, event);
    const { node } = await compareInspect(value);
    assert.equal(node.safeToUnlock, event === "task_complete");
  }
});

test("Python list retains JSON v1 session inspection semantics", async (t) => {
  const value = await testFixture(t);
  const node = await listThreads({ ...value.options, stabilityMs: 250 });
  const py = await runPython("list", value.codexHome);
  assert.equal(py.code, 0);
  assert.equal(py.value.count, node.count);
  assert.deepEqual(py.value.sessions.map(comparable), node.sessions.map(comparable));
});

test("Python and Node agree on absent, stale, and ambiguous transcripts", async (t) => {
  const value = await testFixture(t);
  await compareInspect(value);
  await stopChild(value.child);
  await compareInspect(value);
  const absent = await runPython("inspect", join(value.codexHome, "absent"));
  assert.equal(absent.value.classification, "absent");
  const second = await testFixture(t);
  await mkdir(join(second.codexHome, "archived_sessions"), { recursive: true });
  await link(second.transcriptPath, join(second.codexHome, "archived_sessions", `rollout-copy-${THREAD_ID}.jsonl`));
  await compareInspect(second);
});

test("Python and Node refuse cross-home locks and symlink lock evidence", async (t) => {
  const value = await testFixture(t);
  const extra = await otherLockPath(value.codexHome, "other-home");
  await commandOwner(value.child, { action: "acquire", path: extra });
  const { node } = await compareInspect(value);
  assert.ok(node.blockers.includes("owner_holds_other_thread_locks"));
  const linked = await testFixture(t);
  await stopChild(linked.child);
  await unlink(linked.lockPath);
  await symlink(extra, linked.lockPath);
  await compareInspect(linked);
});

test("Python and Node refuse multiply linked native lock files", async (t) => {
  const value = await testFixture(t);
  await link(value.lockPath, `${value.lockPath}.copy`);
  const node = await inspectThread(THREAD_ID, { ...value.options, stabilityMs: 250 });
  const observed = await runPython("inspect", value.codexHome);
  assert.ok(node.blockers.includes("lock_file_has_multiple_links"));
  assert.ok(observed.value.blockers.includes("lock_file_has_multiple_links"));
  assert.equal(node.safeToUnlock, false);
  assert.equal(observed.value.safeToUnlock, false);
  const py = await runPython("unlock", value.codexHome);
  assert.equal(py.code, 2);
  assert.equal(py.value.signalSent, null);
  assert.equal(value.child.exitCode, null);
});

test("both implementations release a completed synthetic owner and verify invariants", async (t) => {
  const value = await testFixture(t);
  const nodeValue = await testFixture(t);
  const { code, value: result } = await runPython("unlock", value.codexHome);
  const node = await unlockThread(THREAD_ID, { ...nodeValue.options, stabilityMs: 250 });
  assert.equal(code, 0);
  for (const field of ["outcome", "signalSent", "processExited", "lockReleased",
    "transcriptUnchanged", "lockFileRemovedByTool"]) {
    assert.equal(result[field], node[field], field);
  }
  assert.equal(result.outcome, "unlocked");
  assert.equal(result.signalSent, "SIGTERM");
  assert.equal(result.transcriptUnchanged, true);
});

test("Node and Python refuse an active owner without signaling", async (t) => {
  const value = await testFixture(t, "task_started");
  const py = await runPython("unlock", value.codexHome);
  const node = await unlockThread(THREAD_ID, { ...value.options, stabilityMs: 250 });
  assert.equal(py.code, 2);
  assert.equal(py.value.outcome, node.outcome);
  assert.equal(py.value.signalSent, null);
  assert.equal(node.signalSent, null);
  assert.equal(value.child.exitCode, null);
});

test("Python and Node share the same operation lease", async (t) => {
  const value = await testFixture(t);
  const attempt = acquireUnlockLease(value.codexHome, THREAD_ID);
  assert.equal(attempt.status, "acquired");
  try {
    const py = await runPython("unlock", value.codexHome);
    assert.equal(py.code, 2);
    assert.deepEqual(py.value.reasons, ["concurrent_unlock_in_progress"]);
    assert.equal(py.value.signalSent, null);
    assert.equal(value.child.exitCode, null);
  } finally {
    attempt.lease.release();
  }
});

test("both implementations refuse transcript and owner changes after the first inspection", async (t) => {
  for (const kind of ["transcript", "extra-lock", "arguments", "inode"]) {
    const value = await testFixture(t);
    const initial = await inspectThread(THREAD_ID, { ...value.options, stabilityMs: 250 });
    assert.equal(initial.safeToUnlock, true);
    let replacement = null;
    const py = await gatedPython(value, "after-inspect", async () => {
      if (kind === "transcript") {
        await writeFile(value.transcriptPath, `${JSON.stringify({ type: "event_msg", payload: { type: "task_started" } })}\n`, { flag: "a" });
      } else if (kind === "extra-lock") {
        const path = await otherLockPath(value.codexHome, "second-home");
        await commandOwner(value.child, { action: "acquire", path });
      } else if (kind === "arguments") {
        await commandOwner(value.child, { action: "title", value: "changed-codex-fixture" });
      } else {
        await rename(value.lockPath, `${value.lockPath}.old`);
        await writeFile(value.lockPath, "");
        replacement = spawn(resolve("test/fixtures/codex"), [value.lockPath], { stdio: ["ignore", "pipe", "pipe"] });
        value.extraOwners.push(replacement);
        await once(replacement.stdout, "data");
      }
      const node = await unlockInspectedThread(initial, { ...value.options, stabilityMs: 250 });
      assert.equal(node.outcome, "refused", kind);
      assert.equal(node.signalSent, null, kind);
    });
    assert.equal(py.code, 2, kind);
    assert.equal(py.value.outcome, "refused", kind);
    assert.equal(py.value.signalSent, null, kind);
    assert.equal(value.child.exitCode, null, kind);
    if (replacement) assert.equal(replacement.exitCode, null);
  }
});

test("a Python lease blocks Node; only Python signals after release of the gate", async (t) => {
  const value = await testFixture(t);
  const py = await gatedPython(value, "after-lease", async () => {
    const node = await runCli(["unlock", THREAD_ID, "--json", "--codex-home", value.codexHome,
      "--stability-ms", "250"]);
    assert.equal(node.code, 2);
    assert.deepEqual(JSON.parse(node.stdout).reasons, ["concurrent_unlock_in_progress"]);
    assert.equal(value.child.exitCode, null);
  });
  assert.equal(py.code, 0);
  assert.equal(py.value.outcome, "unlocked");
  assert.equal(py.value.signalSent, "SIGTERM");
});

test("post-SIGTERM evidence failure cannot be reported as Python success", async (t) => {
  const value = await testFixture(t, "task_complete", { ownerEnv: { CODEX_FIXTURE_SIGTERM_BREAK_LOCK_PATH: "1" } });
  const py = await runPython("unlock", value.codexHome);
  assert.equal(py.code, 3);
  assert.equal(py.value.signalSent, "SIGTERM");
  assert.notEqual(py.value.outcome, "unlocked");
  assert.equal(py.value.lockReleased, false);
});
