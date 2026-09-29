import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import fs, { readFileSync, statSync } from "node:fs";
import { chmod, link, mkdir, mkdtemp, rename, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { syncBuiltinESMExports } from "node:module";
import { join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import process from "node:process";
import { setTimeout } from "node:timers";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";

import { observeLockFile, probeThreadLockOnce } from "../dist/lock.js";
import { guardedProbeOnce, probeWithRetry, NATIVE_COORDINATION_RETRY_MS } from "../dist/native-coordination.js";
import { inspectThread, listThreads, unlockThread } from "../dist/doctor.js";
import { THREAD_ID, fixture, runCli, stopChild } from "./helpers/owner-fixture.mjs";

const WRITER = resolve("test/fixtures/native-writer.mjs");
async function emptyLock() {
  const home = await mkdtemp(join(tmpdir(), "codex-unlock-native-"));
  const directory = join(home, "thread-writer-locks");
  await mkdir(directory);
  const path = join(directory, `${THREAD_ID}.lock`);
  const guard = join(directory, ".coordination.lock");
  await writeFile(path, "thread contents");
  await writeFile(guard, "guard contents", { mode: 0o644 });
  return { home, path, guard, directory };
}

async function holdGuard(t, path, ms = 0) {
  const child = spawn(process.execPath, [WRITER, "hold", path, String(ms)], {
    stdio: ["pipe", "pipe", "inherit"],
  });
  t.after(async () => await stopChild(child));
  child.stdout.setEncoding("utf8");
  const [ready] = await once(child.stdout, "data");
  assert.match(ready, /ready/);
  return child;
}

// Keep real flock contention, but stop the retry budget's monotonic clock
// until the guard holder has finished. Slow runners can otherwise spend the
// whole 100 ms budget before the child processes its command.
function freezeRetryClock(t) {
  const frozenAt = performance.now();
  const now = t.mock.method(performance, "now", () => frozenAt);
  return () => now.mock.restore();
}

function snapshot(path) {
  const stat = statSync(path, { bigint: true });
  return { contents: readFileSync(path).toString("hex"), dev: stat.dev, ino: stat.ino,
    mode: stat.mode, uid: stat.uid, mtime: stat.mtimeNs };
}

test("native guard prevents the deterministic probe-induced writer WouldBlock", async () => {
  const value = await emptyLock();
  const observations = [];
  const writer = () => {
    const result = spawnSync(process.execPath, [WRITER, "probe", value.path], {
      encoding: "utf8", timeout: 3_000,
    });
    assert.equal(result.status, 0, result.stderr);
    observations.push(result.stdout.trim());
  };
  assert.equal(probeThreadLockOnce(value.path, observeLockFile(value.path), writer).status, "free");
  assert.equal(guardedProbeOnce(value.path, observeLockFile(value.path), {
    afterThreadAcquired: writer,
  }).status, "free");
  assert.deepEqual(observations, ["WOULD_BLOCK", "GUARDED"]);
});

test("native probe leaves contents, identities, mtime, permissions, and ownership intact", async () => {
  const value = await emptyLock();
  const before = [snapshot(value.guard), snapshot(value.path)];
  await chmod(value.guard, 0o664);
  before[0] = snapshot(value.guard);
  const result = await probeWithRetry(value.path);
  assert.equal(result.status, "free");
  assert.deepEqual(result.guard, { status: "acquired", attempts: 1 });
  assert.deepEqual([snapshot(value.guard), snapshot(value.path)], before);
});

test("absent native coordinator stays unknown without creating any file", async (t) => {
  const value = await fixture("task_complete", { coordination: false });
  t.after(async () => await stopChild(value.child));
  const result = await inspectThread(THREAD_ID, value.options);
  assert.equal(result.classification, "unknown");
  assert.equal(result.safeToUnlock, false);
  assert.equal(result.lock.probe.error, "native_coordination_absent");
  assert.equal(result.lock.probe.guard.status, "absent");
  assert.equal((await unlockThread(THREAD_ID, value.options)).signalSent, null);
  assert.throws(() => statSync(join(value.codexHome, "thread-writer-locks", ".coordination.lock")), /ENOENT/);
});

test("native guard contention retries within its monotonic acquisition budget", async (t) => {
  const value = await emptyLock();
  const child = await holdGuard(t, value.path);
  const restoreClock = freezeRetryClock(t);
  let result;
  try {
    const pending = probeWithRetry(value.path);
    setTimeout(() => child.stdin.write("release\n"), 25);
    result = await pending;
  } finally {
    restoreClock();
  }
  assert.equal(result.status, "free");
  assert.equal(result.guard.status, "acquired");
  assert.ok(result.guard.attempts > 1);
});

for (const action of ["unlink", "replace"]) {
  test(`native retry re-observes a coordinated thread ${action}`, async (t) => {
    const value = await emptyLock();
    const before = statSync(value.path, { bigint: true });
    const child = await holdGuard(t, value.path);
    const restoreClock = freezeRetryClock(t);
    let result;
    try {
      const pending = probeWithRetry(value.path);
      // The first attempt has already observed real guard contention. The child
      // changes the fixture while still holding the guard, then releases it.
      child.stdin.write(`${action}\n`);
      result = await pending;
    } finally {
      restoreClock();
    }
    assert.equal(result.status, "free", JSON.stringify(result));
    if (action === "unlink") {
      assert.equal(result.guard, undefined);
      assert.throws(() => statSync(value.path), /ENOENT/);
    } else {
      assert.equal(result.guard.status, "acquired");
      assert.ok(result.guard.attempts > 1);
      assert.notEqual(statSync(value.path, { bigint: true }).ino, before.ino);
    }
  });
}

test("native busy guard exhausts the budget and respects a shorter caller deadline", async (t) => {
  const value = await emptyLock();
  await holdGuard(t, value.path);
  const start = performance.now();
  const result = await probeWithRetry(value.path);
  assert.equal(result.status, "unknown");
  assert.equal(result.error, "native_coordination_busy");
  assert.ok(performance.now() - start >= NATIVE_COORDINATION_RETRY_MS - 5);
  // Timer rounding can produce different attempt counts in 20 real ms. Keep
  // actual flock contention, but advance the monotonic clock deterministically
  // to prove that the caller's 20 ms deadline wins over the 100 ms default.
  let clock = 0;
  const now = t.mock.method(performance, "now", () => {
    const value = clock;
    clock += 10;
    return value;
  });
  try {
    const shorter = await probeWithRetry(value.path, 20);
    assert.equal(shorter.guard.status, "busy");
    assert.equal(shorter.guard.attempts, 2);
  } finally {
    now.mock.restore();
  }
});

test("unsafe native coordination types and hard links fail closed", async (t) => {
  for (const kind of ["directory", "symlink", "hardlink", "fifo"]) {
    await t.test(kind, async () => {
      const value = await emptyLock();
      await rename(value.guard, `${value.guard}.original`);
      if (kind === "directory") await mkdir(value.guard);
      if (kind === "symlink") await symlink(`${value.guard}.original`, value.guard);
      if (kind === "hardlink") await link(`${value.guard}.original`, value.guard);
      if (kind === "fifo") assert.equal(spawnSync("/usr/bin/mkfifo", [value.guard]).status, 0);
      const result = guardedProbeOnce(value.path);
      assert.equal(result.status, "unknown");
      assert.equal(result.guard.status, "unsafe");
    });
  }
});

test("unavailable or mismatching current UID fails closed", async () => {
  const value = await emptyLock();
  const original = process.getuid;
  try {
    process.getuid = () => original() + 1;
    assert.equal(guardedProbeOnce(value.path).guard.status, "unsafe");
    process.getuid = undefined;
    assert.equal(guardedProbeOnce(value.path).guard.status, "unsafe");
  } finally {
    process.getuid = original;
  }
});

test("unreadable native coordinator fails closed without a thread probe", async (t) => {
  const value = await emptyLock();
  await chmod(value.guard, 0o000);
  t.after(async () => await chmod(value.guard, 0o644));
  let probed = false;
  const result = guardedProbeOnce(value.path, observeLockFile(value.path), {
    afterThreadAcquired: () => { probed = true; },
  });
  if (result.status === "free") {
    t.skip("current user can bypass file permissions");
    return;
  }
  assert.equal(result.status, "unknown");
  assert.equal(result.guard.status, "unsafe");
  assert.equal(probed, false);
});

test("descriptor cleanup errors never report a successful probe", async () => {
  const value = await emptyLock();
  const open = fs.openSync;
  const close = fs.closeSync;
  for (const target of [value.path, value.guard]) {
    const canonicalTarget = fs.realpathSync.native(target);
    let descriptor;
    fs.openSync = (path, ...args) => {
      const fd = open(path, ...args);
      if (path === target || path === canonicalTarget) descriptor = fd;
      return fd;
    };
    fs.closeSync = (fd) => {
      close(fd);
      if (fd === descriptor) throw new Error("injected cleanup failure");
    };
    syncBuiltinESMExports();
    try {
      const result = guardedProbeOnce(value.path);
      assert.equal(result.status, "unknown");
      assert.match(result.error, /close_failed/);
    } finally {
      fs.openSync = open;
      fs.closeSync = close;
      syncBuiltinESMExports();
    }
    assert.equal(guardedProbeOnce(value.path).status, "free");
  }
});

test("native and thread release failures fail closed and close their descriptors", async () => {
  const value = await emptyLock();
  for (const mode of ["release-guard", "release-thread"]) {
    const result = spawnSync(process.execPath, [
      "--import", resolve("test/helpers/native-probe-fault.mjs"),
      "--input-type=module", "-e",
      'import {guardedProbeOnce} from "./dist/native-coordination.js"; process.stdout.write(JSON.stringify(guardedProbeOnce(process.argv[1])));',
      value.path,
    ], { encoding: "utf8", timeout: 3_000,
      env: { ...process.env, CODEX_UNLOCK_TEST_NATIVE_FAULT: mode } });
    assert.equal(result.status, 0, result.stderr);
    const probe = JSON.parse(result.stdout);
    assert.equal(probe.status, "unknown");
    assert.match(probe.error, /release_failed/);
    assert.equal(guardedProbeOnce(value.path).status, "free");
  }
});

test("guard and directory replacement during the critical section fail closed and release descriptors", async () => {
  for (const target of ["guard", "directory", "guard_after_thread_probe"]) {
    const value = await emptyLock();
    const fs = await import("node:fs");
    let threadProbed = false;
    const replace = () => {
        if (target !== "directory") {
          fs.renameSync(value.guard, `${value.guard}.old`);
          fs.writeFileSync(value.guard, "new inode");
        } else {
          fs.renameSync(value.directory, `${value.directory}.old`);
          fs.mkdirSync(value.directory);
          fs.writeFileSync(value.path, "replacement");
          fs.writeFileSync(value.guard, "replacement");
        }
    };
    const result = guardedProbeOnce(value.path, observeLockFile(value.path), {
      afterGuardAcquired: () => {
        if (target !== "guard_after_thread_probe") replace();
      },
      afterThreadAcquired: () => {
        threadProbed = true;
        if (target === "guard_after_thread_probe") replace();
      },
    });
    assert.equal(result.status, "unknown");
    assert.equal(result.guard.status, "changed");
    assert.equal(threadProbed, target === "guard_after_thread_probe");
    assert.equal(guardedProbeOnce(value.path).status, "free");
  }
});

test("aliases use the same native guard and list excludes its filename", async (t) => {
  const value = await emptyLock();
  const alias = `${value.home}-alias`;
  await symlink(value.home, alias);
  const linked = await mkdtemp(join(tmpdir(), "codex-unlock-native-alias-"));
  await symlink(value.directory, join(linked, "thread-writer-locks"));
  await holdGuard(t, value.path);
  for (const home of [value.home, alias, linked]) {
    const result = guardedProbeOnce(join(home, "thread-writer-locks", `${THREAD_ID}.lock`));
    assert.equal(result.guard.status, "busy");
  }
  const list = await listThreads({ codexHome: value.home, stabilityMs: 1, terminationTimeoutMs: 100 });
  assert.deepEqual(list.sessions.map((entry) => entry.threadId), [THREAD_ID]);
});

test("shutdown guard contention is retried until the owner exits and the lock releases", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "codex-unlock-drop-guard-"));
  const ready = join(root, "drop-ready");
  const busy = join(root, "busy");
  const value = await fixture("task_complete", { ownerEnv: {
    CODEX_FIXTURE_DROP_GUARD_MS: "200", CODEX_FIXTURE_DROP_GUARD_READY: ready,
  } });
  t.after(async () => await stopChild(value.child));
  const invocation = await runCli([
    "unlock", THREAD_ID, "--json", "--codex-home", value.codexHome,
    "--stability-ms", "250", "--no-update-notice",
  ], { ...process.env, CODEX_UNLOCK_TEST_DROP_READY: ready, CODEX_UNLOCK_TEST_DROP_BUSY: busy },
  ["--import", resolve("test/helpers/drop-guard-barrier.mjs")]);
  assert.equal(invocation.stderr, "");
  const result = JSON.parse(invocation.stdout);
  assert.equal(result.outcome, "unlocked", JSON.stringify(result));
  assert.equal(result.processExited, true);
  assert.equal(result.lockReleased, true);
  assert.equal(result.transcriptUnchanged, true);
  assert.match(readFileSync(busy, "utf8"), /busy/);
});

for (const mode of ["verify", "busy"]) {
  test(`signal boundary ${mode} has no await or held native guard`, async (t) => {
    const value = await fixture();
    t.after(async () => await stopChild(value.child));
    const marker = join(value.codexHome, "signal-boundary.json");
    const result = await runCli([
      "unlock", THREAD_ID, "--json", "--codex-home", value.codexHome,
      "--stability-ms", "250", "--no-update-notice",
    ], { ...process.env, CODEX_UNLOCK_TEST_NATIVE_SIGNAL: mode,
      CODEX_UNLOCK_TEST_NATIVE_SIGNAL_MARKER: marker },
    ["--import", resolve("test/helpers/native-signal-boundary.mjs")]);
    assert.equal(result.stderr, "");
    const parsed = JSON.parse(result.stdout);
    if (mode === "busy") {
      assert.equal(result.code, 2, result.stdout);
      assert.equal(parsed.outcome, "refused");
      assert.equal(parsed.signalSent, null);
      assert.ok(parsed.reasons.includes("native_coordination_busy_before_signal"));
      assert.ok(!parsed.reasons.includes("lock_changed_before_signal"));
      assert.equal(value.child.exitCode, null);
      assert.throws(() => statSync(marker), /ENOENT/);
    } else {
      assert.equal(result.code, 0, result.stdout);
      assert.equal(parsed.outcome, "unlocked");
      assert.deepEqual(JSON.parse(readFileSync(marker, "utf8")), {
        attempts: 5, guardReleased: true, guardClosed: true, microtaskRan: false,
      });
    }
  });
}

test("bounded coordinated acquire and drop stress has zero probe-induced WouldBlock", async (t) => {
  const value = await emptyLock();
  const child = spawn(process.execPath, [WRITER, "stress", value.path, "10000"], {
    stdio: ["pipe", "pipe", "inherit"],
  });
  t.after(async () => await stopChild(child));
  let output = "";
  child.stdout.setEncoding("utf8");
  const [ready] = await once(child.stdout, "data");
  assert.match(ready, /ready/);
  child.stdout.on("data", (chunk) => { output += chunk; });
  const exited = once(child, "exit");
  child.stdin.write("go\n");
  const deadline = performance.now() + 5_000;
  for (let index = 0; index < 2_000 && child.exitCode === null && performance.now() < deadline; index += 1) {
    guardedProbeOnce(value.path);
    if (index % 32 === 0) await delay(0);
  }
  const [code] = await exited;
  assert.equal(code, 0);
  const result = JSON.parse(output);
  assert.equal(result.wouldBlock, 0);
  assert.ok(result.acquired > 0);
});
