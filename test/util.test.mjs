import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import process from "node:process";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";

import { runCommand } from "../dist/util.js";

const limits = {
  timeoutMs: 2_000,
  maxStdoutBytes: 1_024,
  maxStderrBytes: 1_024,
  killGraceMs: 100,
};

async function waitForProcessExit(pid, timeoutMs = 2_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() <= deadline) {
    try {
      process.kill(pid, 0);
    } catch (error) {
      if (error?.code === "ESRCH") return;
      throw error;
    }
    await delay(25);
  }
  assert.fail(`process ${pid} still exists after ${timeoutMs} ms`);
}

test("runs a diagnostic command within explicit limits", async () => {
  const result = await runCommand(
    process.execPath,
    ["-e", "process.stdout.write('ok'); process.stderr.write('note')"],
    limits,
  );
  assert.equal(result.status, 0);
  assert.equal(result.stdout, "ok");
  assert.equal(result.stderr, "note");
  assert.equal(result.failure, undefined);
});

test("terminates a diagnostic command at its deadline", async () => {
  const result = await runCommand(
    process.execPath,
    ["-e", "setInterval(() => {}, 1000)"],
    { ...limits, timeoutMs: 50 },
  );
  assert.equal(result.failure?.kind, "timeout");
  assert.notEqual(result.status, 0);
});

test("cleans up diagnostic command descendants after timeout", async (t) => {
  if (process.platform === "win32") {
    t.skip("process-group cleanup is POSIX-only");
    return;
  }
  const source = [
    "const { spawn } = require('node:child_process')",
    "const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' })",
    "process.stdout.write(String(child.pid) + '\\n')",
    "setInterval(() => {}, 1000)",
  ].join(";");
  const result = await runCommand(
    process.execPath,
    ["-e", source],
    { ...limits, timeoutMs: 100 },
  );
  assert.equal(result.failure?.kind, "timeout");
  const descendantPid = Number(result.stdout.trim());
  assert.ok(Number.isSafeInteger(descendantPid));
  await waitForProcessExit(descendantPid);
});

for (const stream of ["stdout", "stderr"]) {
  test(`terminates a diagnostic command after ${stream} overflow`, async () => {
    const result = await runCommand(
      process.execPath,
      ["-e", `process.${stream}.write('x'.repeat(4096)); setInterval(() => {}, 1000)`],
      { ...limits, maxStdoutBytes: 64, maxStderrBytes: 64 },
    );
    assert.equal(result.failure?.kind, `${stream}_limit`);
    assert.ok(Buffer.byteLength(result[stream]) <= 64);
    assert.notEqual(result.status, 0);
  });
}

test("reports spawn failure as a structured command error", async () => {
  const result = await runCommand(
    "/definitely/missing/codex-unlock-command",
    [],
    limits,
  );
  assert.equal(result.status, -2);
  assert.equal(result.failure?.kind, "spawn_error");
  assert.equal(result.error?.code, "ENOENT");
});
