import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { EventEmitter } from "node:events";
import { resolve } from "node:path";
import process from "node:process";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";

import { DIAGNOSTIC_COMMAND_ENV, runCommand } from "../dist/util.js";

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
    { ...limits, timeoutMs: 1_000 },
  );
  assert.equal(result.failure?.kind, "timeout");
  const descendantPid = Number(result.stdout.trim());
  assert.ok(Number.isSafeInteger(descendantPid) && descendantPid > 0);
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

test("does not pass the caller environment to diagnostic commands", async (t) => {
  const saved = {};
  for (const [name, value] of Object.entries({
    COLUMNS: "40",
    LINES: "5",
    PS_FORMAT: "pid",
    PS_PERSONALITY: "posix",
    LC_CTYPE: "en_US.UTF-8",
  })) {
    saved[name] = process.env[name];
    process.env[name] = value;
  }
  t.after(() => {
    for (const [name, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  });
  const result = await runCommand(
    process.execPath,
    ["-e", "process.stdout.write(JSON.stringify(process.env))"],
    limits,
  );
  assert.equal(result.failure, undefined);
  const environment = JSON.parse(result.stdout);
  for (const name of Object.keys(saved)) assert.equal(environment[name], undefined, name);
  for (const [name, value] of Object.entries(DIAGNOSTIC_COMMAND_ENV)) {
    assert.equal(environment[name], value, name);
  }
});

function errno(code) {
  return Object.assign(new Error(`spawn ${code}`), { code, errno: -1, syscall: "spawn" });
}

test("reports a synchronous spawn throw as a structured command error", async () => {
  const result = await runCommand("/bin/ps", [], limits, () => {
    throw errno("EBADF");
  });
  assert.equal(result.status, null);
  assert.equal(result.failure?.kind, "spawn_error");
  assert.equal(result.error?.code, "EBADF");
});

test("reports a child without stdio pipes as a structured command error", async () => {
  let emitted = false;
  const result = await runCommand("/bin/ps", [], limits, () => {
    const child = new EventEmitter();
    child.stdout = null;
    child.stderr = null;
    child.pid = undefined;
    child.kill = () => false;
    process.nextTick(() => {
      child.emit("error", errno("EMFILE"));
      emitted = true;
    });
    return child;
  });
  assert.equal(emitted, true);
  assert.equal(result.status, null);
  assert.equal(result.failure?.kind, "spawn_error");
  assert.equal(result.error?.code, "EMFILE");

  const silent = await runCommand("/bin/ps", [], limits, () => {
    const child = new EventEmitter();
    child.stdout = null;
    child.stderr = null;
    child.kill = () => false;
    return child;
  });
  assert.equal(silent.failure?.kind, "spawn_error");
  assert.match(silent.failure.message, /stdout\/stderr/);
});

test("survives real descriptor exhaustion without an unhandled error", async (t) => {
  if (process.platform === "win32") {
    t.skip("POSIX descriptor limits only");
    return;
  }
  const script = [
    "import { closeSync, openSync } from 'node:fs'",
    "const output = process.stdout",
    `const { runCommand } = await import(${JSON.stringify(pathToFileURL(resolve("dist/util.js")).href)})`,
    "const held = []",
    "try { for (;;) held.push(openSync('/dev/null', 'r')) } catch {}",
    "const result = await runCommand('/bin/ps', ['-p', String(process.pid)])",
    "for (const fd of held) closeSync(fd)",
    "output.write(JSON.stringify({ kind: result.failure?.kind ?? null, code: result.error?.code ?? null }))",
  ].join("\n");
  const child = await runCommand(
    "/bin/sh",
    ["-c", `ulimit -n 64 && exec "$0" --input-type=module -e "$1"`, process.execPath, script],
    { ...limits, timeoutMs: 10_000 },
  );
  assert.equal(child.status, 0, child.stderr);
  const parsed = JSON.parse(child.stdout);
  assert.equal(parsed.kind, "spawn_error");
});
