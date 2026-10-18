import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { setImmediate } from "node:timers/promises";
import test from "node:test";

import { collectCliOutput } from "./helpers/cli-output.mjs";

function fakeChild() {
  const child = new EventEmitter();
  child.stdout = new PassThrough();
  child.stderr = new PassThrough();
  return child;
}

test("CLI output collection waits for close and retains stdout and stderr arriving after exit", async () => {
  const child = fakeChild();
  const pending = collectCliOutput(child);
  let settled = false;
  pending.then(() => { settled = true; });
  child.stdout.write('{"status":');
  child.stderr.write("before ");
  child.emit("exit", 64, null);
  // Give an exit-based collector a chance to return before producing the
  // remaining data. This schedules an event-loop turn, not a timed sleep.
  await setImmediate();
  assert.equal(settled, false);
  child.stdout.end('"ok"}\n');
  child.stderr.end("after\n");
  child.emit("close", 64, null);
  assert.deepEqual(await pending, {
    code: 64,
    signal: null,
    stdout: '{"status":"ok"}\n',
    stderr: "before after\n",
  });
});

test("CLI output collection preserves signal termination", async () => {
  const child = fakeChild();
  const pending = collectCliOutput(child);
  child.emit("exit", null, "SIGTERM");
  child.stdout.end();
  child.stderr.end("terminated\n");
  child.emit("close", null, "SIGTERM");
  assert.deepEqual(await pending, { code: null, signal: "SIGTERM", stdout: "", stderr: "terminated\n" });
});

test("CLI output collection rejects the original spawn error", async () => {
  const child = fakeChild();
  const pending = collectCliOutput(child);
  const error = new Error("spawn failed");
  const rejected = assert.rejects(pending, (actual) => actual === error);
  child.emit("error", error);
  child.stdout.end();
  child.stderr.end();
  child.emit("close", -2, null);
  await rejected;
});
