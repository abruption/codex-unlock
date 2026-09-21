import assert from "node:assert/strict";
import test from "node:test";

import {
  originalProcessExited,
  processStartTimeFromCommand,
} from "../dist/process.js";

test("interprets process start observations without conflating absence and errors", () => {
  assert.deepEqual(
    processStartTimeFromCommand({
      status: 0,
      stdout: "Sun Sep 20 12:34:56 2026\n",
      stderr: "",
    }),
    {
      status: "present",
      startTime: "Sun Sep 20 12:34:56 2026",
    },
  );
  assert.deepEqual(
    processStartTimeFromCommand({ status: 1, stdout: "", stderr: "" }),
    { status: "absent", startTime: null },
  );

  for (const result of [
    { status: 0, stdout: "", stderr: "" },
    { status: 0, stdout: "not a timestamp", stderr: "" },
    { status: 2, stdout: "", stderr: "ps failed" },
    {
      status: null,
      stdout: "",
      stderr: "",
      failure: { kind: "timeout", message: "command exceeded 10 ms" },
    },
  ]) {
    const observation = processStartTimeFromCommand(result);
    assert.equal(observation.status, "unknown");
    assert.equal(observation.startTime, null);
    assert.ok(observation.error);
  }
});

test("derives exit only from absence or a different process start time", () => {
  const original = "Sun Sep 20 12:34:56 2026";
  assert.equal(
    originalProcessExited(original, { status: "present", startTime: original }),
    false,
  );
  assert.equal(
    originalProcessExited(original, {
      status: "present",
      startTime: "Sun Sep 20 12:35:56 2026",
    }),
    true,
  );
  assert.equal(
    originalProcessExited(original, { status: "absent", startTime: null }),
    true,
  );
  assert.equal(
    originalProcessExited(original, {
      status: "unknown",
      startTime: null,
      error: "ps failed",
    }),
    null,
  );
});
