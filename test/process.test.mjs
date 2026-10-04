import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import test from "node:test";

import {
  originalProcessExited,
  parseLsofFiles,
  parseLsofProcesses,
  parseProcCommandLine,
  processExitObservationFromCommand,
  processStartTimeFromCommand,
  reconcileArguments,
} from "../dist/process.js";

test("parses null-delimited lsof process fields", () => {
  assert.deepEqual(parseLsofProcesses("p42\0ccodex\0u501\0\np7\0cnode\0u502\0"), [
    { pid: 7, command: "node", uid: 502 },
    { pid: 42, command: "codex", uid: 501 },
  ]);
});

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

test("parses Linux lsof file sets that omit the f field", () => {
  const lock = "/home/a/\\xed\\x99\\x88/thread-writer-locks/01a089e8-3731-7202-ba68-0f4b0a3b2711.lock";
  assert.deepEqual(
    parseLsofFiles(`p42\0D0x801\0i880\0n/tmp\0D0x801\0i1048906\0n${lock}\0i7\0n/no-device\0n/name-only\0`),
    [
      { name: "/tmp", device: 0x801n, inode: 880n },
      { name: lock, device: 0x801n, inode: 1048906n },
      { name: "/no-device", device: null, inode: 7n },
      { name: "/name-only", device: null, inode: null },
    ],
  );
  assert.deepEqual(
    parseLsofFiles(`p42\0fcwd\0D0x801\0i1\0n/a\0f3\0D0x802\0i2\0n/b\0p43\0D0x803\0i3\0n/c\0`),
    [
      { name: "/a", device: 0x801n, inode: 1n },
      { name: "/b", device: 0x802n, inode: 2n },
      { name: "/c", device: 0x803n, inode: 3n },
    ],
  );
});

test("parses lsof device and inode fields independently of escaped names", () => {
  const lock = "/Users/a/\\xed\\x99\\x88/thread-writer-locks/01a089e8-3731-7202-ba68-0f4b0a3b2711.lock";
  assert.deepEqual(
    parseLsofFiles(
      `p42\0fcwd\0D0x100001c\0i77\0n/tmp\0f9\0D0x100000e\0i1152921500312607363\0n${lock}\0f10\0Dbogus\0i-1\0n/x\0`,
    ),
    [
      { name: "/tmp", device: 0x100001cn, inode: 77n },
      { name: lock, device: 0x100000en, inode: 1152921500312607363n },
      { name: "/x", device: null, inode: null },
    ],
  );
});

test("reads kernel argv without trailing title padding", () => {
  assert.deepEqual(
    parseProcCommandLine(Buffer.from("codex\0app-server\0\0\0")),
    ["codex", "app-server"],
  );
  assert.deepEqual(parseProcCommandLine(Buffer.alloc(0)), []);
});

test("reconciles ps arguments with kernel argv and fails closed on truncation", () => {
  const long = `/very/long/${"a".repeat(60)}/codex`;
  assert.deepEqual(reconcileArguments(`${long} exec`, null), {
    arguments: `${long} exec`,
    isSharedService: false,
  });
  assert.deepEqual(
    reconcileArguments(`${long} exec`, { status: "present", argv: [long, "exec"] }),
    { arguments: `${long} exec`, isSharedService: false },
  );

  const truncated = reconcileArguments(long.slice(0, 40), {
    status: "present",
    argv: [long, "app-server", "--x"],
  });
  assert.equal(truncated.arguments, null);
  assert.equal(truncated.isSharedService, true);
  assert.match(truncated.error, /^arguments_truncated:/);

  const unverified = reconcileArguments(`${long} exec`, {
    status: "unknown",
    error: "ENOENT: no such file",
  });
  assert.equal(unverified.arguments, null);
  assert.match(unverified.error, /^arguments_unverified:/);

  assert.equal(
    reconcileArguments("codex exec", { status: "present", argv: ["codex", "daemon"] })
      .isSharedService,
    true,
  );
});

function argvEvidence(argv) {
  return reconcileArguments(argv.join(" "), { status: "present", argv });
}

test("verified argv distinguishes shared words in prompts and known option values", () => {
  for (const argv of [
    ["/work/daemon/codex", "resume"],
    ["codex", "fix the daemon"],
    ["codex", "--cd", "/work/app-server", "fix the daemon"],
    ["codex", "-C/work/app-server", "fix remote-control"],
    ["codex", "--config=label='app-server'", "fix the daemon"],
    ["codex", "--model", "daemon-model", "fix app-server"],
    ["codex", "--no-daemon", "exec", "fix the daemon"],
    ["codex", "exec", "--cd", "/work/app-server", "fix the daemon"],
    ["codex", "e", "--output-last-message", "/work/daemon", "fix app-server"],
    ["codex", "exec", "--", "--daemon"],
    ["codex", "resume", "--last", "fix the daemon"],
    ["codex", "resume", "session-daemon", "fix the app-server"],
    ["codex", "fork", "--last", "fix remote-control"],
    ["/usr/bin/node", "/tools/codex", "exec", "fix the daemon"],
  ]) {
    assert.deepEqual(argvEvidence(argv), {
      arguments: argv.join(" "), isSharedService: false,
    }, JSON.stringify(argv));
  }
});

test("verified argv still refuses service modes and remote connections after global options", () => {
  for (const mode of ["app-server", "remote-control", "daemon", "exec-server"]) {
    for (const prefix of [[], ["-c", "model='example'", "--strict-config"], ["-C/work/app-server"]]) {
      const argv = ["codex", ...prefix, mode];
      assert.equal(argvEvidence(argv).isSharedService, true, JSON.stringify(argv));
    }
  }
  for (const argv of [
    ["/tools/codex-daemon", "exec"],
    ["/tools/codex-app-server"],
    ["codex", "--remote", "unix:///work/endpoint"],
    ["codex", "--remote=wss://example.invalid"],
    ["codex", "resume", "--remote-auth-token-env", "EXAMPLE_TOKEN_NAME"],
    ["codex", "--", "app-server"],
  ]) assert.equal(argvEvidence(argv).isSharedService, true, JSON.stringify(argv));
});

test("unsupported or incomplete argv cannot authorize an owner", () => {
  for (const argv of [
    [], ["codex", "-C"], ["codex", "--config="],
    ["codex", "--config", "--no-daemon", "app-server"],
    ["codex", "--unknown", "app-server"],
    ["codex", "--unknown=daemon", "fix the prompt"],
    ["codex", "-xy", "fix daemon"],
    ["codex", "--image", "image.png", "app-server"],
    ["codex", "first operand", "daemon"],
    ["codex", "exec", "resume", "session-id", "fix daemon"],
    ["codex", "review", "fix daemon"],
    ["codex", "daemon-worker"],
    ["codex", "app-server-preview"],
    ["codex", "remote-control-next"],
    ["codex app-server"], // A flattened process title is not kernel argv evidence.
    ["/usr/bin/node", "--require", "anything", "/tools/codex", "app-server"],
    ["/usr/bin/sh", "/tools/codex", "app-server"],
  ]) {
    const evidence = argvEvidence(argv);
    assert.equal(evidence.arguments, null, JSON.stringify(argv));
    assert.match(evidence.error, /^arguments_unverified:/);
  }
  assert.equal(argvEvidence(["codex", "--unknown", "app-server"]).isSharedService, true);
  assert.equal(argvEvidence(["codex", "daemon-worker"]).isSharedService, true);
});

test("conflicting, missing, and flattened evidence remains conservative", () => {
  for (const ps of ["codex exec", "codex --no-daemon", "different exec fix daemon"]) {
    const evidence = reconcileArguments(ps, { status: "present", argv: ["codex", "app-server"] });
    assert.equal(evidence.arguments, null);
    assert.equal(evidence.isSharedService, true);
    assert.match(evidence.error, /^arguments_unverified:/);
  }
  assert.equal(reconcileArguments("codex exec fix daemon", null).isSharedService, true);
  assert.equal(reconcileArguments("codex -C /work/app-server", null).isSharedService, true);
  const unreadable = reconcileArguments("codex exec fix daemon", { status: "unknown", error: "unreadable" });
  assert.equal(unreadable.arguments, null);
  assert.equal(unreadable.isSharedService, true);
  assert.equal(reconcileArguments(null, { status: "present", argv: ["codex", "app-server"] }).arguments, null);
});

test("reads zombie state and start time from one ps sample", () => {
  const start = "Tue Sep 29 08:21:32 2026";
  for (const state of ["Z", "ZN", "Z+", "Zs"]) {
    assert.deepEqual(
      processExitObservationFromCommand({ status: 0, stdout: `${state}   ${start}    \n`, stderr: "" }),
      { status: "present", startTime: start, zombie: true },
    );
  }
  assert.deepEqual(
    processExitObservationFromCommand({ status: 0, stdout: `Ss ${start}\n`, stderr: "" }),
    { status: "present", startTime: start },
  );
  assert.deepEqual(
    processExitObservationFromCommand({ status: 1, stdout: "", stderr: "" }),
    { status: "absent", startTime: null },
  );
  assert.equal(
    processExitObservationFromCommand({ status: 0, stdout: "Z\n", stderr: "" }).status,
    "unknown",
  );
  assert.equal(
    processExitObservationFromCommand({ status: 0, stdout: "Z garbage\n", stderr: "" }).status,
    "unknown",
  );
  assert.equal(
    originalProcessExited(start, { status: "present", startTime: start, zombie: true }),
    true,
  );
});
