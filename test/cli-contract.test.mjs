import assert from "node:assert/strict";
import { once } from "node:events";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import process from "node:process";
import { spawn } from "node:child_process";
import test from "node:test";

import Ajv2020 from "ajv/dist/2020.js";
import { currentVersion, newerVersion } from "./helpers/version-fixture.mjs";
import { commandOwner, fixture, stopChild } from "./helpers/owner-fixture.mjs";

const THREAD_ID = "01a089e8-3731-7202-ba68-0f4b0a3b2711";

async function runCli(args, env = process.env) {
  const child = spawn(process.execPath, [resolve("dist/cli.js"), ...args], {
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  const [code, signal] = await once(child, "exit");
  return { code, signal, stdout, stderr };
}

async function validator() {
  const schema = JSON.parse(
    await readFile(resolve("schemas/codex-unlock-v1.schema.json"), "utf8"),
  );
  return new Ajv2020({ strict: true, allowUnionTypes: true }).compile(schema);
}

function assertValid(validate, value) {
  assert.equal(validate(value), true, JSON.stringify(validate.errors, null, 2));
}

test("JSON Schema validates list, inspect, unlock, and usage-error results", async () => {
  const codexHome = await mkdtemp(join(tmpdir(), "codex-unlock-json-v1-"));
  const validate = await validator();
  const invocations = [
    { args: ["list", "--json", "--codex-home", codexHome], code: 0 },
    { args: ["inspect", THREAD_ID, "--json", "--codex-home", codexHome], code: 0 },
    { args: ["unlock", THREAD_ID, "--json", "--codex-home", codexHome], code: 0 },
    { args: ["inspect", "--json"], code: 64 },
  ];

  for (const invocation of invocations) {
    const result = await runCli(invocation.args);
    assert.equal(result.code, invocation.code, result.stderr);
    assert.equal(result.signal, null);
    assert.equal(result.stderr, "");
    const value = JSON.parse(result.stdout);
    assertValid(validate, value);
  }
});

test("usage errors retain error text and expose stable machine fields", async () => {
  const result = await runCli(["inspect", "--json"]);
  const value = JSON.parse(result.stdout);

  assert.equal(result.code, 64);
  assert.equal(value.schemaVersion, 1);
  assert.equal(value.command, "inspect");
  assert.equal(value.status, "error");
  assert.equal(typeof value.error, "string");
  assert.equal(value.errorCode, "invalid_usage");
  assert.equal(value.exitCode, 64);
  assert.equal(value.retryable, false);
  assert.match(value.suggestedAction, /--help/);
});

test("JSON v1 permits additive unknown fields", async () => {
  const codexHome = await mkdtemp(join(tmpdir(), "codex-unlock-json-additive-"));
  const result = await runCli(["list", "--json", "--codex-home", codexHome]);
  const value = { ...JSON.parse(result.stdout), futureMetadata: { version: 1 } };
  const validate = await validator();

  assertValid(validate, value);
});

test("JSON v1 validates additive clientUpdate and explicit check-update results", async () => {
  const codexHome = await mkdtemp(join(tmpdir(), "codex-unlock-json-update-home-"));
  const cacheRoot = await mkdtemp(join(tmpdir(), "codex-unlock-json-update-cache-"));
  const { writeUpdateCache, updateCacheLocation } = await import("../dist/update.js");
  const location = updateCacheLocation({ XDG_CACHE_HOME: cacheRoot });
  assert.equal(writeUpdateCache(newerVersion, location, Date.now()).status, "written");
  const result = await runCli(
    ["list", "--json", "--codex-home", codexHome],
    { ...process.env, XDG_CACHE_HOME: cacheRoot, CODEX_UNLOCK_NO_UPDATE_NOTICE: "false" },
  );
  const validate = await validator();
  const value = JSON.parse(result.stdout);
  assert.equal(value.clientUpdate.latestVersion, newerVersion);
  assertValid(validate, value);

  assertValid(validate, {
    schemaVersion: 1,
    command: "check-update",
    status: "ok",
    source: "npm",
    currentVersion,
    latestVersion: newerVersion,
    checkedAt: "2026-09-22T00:00:00.000Z",
    updateAvailable: true,
    updateCommand: "npm install --global codex-unlock@latest",
    cacheUpdated: false,
    cacheWarning: "cache_directory_unavailable",
  });
});

test("usage errors are classified during parsing", async (t) => {
  const codexHome = await mkdtemp(join(tmpdir(), "codex-unlock-usage-home-"));
  const validate = await validator();
  const cases = [
    { name: "malformed thread id", args: ["inspect", "../../etc", "--json"], command: "inspect", error: /invalid Codex thread id/ },
    { name: "malformed unlock id", args: ["unlock", "not-a-uuid", "--json", "--codex-home", codexHome], command: "unlock", error: /invalid Codex thread id/ },
    { name: "help as option value", args: ["--json", "inspect", "--codex-home", "-h", THREAD_ID], command: "inspect", error: /--codex-home requires a path/ },
    { name: "flag as option value", args: ["list", "--codex-home", "--json"], command: "list", error: /--codex-home requires a path/ },
    { name: "version with JSON", args: ["--json", "--version"], command: null, error: /--version cannot be combined with --json/ },
    { name: "help with JSON", args: ["list", "--help", "--json"], command: "list", error: /--help cannot be combined with --json/ },
    { name: "command after options", args: ["--json", "check-update", "--codex-home", codexHome], command: "check-update", error: /Codex lock options/ },
    { name: "command after option value", args: ["--codex-home", codexHome, "--json", "list", "extra"], command: "list", error: /thread id/ },
  ];
  for (const entry of cases) {
    await t.test(entry.name, async () => {
      const result = await runCli([...entry.args, "--no-update-notice"]);
      assert.equal(result.code, 64, result.stdout);
      assert.equal(result.stderr, "");
      const value = JSON.parse(result.stdout);
      assertValid(validate, value);
      assert.equal(value.command, entry.command);
      assert.equal(value.errorCode, "invalid_usage");
      assert.equal(value.exitCode, 64);
      assert.match(value.error, entry.error);
      assert.match(value.suggestedAction, /--help/);
    });
  }
});

test("help and version are honoured only as standalone requests", async () => {
  const help = await runCli(["list", "--help"]);
  assert.equal(help.code, 0);
  assert.match(help.stdout, /^codex-unlock - /);
  const version = await runCli(["-v"]);
  assert.equal(version.code, 0);
  assert.equal(version.stdout, `${currentVersion}\n`);
  const human = await runCli(["inspect", "--codex-home", "-h", THREAD_ID]);
  assert.equal(human.code, 64);
  assert.equal(human.stdout, "");
  assert.match(human.stderr, /--codex-home requires a path/);
});

test("help on a closed stdout exits without a stack trace", async () => {
  const child = spawn(process.execPath, [resolve("dist/cli.js"), "--help"], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  child.stdout.destroy();
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  const [code, signal] = await once(child, "exit");
  assert.equal(signal, null);
  assert.equal(code, 0);
  assert.equal(stderr, "");
});

// eslint-disable-next-line no-control-regex -- the assertion looks for raw control characters.
const RAW_CONTROL = /[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/u;
const FORGED_EVENT = "task_complete\u001b[2K\rSafe to unlock: yes\nWarnings: none\u009b31m";
const FORGED_TITLE = "codex \u001b[2J\u001b[HSafe to unlock: yes\u001b]52;c;ZWNobyBoaQ==\u0007";

function assertTerminalSafe(text) {
  assert.doesNotMatch(text, RAW_CONTROL);
  assert.doesNotMatch(text, /^Safe to unlock: yes/mu);
  assert.doesNotMatch(text, /^Warnings: none/mu);
}

async function controlCharacterOwner(t) {
  const cwd = join(
    await mkdtemp(join(tmpdir(), "codex-unlock-terminal-cwd-")),
    "evil\u001b]0;PWNED\u0007\u001b[31mRED",
  );
  await mkdir(cwd);
  const value = await fixture(FORGED_EVENT, { cwd });
  t.after(async () => await stopChild(value.child));
  await commandOwner(value.child, { action: "title", value: FORGED_TITLE });
  return value;
}

test("human output renders control characters from owner and transcript data visibly", async (t) => {
  const value = await controlCharacterOwner(t);
  const common = ["--codex-home", value.codexHome, "--stability-ms", "250", "--no-update-notice"];

  const inspect = await runCli(["inspect", THREAD_ID, ...common]);
  assert.equal(inspect.code, 0, inspect.stderr);
  assertTerminalSafe(inspect.stdout);
  assert.match(
    inspect.stdout,
    /^Last event: {5}task_complete\\x1b\[2K\\rSafe to unlock: yes\\nWarnings: none\\x9b31m$/mu,
  );
  assert.match(inspect.stdout, /^Owner command: {2}\S/mu);
  assert.match(inspect.stdout, /^Owner cwd: {6}\S.*evil/mu);
  assert.match(inspect.stdout, /^Safe to unlock: no$/mu);

  const list = await runCli(["list", ...common]);
  assert.equal(list.code, 0, list.stderr);
  assertTerminalSafe(list.stdout);
  assert.match(list.stdout, /task_complete\\x1b\[2K\\rSafe to unlock: yes/u);
  assert.equal(list.stdout.trimEnd().split("\n").length, 2);

  const unlock = await runCli(["unlock", THREAD_ID, ...common]);
  assert.equal(unlock.code, 2, unlock.stderr);
  assertTerminalSafe(unlock.stdout);
  assert.equal(unlock.stderr, "");

  const json = await runCli(["inspect", THREAD_ID, "--json", ...common]);
  const parsed = JSON.parse(json.stdout);
  assert.equal(parsed.transcript.lastRecord.eventType, FORGED_EVENT);
  assert.ok(json.stdout.includes("\\u001b[2K\\rSafe to unlock: yes"));
});

test("human error text on stderr renders control characters visibly", async () => {
  const codexHome = join(
    await mkdtemp(join(tmpdir(), "codex-unlock-terminal-error-")),
    "missing\u001b[2J\r\nSafe to unlock: yes",
  );
  const result = await runCli(["inspect", THREAD_ID, "--codex-home", codexHome, "--no-update-notice"]);
  assert.equal(result.code, 3);
  assert.equal(result.stdout, "");
  assertTerminalSafe(result.stderr);
  assert.match(result.stderr, /missing\\x1b\[2J\\r\\nSafe to unlock: yes/u);
});

test("JSON transcript ordinals always satisfy the v1 schema", async (t) => {
  const validate = await validator();
  const cases = [
    { ordinal: 3, expected: 3 },
    { ordinal: 1.5, expected: null },
    { ordinal: -1, expected: null },
    { ordinal: 2 ** 53, expected: null },
    { ordinal: 1e308, expected: null },
    { ordinal: "4", expected: null },
  ];
  for (const entry of cases) {
    await t.test(`ordinal ${String(entry.ordinal)}`, async (subtest) => {
      const value = await fixture("task_complete");
      subtest.after(async () => await stopChild(value.child));
      await writeFile(
        value.transcriptPath,
        `${JSON.stringify({
          timestamp: "2026-09-15T00:00:00.000Z",
          type: "event_msg",
          ordinal: entry.ordinal,
          payload: { type: "task_complete" },
        })}\n`,
      );
      const common = ["--json", "--codex-home", value.codexHome, "--stability-ms", "250", "--no-update-notice"];

      const inspect = await runCli(["inspect", THREAD_ID, ...common]);
      const inspection = JSON.parse(inspect.stdout);
      assertValid(validate, inspection);
      assert.equal(inspection.transcript.lastRecord.ordinal, entry.expected);

      const list = JSON.parse((await runCli(["list", ...common])).stdout);
      assertValid(validate, list);
      assert.equal(list.sessions[0].transcript.lastRecord.ordinal, entry.expected);

      const unlock = JSON.parse((await runCli(["unlock", THREAD_ID, ...common])).stdout);
      assertValid(validate, unlock);
      assert.equal(unlock.inspection.transcript.lastRecord.ordinal, entry.expected);
    });
  }
});
