import assert from "node:assert/strict";
import { once } from "node:events";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import process from "node:process";
import { spawn } from "node:child_process";
import test from "node:test";

import Ajv2020 from "ajv/dist/2020.js";
import { currentVersion, newerVersion } from "./helpers/version-fixture.mjs";

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
