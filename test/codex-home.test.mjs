import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import process from "node:process";
import test from "node:test";
import { pathToFileURL } from "node:url";

import { currentVersion } from "./helpers/version-fixture.mjs";

const CLI = resolve("dist/cli.js");
const OPTIONS_MODULE = pathToFileURL(resolve("dist/options.js")).href;
const THREAD_ID = "01a089e8-3731-7202-ba68-0f4b0a3b2711";

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "codex-unlock-home-"));
  t.after(async () => await rm(root, { recursive: true, force: true }));
  const home = join(root, "user-home");
  const cwd = join(root, "working-directory");
  const defaultHome = join(home, ".codex");
  const relativeHome = join(cwd, "relative-home");
  const absoluteHome = join(root, "absolute-home");
  const explicitHome = join(cwd, "explicit-home");
  const whitespaceHome = join(cwd, " ");
  for (const path of [defaultHome, relativeHome, absoluteHome, explicitHome, whitespaceHome]) {
    await mkdir(path, { recursive: true });
  }
  return { root, home, cwd, defaultHome, relativeHome, absoluteHome, explicitHome, whitespaceHome };
}

function environment(value, codexHome) {
  const env = {
    ...process.env,
    HOME: value.home,
    USERPROFILE: value.home,
    CODEX_UNLOCK_NO_UPDATE_NOTICE: "1",
  };
  delete env.CODEX_HOME;
  if (codexHome !== undefined) env.CODEX_HOME = codexHome;
  return env;
}

function runNode(value, args, codexHome) {
  const result = spawnSync(process.execPath, args, {
    cwd: value.cwd,
    env: environment(value, codexHome),
    encoding: "utf8",
    timeout: 10_000,
    maxBuffer: 1_048_576,
  });
  assert.equal(result.error, undefined);
  assert.equal(result.signal, null);
  return result;
}

function runCli(value, args, codexHome) {
  return runNode(value, [CLI, ...args, "--no-update-notice"], codexHome);
}

function homeCases(value) {
  return [
    { name: "unset", configured: undefined, selected: value.defaultHome },
    { name: "empty", configured: "", selected: value.defaultHome },
    { name: "relative", configured: "relative-home", selected: value.relativeHome },
    { name: "absolute", configured: value.absoluteHome, selected: value.absoluteHome },
    { name: "whitespace is not empty", configured: " ", selected: value.whitespaceHome },
  ];
}

test("defaultOptions selects the documented environment home in an isolated cwd", async (t) => {
  const value = await fixture(t);
  for (const entry of homeCases(value)) {
    await t.test(entry.name, () => {
      const result = runNode(value, [
        "--input-type=module", "--eval",
        `import { defaultOptions } from ${JSON.stringify(OPTIONS_MODULE)};
         console.log(JSON.stringify(defaultOptions()));`,
      ], entry.configured);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stderr, "");
      assert.deepEqual(JSON.parse(result.stdout), {
        codexHome: entry.selected,
        stabilityMs: 1_000,
        terminationTimeoutMs: 5_000,
      });
    });
  }
});

test("CLI list reports the selected environment home and confirmed absence", async (t) => {
  const value = await fixture(t);
  for (const entry of homeCases(value)) {
    await t.test(entry.name, () => {
      const result = runCli(value, ["list", "--json"], entry.configured);
      assert.equal(result.status, 0, result.stderr);
      assert.equal(result.stderr, "");
      const json = JSON.parse(result.stdout);
      assert.equal(json.codexHome, entry.selected);
      assert.deepEqual(json.sessions, []);
    });
  }
  assert.deepEqual(await readdir(value.defaultHome), []);
});

test("explicit CLI home overrides empty, relative, absolute, and unavailable environment paths", async (t) => {
  const value = await fixture(t);
  const cases = [
    ...homeCases(value),
    { name: "unavailable", configured: join(value.root, "missing-home") },
  ];
  for (const entry of cases) {
    await t.test(entry.name, () => {
      for (const path of ["explicit-home", value.explicitHome]) {
        const result = runCli(value, ["list", "--json", "--codex-home", path], entry.configured);
        assert.equal(result.status, 0, result.stderr);
        assert.equal(result.stderr, "");
        const json = JSON.parse(result.stdout);
        assert.equal(json.codexHome, value.explicitHome);
        assert.deepEqual(json.sessions, []);
      }
    });
  }
});

test("empty environment uses the default for inspect and unlock without creating native files", async (t) => {
  const value = await fixture(t);
  for (const command of ["inspect", "unlock"]) {
    const result = runCli(value, [command, THREAD_ID, "--json", "--stability-ms", "250"], "");
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, "");
    const json = JSON.parse(result.stdout);
    const inspection = command === "unlock" ? json.inspection : json;
    assert.equal(inspection.codexHome, value.defaultHome);
    assert.equal(inspection.classification, "absent");
    if (command === "unlock") assert.equal(json.outcome, "not_locked");
  }
  assert.deepEqual(await readdir(value.defaultHome), []);
});

test("unavailable or non-directory selected homes fail instead of reporting absence", async (t) => {
  const value = await fixture(t);
  const missingHome = join(value.root, "missing-home");
  const fileHome = join(value.root, "file-home");
  await writeFile(fileHome, "fixture");
  const cases = [
    { name: "missing environment home", configured: missingHome, args: [], error: /does not exist/ },
    { name: "file environment home", configured: fileHome, args: [], error: /not a directory/ },
    { name: "missing explicit home overrides empty", configured: "", args: ["--codex-home", missingHome], error: /does not exist/ },
    { name: "file explicit home overrides valid environment", configured: value.absoluteHome, args: ["--codex-home", fileHome], error: /not a directory/ },
  ];
  for (const entry of cases) {
    await t.test(entry.name, () => {
      const result = runCli(value, ["list", "--json", ...entry.args], entry.configured);
      assert.equal(result.status, 3, result.stdout);
      assert.equal(result.stderr, "");
      const json = JSON.parse(result.stdout);
      assert.equal(json.status, "error");
      assert.equal(json.errorCode, "command_failed");
      assert.equal(json.exitCode, 3);
      assert.match(json.error, entry.error);
      assert.equal("sessions" in json, false);
    });
  }
  await rm(value.defaultHome, { recursive: true });
  const result = runCli(value, ["list", "--json"], "");
  assert.equal(result.status, 3, result.stdout);
  const json = JSON.parse(result.stdout);
  assert.equal(json.errorCode, "command_failed");
  assert.match(json.error, /does not exist/);
  assert.ok(json.error.includes(value.defaultHome));
  assert.equal("sessions" in json, false);
});

test("an empty explicit CLI home is a usage error rather than an environment fallback", async (t) => {
  const value = await fixture(t);
  const result = runCli(value, ["list", "--json", "--codex-home", ""], "");
  assert.equal(result.status, 64, result.stdout);
  assert.equal(result.stderr, "");
  const json = JSON.parse(result.stdout);
  assert.equal(json.errorCode, "invalid_usage");
  assert.equal(json.exitCode, 64);
  assert.match(json.error, /--codex-home requires a path/);
});

test("help and version remain usable with an empty environment and missing default home", async (t) => {
  const value = await fixture(t);
  await rm(value.defaultHome, { recursive: true });
  for (const argument of ["--help", "-h", "--version", "-v"]) {
    const result = runCli(value, [argument], "");
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, "");
    if (argument === "--help" || argument === "-h") {
      assert.match(result.stdout, /^codex-unlock - /);
      assert.match(result.stdout, /nonempty CODEX_HOME or ~\/.codex/);
    } else {
      assert.equal(result.stdout, `${currentVersion}\n`);
    }
  }
  assert.deepEqual(await readdir(value.home), []);
});
