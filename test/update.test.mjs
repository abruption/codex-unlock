import assert from "node:assert/strict";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import process from "node:process";
import test from "node:test";

import {
  UPDATE_CACHE_FUTURE_SKEW_MS,
  UPDATE_CACHE_MAX_BYTES,
  UPDATE_CACHE_TTL_MS,
  UPDATE_NOTICE_ENV,
  UPDATE_REFRESH_ARG,
  UPDATE_REGISTRY_URL,
  acquireUpdateRefreshLease,
  compareStableVersions,
  emitHumanUpdateNotice,
  fetchNpmLatest,
  readUpdateCache,
  prepareUpdateAdvisory,
  refreshUpdateCache,
  stableVersion,
  scheduleUpdateRefresh,
  updateAutomationPolicy,
  updateCacheLocation,
  updateCommand,
  updateInstallation,
  withClientUpdate,
  writeUpdateCache,
} from "../dist/update.js";
import { THREAD_ID, fixture, runCli, stopChild } from "./helpers/owner-fixture.mjs";
import { currentVersion, newerVersion } from "./helpers/version-fixture.mjs";

const NOW = Date.parse("2026-09-22T00:00:00.000Z");

function location(root) {
  const directory = join(root, "codex-unlock");
  return {
    directory,
    cacheFile: join(directory, "update.json"),
    lockFile: join(directory, "update.lock"),
  };
}

async function temporaryLocation(prefix = "codex-unlock-update-") {
  return location(await mkdtemp(join(tmpdir(), prefix)));
}

async function writeRawCache(target, value, mode = 0o600) {
  await mkdir(target.directory, { recursive: true, mode: 0o700 });
  await chmod(target.directory, 0o700);
  await writeFile(target.cacheFile, value, { mode });
  await chmod(target.cacheFile, mode);
}

function cacheRecord(latest, checkedAt) {
  return JSON.stringify({ schemaVersion: 1, latest, checkedAt });
}

function jsonResponse(value, init = {}) {
  const { headers, ...rest } = init;
  return new globalThis.Response(JSON.stringify(value), {
    status: 200,
    ...rest,
    headers: { "content-type": "application/json", ...(headers ?? {}) },
  });
}

test("accepts only strict stable semantic versions", () => {
  for (const value of ["0.0.0", "1.2.3", "999999999999999.2.3"]) {
    assert.equal(stableVersion(value), value);
  }
  for (const value of [
    "v1.2.3",
    "1.2",
    "1.2.3.4",
    "01.2.3",
    "1.02.3",
    "1.2.03",
    "1.2.3-rc.1",
    "1.2.3+build",
    "1.2.3\n",
    "1".repeat(65) + ".0.0",
    null,
  ]) {
    assert.equal(stableVersion(value), null);
  }
  assert.equal(compareStableVersions("1.2.3", "1.2.3"), 0);
  assert.equal(compareStableVersions("1.2.3", "1.2.4"), -1);
  assert.equal(compareStableVersions("2.0.0", "1.999999999999999.999999999999999"), 1);
  assert.throws(() => compareStableVersions("1.0.0-rc.1", "1.0.0"));
});

test("resolves the cache outside Codex homes and ignores relative XDG paths", () => {
  assert.deepEqual(updateCacheLocation({ XDG_CACHE_HOME: "/private/cache" }, "/users/a"), {
    directory: "/private/cache/codex-unlock",
    cacheFile: "/private/cache/codex-unlock/update.json",
    lockFile: "/private/cache/codex-unlock/update.lock",
  });
  assert.equal(
    updateCacheLocation({ XDG_CACHE_HOME: "relative" }, "/users/a").directory,
    "/users/a/.cache/codex-unlock",
  );
});

test("writes only public version metadata with private atomic permissions", async () => {
  const target = await temporaryLocation();
  const result = writeUpdateCache("0.2.1", target, NOW);
  assert.deepEqual(result, {
    status: "written",
    record: {
      schemaVersion: 1,
      latest: "0.2.1",
      checkedAt: "2026-09-22T00:00:00.000Z",
    },
  });
  assert.equal((await stat(target.directory)).mode & 0o777, 0o700);
  assert.equal((await stat(target.cacheFile)).mode & 0o777, 0o600);
  assert.deepEqual(Object.keys(JSON.parse(await readFile(target.cacheFile, "utf8"))).sort(), [
    "checkedAt",
    "latest",
    "schemaVersion",
  ]);
  assert.deepEqual(
    (await readdir(target.directory)).filter((name) => name.endsWith(".tmp")),
    [],
  );
  assert.deepEqual(readUpdateCache(target, NOW), {
    status: "fresh",
    record: result.record,
  });

  const replacement = writeUpdateCache("0.2.2", target, NOW + 1_000);
  assert.equal(replacement.status, "written");
  assert.equal(readUpdateCache(target, NOW + 1_000).status, "fresh");
  assert.equal(JSON.parse(await readFile(target.cacheFile, "utf8")).latest, "0.2.2");
  assert.deepEqual(
    (await readdir(target.directory)).filter((name) => name.endsWith(".tmp")),
    [],
  );
});

test("missing cache is advisory absence", async () => {
  const target = await temporaryLocation("codex-unlock-update-missing-");
  assert.equal(readUpdateCache(target, NOW).status, "missing");
  await mkdir(target.directory, { mode: 0o700 });
  assert.equal(readUpdateCache(target, NOW).status, "missing");
});

test("cache reads reject stale, future, malformed, oversized, and unsafe data", async (t) => {
  const cases = [
    {
      name: "stale",
      value: cacheRecord("0.2.1", new Date(NOW - UPDATE_CACHE_TTL_MS - 1).toISOString()),
      expectedStatus: "stale",
    },
    {
      name: "future",
      value: cacheRecord(
        "0.2.1",
        new Date(NOW + UPDATE_CACHE_FUTURE_SKEW_MS + 1).toISOString(),
      ),
      expectedStatus: "invalid",
    },
    { name: "malformed", value: "{", expectedStatus: "invalid" },
    {
      name: "unknown field",
      value: JSON.stringify({
        schemaVersion: 1,
        latest: "0.2.1",
        checkedAt: new Date(NOW).toISOString(),
        secret: "must-not-be-accepted",
      }),
      expectedStatus: "invalid",
    },
    {
      name: "prerelease",
      value: cacheRecord("0.2.1-rc.1", new Date(NOW).toISOString()),
      expectedStatus: "invalid",
    },
    {
      name: "oversized",
      value: "x".repeat(UPDATE_CACHE_MAX_BYTES + 1),
      expectedStatus: "invalid",
    },
  ];
  for (const entry of cases) {
    await t.test(entry.name, async () => {
      const target = await temporaryLocation(`codex-unlock-update-${entry.name.replaceAll(" ", "-")}-`);
      await writeRawCache(target, entry.value);
      assert.equal(readUpdateCache(target, NOW).status, entry.expectedStatus);
    });
  }

  await t.test("symlink", async () => {
    const target = await temporaryLocation("codex-unlock-update-symlink-");
    await mkdir(target.directory, { recursive: true, mode: 0o700 });
    await chmod(target.directory, 0o700);
    const destination = join(await mkdtemp(join(tmpdir(), "codex-unlock-update-target-")), "data");
    await writeFile(destination, cacheRecord("0.2.1", new Date(NOW).toISOString()), {
      mode: 0o600,
    });
    await symlink(destination, target.cacheFile);
    assert.equal(readUpdateCache(target, NOW).status, "invalid");
  });

  await t.test("world-readable file", async () => {
    const target = await temporaryLocation("codex-unlock-update-mode-");
    await writeRawCache(
      target,
      cacheRecord("0.2.1", new Date(NOW).toISOString()),
      0o644,
    );
    assert.equal(readUpdateCache(target, NOW).status, "invalid");
  });
});

test("cache writes refuse symlinked and hard-linked targets", async (t) => {
  await t.test("symlinked directory", async () => {
    const root = await mkdtemp(join(tmpdir(), "codex-unlock-write-directory-"));
    const destination = await mkdtemp(join(tmpdir(), "codex-unlock-write-directory-target-"));
    const target = location(root);
    await symlink(destination, target.directory);
    assert.equal(writeUpdateCache("0.2.1", target, NOW).status, "error");
    assert.deepEqual(await readdir(destination), []);
  });

  await t.test("symlink", async () => {
    const target = await temporaryLocation("codex-unlock-write-symlink-");
    await mkdir(target.directory, { recursive: true, mode: 0o700 });
    await chmod(target.directory, 0o700);
    const destination = join(await mkdtemp(join(tmpdir(), "codex-unlock-write-target-")), "data");
    await writeFile(destination, "preserve", { mode: 0o600 });
    await symlink(destination, target.cacheFile);
    assert.equal(writeUpdateCache("0.2.1", target, NOW).status, "error");
    assert.equal(await readFile(destination, "utf8"), "preserve");
  });

  await t.test("hard link", async () => {
    const target = await temporaryLocation("codex-unlock-write-hardlink-");
    await mkdir(target.directory, { recursive: true, mode: 0o700 });
    await chmod(target.directory, 0o700);
    const destination = join(target.directory, "other");
    await writeFile(destination, "preserve", { mode: 0o600 });
    await link(destination, target.cacheFile);
    assert.equal(writeUpdateCache("0.2.1", target, NOW).status, "error");
    assert.equal(await readFile(destination, "utf8"), "preserve");
  });
});

test("cache write tightens an owned application directory", async () => {
  const target = await temporaryLocation("codex-unlock-write-directory-mode-");
  await mkdir(target.directory, { recursive: true, mode: 0o755 });
  await chmod(target.directory, 0o755);
  assert.equal(writeUpdateCache("0.2.1", target, NOW).status, "written");
  assert.equal((await stat(target.directory)).mode & 0o777, 0o700);
});

test("refresh lease uses actual advisory locking and reuses stale residue", async () => {
  const target = await temporaryLocation("codex-unlock-refresh-lock-");
  const first = acquireUpdateRefreshLease(target);
  assert.equal(first.status, "acquired");
  if (first.status !== "acquired") return;
  assert.equal((await stat(target.directory)).mode & 0o777, 0o700);
  assert.equal((await stat(target.lockFile)).mode & 0o777, 0o600);
  assert.equal((await stat(target.lockFile)).size, 0);
  const competing = acquireUpdateRefreshLease(target);
  assert.equal(competing.status, "contended");
  first.lease.release();
  first.lease.release();

  assert.equal((await lstat(target.lockFile)).isFile(), true);
  await writeFile(target.lockFile, "stale residue", { mode: 0o600 });
  const afterRelease = acquireUpdateRefreshLease(target);
  assert.equal(afterRelease.status, "acquired");
  if (afterRelease.status === "acquired") {
    assert.equal((await stat(target.lockFile)).size, 0);
    afterRelease.lease.release();
  }
});

test("refresh lease refuses a symlink instead of deleting or stealing it", async () => {
  const target = await temporaryLocation("codex-unlock-refresh-symlink-");
  await mkdir(target.directory, { recursive: true, mode: 0o700 });
  await chmod(target.directory, 0o700);
  const destination = join(await mkdtemp(join(tmpdir(), "codex-unlock-refresh-target-")), "lock");
  await writeFile(destination, "preserve", { mode: 0o600 });
  await symlink(destination, target.lockFile);
  const attempt = acquireUpdateRefreshLease(target);
  assert.equal(attempt.status, "unavailable");
  assert.equal(await readFile(destination, "utf8"), "preserve");
});

test("refresh is single-flight and preserves a valid cache on fetch failure", async () => {
  const target = await temporaryLocation("codex-unlock-refresh-combined-");
  assert.equal(writeUpdateCache("0.2.0", target, NOW).status, "written");
  const before = await readFile(target.cacheFile, "utf8");
  const failed = await refreshUpdateCache({
    location: target,
    nowMs: NOW + 1_000,
    fetchImpl: async () => { throw new Error("offline"); },
  });
  assert.deepEqual(failed, { status: "error", reason: "network_error" });
  assert.equal(await readFile(target.cacheFile, "utf8"), before);

  let markStarted;
  let allowResponse;
  const started = new Promise((resolve) => {
    markStarted = resolve;
  });
  const responseAllowed = new Promise((resolve) => {
    allowResponse = resolve;
  });
  const first = refreshUpdateCache({
    location: target,
    nowMs: NOW + 2_000,
    fetchImpl: async () => {
      markStarted();
      await responseAllowed;
      return jsonResponse({ version: "0.2.1" });
    },
  });
  await started;
  const competing = await refreshUpdateCache({
    location: target,
    nowMs: NOW + 2_000,
    fetchImpl: async () => {
      throw new Error("a contending refresh must not fetch");
    },
  });
  assert.deepEqual(competing, { status: "skipped", reason: "refresh_in_progress" });
  allowResponse();
  const updated = await first;
  assert.equal(updated.status, "updated");
  assert.equal(readUpdateCache(target, NOW + 2_000).status, "fresh");
  assert.equal(JSON.parse(await readFile(target.cacheFile, "utf8")).latest, "0.2.1");
});

test("registry request is fixed, bounded, non-redirecting, and stable-only", async (t) => {
  await t.test("success", async () => {
    let input;
    let init;
    const result = await fetchNpmLatest({
      nowMs: NOW,
      fetchImpl: async (nextInput, nextInit) => {
        input = nextInput;
        init = nextInit;
        return jsonResponse({ version: "0.2.1", ignored: "public registry metadata" });
      },
    });
    assert.equal(input, UPDATE_REGISTRY_URL);
    assert.equal(init.method, "GET");
    assert.equal(init.redirect, "error");
    assert.equal(init.headers.accept, "application/json");
    assert.ok(init.signal instanceof globalThis.AbortSignal);
    assert.deepEqual(result, {
      status: "ok",
      record: {
        schemaVersion: 1,
        latest: "0.2.1",
        checkedAt: "2026-09-22T00:00:00.000Z",
      },
    });
  });

  const failures = [
    ["network error", async () => { throw new Error("offline"); }, "network_error"],
    ["registry error", async () => jsonResponse({}, { status: 500 }), "registry_error"],
    ["redirect", async () => new globalThis.Response(null, { status: 302, headers: { location: "https://example.test" } }), "redirect_rejected"],
    ["wrong content type", async () => new globalThis.Response("{}", { headers: { "content-type": "text/plain" } }), "invalid_content_type"],
    ["invalid JSON", async () => new globalThis.Response("{", { headers: { "content-type": "application/json" } }), "invalid_response"],
    ["prerelease", async () => jsonResponse({ version: "0.2.1-rc.1" }), "invalid_response"],
    ["oversized header", async () => jsonResponse({ version: "0.2.1" }, { headers: { "content-length": "100" } }), "response_too_large"],
    ["oversized body", async () => new globalThis.Response("x".repeat(100), { headers: { "content-type": "application/json" } }), "response_too_large"],
  ];
  for (const [name, fetchImpl, reason] of failures) {
    await t.test(name, async () => {
      const result = await fetchNpmLatest({
        fetchImpl,
        maxResponseBytes: name.startsWith("oversized") ? 16 : 64 * 1024,
        nowMs: NOW,
      });
      assert.deepEqual(result, { status: "error", reason });
    });
  }

  await t.test("timeout", async () => {
    const result = await fetchNpmLatest({
      timeoutMs: 20,
      fetchImpl: async (_input, init) => await new Promise((_resolve, reject) => {
        init.signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
      }),
    });
    assert.deepEqual(result, { status: "error", reason: "timeout" });
  });
});

test("automation policy suppresses opt-out, CI, and non-TTY side effects", () => {
  assert.deepEqual(
    updateAutomationPolicy({
      json: false,
      noUpdateNotice: true,
      stdoutIsTTY: true,
      stderrIsTTY: true,
      environment: {},
    }),
    {
      disabled: true,
      readCache: false,
      attachJson: false,
      showHumanNotice: false,
      scheduleRefresh: false,
    },
  );
  assert.equal(
    updateAutomationPolicy({
      json: true,
      noUpdateNotice: false,
      stdoutIsTTY: true,
      stderrIsTTY: true,
      environment: { [UPDATE_NOTICE_ENV]: "yes" },
    }).disabled,
    true,
  );
  const ciJson = updateAutomationPolicy({
    json: true,
    noUpdateNotice: false,
    stdoutIsTTY: false,
    stderrIsTTY: false,
    environment: { CI: "true" },
  });
  assert.equal(ciJson.readCache, true);
  assert.equal(ciJson.attachJson, true);
  assert.equal(ciJson.showHumanNotice, false);
  assert.equal(ciJson.scheduleRefresh, false);

  const nonInteractiveHuman = updateAutomationPolicy({
    json: false,
    noUpdateNotice: false,
    stdoutIsTTY: false,
    stderrIsTTY: false,
    environment: {},
  });
  assert.equal(nonInteractiveHuman.readCache, false);
  assert.equal(nonInteractiveHuman.showHumanNotice, false);
  assert.equal(nonInteractiveHuman.scheduleRefresh, false);

  const interactiveHuman = updateAutomationPolicy({
    json: false,
    noUpdateNotice: false,
    stdoutIsTTY: true,
    stderrIsTTY: true,
    environment: {},
  });
  assert.equal(interactiveHuman.readCache, true);
  assert.equal(interactiveHuman.showHumanNotice, true);
  assert.equal(interactiveHuman.scheduleRefresh, true);
});

test("fresh update advisories distinguish newer, equal, and older versions", async () => {
  const target = await temporaryLocation("codex-unlock-update-advisory-");
  assert.equal(writeUpdateCache("0.2.1", target, NOW).status, "written");
  const base = {
    json: true,
    noUpdateNotice: false,
    stdoutIsTTY: false,
    stderrIsTTY: false,
    environment: {},
    location: target,
    nowMs: NOW,
    guidance: { sourceCheckout: false, environment: {} },
  };

  const newer = prepareUpdateAdvisory({ ...base, currentVersion: "0.2.0" });
  assert.deepEqual(newer.clientUpdate, {
    schemaVersion: 1,
    source: "npm",
    currentVersion: "0.2.0",
    latestVersion: "0.2.1",
    checkedAt: "2026-09-22T00:00:00.000Z",
    updateAvailable: true,
    updateCommand: "npm install --global codex-unlock@latest",
  });
  assert.equal(newer.humanNotice, null);
  assert.equal(newer.scheduleRefresh, false);
  assert.equal(
    prepareUpdateAdvisory({ ...base, currentVersion: "0.2.1" }).clientUpdate,
    null,
  );
  assert.equal(
    prepareUpdateAdvisory({ ...base, currentVersion: "0.2.2" }).clientUpdate,
    null,
  );
});

test("human notice is emitted after primary output and opt-out suppresses all work", async () => {
  const target = await temporaryLocation("codex-unlock-update-human-");
  assert.equal(writeUpdateCache("0.2.1", target, NOW).status, "written");
  const advisory = prepareUpdateAdvisory({
    currentVersion: "0.2.0",
    json: false,
    noUpdateNotice: false,
    stdoutIsTTY: true,
    stderrIsTTY: true,
    environment: {},
    location: target,
    nowMs: NOW,
    guidance: { sourceCheckout: false, environment: {} },
  });
  const writes = ["primary result\n"];
  emitHumanUpdateNotice(advisory.humanNotice, (value) => writes.push(value));
  assert.deepEqual(writes, [
    "primary result\n",
    "Update available: 0.2.0 → 0.2.1. Run: npm install --global codex-unlock@latest\n",
  ]);
  assert.doesNotThrow(() => emitHumanUpdateNotice(advisory.humanNotice, () => {
    throw new Error("stderr unavailable");
  }));

  const disabled = prepareUpdateAdvisory({
    currentVersion: "0.2.0",
    json: true,
    noUpdateNotice: false,
    stdoutIsTTY: true,
    stderrIsTTY: true,
    environment: { [UPDATE_NOTICE_ENV]: "true" },
    location: target,
    nowMs: NOW,
  });
  assert.deepEqual(disabled, {
    clientUpdate: null,
    humanNotice: null,
    scheduleRefresh: false,
  });
});

test("update guidance is conservative for registry, npx, and source installs", () => {
  assert.equal(updateInstallation({ environment: {}, cliPath: "/usr/local/bin/codex-unlock" }), "registry");
  assert.equal(updateCommand({ environment: {}, cliPath: "/usr/local/bin/codex-unlock" }), "npm install --global codex-unlock@latest");
  assert.equal(updateInstallation({ environment: { npm_command: "exec" } }), "npx");
  assert.equal(updateCommand({ environment: { npm_command: "exec" } }), "npx --yes codex-unlock@latest");
  assert.equal(updateInstallation({ sourceCheckout: true }), "source");
  assert.equal(
    updateCommand({ sourceCheckout: true }),
    "git -C <source-checkout> pull --ff-only && npm --prefix <source-checkout> ci",
  );
});

test("detached refresh scheduling is bounded and swallows spawn errors", () => {
  let invocation;
  let unrefCalled = false;
  let errorHandlerAttached = false;
  const child = {
    once(event) {
      if (event === "error") errorHandlerAttached = true;
      return child;
    },
    unref() {
      unrefCalled = true;
      return child;
    },
  };
  const scheduled = scheduleUpdateRefresh({
    executable: "/usr/bin/node",
    cliPath: "/package/dist/cli.js",
    environment: { PATH: "/usr/bin" },
    spawnImpl(command, args, options) {
      invocation = { command, args, options };
      return child;
    },
  });
  assert.equal(scheduled, true);
  assert.deepEqual(invocation.command, "/usr/bin/node");
  assert.deepEqual(invocation.args, ["/package/dist/cli.js", UPDATE_REFRESH_ARG]);
  assert.equal(invocation.options.detached, true);
  assert.equal(invocation.options.stdio, "ignore");
  assert.deepEqual(invocation.options.env, { PATH: "/usr/bin" });
  assert.equal(errorHandlerAttached, true);
  assert.equal(unrefCalled, true);
  assert.equal(scheduleUpdateRefresh({
    cliPath: "/package/dist/cli.js",
    spawnImpl() { throw new Error("spawn failed"); },
  }), false);
});

test("clientUpdate is an additive root field", () => {
  const primary = { schemaVersion: 1, command: "list", count: 0 };
  assert.equal(withClientUpdate(primary, null), primary);
  const update = {
    schemaVersion: 1,
    source: "npm",
    currentVersion: "0.2.0",
    latestVersion: "0.2.1",
    checkedAt: "2026-09-22T00:00:00.000Z",
    updateAvailable: true,
    updateCommand: "npm install --global codex-unlock@latest",
  };
  assert.deepEqual(withClientUpdate(primary, update), { ...primary, clientUpdate: update });
});

test("JSON CLI attaches a fresh newer advisory on success and usage error only", async () => {
  const root = await mkdtemp(join(tmpdir(), "codex-unlock-update-cli-json-"));
  const target = location(root);
  assert.equal(writeUpdateCache(newerVersion, target, Date.now()).status, "written");
  const codexHome = await mkdtemp(join(tmpdir(), "codex-unlock-update-cli-home-"));
  const environment = {
    ...process.env,
    CI: "false",
    XDG_CACHE_HOME: root,
    CODEX_UNLOCK_NO_UPDATE_NOTICE: "false",
  };

  const success = await runCli(["list", "--json", "--codex-home", codexHome], environment);
  assert.equal(success.code, 0);
  assert.equal(success.stderr, "");
  assert.equal(JSON.parse(success.stdout).clientUpdate.latestVersion, newerVersion);

  const usage = await runCli(["inspect", "--json"], environment);
  assert.equal(usage.code, 64);
  assert.equal(usage.stderr, "");
  assert.equal(JSON.parse(usage.stdout).clientUpdate.latestVersion, newerVersion);

  const flagOptOut = await runCli(
    ["list", "--json", "--no-update-notice", "--codex-home", codexHome],
    environment,
  );
  assert.equal(JSON.parse(flagOptOut.stdout).clientUpdate, undefined);
  const environmentOptOut = await runCli(
    ["list", "--json", "--codex-home", codexHome],
    { ...environment, CODEX_UNLOCK_NO_UPDATE_NOTICE: "yes" },
  );
  assert.equal(JSON.parse(environmentOptOut.stdout).clientUpdate, undefined);
});

test("check-update performs the explicit bounded refresh and returns structured output", async () => {
  const root = await mkdtemp(join(tmpdir(), "codex-unlock-check-update-"));
  const preload = join(root, "registry-response.mjs");
  await writeFile(
    preload,
    `globalThis.fetch = async () => new Response(JSON.stringify({ version: "${newerVersion}" }), { headers: { "content-type": "application/json" } });\n`,
  );
  const environment = {
    ...process.env,
    XDG_CACHE_HOME: root,
    NODE_OPTIONS: `--import=${pathToFileURL(preload).href}`,
  };
  const result = await runCli(["check-update", "--json"], environment);
  assert.equal(result.code, 0, result.stderr);
  assert.equal(result.stderr, "");
  assert.deepEqual(JSON.parse(result.stdout), {
    schemaVersion: 1,
    command: "check-update",
    status: "ok",
    source: "npm",
    currentVersion,
    latestVersion: newerVersion,
    checkedAt: JSON.parse(await readFile(location(root).cacheFile, "utf8")).checkedAt,
    updateAvailable: true,
    updateCommand: "git -C <source-checkout> pull --ff-only && npm --prefix <source-checkout> ci",
  });

  await writeFile(preload, `globalThis.fetch = async () => { throw new Error("offline"); };\n`);
  const failedRoot = await mkdtemp(join(tmpdir(), "codex-unlock-check-update-failed-"));
  const failed = await runCli(
    ["check-update", "--json"],
    { ...environment, XDG_CACHE_HOME: failedRoot },
  );
  assert.equal(failed.code, 3);
  assert.equal(failed.stderr, "");
  assert.equal(JSON.parse(failed.stdout).errorCode, "command_failed");
});

test("cache failures leave primary JSON bytes and exit status unchanged", async () => {
  const root = await mkdtemp(join(tmpdir(), "codex-unlock-update-isolation-"));
  const target = location(root);
  await writeRawCache(target, "{");
  const baseEnvironment = {
    ...process.env,
    CODEX_UNLOCK_NO_UPDATE_NOTICE: "0",
    XDG_CACHE_HOME: join(root, "missing"),
  };
  const baseline = await runCli(["inspect", "--json"], baseEnvironment);
  const malformed = await runCli(
    ["inspect", "--json"],
    { ...baseEnvironment, XDG_CACHE_HOME: root },
  );
  assert.equal(baseline.code, 64);
  assert.equal(baseline.stderr, "");
  assert.deepEqual(malformed, baseline);
});

test("the safety-critical unlock path starts no registry request or update refresher", async (t) => {
  const value = await fixture();
  t.after(async () => await stopChild(value.child));
  const originalFetch = globalThis.fetch;
  const originalSpawn = childProcess.spawn;
  let registryCalls = 0;
  let refreshSpawns = 0;
  globalThis.fetch = async () => {
    registryCalls += 1;
    throw new Error("registry access is forbidden during unlock");
  };
  childProcess.spawn = function instrumentedSpawn(executable, args, options) {
    if (Array.isArray(args) && args.includes(UPDATE_REFRESH_ARG)) refreshSpawns += 1;
    return originalSpawn.call(this, executable, args, options);
  };
  syncBuiltinESMExports();
  try {
    const { unlockThread } = await import(`../dist/unlock.js?isolation=${Date.now()}`);
    const result = await unlockThread(THREAD_ID, value.options);
    assert.equal(result.outcome, "unlocked");
    assert.equal(result.signalSent, "SIGTERM");
    assert.equal(registryCalls, 0);
    assert.equal(refreshSpawns, 0);
  } finally {
    globalThis.fetch = originalFetch;
    childProcess.spawn = originalSpawn;
    syncBuiltinESMExports();
  }
});
