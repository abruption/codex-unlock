import assert from "node:assert/strict";
import { chmod, mkdtemp, readdir, stat, symlink, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { acquireUnlockLease } from "../dist/coordination.js";

const THREAD_ID = "01a089e8-3731-7202-ba68-0f4b0a3b2711";

async function roots() {
  const codexHome = await mkdtemp(join(tmpdir(), "codex-unlock-lease-home-"));
  const runtimeDirectory = await mkdtemp(join(tmpdir(), "codex-unlock-runtime-"));
  await chmod(runtimeDirectory, 0o700);
  return { codexHome, runtimeDirectory };
}

test("unlock lease serializes the same canonical home and thread", async () => {
  const value = await roots();
  const first = acquireUnlockLease(value.codexHome, THREAD_ID, value.runtimeDirectory);
  assert.equal(first.status, "acquired");
  if (first.status !== "acquired") return;
  const coordinationDirectory = join(value.runtimeDirectory, "codex-unlock");
  const [coordinationName] = await readdir(coordinationDirectory);
  assert.equal((await stat(coordinationDirectory)).mode & 0o777, 0o700);
  assert.equal(
    (await stat(join(coordinationDirectory, coordinationName))).mode & 0o777,
    0o600,
  );
  const homeAlias = join(value.runtimeDirectory, "home-alias");
  await symlink(value.codexHome, homeAlias);

  const competing = acquireUnlockLease(
    homeAlias,
    THREAD_ID,
    value.runtimeDirectory,
  );
  assert.equal(competing.status, "contended");

  first.lease.release();
  first.lease.release();
  const later = acquireUnlockLease(value.codexHome, THREAD_ID, value.runtimeDirectory);
  assert.equal(later.status, "acquired");
  if (later.status === "acquired") later.lease.release();
});

test("unlock lease rejects a non-private runtime directory", async () => {
  const value = await roots();
  await chmod(value.runtimeDirectory, 0o755);

  const attempt = acquireUnlockLease(
    value.codexHome,
    THREAD_ID,
    value.runtimeDirectory,
  );
  assert.equal(attempt.status, "unknown");
});

test("unlock lease rejects a symlinked coordination file", async () => {
  const value = await roots();
  const first = acquireUnlockLease(value.codexHome, THREAD_ID, value.runtimeDirectory);
  assert.equal(first.status, "acquired");
  if (first.status !== "acquired") return;
  first.lease.release();

  const directory = join(value.runtimeDirectory, "codex-unlock");
  const [name] = await readdir(directory);
  await unlink(join(directory, name));
  await symlink(value.codexHome, join(directory, name));

  const attempt = acquireUnlockLease(
    value.codexHome,
    THREAD_ID,
    value.runtimeDirectory,
  );
  assert.equal(attempt.status, "unknown");
});
