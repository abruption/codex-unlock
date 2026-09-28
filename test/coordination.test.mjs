import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import {
  chmod,
  mkdir,
  mkdtemp,
  readdir,
  stat,
  symlink,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import process from "node:process";
import test from "node:test";

import { LEASE_DIRECTORY_NAME, acquireUnlockLease } from "../dist/coordination.js";

const THREAD_ID = "01a089e8-3731-7202-ba68-0f4b0a3b2711";
const OTHER_THREAD_ID = "02b190f9-4842-8313-ca79-1f5c1b4c3822";

async function codexHome() {
  const home = await mkdtemp(join(tmpdir(), "codex-unlock-lease-home-"));
  await mkdir(join(home, "thread-writer-locks"));
  await mkdir(join(home, "sessions"));
  return home;
}

function acquired(attempt) {
  assert.equal(attempt.status, "acquired", JSON.stringify(attempt));
  return attempt.lease;
}

test("unlock lease serializes the same native lock and thread", async () => {
  const home = await codexHome();
  const first = acquired(acquireUnlockLease(home, THREAD_ID));
  const coordinationDirectory = join(home, LEASE_DIRECTORY_NAME);
  const [coordinationName] = await readdir(coordinationDirectory);
  assert.equal((await stat(coordinationDirectory)).mode & 0o777, 0o700);
  assert.equal(
    (await stat(join(coordinationDirectory, coordinationName))).mode & 0o777,
    0o600,
  );
  assert.deepEqual(await readdir(join(home, "thread-writer-locks")), []);

  assert.equal(acquireUnlockLease(home, THREAD_ID).status, "contended");
  const other = acquired(acquireUnlockLease(home, OTHER_THREAD_ID));
  other.release();

  first.release();
  first.release();
  acquired(acquireUnlockLease(home, THREAD_ID)).release();
});

test("unlock lease ignores TMPDIR and XDG_RUNTIME_DIR", async () => {
  const home = await codexHome();
  const saved = { TMPDIR: process.env.TMPDIR, XDG_RUNTIME_DIR: process.env.XDG_RUNTIME_DIR };
  const first = acquired(acquireUnlockLease(home, THREAD_ID));
  try {
    const runtime = await mkdtemp(join(tmpdir(), "codex-unlock-runtime-"));
    await chmod(runtime, 0o700);
    for (const environment of [
      { TMPDIR: undefined, XDG_RUNTIME_DIR: undefined },
      { TMPDIR: "/tmp", XDG_RUNTIME_DIR: runtime },
      { TMPDIR: runtime, XDG_RUNTIME_DIR: "relative/runtime" },
    ]) {
      for (const [name, value] of Object.entries(environment)) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
      assert.equal(acquireUnlockLease(home, THREAD_ID).status, "contended");
    }
  } finally {
    for (const [name, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    first.release();
  }
});

test("unlock lease collapses homes aliased through symlinks", async () => {
  const home = await codexHome();
  const homeAlias = `${home}-alias`;
  await symlink(home, homeAlias);
  const linkedHome = await mkdtemp(join(tmpdir(), "codex-unlock-lease-linked-"));
  await symlink(join(home, "thread-writer-locks"), join(linkedHome, "thread-writer-locks"));
  await symlink(join(home, "sessions"), join(linkedHome, "sessions"));

  const first = acquired(acquireUnlockLease(home, THREAD_ID));
  assert.equal(acquireUnlockLease(homeAlias, THREAD_ID).status, "contended");
  assert.equal(acquireUnlockLease(linkedHome, THREAD_ID).status, "contended");
  assert.equal(existsSync(join(linkedHome, LEASE_DIRECTORY_NAME)), false);
  first.release();
  acquired(acquireUnlockLease(linkedHome, THREAD_ID)).release();
});

test("unlock lease collapses case-variant home spellings", async (t) => {
  const home = await codexHome();
  const variant = join(dirname(home), basename(home).toUpperCase());
  if (variant === home || !existsSync(variant)) {
    t.skip("file system is case-sensitive");
    return;
  }
  const first = acquired(acquireUnlockLease(home, THREAD_ID));
  assert.equal(acquireUnlockLease(variant, THREAD_ID).status, "contended");
  first.release();
});

test("unlock lease rejects unsafe pre-created coordination directories", async () => {
  const cases = {
    "group-readable directory": async (path) => {
      await mkdir(path, { mode: 0o700 });
      await chmod(path, 0o755);
    },
    "symlinked directory": async (path) => {
      const target = await mkdtemp(join(tmpdir(), "codex-unlock-lease-target-"));
      await chmod(target, 0o700);
      await symlink(target, path);
    },
    "regular file": async (path) => {
      await writeFile(path, "");
    },
  };
  for (const [label, prepare] of Object.entries(cases)) {
    const home = await codexHome();
    await prepare(join(home, LEASE_DIRECTORY_NAME));
    const attempt = acquireUnlockLease(home, THREAD_ID);
    assert.equal(attempt.status, "unknown", label);
    assert.equal(attempt.reason, "coordination_directory_is_not_private", label);
  }
});

test("unlock lease rejects a symlinked coordination file", async () => {
  const home = await codexHome();
  acquired(acquireUnlockLease(home, THREAD_ID)).release();

  const directory = join(home, LEASE_DIRECTORY_NAME);
  const [name] = await readdir(directory);
  await unlink(join(directory, name));
  await symlink(join(home, "sessions"), join(directory, name));

  const attempt = acquireUnlockLease(home, THREAD_ID);
  assert.equal(attempt.status, "unknown");
});

test("unlock lease requires an existing native lock directory", async () => {
  const home = await mkdtemp(join(tmpdir(), "codex-unlock-lease-empty-"));
  const attempt = acquireUnlockLease(home, THREAD_ID);
  assert.equal(attempt.status, "unknown");
  assert.equal(attempt.reason, "lock_directory_unavailable");
  assert.equal(existsSync(join(home, LEASE_DIRECTORY_NAME)), false);
});
