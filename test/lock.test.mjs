import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, rename, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { observeLockFile, probeLock, probeObservedLock } from "../dist/lock.js";

test("distinguishes confirmed absence from lock observation failure", async () => {
  const root = await mkdtemp(join(tmpdir(), "codex-unlock-lock-observation-"));
  const absent = join(root, "absent.lock");
  assert.deepEqual(observeLockFile(absent), {
    status: "absent",
    exists: false,
    regularFile: null,
    symlink: null,
    ownedByCurrentUser: null,
    snapshot: null,
  });
  assert.equal(probeLock(absent).status, "free");

  const file = join(root, "not-a-directory");
  await writeFile(file, "");
  const invalid = join(file, "thread.lock");
  const observation = observeLockFile(invalid);
  assert.equal(observation.status, "unknown");
  assert.equal(observation.exists, false);
  assert.match(observation.error, /ENOTDIR/);
  const probe = probeLock(invalid);
  assert.equal(probe.status, "unknown");
  assert.match(probe.error, /ENOTDIR/);
});

test("reports replacement between observation and open as unknown", async () => {
  const root = await mkdtemp(join(tmpdir(), "codex-unlock-lock-replacement-"));
  const path = join(root, "thread.lock");
  await writeFile(path, "first");
  const observation = observeLockFile(path);
  await rename(path, `${path}.old`);
  await writeFile(path, "second");

  const probe = probeObservedLock(path, observation);
  assert.equal(probe.status, "unknown");
  assert.equal(probe.error, "lock file changed while it was opened");
});

test("reports permission-denied lock lookup as unknown when enforced", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "codex-unlock-lock-permission-"));
  const protectedDirectory = join(root, "protected");
  await mkdir(protectedDirectory);
  const path = join(protectedDirectory, "thread.lock");
  await writeFile(path, "");
  await chmod(protectedDirectory, 0o000);
  t.after(async () => await chmod(protectedDirectory, 0o700));

  const observation = observeLockFile(path);
  if (observation.status !== "unknown") {
    t.skip("current user can bypass directory permissions");
    return;
  }
  assert.match(observation.error, /EACCES|EPERM/);
  assert.equal(probeLock(path).status, "unknown");
});
