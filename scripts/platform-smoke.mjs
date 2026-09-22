import assert from "node:assert/strict";
import process from "node:process";

import { inspectThread } from "../dist/doctor.js";
import {
  THREAD_ID,
  fixture,
  stopChild,
} from "../test/helpers/owner-fixture.mjs";

const expectedPlatform = process.env.CODEX_UNLOCK_EXPECTED_PLATFORM ?? process.platform;
const expectedArch = process.env.CODEX_UNLOCK_EXPECTED_ARCH ?? process.arch;
const expectedNode =
  process.env.CODEX_UNLOCK_EXPECTED_NODE ?? process.versions.node.split(".")[0];
assert.equal(process.platform, expectedPlatform);
assert.equal(process.arch, expectedArch);
assert.match(
  process.versions.node,
  new RegExp(`^${expectedNode.replaceAll(".", "\\.")}(?:\\.|$)`),
);

const value = await fixture();
try {
  const inspection = await inspectThread(THREAD_ID, value.options);
  assert.equal(inspection.classification, "live_owner");
  assert.equal(inspection.safeToUnlock, true);
  assert.equal(inspection.lock.observation, "present");
  assert.equal(inspection.lock.probe.status, "held");
  assert.equal(inspection.lock.regularFile, true);
  assert.equal(inspection.lock.symlink, false);
  assert.equal(inspection.lock.ownedByCurrentUser, true);
  assert.equal(inspection.lock.snapshot?.links, 1);
  assert.match(inspection.lock.snapshot?.device ?? "", /^\d+$/);
  assert.match(inspection.lock.snapshot?.inode ?? "", /^\d+$/);
  assert.equal(inspection.owner?.pid, value.child.pid);
  assert.equal(inspection.owner?.identityComplete, true);
  assert.equal(inspection.owner?.isCodex, true);
  assert.equal(inspection.owner?.uid, process.getuid?.());
  assert.ok(inspection.owner?.startTime);
  assert.ok(inspection.owner?.lsofCommand);
  assert.deepEqual(inspection.owner?.errors, []);
  assert.deepEqual(inspection.ownerLockFiles, [value.lockPath]);
  assert.equal(inspection.ownerIdentityStable, true);
  assert.equal(inspection.transcript.status, "found");
  assert.equal(inspection.transcript.stable, true);
  assert.equal(inspection.transcript.lastRecord?.eventType, "task_complete");

  process.stdout.write(
    `${JSON.stringify({
      platform: process.platform,
      arch: process.arch,
      node: process.versions.node,
      advisoryLock: inspection.lock.probe.status,
      ownerCorrelation: "verified",
      processStartTime: "verified",
      fileIdentity: "verified",
      nativeDependency: "loaded",
    })}\n`,
  );
} finally {
  await stopChild(value.child);
}
