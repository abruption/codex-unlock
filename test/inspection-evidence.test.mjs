import assert from "node:assert/strict";
import test from "node:test";
import { formatInspectionEvidence } from "./helpers/inspection-evidence.mjs";

function example() {
  return {
    child: { pid: 42, exitCode: null, signalCode: null },
    inspection: {
      classification: "unknown", safeToUnlock: false, ownerIdentityStable: false,
      blockers: ["classification_unknown", "lock_owner_identity_incomplete"], warnings: [],
      lock: {
        observation: "present", stable: true, exists: true, regularFile: true, symlink: false, ownedByCurrentUser: true,
        snapshot: { device: "1", inode: "2", mode: 0o100600, uid: 1001, links: 1, size: 0, modifiedAt: "2026-10-18T00:00:00.000Z", modifiedMs: 1792281600000 },
        probe: { status: "held", method: "flock_exclusive_nonblocking", guard: { status: "acquired", attempts: 1 } },
      },
      owner: { pid: 42 },
      openers: [{ pid: 42, ppid: 7, uid: 1001, startTime: "Sun Oct 18 00:00:00 2026", isCodex: true,
        isSharedService: false, identityComplete: false, errors: ["arguments_unverified"] }],
    },
  };
}

test("inspection evidence captures fixture, lock and opener identity diagnostics from the first observation", () => {
  const { inspection, child } = example();
  const evidence = JSON.parse(formatInspectionEvidence(inspection, child));
  assert.deepEqual(evidence, {
    fixture: child,
    classification: "unknown", safeToUnlock: false, ownerIdentityStable: false,
    blockers: inspection.blockers, warnings: [],
    lock: {
      observation: "present", observationError: null, stable: true, exists: true, regularFile: true, symlink: false, ownedByCurrentUser: true,
      snapshot: inspection.lock.snapshot,
      probe: { status: "held", method: "flock_exclusive_nonblocking", error: null, guard: { status: "acquired", attempts: 1 } },
    },
    ownerPid: 42, openers: inspection.openers,
  });
});

test("inspection evidence never reads excluded metadata, accessors or serialization hooks", () => {
  const { inspection, child } = example();
  // Synthetic metadata only, never a credential.
  const privateMarker = "fixture-only-private-marker";
  let reads = 0;
  const forbidden = (object, key) => Object.defineProperty(object, key, {
    enumerable: true,
    get() { reads++; throw new Error(privateMarker); },
  });
  for (const object of [inspection, child, inspection.lock, inspection.lock.snapshot, inspection.lock.probe,
    inspection.lock.probe.guard, inspection.owner, inspection.openers[0], inspection.blockers, inspection.warnings, inspection.openers[0].errors]) {
    object.extra = { privateMarker };
    forbidden(object, "unrecognized");
    forbidden(object, "toJSON");
  }
  for (const key of ["env", "transcript", "command", "arguments", "argv"]) forbidden(inspection, key);
  for (const key of ["command", "arguments", "argv", "cwd"]) forbidden(inspection.openers[0], key);
  forbidden(inspection.lock, "path");
  forbidden(child, "env");
  // Even an accessor in an allowlisted slot is omitted, not invoked.
  delete inspection.lock.probe.error;
  forbidden(inspection.lock.probe, "error");
  const captured = formatInspectionEvidence(inspection, child);
  assert.equal(reads, 0);
  assert.equal(captured.includes(privateMarker), false);
  const evidence = JSON.parse(captured);
  assert.equal(evidence.lock.probe.error, null);
  assert.equal(evidence.fixture.extra, undefined);
  assert.equal(evidence.lock.path, undefined);
  assert.equal(evidence.openers[0].arguments, undefined);
});

test("later mutation and fixture cleanup cannot rewrite the captured first evidence JSON", () => {
  const { inspection, child } = example();
  const first = formatInspectionEvidence(inspection, child);
  inspection.classification = "live_owner";
  inspection.safeToUnlock = true;
  inspection.blockers.length = 0;
  inspection.lock.probe.status = "free";
  inspection.lock.snapshot.inode = "replacement";
  inspection.openers[0].errors.push("later_error");
  child.exitCode = 0;
  child.signalCode = "SIGTERM";
  const evidence = JSON.parse(first);
  assert.equal(evidence.classification, "unknown");
  assert.equal(evidence.safeToUnlock, false);
  assert.equal(evidence.blockers.length, 2);
  assert.equal(evidence.lock.probe.status, "held");
  assert.equal(evidence.lock.snapshot.inode, "2");
  assert.deepEqual(evidence.openers[0].errors, ["arguments_unverified"]);
  assert.deepEqual(evidence.fixture, { pid: 42, exitCode: null, signalCode: null });
  assert.notEqual(formatInspectionEvidence(inspection, child), first);
});

test("inspection evidence formats a null owner and errored unknown probe without following arbitrary objects", () => {
  const { inspection, child } = example();
  inspection.owner = null;
  inspection.openers = [];
  inspection.lock.snapshot = null;
  inspection.lock.observationError = "observation_failed";
  inspection.lock.probe = { status: "unknown", method: "flock_exclusive_nonblocking", error: "native_coordination_busy",
    guard: { status: "busy", attempts: 3 } };
  const evidence = JSON.parse(formatInspectionEvidence(inspection, child));
  assert.equal(evidence.ownerPid, null);
  assert.deepEqual(evidence.openers, []);
  assert.equal(evidence.lock.snapshot, null);
  assert.equal(evidence.lock.observationError, "observation_failed");
  assert.deepEqual(evidence.lock.probe, { status: "unknown", method: "flock_exclusive_nonblocking", error: "native_coordination_busy",
    guard: { status: "busy", attempts: 3 } });
});
