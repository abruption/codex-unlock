import { acquireUnlockLease } from "./coordination.js";
import { inspectThread } from "./inspection.js";
import { probeLock } from "./lock.js";
import { defaultOptions, validateThreadId } from "./options.js";
import { originalProcessExited, processStartTime } from "./process.js";
import { sameLastRecord, stableFileHash } from "./transcript.js";
import type {
  DoctorOptions,
  InspectionResult,
  ProcessInfo,
  ProcessStartObservation,
  UnlockResult,
} from "./types.js";
import { SCHEMA_VERSION } from "./types.js";
import { delay, errorText, sameSnapshot, unique } from "./util.js";

function unlockResult(
  inspection: InspectionResult,
  overrides: Omit<
    UnlockResult,
    | "schemaVersion"
    | "command"
    | "attemptedAt"
    | "threadId"
    | "inspection"
    | "lockFileRemovedByTool"
  >,
): UnlockResult {
  return {
    schemaVersion: SCHEMA_VERSION,
    command: "unlock",
    attemptedAt: new Date().toISOString(),
    threadId: inspection.threadId,
    lockFileRemovedByTool: false,
    inspection,
    ...overrides,
  };
}

function sameOwnerEvidence(before: ProcessInfo, after: ProcessInfo): boolean {
  return (
    before.pid === after.pid &&
    before.ppid === after.ppid &&
    before.uid === after.uid &&
    before.startTime !== null &&
    before.startTime === after.startTime &&
    before.command === after.command &&
    before.arguments === after.arguments &&
    before.identityComplete === after.identityComplete &&
    before.isCodex === after.isCodex &&
    before.isSharedService === after.isSharedService
  );
}

function sameStringArray(before: string[] | null, after: string[] | null): boolean {
  return before !== null && after !== null && JSON.stringify(before) === JSON.stringify(after);
}

interface RevalidatedUnlockEvidence {
  inspection: InspectionResult;
  owner: ProcessInfo & { startTime: string };
  transcriptPath: string;
  transcriptHash: string;
}

async function terminateRevalidatedOwner(
  evidence: RevalidatedUnlockEvidence,
  options: DoctorOptions,
): Promise<UnlockResult> {
  const { inspection, owner, transcriptPath, transcriptHash } = evidence;
  try {
    process.kill(owner.pid, "SIGTERM");
  } catch (error) {
    return unlockResult(inspection, {
      outcome: "termination_failed",
      changed: false,
      pid: owner.pid,
      signalSent: null,
      processExited: false,
      processObservation: null,
      lockReleased: false,
      transcriptUnchanged: null,
      reasons: [`sigterm_failed:${errorText(error)}`],
    });
  }

  const deadline = Date.now() + options.terminationTimeoutMs;
  let processExited: boolean | null = false;
  let processObservation: ProcessStartObservation = {
    status: "present",
    startTime: owner.startTime,
  };
  let lockReleased = false;
  let lastLockProbe = probeLock(inspection.lock.path);
  while (Date.now() <= deadline) {
    const [startObservation, lockProbe] = await Promise.all([
      processStartTime(owner.pid),
      Promise.resolve(probeLock(inspection.lock.path)),
    ]);
    processObservation = startObservation;
    lastLockProbe = lockProbe;
    processExited = originalProcessExited(owner.startTime, startObservation);
    lockReleased = lockProbe.status === "free";
    if (processExited === true && lockReleased) {
      break;
    }
    await delay(100);
  }

  let transcriptUnchanged: boolean | null = null;
  const reasons: string[] = [];
  try {
    transcriptUnchanged = (await stableFileHash(transcriptPath)).hash === transcriptHash;
    if (!transcriptUnchanged) reasons.push("transcript_changed_during_unlock");
  } catch (error) {
    reasons.push(`post_unlock_transcript_hash_failed:${errorText(error)}`);
  }
  if (processExited === null) {
    reasons.push(
      `owner_exit_unknown:${processObservation.error ?? "process observation failed"}`,
    );
  } else if (!processExited) {
    reasons.push("owner_did_not_exit_before_timeout");
  }
  if (!lockReleased) {
    reasons.push(
      lastLockProbe.status === "unknown"
        ? `lock_release_unknown:${lastLockProbe.error ?? "lock probe failed"}`
        : "lock_was_not_released",
    );
  }

  const verified = processExited === true && lockReleased && transcriptUnchanged === true;
  return unlockResult(inspection, {
    outcome: verified
      ? "unlocked"
      : processExited && lockReleased
        ? "verification_failed"
        : "termination_failed",
    changed: true,
    pid: owner.pid,
    signalSent: "SIGTERM",
    processExited,
    processObservation,
    lockReleased,
    transcriptUnchanged,
    reasons,
  });
}

export async function unlockThread(
  rawThreadId: string,
  options: DoctorOptions = defaultOptions(),
): Promise<UnlockResult> {
  const threadId = validateThreadId(rawThreadId);
  const inspection = await inspectThread(threadId, options);
  if (!inspection.safeToUnlock || !inspection.owner || !inspection.transcript.path) {
    return await unlockInspectedThread(inspection, options);
  }
  const leaseAttempt = acquireUnlockLease(options.codexHome, threadId);
  if (leaseAttempt.status !== "acquired") {
    return unlockResult(inspection, {
      outcome: "refused",
      changed: false,
      pid: inspection.owner?.pid ?? null,
      signalSent: null,
      processExited: null,
      processObservation: null,
      lockReleased: false,
      transcriptUnchanged: null,
      reasons: [
        leaseAttempt.status === "contended"
          ? "concurrent_unlock_in_progress"
          : `unlock_coordination_failed:${leaseAttempt.reason}`,
      ],
    });
  }
  try {
    return await unlockInspectedThread(inspection, options);
  } finally {
    leaseAttempt.lease.release();
  }
}

/**
 * Continue an unlock from previously collected evidence.
 *
 * This internal seam exists so the race matrix can deterministically mutate
 * state after the first inspection. It is not exported by the npm package,
 * and it never trusts the supplied inspection without a complete reinspection.
 */
export async function unlockInspectedThread(
  inspection: InspectionResult,
  options: DoctorOptions = defaultOptions(),
): Promise<UnlockResult> {
  const rawThreadId = inspection.threadId;
  if (
    inspection.classification === "absent" ||
    inspection.classification === "stale_residue"
  ) {
    return unlockResult(inspection, {
      outcome: "not_locked",
      changed: false,
      pid: null,
      signalSent: null,
      processExited: null,
      processObservation: null,
      lockReleased: true,
      transcriptUnchanged: null,
      reasons: [inspection.classification],
    });
  }
  if (!inspection.safeToUnlock || !inspection.owner || !inspection.transcript.path) {
    return unlockResult(inspection, {
      outcome: "refused",
      changed: false,
      pid: inspection.owner?.pid ?? null,
      signalSent: null,
      processExited: null,
      processObservation: null,
      lockReleased: false,
      transcriptUnchanged: null,
      reasons: inspection.blockers,
    });
  }

  const owner = inspection.owner;
  const transcriptPath = inspection.transcript.path;
  const revalidationReasons: string[] = [];
  let beforeHash: string | null = null;
  try {
    const hashed = await stableFileHash(transcriptPath);
    beforeHash = hashed.hash;
    if (!sameSnapshot(hashed.snapshot, inspection.transcript.snapshot)) {
      revalidationReasons.push("transcript_changed_after_inspection");
    }
  } catch (error) {
    revalidationReasons.push(`transcript_hash_failed:${errorText(error)}`);
  }

  const finalInspection = await inspectThread(rawThreadId, options);
  if (!finalInspection.safeToUnlock) {
    for (const blocker of finalInspection.blockers) {
      revalidationReasons.push(`revalidation_${blocker}`);
    }
  }
  if (!finalInspection.owner || !sameOwnerEvidence(owner, finalInspection.owner)) {
    revalidationReasons.push("owner_identity_changed");
  }
  if (!sameSnapshot(inspection.lock.snapshot, finalInspection.lock.snapshot)) {
    revalidationReasons.push("lock_file_changed");
  }
  if (
    finalInspection.lock.probe.status !== "held" ||
    finalInspection.lock.observation !== "present"
  ) {
    revalidationReasons.push("lock_no_longer_held");
  }
  if (!sameStringArray(inspection.ownerLockFiles, finalInspection.ownerLockFiles)) {
    revalidationReasons.push("owner_lock_set_changed");
  }
  if (
    inspection.transcript.path !== finalInspection.transcript.path ||
    !sameSnapshot(inspection.transcript.snapshot, finalInspection.transcript.snapshot) ||
    !sameLastRecord(inspection.transcript.lastRecord, finalInspection.transcript.lastRecord)
  ) {
    revalidationReasons.push("transcript_changed_after_inspection");
  }
  if (finalInspection.transcript.path && beforeHash !== null) {
    try {
      const finalHash = await stableFileHash(finalInspection.transcript.path);
      if (
        finalHash.hash !== beforeHash ||
        !sameSnapshot(finalHash.snapshot, finalInspection.transcript.snapshot)
      ) {
        revalidationReasons.push("transcript_changed_during_revalidation");
      }
    } catch (error) {
      revalidationReasons.push(`transcript_revalidation_hash_failed:${errorText(error)}`);
    }
  }
  if (revalidationReasons.length > 0) {
    return unlockResult(inspection, {
      outcome: "refused",
      changed: false,
      pid: owner.pid,
      signalSent: null,
      processExited: null,
      processObservation: null,
      lockReleased: false,
      transcriptUnchanged: null,
      reasons: unique(revalidationReasons),
    });
  }
  return await terminateRevalidatedOwner(
    {
      inspection,
      owner: { ...owner, startTime: owner.startTime! },
      transcriptPath,
      transcriptHash: beforeHash!,
    },
    options,
  );
}
