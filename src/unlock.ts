import { acquireUnlockLease } from "./coordination.js";
import { inspectThread } from "./inspection.js";
import { performance } from "node:perf_hooks";

import { observeLockFile } from "./lock.js";
import { guardedProbeOnce, probeWithRetry } from "./native-coordination.js";
import { defaultOptions, validateThreadId } from "./options.js";
import {
  inspectLockOpeners,
  originalProcessExited,
  processExitObservation,
  processStartTime,
} from "./process.js";
import { sameLastRecord, stableFileHash } from "./transcript.js";
import type {
  DoctorOptions,
  InspectionResult,
  LockHolder,
  LockProbe,
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

interface PostSignalState {
  processExited: boolean | null;
  processObservation: ProcessStartObservation;
  lockReleased: boolean;
  lastLockProbe: LockProbe | null;
  lockReacquiredBy: LockHolder[] | null;
  lockHolderNote: string | null;
  transcriptUnchanged: boolean | null;
  reasons: string[];
}

type Reacquisition =
  | { status: "other_owner"; holders: LockHolder[] }
  | { status: "owner_descendant"; holders: LockHolder[] }
  | { status: "inconclusive"; error?: string };

/**
 * After the original owner is confirmed exited, a held lock can only belong
 * to a different process. Identify it by PID and start time so the report does
 * not invite a retry that would signal the successor.
 */
async function identifyReacquisition(
  lockPath: string,
  owner: ProcessInfo & { startTime: string },
  ownerDescendants: readonly number[],
): Promise<Reacquisition> {
  const openers = await inspectLockOpeners(lockPath);
  if (openers.error) return { status: "inconclusive", error: openers.error };
  if (openers.processes.length === 0) {
    return { status: "inconclusive", error: "no current lock opener was observed" };
  }
  const different = openers.processes.every(
    (opener) =>
      opener.pid !== owner.pid ||
      (opener.startTime !== null && opener.startTime !== owner.startTime),
  );
  if (!different) {
    return { status: "inconclusive", error: "current opener matches the original owner" };
  }
  const holders = openers.processes.map((opener) => ({
    pid: opener.pid,
    startTime: opener.startTime,
  }));
  // flock belongs to the open file description, so a descendant that
  // inherited the descriptor keeps the original owner's lock alive.
  if (holders.some((holder) => ownerDescendants.includes(holder.pid))) {
    return { status: "owner_descendant", holders };
  }
  return { status: "other_owner", holders };
}

async function observeTermination(
  evidence: RevalidatedUnlockEvidence,
  options: DoctorOptions,
  state: PostSignalState,
): Promise<void> {
  const { inspection, owner, transcriptPath, transcriptHash } = evidence;
  const deadline = Date.now() + options.terminationTimeoutMs;
  const probeDeadline = performance.now() + options.terminationTimeoutMs;
  while (Date.now() <= deadline && performance.now() <= probeDeadline) {
    state.lockHolderNote = null;
    const [exitObservation, lockProbe] = await Promise.all([
      processExitObservation(owner.pid),
      probeWithRetry(inspection.lock.path, probeDeadline),
    ]);
    state.processObservation = exitObservation;
    state.lastLockProbe = lockProbe;
    state.processExited = originalProcessExited(owner.startTime, exitObservation);
    state.lockReleased = lockProbe.status === "free";
    if (state.processExited === true && state.lockReleased) {
      break;
    }
    if (state.processExited === true && lockProbe.status === "held") {
      const reacquisition = await identifyReacquisition(
        inspection.lock.path,
        owner,
        inspection.descendantPids ?? [],
      );
      if (reacquisition.status === "other_owner") {
        state.lockReacquiredBy = reacquisition.holders;
        break;
      }
      state.lockHolderNote =
        reacquisition.status === "owner_descendant"
          ? `lock_held_by_owner_descendant:${reacquisition.holders.map((holder) => holder.pid).join(",")}`
          : `lock_holder_unidentified:${reacquisition.error ?? "unknown"}`;
    }
    await delay(Math.min(100, Math.max(0, probeDeadline - performance.now())));
  }

  try {
    state.transcriptUnchanged =
      (await stableFileHash(transcriptPath)).hash === transcriptHash;
    if (!state.transcriptUnchanged) state.reasons.push("transcript_changed_during_unlock");
  } catch (error) {
    state.reasons.push(`post_unlock_transcript_hash_failed:${errorText(error)}`);
  }
  if (state.processExited === null) {
    state.reasons.push(
      `owner_exit_unknown:${state.processObservation.error ?? "process observation failed"}`,
    );
  } else if (!state.processExited) {
    state.reasons.push("owner_did_not_exit_before_timeout");
  }
  if (state.lockReacquiredBy) {
    state.reasons.push(
      `lock_reacquired_by_other_owner:${state.lockReacquiredBy.map((holder) => holder.pid).join(",")}`,
    );
  } else if (!state.lockReleased) {
    state.reasons.push(
      state.lastLockProbe?.status === "unknown"
        ? `lock_release_unknown:${state.lastLockProbe.error ?? "lock probe failed"}`
        : "lock_was_not_released",
    );
    if (state.lockHolderNote && state.lastLockProbe?.status === "held") {
      state.reasons.push(state.lockHolderNote);
    }
  }
}

async function terminateRevalidatedOwner(
  evidence: RevalidatedUnlockEvidence,
  options: DoctorOptions,
): Promise<UnlockResult> {
  const { inspection, owner } = evidence;
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

  // Past the signal boundary every failure must still report the signal.
  const state: PostSignalState = {
    processExited: null,
    processObservation: {
      status: "unknown",
      startTime: null,
      error: "owner was not observed after SIGTERM",
    },
    lockReleased: false,
    lastLockProbe: null,
    lockReacquiredBy: null,
    lockHolderNote: null,
    transcriptUnchanged: null,
    reasons: [],
  };
  try {
    await observeTermination(evidence, options, state);
  } catch (error) {
    state.reasons.push(`post_signal_verification_failed:${errorText(error)}`);
  }

  const verified =
    state.processExited === true &&
    state.lockReleased &&
    state.transcriptUnchanged === true &&
    state.reasons.length === 0;
  const terminated =
    state.processExited === true && (state.lockReleased || state.lockReacquiredBy !== null);
  return unlockResult(inspection, {
    outcome: verified ? "unlocked" : terminated ? "verification_failed" : "termination_failed",
    changed: true,
    pid: owner.pid,
    signalSent: "SIGTERM",
    processExited: state.processExited,
    processObservation: state.processObservation,
    lockReleased: state.lockReleased,
    transcriptUnchanged: state.transcriptUnchanged,
    ...(state.lockReacquiredBy ? { lockReacquiredBy: state.lockReacquiredBy } : {}),
    reasons: unique(state.reasons),
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
  if (revalidationReasons.length === 0) {
    // The full transcript hash above can take a while; re-sample the cheap
    // identity and lock evidence immediately before the signal boundary.
    const [preSignalStart, preSignalLock] = await Promise.all([
      processStartTime(owner.pid),
      Promise.resolve(observeLockFile(inspection.lock.path)),
    ]);
    if (preSignalStart.status !== "present" || preSignalStart.startTime !== owner.startTime) {
      revalidationReasons.push("owner_changed_before_signal");
    }
    // No await from this try-once probe through process.kill. Its native guard
    // is released before returning; a busy coordinator refuses immediately.
    const preSignalProbe = guardedProbeOnce(inspection.lock.path, preSignalLock);
    if (preSignalProbe.guard?.status === "busy") {
      revalidationReasons.push("native_coordination_busy_before_signal");
    }
    if (
      !sameSnapshot(finalInspection.lock.snapshot, preSignalLock.snapshot) ||
      (preSignalProbe.status !== "held" && preSignalProbe.guard?.status !== "busy")
    ) {
      revalidationReasons.push("lock_changed_before_signal");
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
