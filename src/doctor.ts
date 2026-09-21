import { readdir } from "node:fs/promises";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

import { observeLockFile, probeLock } from "./lock.js";
import {
  currentProcessFamily,
  descendantPids,
  inspectLockOpeners,
  lockFilesOpenedByProcess,
  originalProcessExited,
  processStartTime,
} from "./process.js";
import {
  findTranscriptCandidates,
  inspectTranscriptCandidates,
  sameLastRecord,
  stableFileHash,
} from "./transcript.js";
import type {
  Classification,
  DoctorOptions,
  InspectionResult,
  ListResult,
  ProcessInfo,
  ProcessStartObservation,
  UnlockResult,
} from "./types.js";
import { SCHEMA_VERSION } from "./types.js";
import { delay, errorText, sameSnapshot, unique } from "./util.js";

const THREAD_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function defaultOptions(): DoctorOptions {
  return {
    codexHome: resolve(process.env.CODEX_HOME ?? join(homedir(), ".codex")),
    stabilityMs: 1_000,
    terminationTimeoutMs: 5_000,
  };
}

export function validateThreadId(threadId: string): string {
  if (!THREAD_ID_PATTERN.test(threadId)) {
    throw new Error(`invalid Codex thread id: ${threadId}`);
  }
  return threadId.toLowerCase();
}

function sameProcessIdentity(
  before: ProcessInfo[],
  after: ProcessInfo[],
): boolean | null {
  if (before.length !== 1 || after.length !== 1) {
    return before.length === 0 && after.length === 0 ? null : false;
  }
  return (
    before[0].pid === after[0].pid &&
    before[0].startTime !== null &&
    before[0].startTime === after[0].startTime
  );
}

function classify(
  lockObservation: "present" | "absent" | "unknown",
  lockStable: boolean | null,
  probeStatus: "held" | "free" | "unknown",
  openers: ProcessInfo[],
  openerError: string | undefined,
  ownerIdentityStable: boolean | null,
): Classification {
  if (lockObservation === "unknown") return "unknown";
  if (lockObservation === "absent") {
    return lockStable === false ? "unknown" : "absent";
  }
  if (lockStable === false || probeStatus === "unknown") {
    return "unknown";
  }
  if (probeStatus === "free") {
    return "stale_residue";
  }
  if (
    !openerError &&
    openers.length === 1 &&
    openers[0].identityComplete &&
    ownerIdentityStable === true
  ) {
    return "live_owner";
  }
  return "unknown";
}

function addOnce(values: string[], value: string): void {
  if (!values.includes(value)) {
    values.push(value);
  }
}

function evaluateSafety(
  result: Omit<InspectionResult, "safeToUnlock" | "blockers" | "warnings">,
  currentFamily: Set<number> | null,
  openerError?: string,
  ownerLockError?: string,
): { blockers: string[]; warnings: string[] } {
  const blockers: string[] = [];
  const warnings: string[] = [];
  const { lock, owner, transcript } = result;

  if (result.classification !== "live_owner") {
    addOnce(blockers, `classification_${result.classification}`);
  }
  if (!lock.exists) addOnce(blockers, "lock_file_absent");
  if (lock.observation === "unknown") addOnce(blockers, "lock_file_observation_failed");
  if (lock.regularFile !== true) addOnce(blockers, "lock_file_not_regular");
  if (lock.symlink !== false) addOnce(blockers, "lock_file_symlink_or_unknown");
  if (lock.ownedByCurrentUser !== true) addOnce(blockers, "lock_file_wrong_owner");
  if (lock.snapshot && lock.snapshot.links !== 1) addOnce(blockers, "lock_file_has_multiple_links");
  if (lock.stable !== true) addOnce(blockers, "lock_file_not_stable");
  if (lock.probe.status !== "held") addOnce(blockers, `lock_probe_${lock.probe.status}`);
  if (openerError) addOnce(blockers, "lock_opener_lookup_failed");
  if (result.openers.length !== 1) addOnce(blockers, "lock_owner_not_unique");
  if (result.ownerIdentityStable !== true) addOnce(blockers, "lock_owner_identity_not_stable");

  if (!owner) {
    addOnce(blockers, "lock_owner_unavailable");
  } else {
    if (!owner.identityComplete) addOnce(blockers, "lock_owner_identity_incomplete");
    if (!owner.isCodex) addOnce(blockers, "lock_owner_is_not_codex");
    if (owner.isSharedService) addOnce(blockers, "lock_owner_is_shared_service");
    const uid = process.getuid?.();
    if (uid === undefined || owner.uid !== uid) addOnce(blockers, "lock_owner_wrong_user");
    if (currentFamily === null) {
      addOnce(blockers, "current_process_family_unavailable");
    } else if (currentFamily.has(owner.pid)) {
      addOnce(blockers, "lock_owner_is_current_process_family");
    }
    if (owner.tty === null) addOnce(warnings, "lock_owner_has_no_tty");
  }

  if (ownerLockError) addOnce(blockers, "owner_lock_file_lookup_failed");
  if (result.ownerLockFiles === null) {
    addOnce(blockers, "owner_lock_files_unavailable");
  } else if (result.ownerLockFiles.length !== 1 || result.ownerLockFiles[0] !== lock.path) {
    addOnce(blockers, "owner_holds_other_thread_locks");
  }

  if (result.descendantPids === null) {
    addOnce(warnings, "owner_descendants_unavailable");
  } else if (result.descendantPids.length > 0) {
    addOnce(warnings, `owner_has_descendants:${result.descendantPids.join(",")}`);
  }

  if (transcript.status !== "found") addOnce(blockers, `transcript_${transcript.status}`);
  if (transcript.stable !== true) addOnce(blockers, "transcript_not_stable");
  if (
    transcript.lastRecord?.recordType !== "event_msg" ||
    transcript.lastRecord.eventType !== "task_complete"
  ) {
    addOnce(blockers, "transcript_last_event_not_task_complete");
  }
  return { blockers, warnings };
}

export async function inspectThread(
  rawThreadId: string,
  options: DoctorOptions = defaultOptions(),
): Promise<InspectionResult> {
  const threadId = validateThreadId(rawThreadId);
  const lockDirectory = join(options.codexHome, "thread-writer-locks");
  const lockPath = join(lockDirectory, `${threadId}.lock`);

  const candidatesBefore = await findTranscriptCandidates(options.codexHome, threadId);
  const [lockBefore, probeBefore, openersBefore, transcriptBefore] = await Promise.all([
    Promise.resolve(observeLockFile(lockPath)),
    Promise.resolve(probeLock(lockPath)),
    inspectLockOpeners(lockPath),
    inspectTranscriptCandidates(candidatesBefore),
  ]);

  await delay(options.stabilityMs);

  const candidatesAfter = await findTranscriptCandidates(options.codexHome, threadId);
  const [lockAfter, probeAfter, openersAfter, transcriptAfter] = await Promise.all([
    Promise.resolve(observeLockFile(lockPath)),
    Promise.resolve(probeLock(lockPath)),
    inspectLockOpeners(lockPath),
    inspectTranscriptCandidates(candidatesAfter),
  ]);

  const lockStable =
    lockBefore.status === "unknown" || lockAfter.status === "unknown"
      ? false
      : !lockBefore.exists && !lockAfter.exists
      ? true
      : sameSnapshot(lockBefore.snapshot, lockAfter.snapshot);
  const candidatesStable =
    JSON.stringify(candidatesBefore) === JSON.stringify(candidatesAfter);
  const transcriptStable =
    candidatesStable &&
    transcriptBefore.status === "found" &&
    transcriptAfter.status === "found" &&
    transcriptBefore.path === transcriptAfter.path &&
    transcriptBefore.stable === true &&
    transcriptAfter.stable === true &&
    sameSnapshot(transcriptBefore.snapshot, transcriptAfter.snapshot) &&
    sameLastRecord(transcriptBefore.lastRecord, transcriptAfter.lastRecord);
  transcriptAfter.stable = transcriptStable;
  const ownerIdentityStable = sameProcessIdentity(
    openersBefore.processes,
    openersAfter.processes,
  );
  const openerError = openersBefore.error ?? openersAfter.error;
  const probeStable = probeBefore.status === probeAfter.status;
  const classification = classify(
    lockAfter.status,
    lockStable && probeStable,
    probeAfter.status,
    openersAfter.processes,
    openerError,
    ownerIdentityStable,
  );
  const owner = openersAfter.processes.length === 1 ? openersAfter.processes[0] : null;

  let ownerLockFiles: string[] | null = null;
  let ownerLockError: string | undefined;
  let descendants: number[] | null = null;
  if (owner) {
    const lockFiles = await lockFilesOpenedByProcess(owner.pid, lockPath);
    ownerLockFiles = lockFiles.paths;
    ownerLockError = lockFiles.error;
    descendants = await descendantPids(owner.pid);
  }
  const currentFamily = await currentProcessFamily();

  const base: Omit<InspectionResult, "safeToUnlock" | "blockers" | "warnings"> = {
    schemaVersion: SCHEMA_VERSION,
    command: "inspect" as const,
    inspectedAt: new Date().toISOString(),
    codexHome: options.codexHome,
    threadId,
    classification,
    lock: {
      path: lockPath,
      observation: lockAfter.status,
      exists: lockAfter.exists,
      regularFile: lockAfter.regularFile,
      symlink: lockAfter.symlink,
      ownedByCurrentUser: lockAfter.ownedByCurrentUser,
      snapshot: lockAfter.snapshot,
      stable: lockStable && probeStable,
      probe: probeAfter,
      ...(lockAfter.error ? { observationError: lockAfter.error } : {}),
    },
    owner,
    openers: openersAfter.processes,
    ownerIdentityStable,
    ownerLockFiles,
    descendantPids: descendants,
    transcript: transcriptAfter,
  };
  const safety = evaluateSafety(base, currentFamily, openerError, ownerLockError);
  return {
    ...base,
    safeToUnlock: safety.blockers.length === 0,
    blockers: safety.blockers,
    warnings: safety.warnings,
  };
}

export async function listThreads(
  options: DoctorOptions = defaultOptions(),
): Promise<ListResult> {
  const lockDirectory = join(options.codexHome, "thread-writer-locks");
  let names: string[];
  try {
    names = await readdir(lockDirectory);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      names = [];
    } else {
      throw error;
    }
  }
  const threadIds = unique(
    names
      .filter((name) => name.endsWith(".lock"))
      .map((name) => name.slice(0, -".lock".length))
      .filter((id) => THREAD_ID_PATTERN.test(id))
      .map((id) => id.toLowerCase()),
  ).sort();
  const sessions = await Promise.all(threadIds.map((id) => inspectThread(id, options)));
  return {
    schemaVersion: SCHEMA_VERSION,
    command: "list",
    inspectedAt: new Date().toISOString(),
    codexHome: options.codexHome,
    count: sessions.length,
    sessions,
  };
}

function unlockResult(
  inspection: InspectionResult,
  overrides: Omit<UnlockResult, "schemaVersion" | "command" | "attemptedAt" | "threadId" | "inspection" | "lockFileRemovedByTool">,
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

export async function unlockThread(
  rawThreadId: string,
  options: DoctorOptions = defaultOptions(),
): Promise<UnlockResult> {
  const inspection = await inspectThread(rawThreadId, options);
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
    processExited = originalProcessExited(owner.startTime!, startObservation);
    lockReleased = lockProbe.status === "free";
    if (processExited === true && lockReleased) {
      break;
    }
    await delay(100);
  }

  let transcriptUnchanged: boolean | null = null;
  const reasons: string[] = [];
  try {
    transcriptUnchanged = (await stableFileHash(transcriptPath)).hash === beforeHash;
    if (!transcriptUnchanged) reasons.push("transcript_changed_during_unlock");
  } catch (error) {
    reasons.push(`post_unlock_transcript_hash_failed:${errorText(error)}`);
  }
  if (processExited === null) {
    reasons.push(`owner_exit_unknown:${processObservation.error ?? "process observation failed"}`);
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
