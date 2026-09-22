import type { InspectionResult } from "./types.js";

export type InspectionEvidence = Omit<
  InspectionResult,
  "safeToUnlock" | "blockers" | "warnings"
>;

export interface SafetyContext {
  currentProcessFamily: Set<number> | null;
  openerError?: string;
  ownerLockError?: string;
  currentUid?: number;
}

export interface SafetyDecision {
  safeToUnlock: boolean;
  blockers: string[];
  warnings: string[];
}

function addOnce(values: string[], value: string): void {
  if (!values.includes(value)) {
    values.push(value);
  }
}

/**
 * Decide whether supplied inspection evidence authorizes an unlock.
 *
 * This function is intentionally pure: callers collect OS evidence, then
 * inject the current process family and uid. Unlock execution must still
 * perform a complete reinspection immediately before signaling.
 */
export function evaluateSafety(
  result: InspectionEvidence,
  context: SafetyContext,
): SafetyDecision {
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
  if (lock.snapshot && lock.snapshot.links !== 1) {
    addOnce(blockers, "lock_file_has_multiple_links");
  }
  if (lock.stable !== true) addOnce(blockers, "lock_file_not_stable");
  if (lock.probe.status !== "held") addOnce(blockers, `lock_probe_${lock.probe.status}`);
  if (context.openerError) addOnce(blockers, "lock_opener_lookup_failed");
  if (result.openers.length !== 1) addOnce(blockers, "lock_owner_not_unique");
  if (result.ownerIdentityStable !== true) {
    addOnce(blockers, "lock_owner_identity_not_stable");
  }

  if (!owner) {
    addOnce(blockers, "lock_owner_unavailable");
  } else {
    if (!owner.identityComplete) addOnce(blockers, "lock_owner_identity_incomplete");
    if (!owner.isCodex) addOnce(blockers, "lock_owner_is_not_codex");
    if (owner.isSharedService) addOnce(blockers, "lock_owner_is_shared_service");
    if (context.currentUid === undefined || owner.uid !== context.currentUid) {
      addOnce(blockers, "lock_owner_wrong_user");
    }
    if (context.currentProcessFamily === null) {
      addOnce(blockers, "current_process_family_unavailable");
    } else if (context.currentProcessFamily.has(owner.pid)) {
      addOnce(blockers, "lock_owner_is_current_process_family");
    }
    if (owner.tty === null) addOnce(warnings, "lock_owner_has_no_tty");
  }

  if (context.ownerLockError) addOnce(blockers, "owner_lock_file_lookup_failed");
  if (result.ownerLockFiles === null) {
    addOnce(blockers, "owner_lock_files_unavailable");
  } else if (
    result.ownerLockFiles.length !== 1 ||
    result.ownerLockFiles[0] !== lock.path
  ) {
    addOnce(blockers, "owner_holds_other_thread_locks");
  }

  if (result.descendantPids === null) {
    addOnce(warnings, "owner_descendants_unavailable");
  } else if (result.descendantPids.length > 0) {
    addOnce(warnings, `owner_has_descendants:${result.descendantPids.join(",")}`);
  }

  if (transcript.status !== "found") {
    addOnce(blockers, `transcript_${transcript.status}`);
  }
  if (transcript.stable !== true) addOnce(blockers, "transcript_not_stable");
  if (
    transcript.lastRecord?.recordType !== "event_msg" ||
    transcript.lastRecord.eventType !== "task_complete"
  ) {
    addOnce(blockers, "transcript_last_event_not_task_complete");
  }

  return {
    safeToUnlock: blockers.length === 0,
    blockers,
    warnings,
  };
}
