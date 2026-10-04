import { readdir } from "node:fs/promises";
import { join } from "node:path";

import { observeLockDirectory, observeLockFile } from "./lock.js";
import { probeWithRetry } from "./native-coordination.js";
import { isThreadId, defaultOptions, validateThreadId } from "./options.js";
import { evaluateSafety } from "./policy.js";
import {
  currentProcessFamily,
  descendantPids,
  inspectLockOpeners,
  lockFilesOpenedByProcess,
} from "./process.js";
import {
  findTranscriptCandidates,
  inspectTranscriptCandidates,
  sameLastRecord,
} from "./transcript.js";
import type {
  Classification,
  DoctorOptions,
  InspectionResult,
  ListResult,
  ProcessInfo,
} from "./types.js";
import { SCHEMA_VERSION } from "./types.js";
import { delay, sameSnapshot, unique } from "./util.js";

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

// A missing Codex home is a configuration failure, never a confirmed-absent
// lock. An unusable lock directory stays per-thread `unknown` evidence for
// inspect/unlock, but list cannot enumerate it and fails instead.
function assertCodexHome(lockDirectory: string): void {
  const observation = observeLockDirectory(lockDirectory);
  if (observation.status === "unknown" && observation.scope === "codex_home") {
    throw new Error(observation.error);
  }
}

export async function inspectThread(
  rawThreadId: string,
  options: DoctorOptions = defaultOptions(),
): Promise<InspectionResult> {
  const threadId = validateThreadId(rawThreadId);
  const lockDirectory = join(options.codexHome, "thread-writer-locks");
  const lockPath = join(lockDirectory, `${threadId}.lock`);
  assertCodexHome(lockDirectory);

  const candidatesBefore = await findTranscriptCandidates(options.codexHome, threadId);
  const [lockBefore, probeBefore, openersBefore, transcriptBefore] = await Promise.all([
    Promise.resolve(observeLockFile(lockPath)),
    probeWithRetry(lockPath),
    inspectLockOpeners(lockPath),
    inspectTranscriptCandidates(candidatesBefore),
  ]);

  await delay(options.stabilityMs);

  const candidatesAfter = await findTranscriptCandidates(options.codexHome, threadId);
  const [lockAfter, probeAfter, openersAfter, transcriptAfter] = await Promise.all([
    Promise.resolve(observeLockFile(lockPath)),
    probeWithRetry(lockPath),
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
    command: "inspect",
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
  const safety = evaluateSafety(base, {
    currentProcessFamily: currentFamily,
    currentUid: process.getuid?.(),
    ...(openerError ? { openerError } : {}),
    ...(ownerLockError ? { ownerLockError } : {}),
  });
  return { ...base, ...safety };
}

// Each inspection independently traverses both transcript trees twice and
// starts diagnostic subprocesses. Four workers bound aggregate descriptor
// pressure without sharing evidence across threads or observation windows.
const LIST_INSPECTION_CONCURRENCY = 4;

export async function listThreads(
  options: DoctorOptions = defaultOptions(),
): Promise<ListResult> {
  const lockDirectory = join(options.codexHome, "thread-writer-locks");
  const observation = observeLockDirectory(lockDirectory);
  if (observation.status === "unknown") throw new Error(observation.error);
  const names = observation.status === "not_created" ? [] : await readdir(lockDirectory);
  const threadIds = unique(
    names
      .filter((name) => name.endsWith(".lock"))
      .map((name) => name.slice(0, -".lock".length))
      .filter((id) => isThreadId(id))
      .map((id) => id.toLowerCase()),
  ).sort();
  const sessions = new Array<InspectionResult>(threadIds.length);
  let nextIndex = 0;
  let failed = false;
  let firstError: unknown;
  async function worker(): Promise<void> {
    while (!failed && nextIndex < threadIds.length) {
      const index = nextIndex++;
      try {
        sessions[index] = await inspectThread(threadIds[index], options);
      } catch (error) {
        if (!failed) firstError = error;
        failed = true;
      }
    }
  }
  await Promise.all(
    Array.from(
      { length: Math.min(LIST_INSPECTION_CONCURRENCY, threadIds.length) },
      () => worker(),
    ),
  );
  // Drain the already-started observations before returning the original
  // failure. No new inspections are dispatched once a worker has failed.
  if (failed) throw firstError;
  return {
    schemaVersion: SCHEMA_VERSION,
    command: "list",
    inspectedAt: new Date().toISOString(),
    codexHome: options.codexHome,
    count: sessions.length,
    sessions,
  };
}
