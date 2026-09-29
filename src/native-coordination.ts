import {
  closeSync, constants, fstatSync, lstatSync, openSync, realpathSync, statSync,
  type BigIntStats,
} from "node:fs";
import { dirname, join } from "node:path";
import { performance } from "node:perf_hooks";

import { flockSync } from "fs-ext-extra-prebuilt";

import { observeLockFile, probeThreadLockOnce, type LockFileObservation } from "./lock.js";
import type { LockProbe, NativeGuardEvidence } from "./types.js";
import { delay, errorText } from "./util.js";

export const NATIVE_COORDINATION_FILE = ".coordination.lock";
export const NATIVE_COORDINATION_RETRY_MS = 100;
const RETRY_INTERVAL_MS = 10;

function sameInode(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

function safeGuard(value: BigIntStats, uid: number | undefined): boolean {
  return uid !== undefined && value.isFile() && !value.isSymbolicLink() &&
    value.uid === BigInt(uid) && value.nlink === 1n;
}

function unknown(status: NativeGuardEvidence["status"], error: string): LockProbe {
  return { status: "unknown", method: "flock_exclusive_nonblocking",
    guard: { status, attempts: 1 }, error };
}

/**
 * One fully synchronous critical section, using only nonblocking flock.
 * Lock order is operation lease -> native guard -> thread probe. Never acquire
 * an operation lease here or retain this guard across await/spawn/signal/wait.
 * Optional callbacks are internal deterministic test seams, outside exports.
 */
export function guardedProbeOnce(
  lockPath: string,
  observation: LockFileObservation = observeLockFile(lockPath),
  hooksForTesting?: { afterGuardAcquired?: () => void; afterThreadAcquired?: () => void },
): LockProbe {
  if (observation.status !== "present") {
    return observation.status === "absent"
      ? { status: "free", method: "flock_exclusive_nonblocking" }
      : { status: "unknown", method: "flock_exclusive_nonblocking",
        error: observation.error ?? "lock file observation failed" };
  }
  if (observation.symlink || !observation.regularFile || !observation.snapshot) {
    return unknown("unsafe", "refusing to probe a symlink or non-regular lock file");
  }

  let fd: number | undefined;
  let acquired = false;
  let result = unknown("unsafe", "native_coordination_unavailable");
  try {
    const originalParent = dirname(lockPath);
    const parent = realpathSync.native(originalParent);
    const parentBefore = statSync(originalParent, { bigint: true });
    const canonicalParent = statSync(parent, { bigint: true });
    if (!parentBefore.isDirectory() || !sameInode(parentBefore, canonicalParent)) {
      throw new Error("native_coordination_parent_changed");
    }
    const path = join(parent, NATIVE_COORDINATION_FILE);
    let before: BigIntStats;
    try {
      before = lstatSync(path, { bigint: true });
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        return unknown("absent", "native_coordination_absent");
      }
      throw error;
    }
    const uid = process.getuid?.();
    if (!safeGuard(before, uid)) return unknown("unsafe", "native_coordination_unsafe");
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const opened = fstatSync(fd, { bigint: true });
    if (!safeGuard(opened, uid) || !sameInode(before, opened)) {
      result = unknown("changed", "native_coordination_changed");
    } else {
      try {
        flockSync(fd, "exnb");
        acquired = true;
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code !== "EAGAIN" && code !== "EWOULDBLOCK" && code !== "EACCES") throw error;
        result = unknown("busy", "native_coordination_busy");
      }
      if (acquired) {
        hooksForTesting?.afterGuardAcquired?.();
        const guardedPath = lstatSync(path, { bigint: true });
        const guardedParent = statSync(originalParent, { bigint: true });
        if (!safeGuard(guardedPath, uid) || !sameInode(opened, guardedPath) ||
          !sameInode(parentBefore, guardedParent) ||
          !sameInode(parentBefore, statSync(parent, { bigint: true }))) {
          result = unknown("changed", "native_coordination_changed");
        } else {
          result = {
            ...probeThreadLockOnce(lockPath, observation, hooksForTesting?.afterThreadAcquired),
            guard: { status: "acquired", attempts: 1 },
          };
        }
      }
      const after = lstatSync(path, { bigint: true });
      const descriptorAfter = fstatSync(fd, { bigint: true });
      const parentAfter = statSync(originalParent, { bigint: true });
      if (!safeGuard(after, uid) || !safeGuard(descriptorAfter, uid) ||
        !sameInode(opened, after) || !sameInode(opened, descriptorAfter) ||
        !sameInode(parentBefore, parentAfter) ||
        !sameInode(parentBefore, statSync(parent, { bigint: true }))) {
        result = unknown("changed", "native_coordination_changed");
      }
    }
  } catch (error) {
    result = unknown("unsafe", `native_coordination_unavailable:${errorText(error)}`);
  } finally {
    if (fd !== undefined) {
      if (acquired) {
        try {
          flockSync(fd, "un");
        } catch (error) {
          result = unknown("unsafe", `native_coordination_release_failed:${errorText(error)}`);
        }
      }
      try {
        closeSync(fd);
      } catch (error) {
        result = unknown("unsafe", `native_coordination_close_failed:${errorText(error)}`);
      }
    }
  }
  return result;
}

/** Retry only contention, outside the synchronous guard, on a monotonic clock. */
export async function probeWithRetry(lockPath: string, callerDeadline = Infinity): Promise<LockProbe> {
  const deadline = Math.min(performance.now() + NATIVE_COORDINATION_RETRY_MS, callerDeadline);
  const observation = observeLockFile(lockPath);
  let attempts = 0;
  while (true) {
    const result = guardedProbeOnce(lockPath, observation);
    attempts += 1;
    if (result.guard) result.guard.attempts = attempts;
    const remaining = deadline - performance.now();
    if (result.guard?.status !== "busy" || remaining <= 0) return result;
    await delay(Math.min(RETRY_INTERVAL_MS, remaining));
  }
}
