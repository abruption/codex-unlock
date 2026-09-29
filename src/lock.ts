import { closeSync, constants, fstatSync, lstatSync, openSync, statSync } from "node:fs";
import { dirname } from "node:path";

import { flockSync } from "fs-ext-extra-prebuilt";

import type { LockProbe, PublicFileSnapshot } from "./types.js";
import { errorText, publicSnapshot } from "./util.js";

export interface LockFileObservation {
  status: "present" | "absent" | "unknown";
  exists: boolean;
  regularFile: boolean | null;
  symlink: boolean | null;
  ownedByCurrentUser: boolean | null;
  snapshot: PublicFileSnapshot | null;
  error?: string;
}

export type LockDirectoryObservation =
  | { status: "present" | "not_created" }
  | { status: "unknown"; scope: "codex_home" | "lock_directory"; error: string };

function directoryState(path: string): "directory" | "missing" | "other" {
  try {
    return statSync(path).isDirectory() ? "directory" : "other";
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return "missing";
    throw error;
  }
}

/**
 * Establish whether a missing lock can be confirmed absent.
 *
 * The Codex home must be an existing directory. `thread-writer-locks` may be
 * missing (Codex has not created a lock yet), but a dangling symlink or a
 * non-directory at that path is not evidence of absence.
 */
export function observeLockDirectory(lockDirectory: string): LockDirectoryObservation {
  const codexHome = dirname(lockDirectory);
  try {
    const home = directoryState(codexHome);
    if (home === "missing") {
      return {
        status: "unknown",
        scope: "codex_home",
        error: `Codex home does not exist: ${codexHome}`,
      };
    }
    if (home === "other") {
      return {
        status: "unknown",
        scope: "codex_home",
        error: `Codex home is not a directory: ${codexHome}`,
      };
    }
  } catch (error) {
    return { status: "unknown", scope: "codex_home", error: errorText(error) };
  }
  try {
    const directory = directoryState(lockDirectory);
    if (directory === "directory") return { status: "present" };
    if (directory === "other") {
      return {
        status: "unknown",
        scope: "lock_directory",
        error: `lock directory is not a directory: ${lockDirectory}`,
      };
    }
    try {
      lstatSync(lockDirectory);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return { status: "not_created" };
      throw error;
    }
    return {
      status: "unknown",
      scope: "lock_directory",
      error: `lock directory is a dangling symlink: ${lockDirectory}`,
    };
  } catch (error) {
    return { status: "unknown", scope: "lock_directory", error: errorText(error) };
  }
}

export function observeLockFile(path: string): LockFileObservation {
  try {
    const value = lstatSync(path);
    const uid = process.getuid?.();
    return {
      status: "present",
      exists: true,
      regularFile: value.isFile(),
      symlink: value.isSymbolicLink(),
      ownedByCurrentUser: uid === undefined ? null : value.uid === uid,
      snapshot: publicSnapshot(value),
    };
  } catch (error) {
    const directory = (error as NodeJS.ErrnoException).code === "ENOENT"
      ? observeLockDirectory(dirname(path))
      : null;
    if (directory !== null && directory.status !== "unknown") {
      return {
        status: "absent",
        exists: false,
        regularFile: null,
        symlink: null,
        ownedByCurrentUser: null,
        snapshot: null,
      };
    }
    return {
      status: "unknown",
      exists: false,
      regularFile: null,
      symlink: null,
      ownedByCurrentUser: null,
      snapshot: null,
      error: directory?.status === "unknown" ? directory.error : errorText(error),
    };
  }
}

function isContentionError(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException).code;
  return code === "EAGAIN" || code === "EACCES" || code === "EWOULDBLOCK";
}

export function probeLock(path: string): LockProbe {
  const before = observeLockFile(path);
  return probeObservedLock(path, before);
}

export function probeObservedLock(
  path: string,
  before: LockFileObservation,
): LockProbe {
  if (before.status === "unknown") {
    return {
      status: "unknown",
      method: "flock_exclusive_nonblocking",
      error: before.error ?? "lock file observation failed",
    };
  }
  if (!before.exists) {
    return { status: "free", method: "flock_exclusive_nonblocking" };
  }
  if (before.symlink || !before.regularFile || !before.snapshot) {
    return {
      status: "unknown",
      method: "flock_exclusive_nonblocking",
      error: "refusing to probe a symlink or non-regular lock file",
    };
  }

  let fd: number | undefined;
  try {
    const noFollow = constants.O_NOFOLLOW ?? 0;
    fd = openSync(path, constants.O_RDWR | noFollow);
    const opened = publicSnapshot(fstatSync(fd));
    if (
      opened.device !== before.snapshot.device ||
      opened.inode !== before.snapshot.inode
    ) {
      return {
        status: "unknown",
        method: "flock_exclusive_nonblocking",
        error: "lock file changed while it was opened",
      };
    }

    try {
      flockSync(fd, "exnb");
    } catch (error) {
      if (isContentionError(error)) {
        return { status: "held", method: "flock_exclusive_nonblocking" };
      }
      return {
        status: "unknown",
        method: "flock_exclusive_nonblocking",
        error: errorText(error),
      };
    }

    try {
      flockSync(fd, "un");
    } catch (error) {
      return {
        status: "unknown",
        method: "flock_exclusive_nonblocking",
        error: `probe acquired the lock but unlock failed: ${errorText(error)}`,
      };
    }
    return { status: "free", method: "flock_exclusive_nonblocking" };
  } catch (error) {
    return {
      status: "unknown",
      method: "flock_exclusive_nonblocking",
      error: errorText(error),
    };
  } finally {
    if (fd !== undefined) {
      closeSync(fd);
    }
  }
}
