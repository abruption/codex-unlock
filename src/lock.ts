import { closeSync, constants, fstatSync, lstatSync, openSync } from "node:fs";

import { flockSync } from "fs-ext-extra-prebuilt";

import type { LockProbe, PublicFileSnapshot } from "./types.js";
import { errorText, publicSnapshot } from "./util.js";

export interface LockFileObservation {
  exists: boolean;
  regularFile: boolean | null;
  symlink: boolean | null;
  ownedByCurrentUser: boolean | null;
  snapshot: PublicFileSnapshot | null;
  error?: string;
}

export function observeLockFile(path: string): LockFileObservation {
  try {
    const value = lstatSync(path);
    const uid = process.getuid?.();
    return {
      exists: true,
      regularFile: value.isFile(),
      symlink: value.isSymbolicLink(),
      ownedByCurrentUser: uid === undefined ? null : value.uid === uid,
      snapshot: publicSnapshot(value),
    };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return {
        exists: false,
        regularFile: null,
        symlink: null,
        ownedByCurrentUser: null,
        snapshot: null,
      };
    }
    return {
      exists: false,
      regularFile: null,
      symlink: null,
      ownedByCurrentUser: null,
      snapshot: null,
      error: errorText(error),
    };
  }
}

function isContentionError(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException).code;
  return code === "EAGAIN" || code === "EACCES" || code === "EWOULDBLOCK";
}

export function probeLock(path: string): LockProbe {
  const before = observeLockFile(path);
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
