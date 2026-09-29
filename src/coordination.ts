import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  realpathSync,
  type BigIntStats,
} from "node:fs";
import { dirname, join } from "node:path";

import { flockSync } from "fs-ext-extra-prebuilt";

/**
 * Name of the codex-unlock-owned directory created next to the canonical
 * native lock directory. It is never inside `thread-writer-locks`.
 */
export const LEASE_DIRECTORY_NAME = "codex-unlock";

// Bump when the key derivation changes so that old and new files never alias.
const LEASE_KEY_VERSION = "codex-unlock-lease-v2";

export interface UnlockLease {
  release(): void;
}

export type UnlockLeaseAttempt =
  | { status: "acquired"; lease: UnlockLease }
  | { status: "contended" }
  | { status: "unknown"; reason: string };

interface LeaseLocation {
  directory: string;
  path: string;
}

class CoordinationError extends Error {}

function privateDirectory(value: BigIntStats, uid: number): boolean {
  return (
    value.isDirectory() &&
    !value.isSymbolicLink() &&
    value.uid === BigInt(uid) &&
    (value.mode & 0o077n) === 0n
  );
}

function sameInode(left: BigIntStats, right: BigIntStats): boolean {
  return left.dev === right.dev && left.ino === right.ino;
}

/**
 * Derive the lease from the native lock directory rather than from the
 * caller's spelling of the Codex home or from per-shell environment.
 *
 * Symlinked, case-variant, and otherwise aliased homes resolve to the same
 * physical lock directory, so the lease file lives beside that directory and
 * its name is keyed by the directory's device/inode and the thread UUID.
 */
function leaseLocation(codexHome: string, threadId: string, uid: number): LeaseLocation {
  let lockDirectory: string;
  let identity: BigIntStats;
  try {
    lockDirectory = realpathSync.native(join(codexHome, "thread-writer-locks"));
    identity = lstatSync(lockDirectory, { bigint: true });
  } catch {
    throw new CoordinationError("lock_directory_unavailable");
  }
  if (!identity.isDirectory()) {
    throw new CoordinationError("lock_directory_unavailable");
  }

  const parent = dirname(lockDirectory);
  let parentValue: BigIntStats;
  try {
    parentValue = lstatSync(parent, { bigint: true });
  } catch {
    throw new CoordinationError("coordination_parent_unavailable");
  }
  if (!parentValue.isDirectory() || parentValue.uid !== BigInt(uid)) {
    throw new CoordinationError("coordination_parent_is_not_owned");
  }

  const key = createHash("sha256")
    .update(LEASE_KEY_VERSION)
    .update("\0")
    .update(identity.dev.toString())
    .update("\0")
    .update(identity.ino.toString())
    .update("\0")
    .update(threadId)
    .digest("hex");
  const directory = join(parent, LEASE_DIRECTORY_NAME);
  return { directory, path: join(directory, `${key}.lock`) };
}

function prepareDirectory(directory: string, uid: number): BigIntStats {
  try {
    mkdirSync(directory, { mode: 0o700 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
      throw new CoordinationError("coordination_directory_unavailable");
    }
  }
  let value: BigIntStats;
  try {
    value = lstatSync(directory, { bigint: true });
  } catch {
    throw new CoordinationError("coordination_directory_unavailable");
  }
  if (!privateDirectory(value, uid)) {
    throw new CoordinationError("coordination_directory_is_not_private");
  }
  try {
    chmodSync(directory, 0o700);
  } catch {
    throw new CoordinationError("coordination_directory_unavailable");
  }
  return value;
}

function contentionError(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException).code;
  return code === "EAGAIN" || code === "EACCES" || code === "EWOULDBLOCK";
}

function closeQuietly(descriptor: number): void {
  try {
    closeSync(descriptor);
  } catch {
    // The descriptor may already have been closed by a failed validation.
  }
}

export function acquireUnlockLease(
  codexHome: string,
  threadId: string,
): UnlockLeaseAttempt {
  const uid = process.getuid?.();
  if (uid === undefined) {
    return { status: "unknown", reason: "current_user_is_unavailable" };
  }

  let location: LeaseLocation;
  let directoryValue: BigIntStats;
  try {
    location = leaseLocation(codexHome, threadId, uid);
    directoryValue = prepareDirectory(location.directory, uid);
  } catch (error) {
    return {
      status: "unknown",
      reason:
        error instanceof CoordinationError
          ? error.message
          : "coordination_directory_unavailable",
    };
  }

  let descriptor: number | undefined;
  try {
    descriptor = openSync(
      location.path,
      constants.O_CREAT | constants.O_RDWR | (constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    const value = fstatSync(descriptor, { bigint: true });
    if (
      !value.isFile() ||
      value.uid !== BigInt(uid) ||
      value.nlink !== 1n ||
      (value.mode & 0o077n) !== 0n
    ) {
      closeQuietly(descriptor);
      return { status: "unknown", reason: "coordination_file_is_not_private" };
    }
    try {
      flockSync(descriptor, "exnb");
    } catch (error) {
      closeQuietly(descriptor);
      return contentionError(error)
        ? { status: "contended" }
        : { status: "unknown", reason: "coordination_lock_failed" };
    }

    // A lease only serializes competitors that open the same inode, so the
    // path must still name the locked file inside the validated directory.
    const directoryAfter = lstatSync(location.directory, { bigint: true });
    const pathAfter = lstatSync(location.path, { bigint: true });
    if (
      !sameInode(directoryValue, directoryAfter) ||
      !privateDirectory(directoryAfter, uid) ||
      !sameInode(value, pathAfter)
    ) {
      closeQuietly(descriptor);
      return { status: "unknown", reason: "coordination_path_changed" };
    }

    let released = false;
    const heldDescriptor = descriptor;
    return {
      status: "acquired",
      lease: {
        release(): void {
          if (released) return;
          released = true;
          try {
            flockSync(heldDescriptor, "un");
          } catch {
            // Closing the descriptor below still releases the advisory lock.
          } finally {
            try {
              closeSync(heldDescriptor);
            } catch {
              // Process exit is the final fallback for descriptor cleanup.
            }
          }
        },
      },
    };
  } catch {
    if (descriptor !== undefined) closeQuietly(descriptor);
    return { status: "unknown", reason: "coordination_file_unavailable" };
  }
}
