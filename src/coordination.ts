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
} from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join } from "node:path";

import { flockSync } from "fs-ext-extra-prebuilt";

export interface UnlockLease {
  release(): void;
}

export type UnlockLeaseAttempt =
  | { status: "acquired"; lease: UnlockLease }
  | { status: "contended" }
  | { status: "unknown"; reason: string };

function privateDirectory(path: string, uid: number): boolean {
  const value = lstatSync(path);
  return (
    value.isDirectory() &&
    !value.isSymbolicLink() &&
    value.uid === uid &&
    (value.mode & 0o077) === 0
  );
}

function runtimeRoot(uid: number, override?: string): string {
  const configured = override ?? process.env.XDG_RUNTIME_DIR;
  if (configured !== undefined) {
    if (!isAbsolute(configured) || !privateDirectory(configured, uid)) {
      throw new Error("runtime_directory_is_not_private");
    }
    return join(configured, "codex-unlock");
  }
  return join(tmpdir(), `codex-unlock-${uid}`);
}

function contentionError(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException).code;
  return code === "EAGAIN" || code === "EACCES" || code === "EWOULDBLOCK";
}

export function acquireUnlockLease(
  codexHome: string,
  threadId: string,
  runtimeDirectory?: string,
): UnlockLeaseAttempt {
  const uid = process.getuid?.();
  if (uid === undefined) {
    return { status: "unknown", reason: "current_user_is_unavailable" };
  }

  let root: string;
  let canonicalHome: string;
  try {
    root = runtimeRoot(uid, runtimeDirectory);
    mkdirSync(root, { mode: 0o700, recursive: true });
    if (!privateDirectory(root, uid)) {
      return { status: "unknown", reason: "coordination_directory_is_not_private" };
    }
    chmodSync(root, 0o700);
    canonicalHome = realpathSync(codexHome);
  } catch {
    return { status: "unknown", reason: "coordination_directory_unavailable" };
  }

  const key = createHash("sha256")
    .update(canonicalHome)
    .update("\0")
    .update(threadId)
    .digest("hex");
  const path = join(root, `${key}.lock`);
  let descriptor: number | undefined;
  try {
    descriptor = openSync(
      path,
      constants.O_CREAT | constants.O_RDWR | (constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    const value = fstatSync(descriptor);
    if (
      !value.isFile() ||
      value.uid !== uid ||
      value.nlink !== 1 ||
      (value.mode & 0o077) !== 0
    ) {
      closeSync(descriptor);
      return { status: "unknown", reason: "coordination_file_is_not_private" };
    }
    try {
      flockSync(descriptor, "exnb");
    } catch (error) {
      closeSync(descriptor);
      return contentionError(error)
        ? { status: "contended" }
        : { status: "unknown", reason: "coordination_lock_failed" };
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
    if (descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch {
        // The descriptor may already have been closed by a failed validation.
      }
    }
    return { status: "unknown", reason: "coordination_file_unavailable" };
  }
}
