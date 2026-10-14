import { spawn } from "node:child_process";
import type { ChildProcess, SpawnOptions } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import type { BigIntStats, Stats } from "node:fs";

import type { PublicFileSnapshot } from "./types.js";

export interface CommandResult {
  status: number | null;
  stdout: string;
  stderr: string;
  error?: NodeJS.ErrnoException;
  failure?: CommandFailure;
}

export type CommandFailureKind =
  | "spawn_error"
  | "timeout"
  | "stdout_limit"
  | "stderr_limit";

export interface CommandFailure {
  kind: CommandFailureKind;
  message: string;
}

export interface CommandLimits {
  timeoutMs: number;
  maxStdoutBytes: number;
  maxStderrBytes: number;
  killGraceMs: number;
}

export const DEFAULT_COMMAND_LIMITS: Readonly<CommandLimits> = {
  timeoutMs: 5_000,
  maxStdoutBytes: 1024 * 1024,
  maxStderrBytes: 256 * 1024,
  killGraceMs: 250,
};

// Diagnostic commands never inherit the caller's environment: variables such
// as COLUMNS, LINES, PS_FORMAT, or PS_PERSONALITY change what ps prints, and
// LC_*/LANG change how lsof renders names. Executables are absolute paths.
export const DIAGNOSTIC_COMMAND_ENV: Readonly<NodeJS.ProcessEnv> = Object.freeze({
  LC_ALL: "C",
  LANG: "C",
  PATH: "/usr/bin:/bin:/usr/sbin:/sbin",
});

type SpawnProcess = (
  command: string,
  args: readonly string[],
  options: SpawnOptions,
) => ChildProcess;

let spawnOverride: SpawnProcess | null = null;

/**
 * Test-only seam for spawn failure injection; `null` restores
 * `child_process.spawn`. Not part of the package's supported exports.
 */
export function overrideSpawnForTesting(replacement: SpawnProcess | null): void {
  spawnOverride = replacement;
}

export async function runCommand(
  executable: string,
  args: string[],
  limits: Readonly<CommandLimits> = DEFAULT_COMMAND_LIMITS,
): Promise<CommandResult> {
  return await new Promise((resolve) => {
    const isolatedProcessGroup = process.platform !== "win32";
    const spawnFailure = (error: unknown): CommandResult => ({
      status: null,
      stdout: "",
      stderr: "",
      ...(error instanceof Error ? { error: error as NodeJS.ErrnoException } : {}),
      failure: { kind: "spawn_error", message: errorText(error) },
    });
    const options: SpawnOptions = {
      detached: isolatedProcessGroup,
      env: { ...DIAGNOSTIC_COMMAND_ENV },
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    };
    let child: ChildProcess;
    try {
      child = spawnOverride
        ? spawnOverride(executable, args, options)
        : spawn(executable, args, options);
    } catch (error) {
      resolve(spawnFailure(error));
      return;
    }
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let failure: CommandFailure | undefined;
    let spawnError: NodeJS.ErrnoException | undefined;
    let settled = false;
    let forceKillTimer: NodeJS.Timeout | undefined;

    const settle = (status: number | null): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (forceKillTimer) clearTimeout(forceKillTimer);
      resolve({
        status,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
        ...(spawnError ? { error: spawnError } : {}),
        ...(failure ? { failure } : {}),
      });
    };
    // Attach before touching stdio: EMFILE/ENFILE spawns return a child
    // without pipes and emit "error" asynchronously.
    child.on("error", (error: NodeJS.ErrnoException) => {
      spawnError ??= error;
      failure ??= { kind: "spawn_error", message: errorText(error) };
      if (!child.stdout || !child.stderr) settle(null);
    });

    const signalDiagnosticProcess = (signal: NodeJS.Signals): void => {
      if (isolatedProcessGroup && child.pid !== undefined) {
        try {
          process.kill(-child.pid, signal);
          return;
        } catch {
          // Fall back to the direct child when its process group is already gone.
        }
      }
      try {
        child.kill(signal);
      } catch {
        // A child that never started has nothing left to signal.
      }
    };
    const terminate = (): void => {
      signalDiagnosticProcess("SIGTERM");
      forceKillTimer ??= setTimeout(() => {
        if (!settled) signalDiagnosticProcess("SIGKILL");
      }, limits.killGraceMs);
      forceKillTimer.unref();
    };
    const fail = (next: CommandFailure): void => {
      if (failure) return;
      failure = next;
      terminate();
    };

    const timeout = setTimeout(() => {
      fail({
        kind: "timeout",
        message: `command exceeded ${limits.timeoutMs} ms`,
      });
    }, limits.timeoutMs);
    timeout.unref();

    if (!child.stdout || !child.stderr) {
      if (child.pid !== undefined) terminate();
      // Node reports EMFILE/ENFILE through a nextTick "error"; let it land first.
      setImmediate(() => {
        failure ??= {
          kind: "spawn_error",
          message: "diagnostic command has no stdout/stderr pipes",
        };
        settle(null);
      });
      return;
    }

    const capture = (
      chunk: Buffer | string,
      chunks: Buffer[],
      currentBytes: number,
      maximumBytes: number,
      kind: "stdout_limit" | "stderr_limit",
    ): number => {
      const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      const remaining = Math.max(0, maximumBytes - currentBytes);
      if (remaining > 0) chunks.push(value.subarray(0, remaining));
      const nextBytes = currentBytes + value.length;
      if (nextBytes > maximumBytes) {
        fail({
          kind,
          message: `${kind === "stdout_limit" ? "stdout" : "stderr"} exceeded ${maximumBytes} bytes`,
        });
      }
      return Math.min(nextBytes, maximumBytes);
    };
    child.stdout.on("data", (chunk: Buffer | string) => {
      stdoutBytes = capture(
        chunk,
        stdout,
        stdoutBytes,
        limits.maxStdoutBytes,
        "stdout_limit",
      );
    });
    child.stderr.on("data", (chunk: Buffer | string) => {
      stderrBytes = capture(
        chunk,
        stderr,
        stderrBytes,
        limits.maxStderrBytes,
        "stderr_limit",
      );
    });
    child.on("close", (status: number | null) => {
      settle(status);
    });
  });
}

export function commandFailureText(result: CommandResult): string | null {
  if (result.failure) {
    return `${result.failure.kind}: ${result.failure.message}`;
  }
  if (result.error) return errorText(result.error);
  return null;
}

export function errorText(error: unknown): string {
  if (error instanceof Error) {
    const code = (error as NodeJS.ErrnoException).code;
    return code ? `${code}: ${error.message}` : error.message;
  }
  return String(error);
}

export function publicSnapshot(
  value: Stats | BigIntStats,
): PublicFileSnapshot {
  const integer = (field: string, input: number | bigint): number => {
    const converted = Number(input);
    if (!Number.isSafeInteger(converted) || converted < 0) {
      throw new Error(`file snapshot ${field} is not a safe non-negative integer`);
    }
    return converted;
  };
  const identity = (field: string, input: number | bigint): string => {
    if (typeof input === "bigint") {
      if (input < 0n) throw new Error(`file snapshot ${field} is negative`);
      return input.toString();
    }
    // Already-rounded numeric identities cannot be recovered by BigInt().
    return String(integer(field, input));
  };
  // BigIntStats.mtimeMs truncates sub-millisecond precision. Retain the v1
  // number field and its fractional milliseconds without converting the
  // entire nanosecond timestamp to a (potentially rounded) Number first.
  const modifiedMs = "mtimeNs" in value
    ? Number(value.mtimeNs / 1_000_000n) + Number(value.mtimeNs % 1_000_000n) / 1_000_000
    : value.mtimeMs;
  if (!Number.isFinite(modifiedMs) || Math.abs(modifiedMs) > Number.MAX_SAFE_INTEGER) {
    throw new Error("file snapshot modification time is not representable");
  }
  return {
    device: identity("device", value.dev),
    inode: identity("inode", value.ino),
    mode: integer("mode", value.mode),
    uid: integer("uid", value.uid),
    links: integer("links", value.nlink),
    size: integer("size", value.size),
    modifiedAt: value.mtime.toISOString(),
    modifiedMs,
  };
}

export function sameSnapshot(
  left: PublicFileSnapshot | null,
  right: PublicFileSnapshot | null,
): boolean {
  return (
    left !== null &&
    right !== null &&
    left.device === right.device &&
    left.inode === right.inode &&
    left.size === right.size &&
    left.modifiedMs === right.modifiedMs
  );
}

export async function sha256File(path: string): Promise<string> {
  return await new Promise((resolve, reject) => {
    const hash = createHash("sha256");
    const input = createReadStream(path);
    input.on("error", reject);
    input.on("data", (chunk) => hash.update(chunk));
    input.on("end", () => resolve(hash.digest("hex")));
  });
}

export async function delay(milliseconds: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, milliseconds));
}

export function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}
