import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import type { Stats } from "node:fs";

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

export async function runCommand(
  executable: string,
  args: string[],
  limits: Readonly<CommandLimits> = DEFAULT_COMMAND_LIMITS,
): Promise<CommandResult> {
  return await new Promise((resolve) => {
    const isolatedProcessGroup = process.platform !== "win32";
    const child = spawn(executable, args, {
      detached: isolatedProcessGroup,
      env: { ...process.env, LC_ALL: "C", LANG: "C" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let failure: CommandFailure | undefined;
    let spawnError: NodeJS.ErrnoException | undefined;
    let settled = false;
    let forceKillTimer: NodeJS.Timeout | undefined;

    const signalDiagnosticProcess = (signal: NodeJS.Signals): void => {
      if (isolatedProcessGroup && child.pid !== undefined) {
        try {
          process.kill(-child.pid, signal);
          return;
        } catch {
          // Fall back to the direct child when its process group is already gone.
        }
      }
      child.kill(signal);
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
    const timeout = setTimeout(() => {
      fail({
        kind: "timeout",
        message: `command exceeded ${limits.timeoutMs} ms`,
      });
    }, limits.timeoutMs);
    timeout.unref();
    child.on("error", (error: NodeJS.ErrnoException) => {
      spawnError = error;
      failure ??= { kind: "spawn_error", message: errorText(error) };
    });
    child.on("close", (status) => {
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
  value: Stats,
): PublicFileSnapshot {
  return {
    device: String(value.dev),
    inode: String(value.ino),
    mode: value.mode,
    uid: value.uid,
    links: value.nlink,
    size: value.size,
    modifiedAt: value.mtime.toISOString(),
    modifiedMs: value.mtimeMs,
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
