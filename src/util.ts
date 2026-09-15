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
}

export async function runCommand(
  executable: string,
  args: string[],
): Promise<CommandResult> {
  return await new Promise((resolve) => {
    const child = spawn(executable, args, {
      env: { ...process.env, LC_ALL: "C", LANG: "C" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.on("error", (error: NodeJS.ErrnoException) => {
      resolve({ status: null, stdout, stderr, error });
    });
    child.on("close", (status) => {
      resolve({ status, stdout, stderr });
    });
  });
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
