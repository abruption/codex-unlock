import { homedir } from "node:os";
import { join, resolve } from "node:path";

import type { DoctorOptions } from "./types.js";

const THREAD_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function defaultOptions(): DoctorOptions {
  return {
    codexHome: resolve(process.env.CODEX_HOME ?? join(homedir(), ".codex")),
    stabilityMs: 1_000,
    terminationTimeoutMs: 5_000,
  };
}

export function validateThreadId(threadId: string): string {
  if (!THREAD_ID_PATTERN.test(threadId)) {
    throw new Error(`invalid Codex thread id: ${threadId}`);
  }
  return threadId.toLowerCase();
}

export function isThreadId(value: string): boolean {
  return THREAD_ID_PATTERN.test(value);
}
