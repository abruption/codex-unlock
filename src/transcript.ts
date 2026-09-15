import { open } from "node:fs/promises";
import { lstat, opendir } from "node:fs/promises";
import { basename, join } from "node:path";

import type {
  PublicFileSnapshot,
  TranscriptInspection,
  TranscriptRecord,
} from "./types.js";
import { errorText, publicSnapshot, sameSnapshot } from "./util.js";

const MAX_LAST_RECORD_BYTES = 8 * 1024 * 1024;
const READ_CHUNK_BYTES = 64 * 1024;

async function walkForTranscript(
  root: string,
  expectedName: string,
  output: string[],
): Promise<void> {
  let directory;
  try {
    directory = await opendir(root);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return;
    }
    throw error;
  }
  for await (const entry of directory) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) {
      await walkForTranscript(path, expectedName, output);
    } else if (entry.isFile() && entry.name.endsWith(expectedName)) {
      output.push(path);
    }
  }
}

export async function findTranscriptCandidates(
  codexHome: string,
  threadId: string,
): Promise<string[]> {
  const expectedName = `-${threadId}.jsonl`;
  const output: string[] = [];
  await Promise.all([
    walkForTranscript(join(codexHome, "sessions"), expectedName, output),
    walkForTranscript(join(codexHome, "archived_sessions"), expectedName, output),
  ]);
  return output.sort();
}

async function readLastNonEmptyLine(path: string, size: number): Promise<string | null> {
  if (size === 0) {
    return null;
  }
  const handle = await open(path, "r");
  try {
    let position = size;
    let buffer = Buffer.alloc(0);
    while (position > 0 && buffer.length < MAX_LAST_RECORD_BYTES) {
      const length = Math.min(READ_CHUNK_BYTES, position);
      position -= length;
      const chunk = Buffer.allocUnsafe(length);
      const { bytesRead } = await handle.read(chunk, 0, length, position);
      buffer = Buffer.concat([chunk.subarray(0, bytesRead), buffer]);

      let end = buffer.length;
      while (end > 0 && (buffer[end - 1] === 0x0a || buffer[end - 1] === 0x0d)) {
        end -= 1;
      }
      if (end === 0) {
        continue;
      }
      const newline = buffer.lastIndexOf(0x0a, end - 1);
      if (newline >= 0 || position === 0) {
        const start = newline >= 0 ? newline + 1 : 0;
        return buffer.subarray(start, end).toString("utf8");
      }
    }
    throw new Error(
      `last rollout record exceeds ${MAX_LAST_RECORD_BYTES} bytes or is incomplete`,
    );
  } finally {
    await handle.close();
  }
}

function parseLastRecord(line: string | null): TranscriptRecord | null {
  if (line === null) {
    return null;
  }
  const value: unknown = JSON.parse(line);
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("last rollout record is not a JSON object");
  }
  const record = value as Record<string, unknown>;
  const payload =
    typeof record.payload === "object" && record.payload !== null && !Array.isArray(record.payload)
      ? (record.payload as Record<string, unknown>)
      : null;
  return {
    recordType: typeof record.type === "string" ? record.type : null,
    eventType: payload && typeof payload.type === "string" ? payload.type : null,
    timestamp: typeof record.timestamp === "string" ? record.timestamp : null,
    ordinal: typeof record.ordinal === "number" ? record.ordinal : null,
  };
}

export async function inspectTranscriptPath(
  path: string,
  candidates: string[] = [path],
): Promise<TranscriptInspection> {
  try {
    const beforeStat = await lstat(path);
    if (!beforeStat.isFile() || beforeStat.isSymbolicLink()) {
      return {
        status: "unreadable",
        path,
        candidates,
        snapshot: publicSnapshot(beforeStat),
        lastRecord: null,
        stable: null,
        error: "transcript is a symlink or non-regular file",
      };
    }
    const before = publicSnapshot(beforeStat);
    const lastRecord = parseLastRecord(await readLastNonEmptyLine(path, before.size));
    const after = publicSnapshot(await lstat(path));
    return {
      status: "found",
      path,
      candidates,
      snapshot: after,
      lastRecord,
      stable: sameSnapshot(before, after),
    };
  } catch (error) {
    return {
      status: "unreadable",
      path,
      candidates,
      snapshot: null,
      lastRecord: null,
      stable: null,
      error: errorText(error),
    };
  }
}

export async function inspectTranscriptCandidates(
  candidates: string[],
): Promise<TranscriptInspection> {
  if (candidates.length === 0) {
    return {
      status: "missing",
      path: null,
      candidates: [],
      snapshot: null,
      lastRecord: null,
      stable: null,
    };
  }
  if (candidates.length > 1) {
    return {
      status: "ambiguous",
      path: null,
      candidates,
      snapshot: null,
      lastRecord: null,
      stable: null,
      error: `found ${candidates.length} rollout files ending in ${basename(candidates[0])}`,
    };
  }
  return await inspectTranscriptPath(candidates[0], candidates);
}

export function sameLastRecord(
  left: TranscriptRecord | null,
  right: TranscriptRecord | null,
): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

export async function stableFileHash(
  path: string,
): Promise<{ hash: string; snapshot: PublicFileSnapshot }> {
  const before = publicSnapshot(await lstat(path));
  const { sha256File } = await import("./util.js");
  const hash = await sha256File(path);
  const after = publicSnapshot(await lstat(path));
  if (!sameSnapshot(before, after)) {
    throw new Error("transcript changed while hashing");
  }
  return { hash, snapshot: after };
}
