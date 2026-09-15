import { access, realpath } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";

import type { ProcessInfo } from "./types.js";
import { errorText, runCommand, unique } from "./util.js";

interface LsofProcess {
  pid: number;
  command: string | null;
  uid: number | null;
}

let lsofExecutablePromise: Promise<string | null> | undefined;

async function findLsofExecutable(): Promise<string | null> {
  if (!lsofExecutablePromise) {
    lsofExecutablePromise = (async () => {
      for (const candidate of ["/usr/sbin/lsof", "/usr/bin/lsof"]) {
        try {
          await access(candidate);
          return candidate;
        } catch {
          // Continue to PATH lookup.
        }
      }
      const result = await runCommand("lsof", ["-v"]);
      return result.error?.code === "ENOENT" ? null : "lsof";
    })();
  }
  return await lsofExecutablePromise;
}

export function parseLsofProcesses(output: string): LsofProcess[] {
  const byPid = new Map<number, LsofProcess>();
  let current: LsofProcess | undefined;
  for (const token of output.split(/[\0\n]/)) {
    if (token.length < 2) {
      continue;
    }
    const field = token[0];
    const value = token.slice(1).trim();
    if (field === "p") {
      const pid = Number.parseInt(value, 10);
      if (!Number.isSafeInteger(pid) || pid <= 0) {
        current = undefined;
        continue;
      }
      current = byPid.get(pid) ?? { pid, command: null, uid: null };
      byPid.set(pid, current);
    } else if (field === "c" && current) {
      current.command = value || null;
    } else if (field === "u" && current) {
      const uid = Number.parseInt(value, 10);
      current.uid = Number.isSafeInteger(uid) ? uid : null;
    }
  }
  return [...byPid.values()].sort((left, right) => left.pid - right.pid);
}

export async function findLockOpeners(
  path: string,
): Promise<{ processes: LsofProcess[]; error?: string }> {
  const executable = await findLsofExecutable();
  if (!executable) {
    return { processes: [], error: "lsof is not installed" };
  }
  const result = await runCommand(executable, ["-nP", "-F0pcu", "--", path]);
  if (result.error) {
    return { processes: [], error: errorText(result.error) };
  }
  const processes = parseLsofProcesses(result.stdout);
  if (result.status === 0 || (result.status === 1 && processes.length === 0)) {
    return { processes };
  }
  return {
    processes,
    error: result.stderr.trim() || `lsof exited with status ${result.status}`,
  };
}

async function psField(pid: number, field: string): Promise<string | null> {
  const result = await runCommand("ps", ["-p", String(pid), "-o", `${field}=`]);
  if (result.status !== 0) {
    return null;
  }
  const value = result.stdout.trim();
  return value || null;
}

export async function processStartTime(pid: number): Promise<string | null> {
  return await psField(pid, "lstart");
}

async function processCwd(pid: number): Promise<string | null> {
  if (process.platform === "linux") {
    try {
      const { readlink } = await import("node:fs/promises");
      return await readlink(`/proc/${pid}/cwd`);
    } catch {
      // Fall back to lsof below.
    }
  }
  const executable = await findLsofExecutable();
  if (!executable) {
    return null;
  }
  const result = await runCommand(executable, ["-a", "-p", String(pid), "-d", "cwd", "-Fn"]);
  if (result.status !== 0) {
    return null;
  }
  for (const token of result.stdout.split(/[\0\n]/)) {
    if (token.startsWith("n")) {
      return token.slice(1);
    }
  }
  return null;
}

function parseInteger(value: string | null): number | null {
  if (value === null) {
    return null;
  }
  const parsed = Number.parseInt(value, 10);
  return Number.isSafeInteger(parsed) ? parsed : null;
}

export async function inspectProcess(
  candidate: LsofProcess,
): Promise<ProcessInfo> {
  const [ppidValue, uidValue, startTime, ttyValue, command, argumentsValue, cwd] =
    await Promise.all([
      psField(candidate.pid, "ppid"),
      psField(candidate.pid, "uid"),
      psField(candidate.pid, "lstart"),
      psField(candidate.pid, "tty"),
      psField(candidate.pid, "comm"),
      psField(candidate.pid, "args"),
      processCwd(candidate.pid),
    ]);
  const ppid = parseInteger(ppidValue);
  const uid = parseInteger(uidValue);
  const tty = ttyValue === "?" || ttyValue === "??" || ttyValue === "-" ? null : ttyValue;
  const commandBase = command ? basename(command).toLowerCase() : "";
  const args = argumentsValue ?? null;
  const isCodex =
    candidate.command?.toLowerCase() === "codex" ||
    commandBase === "codex" ||
    commandBase.startsWith("codex-") ||
    /(^|\/)codex(?:\s|$)/i.test(args ?? "");
  const isSharedService = /\b(?:app-server|remote-control|daemon)\b/i.test(args ?? "");
  const errors: string[] = [];
  if (ppid === null) errors.push("ppid_unavailable");
  if (uid === null) errors.push("uid_unavailable");
  if (startTime === null) errors.push("start_time_unavailable");
  if (command === null) errors.push("command_unavailable");
  if (args === null) errors.push("arguments_unavailable");

  return {
    pid: candidate.pid,
    ppid,
    uid,
    startTime,
    tty,
    command,
    arguments: args,
    cwd,
    lsofCommand: candidate.command,
    identityComplete:
      ppid !== null && uid !== null && startTime !== null && command !== null && args !== null,
    isCodex,
    isSharedService,
    errors,
  };
}

export async function inspectLockOpeners(
  path: string,
): Promise<{ processes: ProcessInfo[]; error?: string }> {
  const openers = await findLockOpeners(path);
  return {
    processes: await Promise.all(openers.processes.map(inspectProcess)),
    ...(openers.error ? { error: openers.error } : {}),
  };
}

export async function lockFilesOpenedByProcess(
  pid: number,
  lockDirectory: string,
): Promise<{ paths: string[]; error?: string }> {
  const executable = await findLsofExecutable();
  if (!executable) {
    return { paths: [], error: "lsof is not installed" };
  }
  const result = await runCommand(executable, ["-a", "-p", String(pid), "-Fn"]);
  if (result.status !== 0) {
    return {
      paths: [],
      error: result.stderr.trim() || `lsof exited with status ${result.status}`,
    };
  }
  const wantedDirectory = await realpath(lockDirectory).catch(() => resolve(lockDirectory));
  const candidates = result.stdout
    .split(/[\0\n]/)
    .filter((token) => token.startsWith("n"))
    .map((token) => token.slice(1))
    .filter((path) => /^[0-9a-f-]{36}\.lock$/i.test(basename(path)));
  const paths: string[] = [];
  for (const path of candidates) {
    const canonicalPath = await realpath(path).catch(() => resolve(path));
    if (dirname(canonicalPath) === wantedDirectory) {
      paths.push(join(lockDirectory, basename(path)));
    }
  }
  return { paths: unique(paths).sort() };
}

async function processTable(): Promise<Map<number, number>> {
  const result = await runCommand("ps", ["-axo", "pid=,ppid="]);
  const table = new Map<number, number>();
  if (result.status !== 0) {
    return table;
  }
  for (const line of result.stdout.split("\n")) {
    const match = line.trim().match(/^(\d+)\s+(\d+)$/);
    if (match) {
      table.set(Number(match[1]), Number(match[2]));
    }
  }
  return table;
}

export async function descendantPids(pid: number): Promise<number[] | null> {
  const table = await processTable();
  if (table.size === 0) {
    return null;
  }
  const found: number[] = [];
  const queue = [pid];
  while (queue.length > 0) {
    const parent = queue.shift()!;
    for (const [candidate, candidateParent] of table) {
      if (candidateParent === parent && !found.includes(candidate)) {
        found.push(candidate);
        queue.push(candidate);
      }
    }
  }
  return found.sort((left, right) => left - right);
}

export async function currentProcessFamily(): Promise<Set<number> | null> {
  const table = await processTable();
  if (table.size === 0) {
    return null;
  }
  const family = new Set<number>();
  let current = process.pid;
  while (current > 0 && !family.has(current)) {
    family.add(current);
    current = table.get(current) ?? 0;
  }
  return family;
}
