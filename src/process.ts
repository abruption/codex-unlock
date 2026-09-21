import { access, lstat, realpath } from "node:fs/promises";
import { basename, dirname, isAbsolute, join } from "node:path";

import type { ProcessInfo, ProcessStartObservation } from "./types.js";
import {
  commandFailureText,
  errorText,
  runCommand,
  type CommandResult,
  unique,
} from "./util.js";

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
      return result.failure?.kind === "spawn_error" && result.error?.code === "ENOENT"
        ? null
        : "lsof";
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
  const failure = commandFailureText(result);
  if (failure) {
    return { processes: [], error: failure };
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

interface ProcessFieldObservation {
  status: "present" | "absent" | "unknown";
  value: string | null;
  error?: string;
}

function commandStatusError(result: CommandResult, command: string): string {
  const failure = commandFailureText(result);
  if (failure) return failure;
  return result.stderr.trim() || `${command} exited with status ${result.status}`;
}

async function psField(pid: number, field: string): Promise<ProcessFieldObservation> {
  const result = await runCommand("ps", ["-p", String(pid), "-o", `${field}=`]);
  if (commandFailureText(result)) {
    return { status: "unknown", value: null, error: commandStatusError(result, "ps") };
  }
  const value = result.stdout.trim();
  if (result.status === 0) {
    return value
      ? { status: "present", value }
      : { status: "unknown", value: null, error: `ps returned empty ${field} output` };
  }
  if (result.status === 1 && value === "") {
    return { status: "absent", value: null };
  }
  return { status: "unknown", value: null, error: commandStatusError(result, "ps") };
}

export function processStartTimeFromCommand(
  result: CommandResult,
): ProcessStartObservation {
  const failure = commandFailureText(result);
  if (failure) return { status: "unknown", startTime: null, error: failure };
  const value = result.stdout.trim();
  if (result.status === 1 && value === "") {
    return { status: "absent", startTime: null };
  }
  if (result.status !== 0) {
    return {
      status: "unknown",
      startTime: null,
      error: commandStatusError(result, "ps"),
    };
  }
  if (!value || Number.isNaN(Date.parse(value))) {
    return {
      status: "unknown",
      startTime: null,
      error: value ? "ps returned malformed process start time" : "ps returned empty process start time",
    };
  }
  return { status: "present", startTime: value };
}

export async function processStartTime(pid: number): Promise<ProcessStartObservation> {
  const result = await runCommand("ps", ["-p", String(pid), "-o", "lstart="]);
  const observation = processStartTimeFromCommand(result);
  if (observation.status !== "absent") return observation;
  try {
    process.kill(pid, 0);
    return {
      status: "unknown",
      startTime: null,
      error: "ps reported absence while the PID still exists",
    };
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ESRCH") return observation;
    return {
      status: "unknown",
      startTime: null,
      error: `could not confirm PID absence: ${errorText(error)}`,
    };
  }
}

export function originalProcessExited(
  originalStartTime: string,
  observation: ProcessStartObservation,
): boolean | null {
  if (observation.status === "unknown") return null;
  return observation.status === "absent" || observation.startTime !== originalStartTime;
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
  if (commandFailureText(result) || result.status !== 0) {
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
  const [ppidField, uidField, startTime, ttyField, commandField, argumentsField, cwd] =
    await Promise.all([
      psField(candidate.pid, "ppid"),
      psField(candidate.pid, "uid"),
      processStartTime(candidate.pid),
      psField(candidate.pid, "tty"),
      psField(candidate.pid, "comm"),
      psField(candidate.pid, "args"),
      processCwd(candidate.pid),
    ]);
  const ppid = parseInteger(ppidField.value);
  const uid = parseInteger(uidField.value);
  const ttyValue = ttyField.value;
  const tty = ttyValue === "?" || ttyValue === "??" || ttyValue === "-" ? null : ttyValue;
  const command = commandField.value;
  const argumentsValue = argumentsField.value;
  const commandBase = command ? basename(command).toLowerCase() : "";
  const args = argumentsValue ?? null;
  const isCodex =
    candidate.command?.toLowerCase() === "codex" ||
    commandBase === "codex" ||
    commandBase.startsWith("codex-") ||
    /(^|\/)codex(?:\s|$)/i.test(args ?? "");
  const isSharedService = /\b(?:app-server|remote-control|daemon)\b/i.test(args ?? "");
  const errors: string[] = [];
  if (ppid === null) errors.push(`ppid_${ppidField.status}${ppidField.error ? `:${ppidField.error}` : ""}`);
  if (uid === null) errors.push(`uid_${uidField.status}${uidField.error ? `:${uidField.error}` : ""}`);
  if (startTime.status !== "present") errors.push(`start_time_${startTime.status}${startTime.error ? `:${startTime.error}` : ""}`);
  if (command === null) errors.push(`command_${commandField.status}${commandField.error ? `:${commandField.error}` : ""}`);
  if (args === null) errors.push(`arguments_${argumentsField.status}${argumentsField.error ? `:${argumentsField.error}` : ""}`);

  return {
    pid: candidate.pid,
    ppid,
    uid,
    startTime: startTime.startTime,
    tty,
    command,
    arguments: args,
    cwd,
    lsofCommand: candidate.command,
    identityComplete:
      ppid !== null &&
      uid !== null &&
      startTime.status === "present" &&
      command !== null &&
      args !== null,
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
  intendedLockPath: string,
): Promise<{ paths: string[]; error?: string }> {
  const executable = await findLsofExecutable();
  if (!executable) {
    return { paths: [], error: "lsof is not installed" };
  }
  const result = await runCommand(executable, ["-a", "-p", String(pid), "-Fn"]);
  const failure = commandFailureText(result);
  if (failure) {
    return { paths: [], error: failure };
  }
  if (result.status !== 0) {
    return {
      paths: [],
      error: result.stderr.trim() || `lsof exited with status ${result.status}`,
    };
  }
  const candidates = result.stdout
    .split(/[\0\n]/)
    .filter((token) => token.startsWith("n"))
    .map((token) => token.slice(1))
    .filter((path) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.lock(?: \(deleted\))?$/i.test(basename(path)))
    .filter((path) => basename(dirname(path)) === "thread-writer-locks");
  let intendedCanonical: string;
  try {
    const intendedDirectory = await realpath(dirname(intendedLockPath));
    intendedCanonical = join(intendedDirectory, basename(intendedLockPath));
  } catch (error) {
    return { paths: [], error: `intended lock directory is unresolved: ${errorText(error)}` };
  }
  const paths: string[] = [];
  for (const path of candidates) {
    if (path.endsWith(" (deleted)")) {
      return { paths: [], error: `open lock path was deleted: ${path}` };
    }
    if (!isAbsolute(path)) {
      return { paths: [], error: `lsof returned a relative lock path: ${path}` };
    }
    try {
      const value = await lstat(path);
      if (value.isSymbolicLink() || !value.isFile()) {
        return { paths: [], error: `open lock path is a symlink or non-regular file: ${path}` };
      }
      const canonicalDirectory = await realpath(dirname(path));
      const canonicalPath = join(canonicalDirectory, basename(path));
      paths.push(canonicalPath === intendedCanonical ? intendedLockPath : canonicalPath);
    } catch (error) {
      return { paths: [], error: `open lock path is unresolved: ${errorText(error)}` };
    }
  }
  return { paths: unique(paths).sort() };
}

async function processTable(): Promise<Map<number, number> | null> {
  const result = await runCommand("ps", ["-axo", "pid=,ppid="]);
  if (commandFailureText(result)) return null;
  const table = new Map<number, number>();
  if (result.status !== 0) {
    return null;
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
  if (table === null || table.size === 0) {
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
  if (table === null || table.size === 0) {
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
