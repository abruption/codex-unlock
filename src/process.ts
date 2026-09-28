import { constants } from "node:fs";
import { access, lstat, readFile, realpath, stat } from "node:fs/promises";
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

// Process evidence comes only from fixed system binaries, never from PATH.
const SYSTEM_EXECUTABLES = {
  ps: ["/bin/ps", "/usr/bin/ps"],
  lsof: ["/usr/sbin/lsof", "/usr/bin/lsof"],
} as const;

export type DiagnosticTool = keyof typeof SYSTEM_EXECUTABLES;

const executablePromises = new Map<DiagnosticTool, Promise<string | null>>();

async function findSystemExecutable(tool: DiagnosticTool): Promise<string | null> {
  let pending = executablePromises.get(tool);
  if (!pending) {
    pending = (async () => {
      for (const candidate of SYSTEM_EXECUTABLES[tool]) {
        try {
          if (!(await stat(candidate)).isFile()) continue;
          await access(candidate, constants.X_OK);
          return candidate;
        } catch {
          // Try the next fixed location; PATH is never consulted.
        }
      }
      return null;
    })();
    executablePromises.set(tool, pending);
  }
  return await pending;
}

/**
 * Test-only seam for fault injection. Replaces the resolved executable for
 * this process; `null` restores fixed system-path resolution.
 */
export function overrideDiagnosticExecutableForTesting(
  tool: DiagnosticTool,
  executable: string | null,
): void {
  if (executable === null) executablePromises.delete(tool);
  else executablePromises.set(tool, Promise.resolve(executable));
}

async function runDiagnostic(tool: DiagnosticTool, args: string[]): Promise<CommandResult> {
  const executable = await findSystemExecutable(tool);
  if (!executable) {
    return {
      status: null,
      stdout: "",
      stderr: "",
      failure: {
        kind: "spawn_error",
        message: `${tool} is not installed at ${SYSTEM_EXECUTABLES[tool].join(" or ")}`,
      },
    };
  }
  return await runCommand(executable, args);
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
  const result = await runDiagnostic("lsof", ["-nP", "-F0pcu", "--", path]);
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
  // -ww: never truncate to a terminal width (procps honours COLUMNS otherwise).
  const result = await runDiagnostic("ps", ["-ww", "-p", String(pid), "-o", `${field}=`]);
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
  const result = await runDiagnostic("ps", ["-ww", "-p", String(pid), "-o", "lstart="]);
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
  const result = await runDiagnostic("lsof", ["-a", "-p", String(pid), "-d", "cwd", "-Fn"]);
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

const SHARED_SERVICE_PATTERN = /\b(?:app-server|remote-control|daemon)\b/i;

export type CommandLineObservation =
  | { status: "present"; argv: string[] }
  | { status: "unknown"; error: string };

export function parseProcCommandLine(value: Buffer): string[] {
  const argv = value.toString("utf8").split("\0");
  while (argv.length > 0 && argv[argv.length - 1] === "") argv.pop();
  return argv;
}

async function linuxCommandLine(pid: number): Promise<CommandLineObservation> {
  try {
    return {
      status: "present",
      argv: parseProcCommandLine(await readFile(`/proc/${pid}/cmdline`)),
    };
  } catch (error) {
    return { status: "unknown", error: errorText(error) };
  }
}

export interface ArgumentEvidence {
  arguments: string | null;
  isSharedService: boolean;
  error?: string;
}

/**
 * Combines `ps` arguments with the kernel argv when one is available (Linux).
 * Truncated or unverifiable arguments become unknown, and a shared-service
 * token in either source classifies the owner as shared.
 */
export function reconcileArguments(
  psArguments: string | null,
  commandLine: CommandLineObservation | null,
): ArgumentEvidence {
  const kernelArguments =
    commandLine?.status === "present" ? commandLine.argv.join(" ") : "";
  const isSharedService =
    SHARED_SERVICE_PATTERN.test(psArguments ?? "") ||
    SHARED_SERVICE_PATTERN.test(kernelArguments);
  if (psArguments === null || commandLine === null) {
    return { arguments: psArguments, isSharedService };
  }
  if (commandLine.status === "unknown") {
    return {
      arguments: null,
      isSharedService,
      error: `arguments_unverified:${commandLine.error}`,
    };
  }
  if (
    kernelArguments.length > psArguments.length &&
    kernelArguments.startsWith(psArguments)
  ) {
    return {
      arguments: null,
      isSharedService,
      error: "arguments_truncated:ps output is shorter than the kernel argv",
    };
  }
  return { arguments: psArguments, isSharedService };
}

export async function inspectProcess(
  candidate: LsofProcess,
): Promise<ProcessInfo> {
  const [ppidField, uidField, startTime, ttyField, commandField, argumentsField, cwd, commandLine] =
    await Promise.all([
      psField(candidate.pid, "ppid"),
      psField(candidate.pid, "uid"),
      processStartTime(candidate.pid),
      psField(candidate.pid, "tty"),
      psField(candidate.pid, "comm"),
      psField(candidate.pid, "args"),
      processCwd(candidate.pid),
      process.platform === "linux" ? linuxCommandLine(candidate.pid) : Promise.resolve(null),
    ]);
  const ppid = parseInteger(ppidField.value);
  const uid = parseInteger(uidField.value);
  const ttyValue = ttyField.value;
  const tty = ttyValue === "?" || ttyValue === "??" || ttyValue === "-" ? null : ttyValue;
  const command = commandField.value;
  const argumentEvidence = reconcileArguments(argumentsField.value, commandLine);
  const commandBase = command ? basename(command).toLowerCase() : "";
  const args = argumentEvidence.arguments;
  const isCodex =
    candidate.command?.toLowerCase() === "codex" ||
    commandBase === "codex" ||
    commandBase.startsWith("codex-") ||
    /(^|\/)codex(?:\s|$)/i.test(args ?? "");
  const isSharedService = argumentEvidence.isSharedService;
  const errors: string[] = [];
  if (ppid === null) errors.push(`ppid_${ppidField.status}${ppidField.error ? `:${ppidField.error}` : ""}`);
  if (uid === null) errors.push(`uid_${uidField.status}${uidField.error ? `:${uidField.error}` : ""}`);
  if (startTime.status !== "present") errors.push(`start_time_${startTime.status}${startTime.error ? `:${startTime.error}` : ""}`);
  if (command === null) errors.push(`command_${commandField.status}${commandField.error ? `:${commandField.error}` : ""}`);
  if (argumentEvidence.error) errors.push(argumentEvidence.error);
  else if (args === null) errors.push(`arguments_${argumentsField.status}${argumentsField.error ? `:${argumentsField.error}` : ""}`);

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

interface LsofFile {
  name: string;
  device: bigint | null;
  inode: bigint | null;
}

function parseLsofUnsigned(value: string, radix: 10 | 16): bigint | null {
  const pattern = radix === 16 ? /^0x[0-9a-f]+$/i : /^[0-9]+$/;
  return pattern.test(value) ? BigInt(value) : null;
}

/**
 * Parses `lsof -F0fDin` file sets. Device (`D`, hexadecimal) and inode (`i`,
 * decimal) identify a file independently of how lsof renders its name.
 * macOS lsof starts every set with `f`; Linux lsof 4.9x may omit it, so a
 * repeated field (lsof emits `D`, `i`, then `n` in order) also starts a set.
 */
export function parseLsofFiles(output: string): LsofFile[] {
  const files: LsofFile[] = [];
  let current: LsofFile | undefined;
  const flush = (): void => {
    if (current?.name) files.push(current);
    current = undefined;
  };
  const begin = (): LsofFile => {
    flush();
    current = { name: "", device: null, inode: null };
    return current;
  };
  for (const token of output.split(/[\0\n]/)) {
    if (token.length < 1) continue;
    const field = token[0];
    const value = token.slice(1);
    if (field === "p") {
      flush();
    } else if (field === "f") {
      begin();
    } else if (field === "D") {
      const file =
        !current || current.name || current.device !== null || current.inode !== null
          ? begin()
          : current;
      file.device = parseLsofUnsigned(value, 16);
    } else if (field === "i") {
      const file = !current || current.name || current.inode !== null ? begin() : current;
      file.inode = parseLsofUnsigned(value, 10);
    } else if (field === "n") {
      const file = !current || current.name ? begin() : current;
      file.name = value;
    }
  }
  flush();
  return files;
}

function isThreadLockName(path: string): boolean {
  return (
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.lock(?: \(deleted\))?$/i.test(basename(path)) &&
    basename(dirname(path)) === "thread-writer-locks"
  );
}

export async function lockFilesOpenedByProcess(
  pid: number,
  intendedLockPath: string,
): Promise<{ paths: string[]; error?: string }> {
  const result = await runDiagnostic("lsof", ["-a", "-p", String(pid), "-F0fDin"]);
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
  const candidates = parseLsofFiles(result.stdout).filter((file) => isThreadLockName(file.name));
  let intendedCanonical: string;
  let intendedDevice: bigint;
  let intendedInode: bigint;
  try {
    const intendedDirectory = await realpath(dirname(intendedLockPath));
    intendedCanonical = join(intendedDirectory, basename(intendedLockPath));
    const intended = await lstat(intendedLockPath, { bigint: true });
    intendedDevice = intended.dev;
    intendedInode = intended.ino;
  } catch (error) {
    return { paths: [], error: `intended lock is unresolved: ${errorText(error)}` };
  }
  const paths: string[] = [];
  for (const { name: path, device, inode } of candidates) {
    if (path.endsWith(" (deleted)")) {
      return { paths: [], error: `open lock path was deleted: ${path}` };
    }
    // Match the intended lock by identity: in the C locale lsof escapes
    // non-ASCII name bytes (\xNN), so the rendered name may not be a real path.
    if (device !== null && inode !== null && device === intendedDevice && inode === intendedInode) {
      paths.push(intendedLockPath);
      continue;
    }
    if (!isAbsolute(path)) {
      return { paths: [], error: `lsof returned a relative lock path: ${path}` };
    }
    try {
      const value = await lstat(path, { bigint: true });
      if (value.isSymbolicLink() || !value.isFile()) {
        return { paths: [], error: `open lock path is a symlink or non-regular file: ${path}` };
      }
      const canonicalDirectory = await realpath(dirname(path));
      const canonicalPath = join(canonicalDirectory, basename(path));
      if (canonicalPath === intendedCanonical) {
        return {
          paths: [],
          error: `open lock path names the intended lock but not its device/inode: ${path}`,
        };
      }
      paths.push(canonicalPath);
    } catch (error) {
      return { paths: [], error: `open lock path is unresolved: ${errorText(error)}` };
    }
  }
  return { paths: unique(paths).sort() };
}

async function processTable(): Promise<Map<number, number> | null> {
  const result = await runDiagnostic("ps", ["-ww", "-axo", "pid=,ppid="]);
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
