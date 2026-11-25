import { closeSync, constants, openSync, opendirSync, readSync, readlinkSync, realpathSync, statSync, statfsSync } from "node:fs";
import { performance } from "node:perf_hooks";
import { createHash } from "node:crypto";

// A positive row proves participation by an open description, not exclusive
// lifetime control: inherited and otherwise hidden references remain possible.
const BYTE_LIMIT = 65536;
const FD_LIMIT = 256;
const BUDGET_MS = 25;
const FILESYSTEMS = new Set([0xef53n, 0x01021994n, 0x58465342n]); // ext, tmpfs, XFS

export interface LinuxParticipation { pid: number; startTicks: string; descriptor: string }
export interface LinuxPreparation {
  pid: number; descriptors: string[]; candidates: string[];
  targetPath: string; mountNamespace: string; startTicks: string; commandFingerprint: string; uid: bigint;
}

function checkDeadline(deadline: number): void {
  if (performance.now() > deadline) throw new Error("linux_attribution_budget");
}

function boundedBytes(path: string, deadline = performance.now() + BUDGET_MS): Buffer {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
  try {
    const buffer = Buffer.alloc(BYTE_LIMIT + 1);
    let used = 0;
    while (used < buffer.length) {
      checkDeadline(deadline);
      const count = readSync(fd, buffer, used, buffer.length - used, null);
      if (count === 0) break;
      used += count;
    }
    if (used > BYTE_LIMIT) throw new Error("linux_attribution_truncated");
    return buffer.subarray(0, used);
  } finally { closeSync(fd); }
}

function boundedRead(path: string, deadline = performance.now() + BUDGET_MS): string {
  return boundedBytes(path, deadline).toString("utf8");
}

export function fingerprintCommand(commandLine: Uint8Array, executable: string): string {
  return createHash("sha256").update(executable).update("\0").update(commandLine).digest("hex");
}

export function linuxCommandFingerprint(pid: number, deadline = performance.now() + BUDGET_MS): string {
  const executable = readlinkSync(`/proc/${pid}/exe`);
  if (!executable.startsWith("/") || executable.endsWith(" (deleted)")) throw new Error("linux_image_unverified");
  const commandLine = boundedBytes(`/proc/${pid}/cmdline`, deadline);
  if (!commandLine.length) throw new Error("linux_command_unverified");
  checkDeadline(deadline);
  return fingerprintCommand(commandLine, executable);
}

export function parseStartTicks(text: string, pid: number): string {
  const end = text.lastIndexOf(") ");
  if (!text.startsWith(`${pid} (`) || end < 0) throw new Error("linux_identity_malformed");
  const fields = text.slice(end + 2).trim().split(/\s+/);
  if (fields[0] === "Z" || fields[0] === "X" || !/^\d+$/.test(fields[19] ?? "")) {
    throw new Error("linux_identity_unavailable");
  }
  return fields[19];
}

export function parseFlockRows(text: string): { major: bigint; minor: bigint; inode: bigint }[] {
  const rows = [];
  for (const line of text.split("\n")) {
    if (!line.startsWith("lock:")) continue;
    const match = /^lock:\s+\d+:\s+FLOCK\s+ADVISORY\s+WRITE\s+-?\d+\s+([\da-f]+):([\da-f]+):(\d+)\s+0\s+EOF\s*$/i.exec(line);
    // Any other lock row is unsupported, never negative evidence of absence.
    if (!match) throw new Error("linux_lock_row_unsupported");
    const row = { major: BigInt(`0x${match[1]}`), minor: BigInt(`0x${match[2]}`), inode: BigInt(match[3]) };
    if (row.major > 0xffffffffn || row.minor > 0xffffffffn || row.inode > 0xffffffffffffffffn) {
      throw new Error("linux_lock_row_unsupported");
    }
    rows.push(row);
  }
  return rows;
}

function checkNamespace(): void {
  if (statfsSync("/proc", { bigint: true }).type !== 0x9fa0n) throw new Error("linux_proc_filesystem_untrusted");
  assertProcNamespace(readlinkSync("/proc/self"), process.pid);
}

export function assertProcNamespace(procSelf: string, pid: number): void {
  if (procSelf !== String(pid)) throw new Error("linux_proc_namespace_mismatch");
}

function descriptors(pid: number, deadline: number): string[] {
  const directory = opendirSync(`/proc/${pid}/fd`, { bufferSize: 1 });
  const entries: string[] = [];
  let seen = 0;
  try {
    while (true) {
      checkDeadline(deadline);
      const entry = directory.readSync();
      if (!entry) break;
      seen += 1;
      if (seen > FD_LIMIT || !/^\d+$/.test(entry.name)) throw new Error("linux_descriptor_limit");
      // Self-observation's directory cursor is an observer-created descriptor,
      // not candidate evidence. Production policy separately refuses our family.
      if (pid === process.pid && readlinkSync(`/proc/${pid}/fd/${entry.name}`) === `/proc/${pid}/fd`) continue;
      entries.push(entry.name);
    }
  } finally { directory.closeSync(); }
  return entries.sort((a, b) => Number(a) - Number(b));
}

export function filterCandidateDescriptors(
  pid: number, names: string[], targetPath: string, deadline: number,
  readLink: (path: string) => string = readlinkSync,
): string[] {
  const candidates: string[] = [];
  for (const name of names) {
    checkDeadline(deadline);
    const target = readLink(`/proc/${pid}/fd/${name}`);
    if (target === `${targetPath} (deleted)`) throw new Error("linux_target_deleted");
    if (target === targetPath) candidates.push(name);
  }
  return candidates;
}

export function prepareLinuxParticipation(pid: number, lockPath: string): LinuxPreparation {
  const deadline = performance.now() + BUDGET_MS;
  checkNamespace();
  const uid = process.getuid?.();
  if (!Number.isSafeInteger(pid) || pid <= 0 || uid === undefined) throw new Error("linux_identity_unavailable");
  const directory = statSync(`/proc/${pid}`, { bigint: true });
  if (directory.uid !== BigInt(uid)) throw new Error("linux_uid_mismatch");
  const mountNamespace = readlinkSync("/proc/self/ns/mnt");
  if (readlinkSync(`/proc/${pid}/ns/mnt`) !== mountNamespace) throw new Error("linux_mount_namespace_mismatch");
  const targetPath = realpathSync.native(lockPath);
  const names = descriptors(pid, deadline);
  // Paths only exclude unrelated descriptions. Never stat an unrelated FD:
  // it may point at a blocking FUSE/NFS filesystem while coordination is held.
  const candidates = filterCandidateDescriptors(pid, names, targetPath, deadline);
  checkDeadline(deadline);
  return { pid, uid: directory.uid, targetPath, mountNamespace, candidates,
    startTicks: parseStartTicks(boundedRead(`/proc/${pid}/stat`, deadline), pid),
    commandFingerprint: linuxCommandFingerprint(pid, deadline), descriptors: names };
}

export function linuxStartTicks(pid: number): string {
  checkNamespace();
  return parseStartTicks(boundedRead(`/proc/${pid}/stat`), pid);
}

/** Called synchronously under native coordination, after independent held probe. */
export function verifyLinuxParticipation(lockPath: string, prepared: LinuxPreparation): LinuxParticipation {
  const deadline = performance.now() + BUDGET_MS;
  const checkBudget = (): void => { if (performance.now() > deadline) throw new Error("linux_attribution_budget"); };
  checkNamespace();
  if (!FILESYSTEMS.has(statfsSync(lockPath, { bigint: true }).type)) throw new Error("linux_filesystem_unsupported");
  const target = statSync(lockPath, { bigint: true });
  if (!target.isFile() || target.nlink !== 1n || target.uid !== prepared.uid) throw new Error("linux_target_changed");
  const validateIdentity = (): void => {
    checkBudget();
    if (statSync(`/proc/${prepared.pid}`, { bigint: true }).uid !== prepared.uid ||
      readlinkSync("/proc/self/ns/mnt") !== prepared.mountNamespace ||
      readlinkSync(`/proc/${prepared.pid}/ns/mnt`) !== prepared.mountNamespace ||
      parseStartTicks(boundedRead(`/proc/${prepared.pid}/stat`, deadline), prepared.pid) !== prepared.startTicks ||
      linuxCommandFingerprint(prepared.pid, deadline) !== prepared.commandFingerprint ||
      JSON.stringify(descriptors(prepared.pid, deadline)) !== JSON.stringify(prepared.descriptors)) {
      throw new Error("linux_identity_changed");
    }
  };
  validateIdentity();
  const matches: string[] = [];
  for (const descriptor of prepared.candidates) {
    checkBudget();
    const path = `/proc/${prepared.pid}/fd/${descriptor}`;
    if (!prepared.descriptors.includes(descriptor) || readlinkSync(path) !== prepared.targetPath) throw new Error("linux_descriptor_changed");
    const before = statSync(path, { bigint: true });
    if (before.dev !== target.dev || before.ino !== target.ino) throw new Error("linux_descriptor_changed");
    const rows = parseFlockRows(boundedRead(`/proc/${prepared.pid}/fdinfo/${descriptor}`, deadline));
    const after = statSync(path, { bigint: true });
    if (readlinkSync(path) !== prepared.targetPath || before.dev !== after.dev || before.ino !== after.ino) throw new Error("linux_descriptor_changed");
    const major = ((target.dev >> 8n) & 0xfffn) | ((target.dev >> 32n) & 0xfffff000n);
    const minor = (target.dev & 0xffn) | ((target.dev >> 12n) & 0xffffff00n);
    if (rows.some((row) => row.major !== major || row.minor !== minor || row.inode !== target.ino)) throw new Error("linux_row_identity_mismatch");
    if (rows.length === 1) matches.push(descriptor);
    else if (rows.length > 1) throw new Error("linux_rows_ambiguous");
  }
  validateIdentity();
  const after = statSync(lockPath, { bigint: true });
  if (!after.isFile() || after.nlink !== 1n || after.uid !== prepared.uid ||
    after.dev !== target.dev || after.ino !== target.ino || matches.length !== 1) throw new Error("linux_participation_unproven");
  checkBudget();
  return { pid: prepared.pid, startTicks: prepared.startTicks, descriptor: matches[0] };
}
