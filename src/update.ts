import { randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import {
  chmodSync,
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  ftruncateSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import type { Stats } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join } from "node:path";
import type { ChildProcess, SpawnOptions } from "node:child_process";

import type { ClientUpdate } from "./types.js";

import { flockSync } from "fs-ext-extra-prebuilt";

export const UPDATE_CACHE_SCHEMA_VERSION = 1 as const;
export const UPDATE_CACHE_TTL_MS = 24 * 60 * 60 * 1_000;
export const UPDATE_CACHE_FUTURE_SKEW_MS = 5 * 60 * 1_000;
export const UPDATE_CACHE_MAX_BYTES = 4_096;
export const UPDATE_RESPONSE_MAX_BYTES = 64 * 1_024;
export const UPDATE_REQUEST_TIMEOUT_MS = 5_000;
export const UPDATE_REGISTRY_URL = "https://registry.npmjs.org/codex-unlock/latest";
export const UPDATE_NOTICE_ENV = "CODEX_UNLOCK_NO_UPDATE_NOTICE";
export const UPDATE_REFRESH_ARG = "--_refresh-update-cache";

const STABLE_VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const MAX_VERSION_LENGTH = 64;
const TRUE_VALUES = new Set(["1", "true", "yes", "on"]);

export interface UpdateCacheRecord {
  schemaVersion: typeof UPDATE_CACHE_SCHEMA_VERSION;
  latest: string;
  checkedAt: string;
}

export interface UpdateCacheLocation {
  directory: string;
  cacheFile: string;
  lockFile: string;
}

export type UpdateCacheObservation =
  | { status: "fresh"; record: UpdateCacheRecord }
  | { status: "missing" | "stale" | "invalid" | "unavailable"; reason: string };

export type UpdateCacheWriteResult =
  | { status: "written"; record: UpdateCacheRecord }
  | { status: "error"; reason: string };

export interface UpdateRefreshLease {
  release(): void;
}

export type UpdateRefreshLeaseAttempt =
  | { status: "acquired"; lease: UpdateRefreshLease }
  | { status: "contended" }
  | { status: "unavailable"; reason: string };

export type FetchLatestResult =
  | { status: "ok"; record: UpdateCacheRecord }
  | {
      status: "error";
      reason:
        | "timeout"
        | "network_error"
        | "redirect_rejected"
        | "registry_error"
        | "invalid_content_type"
        | "response_too_large"
        | "invalid_response";
    };

export interface FetchLatestOptions {
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  maxResponseBytes?: number;
  nowMs?: number;
}

export interface RefreshUpdateCacheOptions extends FetchLatestOptions {
  location?: UpdateCacheLocation;
}

export type RefreshUpdateCacheResult =
  | { status: "updated"; record: UpdateCacheRecord }
  | { status: "skipped"; reason: "refresh_in_progress" }
  | { status: "error"; reason: string };

export interface UpdateAutomationContext {
  json: boolean;
  noUpdateNotice: boolean;
  stdoutIsTTY: boolean;
  stderrIsTTY: boolean;
  environment?: NodeJS.ProcessEnv;
}

export interface UpdateAutomationPolicy {
  disabled: boolean;
  readCache: boolean;
  attachJson: boolean;
  showHumanNotice: boolean;
  scheduleRefresh: boolean;
}

export type UpdateInstallation = "registry" | "npx" | "source";

export interface UpdateGuidanceContext {
  environment?: NodeJS.ProcessEnv;
  cliPath?: string;
  sourceCheckout?: boolean;
}

export interface PreparedUpdateAdvisory {
  clientUpdate: ClientUpdate | null;
  humanNotice: string | null;
  scheduleRefresh: boolean;
}

export interface PrepareUpdateAdvisoryOptions extends UpdateAutomationContext {
  currentVersion: string;
  location?: UpdateCacheLocation;
  nowMs?: number;
  guidance?: UpdateGuidanceContext;
}

export interface ScheduleUpdateRefreshOptions {
  executable?: string;
  cliPath: string;
  environment?: NodeJS.ProcessEnv;
  spawnImpl?: (
    command: string,
    args: readonly string[],
    options: SpawnOptions,
  ) => ChildProcess;
}

function errno(error: unknown): string | undefined {
  return (error as NodeJS.ErrnoException).code;
}

function currentUid(): number | null {
  return process.getuid?.() ?? null;
}

function noFollowFlag(): number {
  return constants.O_NOFOLLOW ?? 0;
}

function privateDirectory(path: string, uid: number): boolean {
  const value = lstatSync(path);
  return (
    value.isDirectory() &&
    !value.isSymbolicLink() &&
    value.uid === uid &&
    (value.mode & 0o077) === 0
  );
}

function privateRegularFile(value: Stats, uid: number): boolean {
  return (
    value.isFile() &&
    value.uid === uid &&
    value.nlink === 1 &&
    (value.mode & 0o077) === 0
  );
}

function ensurePrivateDirectory(path: string, uid: number): string | null {
  try {
    mkdirSync(path, { recursive: true, mode: 0o700 });
    const initial = lstatSync(path);
    if (
      !initial.isDirectory() ||
      initial.isSymbolicLink() ||
      initial.uid !== uid
    ) {
      return "cache_directory_is_unsafe";
    }
    if ((initial.mode & 0o077) !== 0) chmodSync(path, 0o700);
    return privateDirectory(path, uid) ? null : "cache_directory_is_not_private";
  } catch {
    return "cache_directory_unavailable";
  }
}

function strictRecord(value: unknown): UpdateCacheRecord | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  if (keys.join("\0") !== ["checkedAt", "latest", "schemaVersion"].join("\0")) {
    return null;
  }
  if (
    record.schemaVersion !== UPDATE_CACHE_SCHEMA_VERSION ||
    typeof record.latest !== "string" ||
    stableVersion(record.latest) === null ||
    typeof record.checkedAt !== "string"
  ) {
    return null;
  }
  const checkedAtMs = Date.parse(record.checkedAt);
  if (!Number.isFinite(checkedAtMs) || new Date(checkedAtMs).toISOString() !== record.checkedAt) {
    return null;
  }
  return {
    schemaVersion: UPDATE_CACHE_SCHEMA_VERSION,
    latest: record.latest,
    checkedAt: record.checkedAt,
  };
}

function validateExistingTarget(path: string, uid: number): string | null {
  try {
    const value = lstatSync(path);
    if (
      !value.isFile() ||
      value.isSymbolicLink() ||
      value.uid !== uid ||
      value.nlink !== 1 ||
      (value.mode & 0o077) !== 0
    ) {
      return "cache_target_is_unsafe";
    }
    return null;
  } catch (error) {
    return errno(error) === "ENOENT" ? null : "cache_target_unavailable";
  }
}

function contentionError(error: unknown): boolean {
  const code = errno(error);
  return code === "EAGAIN" || code === "EACCES" || code === "EWOULDBLOCK";
}

function environmentFlag(value: string | undefined): boolean {
  return value !== undefined && TRUE_VALUES.has(value.trim().toLowerCase());
}

export function stableVersion(value: unknown): string | null {
  if (typeof value !== "string" || value.length > MAX_VERSION_LENGTH) return null;
  return STABLE_VERSION.test(value) ? value : null;
}

export function compareStableVersions(left: string, right: string): -1 | 0 | 1 {
  if (stableVersion(left) === null || stableVersion(right) === null) {
    throw new Error("stable semantic versions are required");
  }
  const leftParts = left.split(".").map((part) => BigInt(part));
  const rightParts = right.split(".").map((part) => BigInt(part));
  for (let index = 0; index < leftParts.length; index += 1) {
    if (leftParts[index] < rightParts[index]) return -1;
    if (leftParts[index] > rightParts[index]) return 1;
  }
  return 0;
}

export function updateCacheLocation(
  environment: NodeJS.ProcessEnv = process.env,
  userHome: string = homedir(),
): UpdateCacheLocation {
  const configured = environment.XDG_CACHE_HOME;
  const root = configured && isAbsolute(configured) ? configured : join(userHome, ".cache");
  const directory = join(root, "codex-unlock");
  return {
    directory,
    cacheFile: join(directory, "update.json"),
    lockFile: join(directory, "update.lock"),
  };
}

export function readUpdateCache(
  location: UpdateCacheLocation = updateCacheLocation(),
  nowMs: number = Date.now(),
): UpdateCacheObservation {
  const uid = currentUid();
  if (uid === null) return { status: "unavailable", reason: "current_user_is_unavailable" };
  if (!Number.isFinite(nowMs) || nowMs < 0) {
    return { status: "unavailable", reason: "current_time_is_invalid" };
  }

  try {
    if (!privateDirectory(location.directory, uid)) {
      return { status: "invalid", reason: "cache_directory_is_not_private" };
    }
  } catch (error) {
    return errno(error) === "ENOENT"
      ? { status: "missing", reason: "cache_directory_missing" }
      : { status: "unavailable", reason: "cache_directory_unavailable" };
  }

  let descriptor: number | undefined;
  try {
    descriptor = openSync(location.cacheFile, constants.O_RDONLY | noFollowFlag());
    const before = fstatSync(descriptor);
    if (!privateRegularFile(before, uid)) {
      return { status: "invalid", reason: "cache_file_is_not_private" };
    }
    if (before.size <= 0 || before.size > UPDATE_CACHE_MAX_BYTES) {
      return { status: "invalid", reason: "cache_size_is_invalid" };
    }
    const bytes = readFileSync(descriptor);
    if (bytes.length <= 0 || bytes.length > UPDATE_CACHE_MAX_BYTES) {
      return { status: "invalid", reason: "cache_size_is_invalid" };
    }
    const after = fstatSync(descriptor);
    if (
      before.dev !== after.dev ||
      before.ino !== after.ino ||
      before.size !== after.size ||
      before.mtimeMs !== after.mtimeMs
    ) {
      return { status: "invalid", reason: "cache_changed_during_read" };
    }
    const record = strictRecord(JSON.parse(bytes.toString("utf8")));
    if (record === null) return { status: "invalid", reason: "cache_record_is_invalid" };
    const checkedAtMs = Date.parse(record.checkedAt);
    if (checkedAtMs > nowMs + UPDATE_CACHE_FUTURE_SKEW_MS) {
      return { status: "invalid", reason: "cache_timestamp_is_in_the_future" };
    }
    if (nowMs - checkedAtMs > UPDATE_CACHE_TTL_MS) {
      return { status: "stale", reason: "cache_record_is_stale" };
    }
    return { status: "fresh", record };
  } catch (error) {
    if (errno(error) === "ENOENT") return { status: "missing", reason: "cache_file_missing" };
    if (errno(error) === "ELOOP") return { status: "invalid", reason: "cache_file_is_symlink" };
    if (error instanceof SyntaxError) {
      return { status: "invalid", reason: "cache_record_is_invalid" };
    }
    return { status: "unavailable", reason: "cache_read_failed" };
  } finally {
    if (descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch {
        // A failed close cannot make cache data authoritative.
      }
    }
  }
}

export function writeUpdateCache(
  latest: string,
  location: UpdateCacheLocation = updateCacheLocation(),
  nowMs: number = Date.now(),
): UpdateCacheWriteResult {
  const uid = currentUid();
  if (uid === null) return { status: "error", reason: "current_user_is_unavailable" };
  if (stableVersion(latest) === null) {
    return { status: "error", reason: "latest_version_is_invalid" };
  }
  if (!Number.isFinite(nowMs) || nowMs < 0) {
    return { status: "error", reason: "current_time_is_invalid" };
  }
  const directoryError = ensurePrivateDirectory(location.directory, uid);
  if (directoryError) return { status: "error", reason: directoryError };
  const targetError = validateExistingTarget(location.cacheFile, uid);
  if (targetError) return { status: "error", reason: targetError };

  const record: UpdateCacheRecord = {
    schemaVersion: UPDATE_CACHE_SCHEMA_VERSION,
    latest,
    checkedAt: new Date(nowMs).toISOString(),
  };
  const bytes = Buffer.from(`${JSON.stringify(record)}\n`, "utf8");
  if (bytes.length > UPDATE_CACHE_MAX_BYTES) {
    return { status: "error", reason: "cache_record_is_oversized" };
  }

  const temporary = join(
    location.directory,
    `.update.json.${process.pid}.${randomBytes(12).toString("hex")}.tmp`,
  );
  let descriptor: number | undefined;
  let directoryDescriptor: number | undefined;
  let renamed = false;
  try {
    descriptor = openSync(
      temporary,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | noFollowFlag(),
      0o600,
    );
    const value = fstatSync(descriptor);
    if (!privateRegularFile(value, uid)) throw new Error("temporary_cache_file_is_unsafe");
    writeFileSync(descriptor, bytes);
    fchmodSync(descriptor, 0o600);
    fsyncSync(descriptor);
    closeSync(descriptor);
    descriptor = undefined;

    const finalTargetError = validateExistingTarget(location.cacheFile, uid);
    if (finalTargetError) return { status: "error", reason: finalTargetError };
    renameSync(temporary, location.cacheFile);
    renamed = true;
    directoryDescriptor = openSync(
      location.directory,
      constants.O_RDONLY | (constants.O_DIRECTORY ?? 0),
    );
    fsyncSync(directoryDescriptor);
    closeSync(directoryDescriptor);
    directoryDescriptor = undefined;

    const finalDescriptor = openSync(location.cacheFile, constants.O_RDONLY | noFollowFlag());
    try {
      if (!privateRegularFile(fstatSync(finalDescriptor), uid)) {
        return { status: "error", reason: "cache_file_is_not_private" };
      }
    } finally {
      closeSync(finalDescriptor);
    }
    return { status: "written", record };
  } catch {
    return { status: "error", reason: "cache_write_failed" };
  } finally {
    if (descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch {
        // Cleanup continues with the temporary name.
      }
    }
    if (directoryDescriptor !== undefined) {
      try {
        closeSync(directoryDescriptor);
      } catch {
        // The cache write already failed closed.
      }
    }
    if (!renamed) {
      try {
        unlinkSync(temporary);
      } catch {
        // The temporary name may not have been created.
      }
    }
  }
}

export function acquireUpdateRefreshLease(
  location: UpdateCacheLocation = updateCacheLocation(),
): UpdateRefreshLeaseAttempt {
  const uid = currentUid();
  if (uid === null) {
    return { status: "unavailable", reason: "current_user_is_unavailable" };
  }
  const directoryError = ensurePrivateDirectory(location.directory, uid);
  if (directoryError) return { status: "unavailable", reason: directoryError };

  let descriptor: number | undefined;
  try {
    descriptor = openSync(
      location.lockFile,
      constants.O_CREAT | constants.O_RDWR | noFollowFlag(),
      0o600,
    );
    const value = fstatSync(descriptor);
    if (!privateRegularFile(value, uid)) {
      closeSync(descriptor);
      return { status: "unavailable", reason: "refresh_lock_is_not_private" };
    }
    fchmodSync(descriptor, 0o600);
    try {
      flockSync(descriptor, "exnb");
    } catch (error) {
      closeSync(descriptor);
      return contentionError(error)
        ? { status: "contended" }
        : { status: "unavailable", reason: "refresh_lock_failed" };
    }
    try {
      ftruncateSync(descriptor, 0);
      fsyncSync(descriptor);
    } catch {
      try {
        flockSync(descriptor, "un");
      } catch {
        // Closing below remains the lock-release fallback.
      }
      closeSync(descriptor);
      return { status: "unavailable", reason: "refresh_lock_prepare_failed" };
    }
    const heldDescriptor = descriptor;
    let released = false;
    return {
      status: "acquired",
      lease: {
        release(): void {
          if (released) return;
          released = true;
          try {
            flockSync(heldDescriptor, "un");
          } catch {
            // Closing the descriptor still releases the advisory lock.
          } finally {
            try {
              closeSync(heldDescriptor);
            } catch {
              // Process exit is the final descriptor cleanup fallback.
            }
          }
        },
      },
    };
  } catch (error) {
    if (descriptor !== undefined) {
      try {
        closeSync(descriptor);
      } catch {
        // The descriptor may have been closed during validation.
      }
    }
    return {
      status: "unavailable",
      reason: errno(error) === "ELOOP" ? "refresh_lock_is_symlink" : "refresh_lock_unavailable",
    };
  }
}

async function boundedResponseBytes(response: Response, maximumBytes: number): Promise<Buffer> {
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null) {
    const parsed = Number(contentLength);
    if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > maximumBytes) {
      throw new Error("response_too_large");
    }
  }
  if (response.body === null) throw new Error("invalid_response");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    while (true) {
      const value = await reader.read();
      if (value.done) break;
      bytes += value.value.byteLength;
      if (bytes > maximumBytes) {
        await reader.cancel().catch(() => undefined);
        throw new Error("response_too_large");
      }
      chunks.push(value.value);
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)), bytes);
}

async function fetchNpmLatestUnchecked(
  fetchImpl: typeof fetch,
  signal: AbortSignal,
  maximumBytes: number,
  nowMs: number,
): Promise<FetchLatestResult> {
  const response = await fetchImpl(UPDATE_REGISTRY_URL, {
    method: "GET",
    redirect: "error",
    signal,
    headers: { accept: "application/json" },
  });
  if (response.redirected || (response.url !== "" && response.url !== UPDATE_REGISTRY_URL)) {
    return { status: "error", reason: "redirect_rejected" };
  }
  if (response.status >= 300 && response.status < 400) {
    return { status: "error", reason: "redirect_rejected" };
  }
  if (!response.ok) return { status: "error", reason: "registry_error" };
  const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
  if (!contentType.startsWith("application/json")) {
    return { status: "error", reason: "invalid_content_type" };
  }

  let bytes: Buffer;
  try {
    bytes = await boundedResponseBytes(response, maximumBytes);
  } catch (error) {
    return {
      status: "error",
      reason: error instanceof Error && error.message === "response_too_large"
        ? "response_too_large"
        : "invalid_response",
    };
  }
  try {
    const value = JSON.parse(bytes.toString("utf8")) as unknown;
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      return { status: "error", reason: "invalid_response" };
    }
    const version = (value as Record<string, unknown>).version;
    if (stableVersion(version) === null) {
      return { status: "error", reason: "invalid_response" };
    }
    return {
      status: "ok",
      record: {
        schemaVersion: UPDATE_CACHE_SCHEMA_VERSION,
        latest: version as string,
        checkedAt: new Date(nowMs).toISOString(),
      },
    };
  } catch {
    return { status: "error", reason: "invalid_response" };
  }
}

export async function fetchNpmLatest(
  options: FetchLatestOptions = {},
): Promise<FetchLatestResult> {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const timeoutMs = options.timeoutMs ?? UPDATE_REQUEST_TIMEOUT_MS;
  const maximumBytes = options.maxResponseBytes ?? UPDATE_RESPONSE_MAX_BYTES;
  const nowMs = options.nowMs ?? Date.now();
  if (
    typeof fetchImpl !== "function" ||
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs <= 0 ||
    !Number.isSafeInteger(maximumBytes) ||
    maximumBytes <= 0 ||
    !Number.isFinite(nowMs) ||
    nowMs < 0
  ) {
    return { status: "error", reason: "invalid_response" };
  }

  const controller = new AbortController();
  let timedOut = false;
  let timeout: NodeJS.Timeout | undefined;
  const deadline = new Promise<FetchLatestResult>((resolve) => {
    timeout = setTimeout(() => {
      timedOut = true;
      controller.abort();
      resolve({ status: "error", reason: "timeout" });
    }, timeoutMs);
  });
  try {
    const request = fetchNpmLatestUnchecked(
      fetchImpl,
      controller.signal,
      maximumBytes,
      nowMs,
    ).catch((): FetchLatestResult => ({
      status: "error",
      reason: timedOut ? "timeout" : "network_error",
    }));
    return await Promise.race([request, deadline]);
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}

export async function refreshUpdateCache(
  options: RefreshUpdateCacheOptions = {},
): Promise<RefreshUpdateCacheResult> {
  const location = options.location ?? updateCacheLocation();
  const leaseAttempt = acquireUpdateRefreshLease(location);
  if (leaseAttempt.status === "contended") {
    return { status: "skipped", reason: "refresh_in_progress" };
  }
  if (leaseAttempt.status === "unavailable") {
    return { status: "error", reason: leaseAttempt.reason };
  }
  try {
    const fetched = await fetchNpmLatest(options);
    if (fetched.status === "error") return fetched;
    const written = writeUpdateCache(
      fetched.record.latest,
      location,
      Date.parse(fetched.record.checkedAt),
    );
    return written.status === "written"
      ? { status: "updated", record: written.record }
      : written;
  } finally {
    leaseAttempt.lease.release();
  }
}

export function updateAutomationPolicy(
  context: UpdateAutomationContext,
): UpdateAutomationPolicy {
  const environment = context.environment ?? process.env;
  const disabled =
    context.noUpdateNotice || environmentFlag(environment[UPDATE_NOTICE_ENV]);
  if (disabled) {
    return {
      disabled: true,
      readCache: false,
      attachJson: false,
      showHumanNotice: false,
      scheduleRefresh: false,
    };
  }
  const ci = environmentFlag(environment.CI);
  const interactive = context.stdoutIsTTY && context.stderrIsTTY;
  return {
    disabled: false,
    readCache: context.json || (!ci && context.stderrIsTTY),
    attachJson: context.json,
    showHumanNotice: !context.json && !ci && context.stderrIsTTY,
    scheduleRefresh: !ci && interactive,
  };
}

export function updateInstallation(
  context: UpdateGuidanceContext = {},
): UpdateInstallation {
  if (context.sourceCheckout === true) return "source";
  const environment = context.environment ?? process.env;
  const cliPath = context.cliPath ?? process.argv[1] ?? "";
  if (
    environment.npm_command === "exec" ||
    environment.npm_lifecycle_event === "npx" ||
    /(?:^|[/\\])_npx(?:[/\\]|$)/.test(cliPath)
  ) {
    return "npx";
  }
  return "registry";
}

export function updateCommand(context: UpdateGuidanceContext = {}): string {
  const installation = updateInstallation(context);
  if (installation === "source") {
    return "git -C <source-checkout> pull --ff-only && npm --prefix <source-checkout> ci";
  }
  if (installation === "npx") return "npx --yes codex-unlock@latest";
  return "npm install --global codex-unlock@latest";
}

export function prepareUpdateAdvisory(
  options: PrepareUpdateAdvisoryOptions,
): PreparedUpdateAdvisory {
  const policy = updateAutomationPolicy(options);
  if (policy.disabled) {
    return { clientUpdate: null, humanNotice: null, scheduleRefresh: false };
  }

  const observation = policy.readCache
    ? readUpdateCache(options.location, options.nowMs)
    : { status: "missing" as const, reason: "cache_read_suppressed" };
  const command = updateCommand(options.guidance);
  let clientUpdate: ClientUpdate | null = null;
  let humanNotice: string | null = null;
  if (
    observation.status === "fresh" &&
    stableVersion(options.currentVersion) !== null &&
    compareStableVersions(options.currentVersion, observation.record.latest) < 0
  ) {
    clientUpdate = {
      schemaVersion: UPDATE_CACHE_SCHEMA_VERSION,
      source: "npm",
      currentVersion: options.currentVersion,
      latestVersion: observation.record.latest,
      checkedAt: observation.record.checkedAt,
      updateAvailable: true,
      updateCommand: command,
    };
    if (policy.showHumanNotice) {
      humanNotice =
        `Update available: ${options.currentVersion} → ${observation.record.latest}. ` +
        `Run: ${command}`;
    }
  }

  return {
    clientUpdate: policy.attachJson ? clientUpdate : null,
    humanNotice,
    scheduleRefresh: policy.scheduleRefresh && observation.status !== "fresh",
  };
}

export function withClientUpdate<T extends object>(
  value: T,
  clientUpdate: ClientUpdate | null,
): T | (T & { clientUpdate: ClientUpdate }) {
  return clientUpdate === null ? value : { ...value, clientUpdate };
}

export function emitHumanUpdateNotice(
  notice: string | null,
  write: (value: string) => unknown = (value) => process.stderr.write(value),
): void {
  if (notice === null) return;
  try {
    write(`${notice}\n`);
  } catch {
    // Advisory output cannot change the primary command result.
  }
}

export function scheduleUpdateRefresh(
  options: ScheduleUpdateRefreshOptions,
): boolean {
  try {
    const spawnImpl = options.spawnImpl ?? spawn;
    const child = spawnImpl(
      options.executable ?? process.execPath,
      [options.cliPath, UPDATE_REFRESH_ARG],
      {
        detached: true,
        stdio: "ignore",
        env: options.environment ?? process.env,
      },
    );
    child.once("error", () => undefined);
    child.unref();
    return true;
  } catch {
    return false;
  }
}
