#!/usr/bin/env node

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { defaultOptions, inspectThread, listThreads, unlockThread } from "./doctor.js";
import { isThreadId } from "./options.js";
import {
  SCHEMA_VERSION,
  type CliErrorCode,
  type CliErrorResult,
  type CheckUpdateResult,
  type CommandName,
  type DoctorOptions,
  type InspectionResult,
  type ListResult,
  type UnlockResult,
} from "./types.js";
import {
  UPDATE_REFRESH_ARG,
  checkForUpdate,
  compareStableVersions,
  emitHumanUpdateNotice,
  prepareUpdateAdvisory,
  refreshUpdateCache,
  scheduleUpdateRefresh,
  updateCommand,
  withClientUpdate,
  type PreparedUpdateAdvisory,
} from "./update.js";
import { errorText } from "./util.js";

const HELP = `codex-unlock - diagnose and safely release Codex thread writer locks

Usage:
  codex-unlock list [options]
  codex-unlock inspect <thread-id> [options]
  codex-unlock unlock <thread-id> [options]
  codex-unlock check-update [options]

Options:
  --json                   Emit machine-readable JSON
  --codex-home <path>      Codex home (default: CODEX_HOME or ~/.codex)
  --stability-ms <ms>      Observation window, 250..30000 (default: 1000)
  --timeout-ms <ms>        SIGTERM wait, 100..60000 (default: 5000)
  --no-update-notice       Disable update notices and automatic refresh
  -h, --help               Show help
  -v, --version            Show version

Safety:
  list and inspect leave files unchanged and briefly take the native coordinator.
  unlock never deletes a lock file and never
  sends SIGKILL. It refuses unless the lock has one stable Codex owner, that
  owner holds no other thread locks, and the stable transcript ends in
  task_complete. Shared app-server and Remote Control owners are refused.
`;

interface ParsedArguments {
  command: CommandName;
  threadId?: string;
  json: boolean;
  noUpdateNotice: boolean;
  options: DoctorOptions;
}

const VALUE_OPTIONS = new Set(["--codex-home", "--stability-ms", "--timeout-ms"]);

function isCommandName(value: string | undefined): value is CommandName {
  return value === "list" || value === "inspect" || value === "unlock" || value === "check-update";
}

function requestedCommand(argv: string[]): CommandName | null {
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (VALUE_OPTIONS.has(argument)) {
      index += 1;
    } else if (!argument.startsWith("-")) {
      return isCommandName(argument) ? argument : null;
    }
  }
  return null;
}

function optionValue(value: string | undefined): string | undefined {
  return value === undefined || value.startsWith("-") ? undefined : value;
}

function cliError(
  command: CommandName | null,
  errorCode: CliErrorCode,
  exitCode: 3 | 64,
  message: string,
): CliErrorResult {
  return {
    schemaVersion: SCHEMA_VERSION,
    command,
    status: "error",
    error: message,
    errorCode,
    exitCode,
    retryable: false,
    suggestedAction:
      errorCode === "invalid_usage" ? "Run codex-unlock --help for usage." : null,
  };
}

function packageVersion(): string {
  const manifest = JSON.parse(
    readFileSync(new URL("../package.json", import.meta.url), "utf8"),
  ) as { version?: unknown };
  if (typeof manifest.version !== "string") {
    throw new Error("package.json does not contain a version");
  }
  return manifest.version;
}

function integerOption(name: string, value: string | undefined, min: number, max: number): number {
  if (value === undefined || !/^\d+$/.test(value)) {
    throw new Error(`${name} requires an integer`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`${name} must be between ${min} and ${max}`);
  }
  return parsed;
}

function parseArguments(argv: string[]): ParsedArguments | "help" | "version" {
  const options = defaultOptions();
  const positional: string[] = [];
  let json = false;
  let noUpdateNotice = false;
  let doctorOptionSeen = false;
  let standalone: "help" | "version" | null = null;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--help" || argument === "-h") {
      standalone ??= "help";
    } else if (argument === "--version" || argument === "-v") {
      standalone ??= "version";
    } else if (argument === "--json") {
      json = true;
    } else if (argument === "--no-update-notice") {
      noUpdateNotice = true;
    } else if (argument === "--codex-home") {
      doctorOptionSeen = true;
      const value = optionValue(argv[++index]);
      if (!value) throw new Error("--codex-home requires a path");
      options.codexHome = resolve(value);
    } else if (argument === "--stability-ms") {
      doctorOptionSeen = true;
      options.stabilityMs = integerOption(argument, argv[++index], 250, 30_000);
    } else if (argument === "--timeout-ms") {
      doctorOptionSeen = true;
      options.terminationTimeoutMs = integerOption(argument, argv[++index], 100, 60_000);
    } else if (argument.startsWith("-")) {
      throw new Error(`unknown option: ${argument}`);
    } else {
      positional.push(argument);
    }
  }

  if (standalone !== null) {
    if (json) throw new Error(`--${standalone} cannot be combined with --json`);
    return standalone;
  }
  const command = positional.shift();
  if (command !== "list" && command !== "inspect" && command !== "unlock" && command !== "check-update") {
    throw new Error("expected command: list, inspect, unlock, or check-update");
  }
  if (command === "check-update") {
    if (positional.length > 0) throw new Error("check-update does not accept a thread id");
    if (doctorOptionSeen) throw new Error("check-update does not accept Codex lock options");
    return { command, json, noUpdateNotice, options };
  }
  if (command === "list") {
    if (positional.length > 0) throw new Error("list does not accept a thread id");
    return { command, json, noUpdateNotice, options };
  }
  const threadId = positional.shift();
  if (!threadId || positional.length > 0) {
    throw new Error(`${command} requires exactly one thread id`);
  }
  if (!isThreadId(threadId)) throw new Error(`invalid Codex thread id: ${threadId}`);
  return { command, threadId, json, noUpdateNotice, options };
}

// eslint-disable-next-line no-control-regex -- matching control characters is the purpose.
const TERMINAL_CONTROL = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/gu;
const NAMED_ESCAPES: Readonly<Record<string, string>> = { "\n": "\\n", "\r": "\\r", "\t": "\\t" };

// Human output renders externally derived text (argv, cwd, paths, transcript
// fields, error text) with visible escapes so it cannot drive the terminal or
// forge lines. JSON output is left to JSON.stringify escaping.
function terminalSafe(value: string): string {
  return value.replace(TERMINAL_CONTROL, (character) => {
    const named = NAMED_ESCAPES[character];
    if (named) return named;
    const code = character.codePointAt(0)!;
    return code <= 0xff
      ? `\\x${code.toString(16).padStart(2, "0")}`
      : `\\u${code.toString(16).padStart(4, "0")}`;
  });
}

function printable(value: string | number | null): string {
  return value === null || value === "" ? "-" : terminalSafe(String(value));
}

function printableList(values: readonly string[]): string {
  return values.map(terminalSafe).join(", ");
}

function printInspection(result: InspectionResult): void {
  console.log(`Thread:         ${result.threadId}`);
  console.log(`Classification: ${result.classification}`);
  console.log(`Lock probe:     ${result.lock.probe.status}`);
  console.log(`Lock path:      ${printable(result.lock.path)}`);
  if (result.owner) {
    console.log(`Owner PID:      ${result.owner.pid}`);
    console.log(`Owner command:  ${printable(result.owner.arguments)}`);
    console.log(`Owner start:    ${printable(result.owner.startTime)}`);
    console.log(`Owner PPID:     ${printable(result.owner.ppid)}`);
    console.log(`Owner TTY:      ${printable(result.owner.tty)}`);
    console.log(`Owner cwd:      ${printable(result.owner.cwd)}`);
  } else {
    console.log("Owner:          -");
  }
  console.log(`Transcript:     ${printable(result.transcript.path)}`);
  console.log(
    `Last event:     ${printable(result.transcript.lastRecord?.eventType ?? null)}`,
  );
  console.log(`Stable:         ${result.transcript.stable === true ? "yes" : "no"}`);
  console.log(`Safe to unlock: ${result.safeToUnlock ? "yes" : "no"}`);
  if (result.blockers.length > 0) {
    console.log(`Blockers:       ${printableList(result.blockers)}`);
  }
  if (result.warnings.length > 0) {
    console.log(`Warnings:       ${printableList(result.warnings)}`);
  }
}

function printList(result: ListResult): void {
  if (result.sessions.length === 0) {
    console.log(`No Codex thread lock files found under ${printable(result.codexHome)}.`);
    return;
  }
  const headers = ["THREAD", "CLASSIFICATION", "PROBE", "PID", "LAST EVENT", "STABLE", "SAFE"];
  const rows = result.sessions.map((session) => [
    session.threadId,
    session.classification,
    session.lock.probe.status,
    printable(session.owner?.pid ?? null),
    printable(session.transcript.lastRecord?.eventType ?? null),
    session.transcript.stable === true ? "yes" : "no",
    session.safeToUnlock ? "yes" : "no",
  ]);
  const widths = headers.map((header, index) =>
    Math.max(header.length, ...rows.map((row) => row[index].length)),
  );
  console.log(headers.map((header, index) => header.padEnd(widths[index])).join("  "));
  for (const row of rows) {
    console.log(row.map((value, index) => value.padEnd(widths[index])).join("  "));
  }
}

function printUnlock(result: UnlockResult): void {
  console.log(`Thread:               ${result.threadId}`);
  console.log(`Outcome:              ${result.outcome}`);
  console.log(`PID:                  ${printable(result.pid)}`);
  console.log(`Signal:               ${printable(result.signalSent)}`);
  console.log(`Process exited:        ${printable(result.processExited === null ? null : result.processExited ? result.processObservation?.zombie ? "yes (zombie, not yet reaped by its parent)" : "yes" : "no")}`);
  if (result.lockReacquiredBy) {
    const holders = result.lockReacquiredBy.map((holder) => holder.pid).join(", ");
    console.log(`Lock released:        no; the original owner exited and PID ${holders} now holds the lock`);
    console.log("The original owner is gone. Retrying unlock would target the new holder, not the process that was signaled.");
  } else {
    console.log(`Lock released:        ${result.lockReleased ? "yes" : "no"}`);
  }
  console.log(`Transcript unchanged: ${printable(result.transcriptUnchanged === null ? null : result.transcriptUnchanged ? "yes" : "no")}`);
  console.log("Lock file removed by codex-unlock: no");
  if (result.reasons.length > 0) {
    console.log(`Reasons:              ${printableList(result.reasons)}`);
  }
}

function sourceCheckout(): boolean {
  return existsSync(new URL("../.git", import.meta.url));
}

function prepareAutomaticAdvisory(
  json: boolean,
  noUpdateNotice: boolean,
): PreparedUpdateAdvisory {
  return prepareUpdateAdvisory({
    currentVersion: packageVersion(),
    json,
    noUpdateNotice,
    stdoutIsTTY: process.stdout.isTTY === true,
    stderrIsTTY: process.stderr.isTTY === true,
    guidance: {
      environment: process.env,
      cliPath: process.argv[1],
      sourceCheckout: sourceCheckout(),
    },
  });
}

function finishAutomaticAdvisory(advisory: PreparedUpdateAdvisory): void {
  emitHumanUpdateNotice(advisory.humanNotice);
  if (advisory.scheduleRefresh) {
    scheduleUpdateRefresh({ cliPath: process.argv[1] });
  }
}

async function checkUpdate(json: boolean): Promise<number> {
  const checked = await checkForUpdate();
  if (checked.status === "error") {
    throw new Error(`update check failed: ${checked.reason}`);
  }
  const currentVersion = packageVersion();
  const result: CheckUpdateResult = {
    schemaVersion: SCHEMA_VERSION,
    command: "check-update",
    status: "ok",
    source: "npm",
    currentVersion,
    latestVersion: checked.record.latest,
    checkedAt: checked.record.checkedAt,
    updateAvailable:
      compareStableVersions(currentVersion, checked.record.latest) < 0,
    updateCommand: updateCommand({
      environment: process.env,
      cliPath: process.argv[1],
      sourceCheckout: sourceCheckout(),
    }),
    cacheUpdated: checked.cacheUpdated,
    cacheWarning: checked.cacheWarning,
  };
  if (json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`Current version: ${result.currentVersion}`);
    console.log(`Latest version:  ${result.latestVersion}`);
    console.log(`Checked at:      ${result.checkedAt}`);
    console.log(`Update available: ${result.updateAvailable ? "yes" : "no"}`);
    if (result.updateAvailable) console.log(`Update command:   ${result.updateCommand}`);
    if (checked.cacheWarning !== null) {
      console.error(`codex-unlock: warning: update cache not updated: ${terminalSafe(checked.cacheWarning)}`);
    }
  }
  return 0;
}

async function main(): Promise<number> {
  let parsed: ParsedArguments | "help" | "version";
  try {
    parsed = parseArguments(process.argv.slice(2));
  } catch (error) {
    const wantsJson = process.argv.includes("--json");
    const advisory = prepareAutomaticAdvisory(
      wantsJson,
      process.argv.includes("--no-update-notice"),
    );
    if (wantsJson) {
      console.log(
        JSON.stringify(
          withClientUpdate(
            cliError(
              requestedCommand(process.argv.slice(2)),
              "invalid_usage",
              64,
              errorText(error),
            ),
            advisory.clientUpdate,
          ),
          null,
          2,
        ),
      );
    } else {
      console.error(`codex-unlock: ${terminalSafe(errorText(error))}`);
      console.error("Run codex-unlock --help for usage.");
    }
    finishAutomaticAdvisory(advisory);
    return 64;
  }
  if (parsed === "help") {
    process.stdout.write(HELP);
    return 0;
  }
  if (parsed === "version") {
    console.log(packageVersion());
    return 0;
  }

  if (parsed.command === "check-update") {
    try {
      return await checkUpdate(parsed.json);
    } catch (error) {
      if (parsed.json) {
        console.log(JSON.stringify(cliError("check-update", "command_failed", 3, errorText(error)), null, 2));
      } else {
        console.error(`codex-unlock: ${terminalSafe(errorText(error))}`);
      }
      return 3;
    }
  }

  const advisory = prepareAutomaticAdvisory(parsed.json, parsed.noUpdateNotice);

  try {
    if (parsed.command === "list") {
      const result = await listThreads(parsed.options);
      if (parsed.json) console.log(JSON.stringify(withClientUpdate(result, advisory.clientUpdate), null, 2));
      else printList(result);
      finishAutomaticAdvisory(advisory);
      return 0;
    }
    if (parsed.command === "inspect") {
      const result = await inspectThread(parsed.threadId!, parsed.options);
      if (parsed.json) console.log(JSON.stringify(withClientUpdate(result, advisory.clientUpdate), null, 2));
      else printInspection(result);
      finishAutomaticAdvisory(advisory);
      return 0;
    }
    const result = await unlockThread(parsed.threadId!, parsed.options);
    if (parsed.json) console.log(JSON.stringify(withClientUpdate(result, advisory.clientUpdate), null, 2));
    else printUnlock(result);
    finishAutomaticAdvisory(advisory);
    if (result.outcome === "unlocked" || result.outcome === "not_locked") return 0;
    if (result.outcome === "refused") return 2;
    return 3;
  } catch (error) {
    if (parsed.json) {
      console.log(
        JSON.stringify(
          withClientUpdate(
            cliError(parsed.command, "command_failed", 3, errorText(error)),
            advisory.clientUpdate,
          ),
          null,
          2,
        ),
      );
    } else {
      console.error(`codex-unlock: ${terminalSafe(errorText(error))}`);
    }
    finishAutomaticAdvisory(advisory);
    return 3;
  }
}

// A closed stdout (for example `codex-unlock --help | head -0`) ends output
// quietly instead of surfacing an unhandled stream error.
process.stdout.on("error", (error: NodeJS.ErrnoException) => {
  if (error.code !== "EPIPE") process.exitCode = 3;
});

if (process.argv.length === 3 && process.argv[2] === UPDATE_REFRESH_ARG) {
  await refreshUpdateCache().catch(() => undefined);
  process.exitCode = 0;
} else {
  process.exitCode = await main();
}
