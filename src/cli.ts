#!/usr/bin/env node

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { defaultOptions, inspectThread, listThreads, unlockThread } from "./doctor.js";
import {
  SCHEMA_VERSION,
  type CliErrorCode,
  type CliErrorResult,
  type CommandName,
  type DoctorOptions,
  type InspectionResult,
  type ListResult,
  type UnlockResult,
} from "./types.js";
import { errorText } from "./util.js";

const HELP = `codex-unlock - diagnose and safely release Codex thread writer locks

Usage:
  codex-unlock list [options]
  codex-unlock inspect <thread-id> [options]
  codex-unlock unlock <thread-id> [options]

Options:
  --json                   Emit machine-readable JSON
  --codex-home <path>      Codex home (default: CODEX_HOME or ~/.codex)
  --stability-ms <ms>      Observation window, 250..30000 (default: 1000)
  --timeout-ms <ms>        SIGTERM wait, 100..60000 (default: 5000)
  -h, --help               Show help
  -v, --version            Show version

Safety:
  list and inspect are read-only. unlock never deletes a lock file and never
  sends SIGKILL. It refuses unless the lock has one stable Codex owner, that
  owner holds no other thread locks, and the stable transcript ends in
  task_complete. Shared app-server and Remote Control owners are refused.
`;

interface ParsedArguments {
  command: CommandName;
  threadId?: string;
  json: boolean;
  options: DoctorOptions;
}

function requestedCommand(argv: string[]): CommandName | null {
  const candidate = argv[0];
  return candidate === "list" || candidate === "inspect" || candidate === "unlock"
    ? candidate
    : null;
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
  if (argv.includes("--help") || argv.includes("-h")) return "help";
  if (argv.includes("--version") || argv.includes("-v")) return "version";

  const options = defaultOptions();
  const positional: string[] = [];
  let json = false;
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--json") {
      json = true;
    } else if (argument === "--codex-home") {
      const value = argv[++index];
      if (!value) throw new Error("--codex-home requires a path");
      options.codexHome = resolve(value);
    } else if (argument === "--stability-ms") {
      options.stabilityMs = integerOption(argument, argv[++index], 250, 30_000);
    } else if (argument === "--timeout-ms") {
      options.terminationTimeoutMs = integerOption(argument, argv[++index], 100, 60_000);
    } else if (argument.startsWith("-")) {
      throw new Error(`unknown option: ${argument}`);
    } else {
      positional.push(argument);
    }
  }

  const command = positional.shift();
  if (command !== "list" && command !== "inspect" && command !== "unlock") {
    throw new Error("expected command: list, inspect, or unlock");
  }
  if (command === "list") {
    if (positional.length > 0) throw new Error("list does not accept a thread id");
    return { command, json, options };
  }
  const threadId = positional.shift();
  if (!threadId || positional.length > 0) {
    throw new Error(`${command} requires exactly one thread id`);
  }
  return { command, threadId, json, options };
}

function printable(value: string | number | null): string {
  return value === null || value === "" ? "-" : String(value);
}

function printInspection(result: InspectionResult): void {
  console.log(`Thread:         ${result.threadId}`);
  console.log(`Classification: ${result.classification}`);
  console.log(`Lock probe:     ${result.lock.probe.status}`);
  console.log(`Lock path:      ${result.lock.path}`);
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
    console.log(`Blockers:       ${result.blockers.join(", ")}`);
  }
  if (result.warnings.length > 0) {
    console.log(`Warnings:       ${result.warnings.join(", ")}`);
  }
}

function printList(result: ListResult): void {
  if (result.sessions.length === 0) {
    console.log(`No Codex thread lock files found under ${result.codexHome}.`);
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
  console.log(`Process exited:        ${printable(result.processExited === null ? null : result.processExited ? "yes" : "no")}`);
  console.log(`Lock released:        ${result.lockReleased ? "yes" : "no"}`);
  console.log(`Transcript unchanged: ${printable(result.transcriptUnchanged === null ? null : result.transcriptUnchanged ? "yes" : "no")}`);
  console.log("Lock file removed by codex-unlock: no");
  if (result.reasons.length > 0) {
    console.log(`Reasons:              ${result.reasons.join(", ")}`);
  }
}

async function main(): Promise<number> {
  let parsed: ParsedArguments | "help" | "version";
  try {
    parsed = parseArguments(process.argv.slice(2));
  } catch (error) {
    const wantsJson = process.argv.includes("--json");
    if (wantsJson) {
      console.log(
        JSON.stringify(
          cliError(
            requestedCommand(process.argv.slice(2)),
            "invalid_usage",
            64,
            errorText(error),
          ),
          null,
          2,
        ),
      );
    } else {
      console.error(`codex-unlock: ${errorText(error)}`);
      console.error("Run codex-unlock --help for usage.");
    }
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

  try {
    if (parsed.command === "list") {
      const result = await listThreads(parsed.options);
      if (parsed.json) console.log(JSON.stringify(result, null, 2));
      else printList(result);
      return 0;
    }
    if (parsed.command === "inspect") {
      const result = await inspectThread(parsed.threadId!, parsed.options);
      if (parsed.json) console.log(JSON.stringify(result, null, 2));
      else printInspection(result);
      return 0;
    }
    const result = await unlockThread(parsed.threadId!, parsed.options);
    if (parsed.json) console.log(JSON.stringify(result, null, 2));
    else printUnlock(result);
    if (result.outcome === "unlocked" || result.outcome === "not_locked") return 0;
    if (result.outcome === "refused") return 2;
    return 3;
  } catch (error) {
    if (parsed.json) {
      console.log(
        JSON.stringify(
          cliError(parsed.command, "command_failed", 3, errorText(error)),
          null,
          2,
        ),
      );
    } else {
      console.error(`codex-unlock: ${errorText(error)}`);
    }
    return 3;
  }
}

process.exitCode = await main();
