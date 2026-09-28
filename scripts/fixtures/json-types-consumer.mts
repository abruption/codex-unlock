import type {
  CheckUpdateResult,
  Classification,
  ClientUpdate,
  CliErrorResult,
  InspectionResult,
  JsonResult,
  ListResult,
  UnlockResult,
} from "codex-unlock/types";

export const advisory: ClientUpdate = {
  schemaVersion: 1,
  source: "npm",
  currentVersion: "0.3.0",
  latestVersion: "1.0.0",
  checkedAt: "2026-09-28T00:00:00Z",
  updateAvailable: true,
  updateCommand: "npm install --global codex-unlock@latest",
};

export const list: ListResult = {
  schemaVersion: 1,
  command: "list",
  inspectedAt: "2026-09-28T00:00:00Z",
  codexHome: "/example",
  count: 0,
  sessions: [],
  clientUpdate: advisory,
};

export const error: CliErrorResult = {
  schemaVersion: 1,
  command: null,
  status: "error",
  error: "Invalid command",
  errorCode: "invalid_usage",
  exitCode: 64,
  retryable: false,
  suggestedAction: null,
  clientUpdate: advisory,
};

export const checkUpdate: CheckUpdateResult = {
  schemaVersion: 1,
  command: "check-update",
  status: "ok",
  source: "npm",
  currentVersion: "0.3.0",
  latestVersion: "0.3.0",
  checkedAt: "2026-09-28T00:00:00Z",
  updateAvailable: false,
  updateCommand: "npm install --global codex-unlock@latest",
};

export function describe(result: JsonResult): string {
  if ("errorCode" in result) return `${result.exitCode}: ${result.error}`;
  switch (result.command) {
    case "list": return `${result.count}`;
    case "inspect": return result.classification;
    case "unlock": return result.outcome;
    case "check-update": return result.latestVersion;
    default: {
      const exhaustive: never = result;
      return exhaustive;
    }
  }
}

export function advisories(
  inspection: InspectionResult,
  unlock: UnlockResult,
): Array<ClientUpdate | undefined> {
  return [inspection.clientUpdate, unlock.clientUpdate];
}

export const nullableOwner: InspectionResult["owner"] = null;
export const nativeLockNeverDeleted: UnlockResult["lockFileRemovedByTool"] = false;

// @ts-expect-error: Unknown classification is not part of JSON v1.
export const invalidClassification: Classification = "idle";
// @ts-expect-error: Native lock deletion is never an allowed result.
export const invalidDeletion: UnlockResult["lockFileRemovedByTool"] = true;
// @ts-expect-error: An advisory always reports a newer version.
export const invalidAdvisory: ClientUpdate["updateAvailable"] = false;
// @ts-expect-error: Public models describe schema version one only.
export const invalidSchemaVersion: JsonResult["schemaVersion"] = 2;
// @ts-expect-error: A CLI error cannot use the successful exit code.
export const invalidErrorExit: CliErrorResult["exitCode"] = 0;
// @ts-expect-error: Internal operational options are not public JSON models.
export type { DoctorOptions } from "codex-unlock/types";
// @ts-expect-error: Runtime constants are not exported by the type-only surface.
export { SCHEMA_VERSION } from "codex-unlock/types";
// @ts-expect-error: The package root is not a supported import entry point.
export type { InspectionResult as RootInspection } from "codex-unlock";
// @ts-expect-error: Generated declaration deep imports remain unsupported.
export type { DoctorOptions as DeepOptions } from "codex-unlock/dist/types.js";
// @ts-expect-error: Declaration files do not grant a deep-import entry point.
export type { DoctorOptions as DeepDeclaration } from "codex-unlock/dist/types.d.ts";
