/** Type-only models for the CLI's JSON v1 contract; no executable library API. */
import type {
  CheckUpdateResult,
  CliErrorResult,
  InspectionResult,
  ListResult,
  UnlockResult,
} from "./types.js";

export type {
  CheckUpdateResult,
  Classification,
  ClientUpdate,
  CliErrorCode,
  CliErrorResult,
  CommandName,
  InspectionResult,
  ListResult,
  LockHolder,
  LockInspection,
  LockProbe,
  ProbeStatus,
  ProcessInfo,
  ProcessObservationStatus,
  ProcessStartObservation,
  PublicFileSnapshot,
  TranscriptInspection,
  TranscriptRecord,
  TranscriptStatus,
  UnlockOutcome,
  UnlockResult,
} from "./types.js";

/** A command result or structured CLI error, not a runtime JSON validator. */
export type JsonResult =
  | ListResult
  | InspectionResult
  | UnlockResult
  | CheckUpdateResult
  | CliErrorResult;
