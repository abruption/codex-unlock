export const SCHEMA_VERSION = 1;

export type CommandName = "list" | "inspect" | "unlock" | "check-update";

export type CliErrorCode = "invalid_usage" | "command_failed";

export interface CliErrorResult {
  schemaVersion: typeof SCHEMA_VERSION;
  command: CommandName | null;
  status: "error";
  error: string;
  errorCode: CliErrorCode;
  exitCode: 3 | 64;
  retryable: boolean;
  suggestedAction: string | null;
}

export interface ClientUpdate {
  schemaVersion: 1;
  source: "npm";
  currentVersion: string;
  latestVersion: string;
  checkedAt: string;
  updateAvailable: true;
  updateCommand: string;
}

export interface CheckUpdateResult {
  schemaVersion: typeof SCHEMA_VERSION;
  command: "check-update";
  status: "ok";
  source: "npm";
  currentVersion: string;
  latestVersion: string;
  checkedAt: string;
  updateAvailable: boolean;
  updateCommand: string;
}

export type Classification =
  | "absent"
  | "stale_residue"
  | "live_owner"
  | "unknown";

export type ProbeStatus = "held" | "free" | "unknown";

export interface PublicFileSnapshot {
  device: string;
  inode: string;
  mode: number;
  uid: number;
  links: number;
  size: number;
  modifiedAt: string;
  modifiedMs: number;
}

export interface LockProbe {
  status: ProbeStatus;
  method: "flock_exclusive_nonblocking";
  error?: string;
}

export type ProcessObservationStatus = "present" | "absent" | "unknown";

export interface ProcessStartObservation {
  status: ProcessObservationStatus;
  startTime: string | null;
  error?: string;
}

export interface ProcessInfo {
  pid: number;
  ppid: number | null;
  uid: number | null;
  startTime: string | null;
  tty: string | null;
  command: string | null;
  arguments: string | null;
  cwd: string | null;
  lsofCommand: string | null;
  identityComplete: boolean;
  isCodex: boolean;
  isSharedService: boolean;
  errors: string[];
}

export interface TranscriptRecord {
  recordType: string | null;
  eventType: string | null;
  timestamp: string | null;
  ordinal: number | null;
}

export type TranscriptStatus =
  | "found"
  | "missing"
  | "ambiguous"
  | "unreadable";

export interface TranscriptInspection {
  status: TranscriptStatus;
  path: string | null;
  candidates: string[];
  snapshot: PublicFileSnapshot | null;
  lastRecord: TranscriptRecord | null;
  stable: boolean | null;
  error?: string;
}

export interface LockInspection {
  path: string;
  observation: "present" | "absent" | "unknown";
  exists: boolean;
  regularFile: boolean | null;
  symlink: boolean | null;
  ownedByCurrentUser: boolean | null;
  snapshot: PublicFileSnapshot | null;
  stable: boolean | null;
  probe: LockProbe;
  observationError?: string;
}

export interface InspectionResult {
  schemaVersion: typeof SCHEMA_VERSION;
  command: "inspect";
  inspectedAt: string;
  codexHome: string;
  threadId: string;
  classification: Classification;
  safeToUnlock: boolean;
  blockers: string[];
  warnings: string[];
  lock: LockInspection;
  owner: ProcessInfo | null;
  openers: ProcessInfo[];
  ownerIdentityStable: boolean | null;
  ownerLockFiles: string[] | null;
  descendantPids: number[] | null;
  transcript: TranscriptInspection;
}

export interface ListResult {
  schemaVersion: typeof SCHEMA_VERSION;
  command: "list";
  inspectedAt: string;
  codexHome: string;
  count: number;
  sessions: InspectionResult[];
}

export type UnlockOutcome =
  | "unlocked"
  | "not_locked"
  | "refused"
  | "termination_failed"
  | "verification_failed";

export interface UnlockResult {
  schemaVersion: typeof SCHEMA_VERSION;
  command: "unlock";
  attemptedAt: string;
  threadId: string;
  outcome: UnlockOutcome;
  changed: boolean;
  pid: number | null;
  signalSent: "SIGTERM" | null;
  processExited: boolean | null;
  processObservation: ProcessStartObservation | null;
  lockReleased: boolean;
  lockFileRemovedByTool: false;
  transcriptUnchanged: boolean | null;
  reasons: string[];
  inspection: InspectionResult;
}

export interface DoctorOptions {
  codexHome: string;
  stabilityMs: number;
  terminationTimeoutMs: number;
}
