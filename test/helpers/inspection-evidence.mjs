// First-observation diagnostics for typed synthetic test records only. Copy
// named own data properties, skipping accessors and toJSON hooks. Selected
// error strings are not redacted; this is not a general user-data sanitizer.
const record = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const field = (value, name) => {
  if (value === null || typeof value !== "object") return undefined;
  const descriptor = Object.getOwnPropertyDescriptor(value, name);
  return descriptor && Object.hasOwn(descriptor, "value") ? descriptor.value : undefined;
};
const scalar = (value) => value === null || typeof value === "string" || typeof value === "boolean" ||
  (typeof value === "number" && Number.isFinite(value)) ? value : null;
const pick = (value, names) => record(value)
  ? Object.fromEntries(names.map((name) => [name, scalar(field(value, name))])) : null;
const strings = (value) => {
  if (!Array.isArray(value)) return null;
  const result = [];
  for (let index = 0; index < value.length; index++) {
    const entry = field(value, String(index));
    result.push(typeof entry === "string" ? entry : null);
  }
  return result;
};

export function formatInspectionEvidence(inspection, child) {
  const lock = field(inspection, "lock");
  const probe = field(lock, "probe");
  const openers = field(inspection, "openers");
  const identities = [];
  if (Array.isArray(openers)) {
    for (let index = 0; index < openers.length; index++) {
      const opener = field(openers, String(index));
      identities.push(record(opener) ? {
        ...pick(opener, ["pid", "ppid", "uid", "startTime", "isCodex", "isSharedService", "identityComplete"]),
        errors: strings(field(opener, "errors")),
      } : null);
    }
  }
  // Return a string immediately: later mutation or cleanup cannot rewrite
  // this first observation's assertion evidence.
  return JSON.stringify({
    fixture: pick(child, ["pid", "exitCode", "signalCode"]),
    ...pick(inspection, ["classification", "safeToUnlock", "ownerIdentityStable"]),
    blockers: strings(field(inspection, "blockers")),
    warnings: strings(field(inspection, "warnings")),
    lock: record(lock) ? {
      ...pick(lock, ["observation", "observationError", "stable", "exists", "regularFile", "symlink", "ownedByCurrentUser"]),
      snapshot: pick(field(lock, "snapshot"), ["device", "inode", "mode", "uid", "links", "size", "modifiedAt", "modifiedMs"]),
      probe: record(probe) ? {
        ...pick(probe, ["status", "method", "error"]),
        guard: pick(field(probe, "guard"), ["status", "attempts"]),
      } : null,
    } : null,
    ownerPid: scalar(field(field(inspection, "owner"), "pid")),
    openers: Array.isArray(openers) ? identities : null,
  }, null, 2);
}
