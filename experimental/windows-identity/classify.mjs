// Fixture-only classifier for Windows identity observations (#146, #147, #148).
// Pure functions over JSON records produced by WinIdentityLab.cs. Nothing here
// opens, locks, signals or deletes anything. Every result carries
// safeToUnlock=false, and missing, denied or ambiguous evidence is `unknown`.
// A run is judged against the closed MANIFEST below, never against the
// expectations the producer wrote into its own records.
import { readFileSync } from 'node:fs'
import process from 'node:process'
import { isDeepStrictEqual } from 'node:util'
import { pathToFileURL } from 'node:url'

export const FILE_ATTRIBUTE_DIRECTORY = 0x10
export const FILE_ATTRIBUTE_REPARSE_POINT = 0x400

// Rights that let a principal change the object, its contents, its DACL or
// owner, or (for directories) add or remove children. MAXIMUM_ALLOWED and the
// generic rights are included because their effective meaning is not visible
// from the ACE alone.
export const WRITE_MASK =
  0x00000002 | // FILE_WRITE_DATA / FILE_ADD_FILE
  0x00000004 | // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
  0x00000010 | // FILE_WRITE_EA
  0x00000040 | // FILE_DELETE_CHILD
  0x00000100 | // FILE_WRITE_ATTRIBUTES
  0x00010000 | // DELETE
  0x00040000 | // WRITE_DAC
  0x00080000 | // WRITE_OWNER
  0x02000000 | // MAXIMUM_ALLOWED
  0x10000000 | // GENERIC_ALL
  0x40000000 // GENERIC_WRITE

// Research threat-model assumption only (see README): these principals
// already bypass any DACL through privileges, so their ACEs are recorded
// rather than refused. This is never a production authorization.
const PRIVILEGED_WRITERS = new Set(['system', 'administrators'])
const SELF_EQUIVALENT = new Set(['self', 'owner_rights'])

// Mirrors the flattened-argument shared-service checks in src/process.ts
// (SHARED_SERVICE_PATTERN, FLATTENED_REMOTE_OPTION_PATTERN). A Windows command
// line is a single string whose argv split is program-defined, so only the
// conservative flattened form is applied. classify.test.mjs asserts that these
// copies still equal the production source.
export const SHARED_SERVICE_PATTERN = /\b(?:app-server|remote-control|daemon|exec-server)\b/i
export const FLATTENED_REMOTE_OPTION_PATTERN = /(?:^|\s)--(?:remote|remote-auth-token-env)(?=\s|=|$)/i

const HEX16 = /^[0-9a-f]{16}$/
const HEX32 = /^[0-9a-f]{32}$/
// A process creation FILETIME as GetProcessTimes reports it through a signed
// 64-bit value: a decimal string without sign or leading zeros, 1..2^63-1.
const FILETIME = /^[1-9][0-9]{0,18}$/
const FILETIME_MAX = 9223372036854775807n

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function isUint32(value) {
  return Number.isInteger(value) && value >= 0 && value <= 0xffffffff
}

export function isValidPid(value) {
  return Number.isInteger(value) && value > 0 && value <= 0xffffffff
}

export function isValidFiletime(value) {
  return typeof value === 'string' && FILETIME.test(value) && BigInt(value) <= FILETIME_MAX
}

function unknown(reason, extra = {}) {
  return { state: 'unknown', reason, ...extra, safeToUnlock: false }
}

function refuse(reason, extra = {}) {
  return { state: 'refuse', reason, ...extra, safeToUnlock: false }
}

function failure(obs) {
  const stage = typeof obs.stage === 'string' && /^[a-z_]+$/.test(obs.stage) ? obs.stage : 'observation'
  return unknown(`${stage}_failed`, Number.isInteger(obs.win32) ? { win32: obs.win32 } : {})
}

// GetFinalPathNameByHandleW(VOLUME_NAME_DOS) returns `\\?\C:\...` or
// `\\?\UNC\server\share\...`. After removing that prefix and any trailing
// separator, only absolute drive (`C:\...`) or UNC (`\\server\share\...`)
// forms are accepted; relative, device, forward-slash and `.`/`..` forms are
// rejected.
export function normalizeWindowsPath(value) {
  if (typeof value !== 'string' || value.length === 0) return null
  let path = value
  if (path.startsWith('\\\\?\\UNC\\')) path = '\\\\' + path.slice(8)
  else if (path.startsWith('\\\\?\\')) path = path.slice(4)
  if (path.includes('/')) return null
  while (path.length > 3 && path.endsWith('\\')) path = path.slice(0, -1)
  let rest
  if (/^[A-Za-z]:\\/.test(path)) rest = path.slice(3)
  else if (/^\\\\[^\\?.][^\\]*\\[^\\]+/.test(path)) rest = path.slice(2).split('\\').slice(2).join('\\')
  else return null
  if (rest.length > 0 && rest.split('\\').some((part) => part === '' || part === '.' || part === '..')) return null
  return path
}

// NTFS and ReFS compare names through the volume upcase table. Only an ASCII
// case-insensitive comparison is reproduced here; any non-ASCII difference is
// not decided and stays unequal (fail closed).
export function samePathName(left, right) {
  const a = normalizeWindowsPath(left)
  const b = normalizeWindowsPath(right)
  if (a === null || b === null) return false
  if (a === b) return true
  const foldAscii = (value) => value.replace(/[A-Z]/g, (char) => char.toLowerCase())
  return foldAscii(a) === foldAscii(b)
}

/**
 * W1: one observation through one no-follow handle. Identity is the volume
 * serial plus the 128-bit FILE_ID_INFO identifier; the 64-bit legacy index is
 * informational only and is never used as a fallback. No-follow covers the
 * last path component only; ancestor traversal is not proven.
 */
export function classifyFileObservation(obs, options = {}) {
  if (!isObject(obs)) return unknown('missing_observation')
  if (obs.ok !== true) return failure(obs)
  if (obs.noFollow !== true) return unknown('follow_policy')
  if (!isUint32(obs.attributes) || !isUint32(obs.reparseTag)) return unknown('attributes_missing')
  if ((obs.attributes & FILE_ATTRIBUTE_REPARSE_POINT) !== 0 || obs.reparseTag !== 0) {
    return unknown('reparse_point')
  }
  if (typeof obs.volumeSerial !== 'string' || !HEX16.test(obs.volumeSerial) ||
    typeof obs.fileId !== 'string' || !HEX32.test(obs.fileId) ||
    /^0+$/.test(obs.fileId) || /^f+$/.test(obs.fileId)) {
    return unknown('file_id_128_missing')
  }
  if (!Number.isInteger(obs.links) || obs.links < 1 ||
    typeof obs.deletePending !== 'boolean' || typeof obs.directory !== 'boolean') {
    return unknown('standard_info_missing')
  }
  if (typeof obs.filesystem !== 'string' || obs.filesystem.length === 0) return unknown('filesystem_missing')
  const attributeDirectory = (obs.attributes & FILE_ATTRIBUTE_DIRECTORY) !== 0
  if (attributeDirectory !== obs.directory) return unknown('directory_flag_conflict')
  if (obs.deletePending) return unknown('delete_pending')
  if (options.kind === 'file' && obs.directory) return unknown('kind_mismatch')
  if (options.kind === 'directory' && !obs.directory) return unknown('kind_mismatch')
  if (!obs.directory && obs.links !== 1) return unknown('hard_link', { links: obs.links })
  if (!samePathName(obs.requestedPath, obs.finalPath)) return unknown('path_handle_mismatch')
  return {
    state: 'match',
    identity: `${obs.volumeSerial}:${obs.fileId}`,
    directory: obs.directory,
    filesystem: obs.filesystem,
    safeToUnlock: false,
  }
}

/**
 * W1: compare-before and compare-after (same handle or a fresh path open).
 * Both observations must name the same requested path; a case-only variant
 * is the same path.
 */
export function classifyFileCompare(before, after, options = {}) {
  const first = classifyFileObservation(before, options)
  if (first.state !== 'match') return { ...first, side: 'before' }
  const second = classifyFileObservation(after, options)
  if (second.state !== 'match') return { ...second, side: 'after' }
  if (!samePathName(before.requestedPath, after.requestedPath)) return unknown('requested_path_mismatch')
  if (first.identity !== second.identity || first.directory !== second.directory) {
    return unknown('identity_changed')
  }
  if (first.filesystem !== second.filesystem) return unknown('filesystem_changed')
  return { state: 'match', identity: first.identity, safeToUnlock: false }
}

/**
 * W2: owner SID and DACL read through GetSecurityInfo on a no-follow handle.
 * SIDs arrive as classes relative to the current token user (`self`), never
 * as raw values. Only an exact current-user owner can match, and an allow ACE
 * that grants write-like rights to anyone other than the owner, SYSTEM or
 * Administrators is refused.
 */
export function classifySecurity(obs) {
  if (!isObject(obs)) return unknown('missing_observation')
  if (obs.ok !== true) return failure(obs)
  if (obs.noFollow !== true) return unknown('follow_policy')
  if (!isUint32(obs.attributes) || !isUint32(obs.reparseTag)) return unknown('attributes_missing')
  if ((obs.attributes & FILE_ATTRIBUTE_REPARSE_POINT) !== 0 || obs.reparseTag !== 0) {
    return unknown('reparse_point')
  }
  if (obs.tokenUserClass !== 'self') return unknown('token_user_missing')
  if (typeof obs.ownerClass !== 'string' || obs.ownerClass.length === 0) return unknown('owner_missing')
  if (obs.ownerClass !== 'self') return refuse('owner_not_current_user', { ownerClass: obs.ownerClass })
  // An observed NULL or absent DACL is refused; a missing observation of the
  // DACL state is not evidence and stays unknown.
  if (obs.daclState === 'null') return refuse('null_dacl')
  if (obs.daclState === 'absent') return refuse('dacl_absent')
  if (obs.daclState !== 'present') return unknown('dacl_missing')
  if (!Array.isArray(obs.aces)) return unknown('dacl_unparsed')
  const privilegedWriters = []
  let inherited = 0
  let explicit = 0
  for (const ace of obs.aces) {
    if (!isObject(ace) || !isUint32(ace.mask) || typeof ace.sidClass !== 'string' ||
      typeof ace.inherited !== 'boolean' || typeof ace.inheritOnly !== 'boolean') {
      return unknown('dacl_unparsed')
    }
    if (ace.type !== 'allow' && ace.type !== 'deny') return unknown('unsupported_ace')
    if (ace.inherited) inherited += 1
    else explicit += 1
    // An inherit-only ACE does not apply to this object; children that inherit
    // it are observed separately.
    if (ace.inheritOnly || ace.type === 'deny') continue
    if (ace.sidClass === 'creator_owner') return unknown('unsupported_ace')
    if ((ace.mask & WRITE_MASK) === 0) continue
    if (SELF_EQUIVALENT.has(ace.sidClass)) continue
    if (PRIVILEGED_WRITERS.has(ace.sidClass)) {
      if (!privilegedWriters.includes(ace.sidClass)) privilegedWriters.push(ace.sidClass)
      continue
    }
    return refuse('other_writer', { sidClass: ace.sidClass, inherited: ace.inherited })
  }
  return {
    state: 'match',
    inheritedAces: inherited,
    explicitAces: explicit,
    privilegedWriters,
    limits: ['privileged_administrators_system', 'backup_restore_privileges'],
    safeToUnlock: false,
  }
}

/**
 * W3: process identity through one handle bound to one process instance.
 * The observed PID (GetProcessId on the handle) must equal the recorded PID,
 * the handle must be `held` or `fresh_open`, and the creation FILETIME must be
 * well formed and equal. Liveness comes only from WaitForSingleObject(h, 0)
 * before and after identity collection; an exit code is never evidence.
 */
export function classifyProcess(recorded, obs) {
  if (!isObject(recorded) || !isValidPid(recorded.pid) || !isValidFiletime(recorded.createFiletime)) {
    return unknown('recorded_identity_missing')
  }
  if (!isObject(obs)) return unknown('missing_observation')
  if (obs.ok !== true) return failure(obs)
  if (obs.handleSource !== 'held' && obs.handleSource !== 'fresh_open') return unknown('handle_source_unknown')
  if (!isValidPid(obs.pid)) return unknown('pid_missing')
  if (obs.pid !== recorded.pid) return unknown('pid_mismatch')
  if (obs.createFiletime === null || obs.createFiletime === undefined) return unknown('process_times_missing')
  if (!isValidFiletime(obs.createFiletime)) return unknown('process_times_malformed')
  // A different creation time means a different process object, even when
  // that object has already exited (for example a reused PID).
  if (BigInt(obs.createFiletime) !== BigInt(recorded.createFiletime)) {
    return unknown('identity_changed', obs.handleSource === 'fresh_open' ? { pidMayBeReused: true } : {})
  }
  if (obs.wait === 'signaled') return { state: 'exited', safeToUnlock: false }
  if (obs.wait !== 'timeout') return unknown('wait_failed')
  if (typeof obs.sidClass !== 'string' || obs.sidClass.length === 0) return unknown('token_sid_missing')
  if (obs.sidClass !== 'self') return refuse('other_user', { sidClass: obs.sidClass })
  if (obs.waitAfter === 'signaled') return { state: 'exited', safeToUnlock: false }
  if (obs.waitAfter !== 'timeout') return unknown('wait_failed')
  return { state: 'live_same_user', safeToUnlock: false }
}

/**
 * W3: owner mode from the image name and the flattened command line. Shared
 * app-server, daemon and Remote Control spellings are refused as on Unix.
 * No Windows Codex argv grammar has been observed (W7), so no case is promoted
 * to a standalone owner; everything else stays unknown.
 */
export function classifyOwnerMode(obs) {
  if (!isObject(obs)) return unknown('missing_observation')
  if (obs.ok !== true) return failure(obs)
  if (typeof obs.imageBase !== 'string' || typeof obs.commandLine !== 'string') {
    return unknown('command_line_missing')
  }
  const image = obs.imageBase.toLowerCase()
  if (image !== 'codex.exe' && !/^codex-[a-z0-9_-]+\.exe$/.test(image)) return unknown('not_codex_image')
  if (SHARED_SERVICE_PATTERN.test(image) || SHARED_SERVICE_PATTERN.test(obs.commandLine) || FLATTENED_REMOTE_OPTION_PATTERN.test(obs.commandLine)) {
    return refuse('shared_service')
  }
  return unknown('windows_argv_grammar_unverified')
}

/** Cleanup regression probe: a replaced root or parent must delete nothing. */
export function classifyCleanupProbe(obs) {
  if (!isObject(obs)) return unknown('missing_observation')
  if (obs.ok !== true) return failure(obs)
  if (typeof obs.preserved !== 'boolean' || !Number.isInteger(obs.removed) || obs.removed < 0 ||
    typeof obs.sentinelIntact !== 'boolean' || typeof obs.originalIntact !== 'boolean') {
    return unknown('probe_fields_missing')
  }
  if (obs.removed > 0 || !obs.sentinelIntact || !obs.originalIntact) {
    return { state: 'unsafe_delete', safeToUnlock: false }
  }
  if (obs.preserved) return { state: 'preserved', safeToUnlock: false }
  return unknown('probe_inconsistent')
}

function classify(kind, record, expectKind) {
  switch (kind) {
    case 'file': return classifyFileObservation(record.obs, { kind: expectKind })
    case 'file_compare': return classifyFileCompare(record.before, record.after, { kind: expectKind })
    case 'security': return classifySecurity(record.obs)
    case 'process': return classifyProcess(record.recorded, record.obs)
    case 'mode': return classifyOwnerMode(record.obs)
    case 'cleanup_probe': return classifyCleanupProbe(record.obs)
    default: return null
  }
}

// ---- Closed case manifest ---------------------------------------------------

const MATCH = { state: 'match' }
const u = (reason) => ({ state: 'unknown', reason })
const r = (reason) => ({ state: 'refuse', reason })

function entry(phase, name, ...alternatives) {
  return Object.freeze({ case: name, phase, alternatives: Object.freeze(alternatives) })
}
const setup = (phase, name) => entry(phase, name, { kind: 'setup', track: 'setup' })
const fileCase = (name, expectKind, expect) => entry(1, name, { kind: 'file', track: 'W1', expectKind, expect })
const compareCase = (name, expectKind, expect) => entry(1, name, { kind: 'file_compare', track: 'W1', expectKind, expect })
const secCase = (phase, name, expect) => entry(phase, name, { kind: 'security', track: 'W2', expect })
const procCase = (name, expect) => entry(3, name, { kind: 'process', track: 'W3', expect })

/**
 * Every case a complete run must contain, in emission order. Phases: 0
 * environment, 1 W1, 2 W2, 3 W3, 4 cleanup probes, 5 suite_end, 6 cleanup.
 * `expect: null` means recorded without a hypothesis. A function expectation
 * is derived from the environment record. `skipWin32` lists the only error
 * codes that make a skip acceptable.
 */
export const MANIFEST = Object.freeze([
  entry(0, 'environment', { kind: 'environment', track: 'env' }),
  ...['create:home', 'create:locks', 'create:sessions', 'create:coordination', 'create:thread', 'create:transcript']
    .map((name) => setup(1, name)),
  fileCase('file:home', 'directory', MATCH),
  fileCase('file:lock_dir', 'directory', MATCH),
  fileCase('file:coordination', 'file', MATCH),
  fileCase('file:thread_lock', 'file', MATCH),
  fileCase('file:transcript', 'file', MATCH),
  compareCase('same_handle:before_after', 'file', MATCH),
  compareCase('case_variant:path', 'file', MATCH),
  setup(1, 'create:replaced'),
  setup(1, 'rename:replaced'),
  setup(1, 'create:replacement'),
  compareCase('path_replacement:file', 'file', u('identity_changed')),
  fileCase('path_replacement:same_handle', 'file', u('path_handle_mismatch')),
  setup(1, 'create:replaced_dir'),
  setup(1, 'rename:replaced_dir'),
  setup(1, 'create:replacement_dir'),
  compareCase('parent_replacement:dir', 'directory', u('identity_changed')),
  setup(1, 'create:linked'),
  setup(1, 'create:hard_link'),
  fileCase('hard_link:target', 'file', u('hard_link')),
  fileCase('hard_link:alias', 'file', u('hard_link')),
  setup(1, 'create:junction_target'),
  setup(1, 'create:junction'),
  fileCase('junction:nofollow', 'directory', u('reparse_point')),
  secCase(1, 'sec:junction', u('reparse_point')),
  entry(1, 'symlink:file',
    { kind: 'file', track: 'W1', expectKind: 'file', expect: u('reparse_point') },
    // 1314 ERROR_PRIVILEGE_NOT_HELD; 87 ERROR_INVALID_PARAMETER on builds
    // without unprivileged symlink creation.
    { kind: 'skipped', track: 'W1', skipWin32: [1314, 87] }),
  fileCase('missing:path', 'file', u('open_failed')),
  secCase(2, 'sec:scratch_root', MATCH),
  ...['home', 'lock_dir', 'coordination', 'thread_lock', 'transcript'].map((name) => secCase(2, `sec:${name}`, MATCH)),
  setup(2, 'create:sec'),
  setup(2, 'create:default_owner'),
  secCase(2, 'sec:default_owner',
    (env) => env.tokenOwnerClass === 'self' ? MATCH : r('owner_not_current_user')),
  entry(2, 'sec:owner_administrators',
    { kind: 'security', track: 'W2', expect: r('owner_not_current_user') },
    // 1307 ERROR_INVALID_OWNER: the token cannot assign that owner.
    { kind: 'skipped', track: 'W2', skipWin32: [1307] }),
  setup(2, 'create:other_writer_explicit'),
  secCase(2, 'sec:other_writer_explicit', r('other_writer')),
  setup(2, 'create:other_reader_only'),
  secCase(2, 'sec:other_reader_only', MATCH),
  setup(2, 'create:deny_other'),
  secCase(2, 'sec:deny_other', MATCH),
  setup(2, 'create:privileged_writers'),
  secCase(2, 'sec:privileged_writers', MATCH),
  setup(2, 'create:null_dacl'),
  secCase(2, 'sec:null_dacl', r('null_dacl')),
  setup(2, 'create:inherit_everyone'),
  secCase(2, 'sec:inherit_everyone_dir', r('other_writer')),
  setup(2, 'create:inherit_everyone_child'),
  secCase(2, 'sec:inherit_everyone_file', r('other_writer')),
  secCase(2, 'sec:missing', u('open_failed')),
  procCase('proc:self', { state: 'live_same_user' }),
  entry(3, 'mode:self', { kind: 'mode', track: 'W3', expect: u('not_codex_image') }),
  setup(3, 'launch:child'),
  procCase('proc:child_live', { state: 'live_same_user' }),
  procCase('proc:child_start_mismatch', u('identity_changed')),
  entry(3, 'mode:child', { kind: 'mode', track: 'W3', expect: u('not_codex_image') }),
  setup(3, 'eof:child'),
  procCase('proc:child_after_exit', { state: 'exited' }),
  procCase('proc:child_fresh_open_while_held', { state: 'exited' }),
  procCase('proc:fresh_open_after_release', null),
  entry(3, 'proc:pid_reuse',
    { kind: 'process', track: 'W3', expect: u('identity_changed'), coverage: 'verified' },
    { kind: 'recorded', track: 'W3', coverage: 'unobserved' }),
  setup(3, 'reuse:children'),
  ...['create:probe_root', 'create:probe_root_item', 'rename:probe_root', 'create:probe_root_replacement',
    'create:probe_root_sentinel'].map((name) => setup(4, name)),
  entry(4, 'cleanup:replaced_root', { kind: 'cleanup_probe', track: 'cleanup', expect: { state: 'preserved' } }),
  ...['create:probe_parent_root', 'create:probe_parent', 'create:probe_parent_item', 'rename:probe_parent',
    'create:probe_parent_replacement', 'create:probe_parent_sentinel'].map((name) => setup(4, name)),
  entry(4, 'cleanup:replaced_parent', { kind: 'cleanup_probe', track: 'cleanup', expect: { state: 'preserved' } }),
  entry(5, 'suite_end', { kind: 'suite_end', track: 'setup' }),
  entry(6, 'cleanup', { kind: 'cleanup', track: 'cleanup' }),
])

const MANIFEST_INDEX = new Map(MANIFEST.map((item, index) => [item.case, index]))
const BODY = MANIFEST.slice(1, -2)
const W3_AFTER_EOF = new Set(BODY.slice(BODY.findIndex((item) => item.case === 'eof:child') + 1)
  .filter((item) => item.phase === 3).map((item) => item.case))

/**
 * Synthetic fault-injection modes. Exception faults stop the suite after
 * `stopAfter` and require a suite_error naming the fault, confirmed children
 * and a successful cleanup. The other two make one setup step fail in a
 * defined way.
 */
export const FAULTS = Object.freeze({
  during_file_cases: { stopAfter: 'file:transcript', suiteError: true, cleanupOk: true },
  after_child_launch: { stopAfter: 'launch:child', suiteError: true, cleanupOk: true },
  during_child_observation: { stopAfter: 'proc:child_live', suiteError: true, cleanupOk: true },
  child_abnormal_exit: {
    suiteError: false,
    cleanupOk: true,
    failure: { case: 'eof:child', exited: true, exitCode: 7 },
  },
  child_ignores_eof: {
    suiteError: false,
    cleanupOk: false,
    omit: W3_AFTER_EOF,
    failure: { case: 'eof:child', exited: false, exitCode: null },
  },
})

function plannedBody(fault) {
  if (fault === null) return BODY
  const spec = FAULTS[fault]
  if (spec.stopAfter) return BODY.slice(0, BODY.findIndex((item) => item.case === spec.stopAfter) + 1)
  if (spec.omit) return BODY.filter((item) => !spec.omit.has(item.case))
  return BODY
}

function normalizedExpect(value) {
  if (!isObject(value)) return value
  const out = { state: value.state }
  if (value.reason !== undefined) out.reason = value.reason
  return out
}

function checkSetup(record, spec) {
  if (typeof record.ok !== 'boolean') return { verdict: 'error', reason: 'setup_fields_missing' }
  if (record.case === 'eof:child') {
    const consistent = record.ok === (record.exited === true && record.exitCode === 0) &&
      (record.exited === true ? Number.isInteger(record.exitCode) : record.exited === false && record.exitCode === null)
    if (!consistent) return { verdict: 'error', reason: 'setup_contradiction' }
  }
  if (record.case === 'reuse:children') {
    const consistent = Number.isInteger(record.abnormalExits) && typeof record.unconfirmedExit === 'boolean' &&
      record.ok === (record.abnormalExits === 0 && record.unconfirmedExit === false)
    if (!consistent) return { verdict: 'error', reason: 'setup_contradiction' }
  }
  if (record.case === 'launch:child' && record.ok && !isValidPid(record.pid)) {
    return { verdict: 'error', reason: 'setup_fields_missing' }
  }
  if (record.ok) return { verdict: 'setup_ok' }
  const failure = spec?.failure
  if (failure && failure.case === record.case && record.exited === failure.exited && record.exitCode === failure.exitCode) {
    return { verdict: 'expected_failure' }
  }
  return { verdict: 'error', reason: 'setup_failed' }
}

function evaluateCase(record, item, env, spec) {
  const alternative = item.alternatives.find((alt) => alt.kind === record.kind)
  if (!alternative) return { verdict: 'error', reason: 'kind_mismatch' }
  if (record.track !== alternative.track) return { verdict: 'error', reason: 'track_mismatch' }
  if (alternative.kind === 'setup') return checkSetup(record, spec)
  if (alternative.kind === 'skipped') {
    if (!alternative.skipWin32.includes(record.win32)) return { verdict: 'error', reason: 'unexpected_skip' }
    return { verdict: 'skipped' }
  }
  if (alternative.kind === 'recorded') {
    if (record.observed !== false || !Number.isSafeInteger(record.attempts) || record.attempts < 0 ||
      !Number.isSafeInteger(record.elapsedMs) || record.elapsedMs < 0) {
      return { verdict: 'error', reason: 'recorded_fields_missing' }
    }
    if (!isObject(env.budgets) || record.attempts > env.budgets.reuseAttempts ||
      (record.attempts !== env.budgets.reuseAttempts && record.elapsedMs < env.budgets.reuseMs)) {
      return { verdict: 'error', reason: 'reuse_budget_not_exhausted' }
    }
    return { verdict: 'unobserved', coverage: alternative.coverage }
  }
  if (alternative.expectKind !== undefined && record.expectKind !== alternative.expectKind) {
    return { verdict: 'error', reason: 'expect_kind_mismatch' }
  }
  const expected = typeof alternative.expect === 'function' ? alternative.expect(env) : alternative.expect
  if (expected === null) {
    if (record.expect !== undefined) return { verdict: 'error', reason: 'tampered_expect' }
  } else if (!isDeepStrictEqual(normalizedExpect(record.expect), normalizedExpect(expected))) {
    return { verdict: 'error', reason: 'tampered_expect' }
  }
  const observed = alternative.kind === 'file_compare'
    ? isObject(record.before) && isObject(record.after)
    : isObject(record.obs)
  if (!observed) return { verdict: 'incomplete' }
  if (alternative.kind === 'process' && record.obs.ok === true) {
    const source = ['proc:self', 'proc:child_fresh_open_while_held', 'proc:fresh_open_after_release', 'proc:pid_reuse']
      .includes(record.case) ? 'fresh_open' : 'held'
    if (record.obs.handleSource !== source) return { verdict: 'error', reason: 'handle_source_case_mismatch' }
  }
  const result = classify(alternative.kind, record, alternative.expectKind)
  if (expected === null) return { verdict: 'recorded', result }
  const sameState = result.state === expected.state
  const sameReason = expected.reason === undefined || result.reason === expected.reason
  return { verdict: sameState && sameReason ? 'match' : 'mismatch', result, coverage: alternative.coverage }
}

function checkEnvironment(record, fault) {
  if (!isObject(record) || record.kind !== 'environment' || record.case !== 'environment' || record.track !== 'env') {
    return 'environment_missing'
  }
  if (record.safeToUnlock !== false) return 'safe_to_unlock_not_false'
  if (!['NTFS', 'ReFS'].includes(record.filesystem) ||
    typeof record.tokenOwnerClass !== 'string' || record.tokenOwnerClass.length === 0 ||
    !/^Microsoft Windows NT \d+\.\d+\.\d+(?:\.\d+)?$/.test(record.os ?? '') ||
    !/^\d+\.\d+\.\d+(?:\.\d+)?$/.test(record.clr ?? '') ||
    typeof record.is64BitProcess !== 'boolean' || !/^\d+$/.test(record.integrityRid ?? '') ||
    !isObject(record.budgets)) {
    return 'environment_fields_missing'
  }
  for (const [key, max] of [['waitMs', 600000], ['childWaitMs', 600000], ['reuseAttempts', 4096], ['reuseMs', 600000]]) {
    if (!Number.isInteger(record.budgets[key]) || record.budgets[key] < 0 || record.budgets[key] > max) return 'environment_budget_invalid'
  }
  const childBudget = fault === 'child_ignores_eof' ? Math.min(record.budgets.waitMs, 2000) : record.budgets.waitMs
  if (record.budgets.childWaitMs !== childBudget) return 'environment_budget_inconsistent'
  if ((record.fault ?? null) !== fault) return 'environment_fault_mismatch'
  return null
}

function checkCleanup(record, spec) {
  if (!isObject(record) || record.kind !== 'cleanup' || record.case !== 'cleanup' || record.track !== 'cleanup') {
    return 'cleanup_missing'
  }
  if (record.safeToUnlock !== false) return 'safe_to_unlock_not_false'
  if (typeof record.ok !== 'boolean' || typeof record.preserved !== 'boolean' ||
    !Number.isInteger(record.registered) || !Number.isInteger(record.removed) ||
    !Number.isInteger(record.childrenStillRunning) || record.childrenStillRunning < 0) {
    return 'cleanup_fields_missing'
  }
  const clean = !record.preserved && record.childrenStillRunning === 0 && record.removed === record.registered &&
    record.registered > 0 && record.reason === null
  if (record.ok !== clean || record.preserved === record.ok) return 'cleanup_contradiction'
  const wantOk = spec ? spec.cleanupOk : true
  if (record.ok !== wantOk) return wantOk ? 'cleanup_failed' : 'cleanup_unexpectedly_ok'
  if (!wantOk && (record.childrenStillRunning < 1 || record.reason !== 'children_running' || record.removed !== 0)) {
    return 'cleanup_fault_mismatch'
  }
  return null
}

function crossChecks(byCase, env) {
  const errors = []
  for (const [name, record] of byCase) {
    if (record.kind === 'security' && record.obs?.ok === true && record.obs.tokenOwnerClass !== env.tokenOwnerClass) {
      errors.push(`environment_contradiction:${name}`)
    }
    for (const observation of record.kind === 'file_compare' ? [record.before, record.after] : record.kind === 'file' ? [record.obs] : []) {
      if (observation?.ok === true && observation.filesystem !== env.filesystem) errors.push(`filesystem_contradiction:${name}`)
    }
  }
  const launch = byCase.get('launch:child')
  const live = byCase.get('proc:child_live')
  if (live) {
    const bound = live.recorded
    if (!launch || launch.pid !== bound?.pid) errors.push('binding_contradiction:launch:child')
    for (const name of ['proc:child_after_exit', 'proc:child_fresh_open_while_held', 'proc:fresh_open_after_release']) {
      const other = byCase.get(name)
      if (other && !isDeepStrictEqual(other.recorded, bound)) errors.push(`binding_contradiction:${name}`)
    }
    const reuse = byCase.get('proc:pid_reuse')
    if (reuse?.kind === 'process' && !isDeepStrictEqual(reuse.recorded, bound)) errors.push('binding_contradiction:proc:pid_reuse')
    const shifted = byCase.get('proc:child_start_mismatch')
    if (shifted) {
      const ok = isValidFiletime(bound?.createFiletime) && isValidFiletime(shifted.recorded?.createFiletime) &&
        shifted.recorded.pid === bound.pid && BigInt(shifted.recorded.createFiletime) === BigInt(bound.createFiletime) + 1n
      if (!ok) errors.push('binding_contradiction:proc:child_start_mismatch')
      if (shifted.obs?.pid !== bound?.pid || shifted.obs?.createFiletime !== bound?.createFiletime) {
        errors.push('observation_contradiction:proc:child_start_mismatch')
      }
    }
  }
  const self = byCase.get('proc:self')
  if (self && self.obs?.ok === true && self.obs.pid !== self.recorded?.pid) errors.push('binding_contradiction:proc:self')
  for (const [mode, processCase] of [['mode:self', 'proc:self'], ['mode:child', 'proc:child_live']]) {
    const observation = byCase.get(mode)
    if (observation && !isDeepStrictEqual(observation.obs, byCase.get(processCase)?.obs)) {
      errors.push(`binding_contradiction:${mode}`)
    }
  }
  return errors
}

/**
 * Evaluates a whole run against MANIFEST. Collection completeness, hypothesis
 * results and coverage are reported separately. Exit codes in normal mode: 0
 * complete, every hypothesis matched and full coverage; 4 complete and
 * matched but coverage is partial (skips or PID reuse unobserved); 1 any
 * mismatch; 2 collection incomplete or any error. In fault mode, 0 means the
 * run failed exactly as the fault specifies.
 */
export function evaluateJsonl(text, options = {}) {
  const fault = options.fault ?? null
  if (fault !== null && !Object.hasOwn(FAULTS, fault)) throw new Error(`unknown fault: ${fault}`)
  const spec = fault === null ? null : FAULTS[fault]
  const errors = []
  const results = []
  const records = []
  for (const [index, line] of text.split('\n').entries()) {
    if (line.length === 0) continue
    try {
      records.push({ line: index + 1, record: JSON.parse(line) })
    } catch {
      errors.push(`invalid_json:${index + 1}`)
    }
  }
  const env = records[0]?.record
  const envError = checkEnvironment(env, fault)
  if (envError) errors.push(envError)
  const cleanupError = checkCleanup(records.at(-1)?.record, spec)
  if (records.length < 3 || cleanupError) errors.push(cleanupError ?? 'cleanup_missing')
  const end = records.at(-2)?.record
  if (!isObject(end) || end.kind !== 'suite_end' || end.case !== 'suite_end' || end.track !== 'setup' ||
    end.safeToUnlock !== false) {
    errors.push('suite_end_missing')
  } else if (end.emitted !== records.length - 2) {
    errors.push('suite_end_count_mismatch')
  }
  let body = records.slice(1, -2)
  const suiteErrors = body.filter((entry) => entry.record?.kind === 'suite_error')
  if (suiteErrors.length > 1) errors.push('suite_error_duplicate')
  if (suiteErrors.length === 1) {
    if (body.at(-1) !== suiteErrors[0]) errors.push('suite_error_not_last')
    body = body.filter((entry) => entry !== suiteErrors[0])
    const message = suiteErrors[0].record
    if (!spec?.suiteError) errors.push('suite_error')
    else if (message.case !== 'suite_error' || message.track !== 'setup' ||
      message.fault !== fault || typeof message.message !== 'string' ||
      !message.message.includes(`fault injected: ${fault}`) || message.safeToUnlock !== false) {
      errors.push('suite_error_fault_mismatch')
    }
  } else if (spec?.suiteError) {
    errors.push('suite_error_missing')
  }

  const planned = plannedBody(fault)
  const plannedNames = new Set(planned.map((item) => item.case))
  const byCase = new Map()
  let lastIndex = 0
  let matched = 0
  let mismatched = 0
  let recorded = 0
  const skipped = []
  let pidReuse = 'not_reached'
  for (const { line, record } of body) {
    if (!isObject(record) || typeof record.case !== 'string') {
      errors.push(`malformed_record:${line}`)
      continue
    }
    const name = record.case
    const index = MANIFEST_INDEX.get(name)
    if (index === undefined || index === 0 || index >= MANIFEST.length - 2) {
      errors.push(`unexpected_case:${name}`)
      continue
    }
    if (byCase.has(name)) {
      errors.push(`duplicate_case:${name}`)
      continue
    }
    if (!plannedNames.has(name)) errors.push(`unplanned_case:${name}`)
    if (index <= lastIndex) errors.push(`out_of_order:${name}`)
    lastIndex = Math.max(lastIndex, index)
    byCase.set(name, record)
    let outcome
    if (record.safeToUnlock !== false) outcome = { verdict: 'error', reason: 'safe_to_unlock_not_false' }
    else outcome = evaluateCase(record, MANIFEST[index], isObject(env) ? env : {}, spec)
    results.push({ line, case: name, ...outcome })
    if (outcome.verdict === 'match') matched += 1
    else if (outcome.verdict === 'mismatch') mismatched += 1
    else if (outcome.verdict === 'recorded') recorded += 1
    else if (outcome.verdict === 'skipped') skipped.push(name)
    else if (outcome.verdict === 'error' || outcome.verdict === 'incomplete') {
      errors.push(`${outcome.verdict}:${name}${outcome.reason ? ':' + outcome.reason : ''}`)
    }
    if (name === 'proc:pid_reuse') {
      if (outcome.verdict === 'unobserved') pidReuse = 'unobserved'
      else if (outcome.verdict === 'match') pidReuse = 'verified'
      else pidReuse = 'failed'
    }
  }
  for (const item of planned) {
    if (!byCase.has(item.case)) errors.push(`missing_case:${item.case}`)
  }
  if (spec?.failure && byCase.has(spec.failure.case) &&
    results.find((entry) => entry.case === spec.failure.case)?.verdict !== 'expected_failure') {
    errors.push(`fault_not_observed:${spec.failure.case}`)
  }
  if (isObject(env)) errors.push(...crossChecks(byCase, env))

  const complete = errors.length === 0
  const fullCoverage = complete && skipped.length === 0 && pidReuse === 'verified'
  let exitCode
  if (!complete) exitCode = 2
  else if (mismatched > 0) exitCode = 1
  else if (fault === null && !fullCoverage) exitCode = 4
  else exitCode = 0
  return {
    results,
    collection: { complete, records: records.length, errors },
    hypotheses: { matched, mismatched, recorded, pass: complete && mismatched === 0 },
    coverage: { skipped, pidReuse, full: fullCoverage },
    fault,
    exitCode,
    safeToUnlock: false,
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = process.argv.slice(2)
  let fault = null
  if (args[0] === '--fault') {
    fault = args[1] ?? ''
    args.splice(0, 2)
  }
  if (args.length !== 1 || (fault !== null && !Object.hasOwn(FAULTS, fault))) {
    process.stderr.write('usage: node classify.mjs [--fault <name>] <results.jsonl>\n')
    process.exit(2)
  }
  const summary = evaluateJsonl(readFileSync(args[0], 'utf8'), { fault })
  for (const entry of summary.results) process.stdout.write(JSON.stringify(entry) + '\n')
  const { results: _results, ...rest } = summary
  process.stdout.write(JSON.stringify(rest) + '\n')
  process.exit(summary.exitCode)
}
