// Expected-result table, typed per-step schemas, and format validators for the
// W6/W7 Windows native observer (#151, #152). Pure data plus small pure
// predicates. observer.ps1 emits records whose `step` names match this table;
// lib.mjs re-derives every provenance verdict from the raw recorded fields and
// never trusts a harness-provided boolean or verdict.
//
// Expectation fields:
//   id          stable row identifier used in summaries and W6 pairing
//   mode        'preflight' or 'observe'
//   step        record step name emitted by observer.ps1
//   perSample   true when one record per observation sample is required
//   hypothesis  dotted observed paths and expected RAW values; null unless a
//               row is a plain raw-field comparison. Derived rows use `derive`
//   derive      name of a lib.mjs derivation that recomputes the verdict from
//               raw fields and validated baselines (booleans are never trusted)
//   compare     extra observed paths compared between integrity levels (W6)
//   measurable  false when the harness cannot measure it (always unknown)
//   gates       issues the row contributes evidence to
//   basis       why the hypothesis is expected

export const SCHEMA = 'codex-unlock-win-observer/1'

export const INTEGRITY = Object.freeze({
  medium: 'S-1-16-8192',
  high: 'S-1-16-12288',
})

// The exact harness file-name set. A manifest, preflight or observe harness
// record whose key set differs is out of schema, and a `--baseline` harness map
// with a different key set is not a usable baseline. The baseline is an exact
// map of this checkout's bytes (line-ending changes included); it is not proof
// of independent external provenance.
export const HARNESS_FILES = Object.freeze([
  'observer.ps1', 'WinObserver.cs', 'check.ps1', 'expectations.mjs', 'lib.mjs', 'evaluate.mjs',
])

// Restart Manager opener roles are a closed set, recomputed by the evaluator
// from the run record's PIDs and the process creation FILETIME.
export const ROLES = Object.freeze(['launched_codex', 'observer', 'other'])

export const MAX_SAMPLES = 10

// The disposable parent directory name shape. Observe re-derives it instead of
// trusting any recorded flag, and -OutFile is refused inside such a directory
// regardless of the current %TEMP%.
export const DISPOSABLE_DIR = /^codex-win-obs-[0-9a-f]{12}$/

const FORBIDDEN_PATH_CHARS = /["<>|*?]/
// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/

// Strict spelling rules for a recorded Windows path, applied before the path is
// compared, opened, read, hashed or created. Returns the lowercased path with
// no trailing separator, or null when the spelling is not accepted. Only
// absolute local DRIVE paths are accepted: UNC (`\\server\share`), device
// (`\\?\`, `\\.\`), relative, rooted-without-drive (`\x`) and drive-relative
// (`C:x`) spellings are rejected rather than normalized, as are `.`/`..`
// components, empty components, components ending in a space or dot, and
// characters Windows does not allow in a name. An ambiguous spelling is
// refused; it is never rewritten into something that looks safe.
export function normalizeLocalPath(p) {
  if (typeof p !== 'string' || p.length === 0 || p.length > 32767) return null
  if (CONTROL_CHARS.test(p) || FORBIDDEN_PATH_CHARS.test(p) || p.includes('/')) return null
  if (!/^[A-Za-z]:\\/.test(p)) return null
  const parts = p.split('\\')
  const drive = parts.shift()
  if (!/^[A-Za-z]:$/.test(drive)) return null
  // A single trailing separator spells the drive root or an existing directory;
  // anything else empty is a double separator.
  if (parts.length > 1 && parts[parts.length - 1] === '') parts.pop()
  if (parts.length === 1 && parts[0] === '') return drive.toLowerCase() + '\\'
  for (const part of parts) {
    if (part.length === 0 || part === '.' || part === '..') return null
    if (part.includes(':')) return null
    if (part.endsWith(' ') || part.endsWith('.')) return null
    if (part.startsWith(' ')) return null
  }
  return (drive + '\\' + parts.join('\\')).toLowerCase()
}

// Field-format validators. A format failure means the field is not usable
// evidence, so the row is `unknown`, never a silent success.
export const FORMATS = Object.freeze({
  sha256: (v) => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v),
  commit: (v) => typeof v === 'string' && /^[0-9a-f]{40}$/.test(v),
  // VolumeSerial(16 hex):IdHigh(16 hex)IdLow(16 hex), from GetFileIdInfo.
  fileId: (v) => typeof v === 'string' && /^[0-9a-f]{16}:[0-9a-f]{32}$/.test(v),
  // Mandatory integrity label SID.
  sid: (v) => typeof v === 'string' && /^S-1-16-\d+$/.test(v),
  // Any SID, used for user and owner SIDs.
  anySid: (v) => typeof v === 'string' && /^S-1-\d+(-\d+)+$/.test(v),
  // Absolute local drive path with an accepted spelling (see normalizeLocalPath).
  localPath: (v) => normalizeLocalPath(v) !== null,
  nullableLocalPath: (v) => v === null || normalizeLocalPath(v) !== null,
  int: (v) => Number.isInteger(v),
  nonNegInt: (v) => Number.isInteger(v) && v >= 0,
  posInt: (v) => Number.isSafeInteger(v) && v > 0,
  // FILETIME (100ns since 1601) exceeds 2^53, so it is carried as an exact
  // decimal string and compared as a string; a JSON number would lose precision.
  filetime: (v) => typeof v === 'string' && /^[1-9]\d*$/.test(v),
  bool: (v) => typeof v === 'boolean',
  string: (v) => typeof v === 'string' && v.length > 0,
  // A string that may be absent as an explicit null, never undefined.
  nullableString: (v) => v === null || typeof v === 'string',
  anyString: (v) => typeof v === 'string',
  array: (v) => Array.isArray(v),
  label: (v) => v === 'medium' || v === 'high',
  relation: (v) => ['same', 'inside', 'contains', 'disjoint'].includes(v),
  nullableRelation: (v) => v === null || ['same', 'inside', 'contains', 'disjoint'].includes(v),
  // A map of names to SHA-256 digests, at least one entry.
  hashMap: (v) => v !== null && typeof v === 'object' && !Array.isArray(v) &&
    Object.keys(v).length > 0 && Object.values(v).every((h) => typeof h === 'string' && /^[0-9a-f]{64}$/.test(h)),
})

function f(format) {
  const fn = FORMATS[format]
  if (!fn) throw new Error(`unknown format ${format}`)
  return fn
}

export function sameKeySet(value, names) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const keys = Object.keys(value).sort()
  const want = [...names].sort()
  return keys.length === want.length && keys.every((k, i) => k === want[i])
}

// The ACL contract of the disposable parent and home: owned by the current
// user, protected (no inheritance from above), exactly one inherited-everywhere
// Allow FullControl entry for that same user. Recorded as raw fields; the
// evaluator recomputes the verdict and never reads an `aceIsCurrentUser`-style
// boolean.
export const ACL_RIGHTS = 'FullControl'
export const ACL_INHERITANCE = 'ContainerInherit, ObjectInherit'
export const ACL_TYPE = 'Allow'

const ACL_FIELDS = {
  owner: f('anySid'), daclProtected: f('bool'), aceCount: f('int'),
  aceIdentity: f('anySid'), aceRights: f('string'), aceInheritance: f('anyString'), aceType: f('string'),
  parentOwner: f('anySid'), parentDaclProtected: f('bool'), parentAceCount: f('int'),
  parentAceIdentity: f('anySid'), parentAceRights: f('string'), parentAceInheritance: f('anyString'),
  parentAceType: f('string'),
}

const PATH_FIELDS = {
  home: f('localPath'), parent: f('localPath'),
  userCodexHome: f('localPath'), envCodexHome: f('nullableLocalPath'),
  userRelation: f('relation'), envRelation: f('nullableRelation'),
  currentUserSid: f('anySid'),
  fileId: f('fileId'), parentFileId: f('fileId'),
  // No-follow ancestry of the parent directory, root first. Every component
  // must be a plain directory; a reparse point anywhere above is refused.
  ancestry: f('array'),
}

const IDENTITY_FIELDS = {
  complete: f('bool'), attributes: f('int'), reparse: f('bool'), directory: f('bool'),
  fileId: f('fileId'), links: f('int'), deletePending: f('bool'), finalPath: f('string'),
}

const RANGE_NAMES = Object.freeze(['rust', 'fsext', 'beyond_fsext', 'tail'])

// Each probed range must be internally consistent: a Win32 code of 0 is exactly
// an acquired lock, an acquired lock must report its release, and a failed lock
// must not claim a release.
function rangesConsistent(ranges) {
  if (ranges === null || typeof ranges !== 'object' || Array.isArray(ranges)) return false
  if (!sameKeySet(ranges, RANGE_NAMES)) return false
  return RANGE_NAMES.every((name) => {
    const r = ranges[name]
    if (r === null || typeof r !== 'object') return false
    if (!FORMATS.nonNegInt(r.win32) || !FORMATS.bool(r.acquired)) return false
    if ((r.win32 === 0) !== (r.acquired === true)) return false
    if (r.acquired === true) return r.released === true
    return r.released === null
  })
}

function rmProcessesConsistent(o) {
  if (!Array.isArray(o.processes)) return false
  if (o.count !== o.processes.length) return false
  const seen = new Set()
  for (const p of o.processes) {
    if (p === null || typeof p !== 'object' || Array.isArray(p)) return false
    if (!FORMATS.posInt(p.pid) || !FORMATS.filetime(p.startFiletime)) return false
    if (!ROLES.includes(p.role)) return false
    if (!FORMATS.anyString(p.app) || !FORMATS.nullableString(p.service)) return false
    if (!FORMATS.int(p.type) || !FORMATS.int(p.session)) return false
    const key = `${p.pid}/${p.startFiletime}`
    if (seen.has(key)) return false
    seen.add(key)
  }
  return true
}

// Typed per-step schemas, keyed by `${mode}:${step}`. `required` fields must be
// present and pass their format; `nested` uses dotted paths; `invariants` are
// internal-consistency predicates that must hold for the record to be usable.
// A record that fails any of them is unmeasured (`unknown`), including
// recorded-only rows: a bare `{ok:true}` never counts as a recorded success.
export const STEP_SCHEMAS = Object.freeze({
  'preflight:harness': {
    required: { complete: f('bool'), files: f('hashMap'), sourceCommit: f('commit') },
    invariants: { harness_name_set: (o) => sameKeySet(o.files, HARNESS_FILES) },
  },
  'preflight:token.self': { required: { integritySid: f('sid'), userSid: f('anySid'), tokenOpened: f('bool'), pid: f('posInt') } },
  'preflight:binary.sha256': {
    required: { path: f('localPath'), size: f('posInt'), sha256: f('sha256'), expected: f('sha256') },
  },
  'preflight:binary.signature': { required: { status: f('string'), statusMessage: f('nullableString'), signer: f('nullableString'), thumbprint: f('nullableString') } },
  'preflight:binary.pe_version': {
    required: { declared: f('bool'), fileVersion: f('nullableString'), productVersion: f('nullableString'), productName: f('nullableString') },
    invariants: { declared_version_present: (o) => o.declared === false || FORMATS.string(o.fileVersion) },
  },
  'preflight:home.isolated': {
    required: {
      ...PATH_FIELDS, ...ACL_FIELDS,
      empty: f('bool'), entries: f('array'), isolated: f('bool'),
    },
    invariants: { empty_matches_entries: (o) => o.empty === (o.entries.length === 0) },
  },
  'preflight:binary.version': {
    required: {
      exitCode: f('int'), pid: f('posInt'), stdoutFirstLine: f('string'), expected: f('string'),
      stdoutComplete: f('bool'), stderrComplete: f('bool'), stdoutTruncated: f('bool'), stderrTruncated: f('bool'),
      stderr: f('anyString'), timedOut: f('bool'), exited: f('bool'), envAllowlist: f('array'),
    },
    invariants: {
      // Usable version output requires both streams to have been read to the
      // end, inside the deadline and without overflowing the byte cap.
      streams_complete: (o) => o.stdoutComplete === true && o.stderrComplete === true &&
        o.stdoutTruncated === false && o.stderrTruncated === false && o.timedOut === false && o.exited === true,
    },
  },
  'preflight:home.after_version': { required: { count: f('nonNegInt'), entries: f('array') }, invariants: { count_matches_entries: (o) => o.count === o.entries.length } },
  'preflight:host.execution_policy': { required: { effective: f('string'), scopes: f('array') } },
  'preflight:host.defender': { required: { amServiceEnabled: f('bool'), realTimeProtectionEnabled: f('bool'), antivirusEnabled: f('bool') } },
  'preflight:host.volume': { required: { fileSystem: f('string'), probePath: f('localPath') } },
  'preflight:host.os': { required: { os: f('string'), ps: f('string'), elevated: f('bool'), sshSession: f('bool') } },
  'preflight:manifest': {
    required: {
      complete: f('bool'), home: f('localPath'), homeFileId: f('fileId'),
      parent: f('localPath'), parentFileId: f('fileId'),
      binaryPath: f('localPath'), binarySha256: f('sha256'), binarySize: f('posInt'), version: f('string'),
      sourceCommit: f('commit'), integritySid: f('sid'), label: f('label'), harness: f('hashMap'),
      createdUtc: f('string'),
    },
    invariants: { harness_name_set: (o) => sameKeySet(o.harness, HARNESS_FILES) },
  },
  'observe:harness': {
    required: { complete: f('bool'), files: f('hashMap'), manifestSha256: f('sha256') },
    invariants: { harness_name_set: (o) => sameKeySet(o.files, HARNESS_FILES) },
  },
  'observe:token.self': { required: { integritySid: f('sid'), userSid: f('anySid'), tokenOpened: f('bool'), pid: f('posInt') } },
  'observe:home.identity': { required: { ...PATH_FIELDS, ...ACL_FIELDS } },
  'observe:run': {
    required: {
      samples: f('int'), codexPid: f('posInt'), codexLabel: f('label'),
      observerPid: f('posInt'), observerUserSid: f('anySid'), startedUtc: f('string'),
    },
    invariants: {
      samples_in_range: (o) => o.samples >= 1 && o.samples <= MAX_SAMPLES,
      observer_is_not_target: (o) => o.observerPid !== o.codexPid,
    },
  },
  'observe:process.identity': {
    required: {
      pid: f('posInt'), opened: f('bool'), state: f('string'), createFiletime: f('filetime'),
      image: f('localPath'), tokenOpened: f('bool'), integritySid: f('sid'), userSid: f('anySid'),
    },
    invariants: { live_requires_handles: (o) => o.state !== 'live' || (o.opened === true && o.tokenOpened === true) },
  },
  // Re-queried before every sample's active operations; same fields as the
  // first process record, carrying the PID that was actually queried.
  'observe:process.sample': {
    required: {
      pid: f('posInt'), opened: f('bool'), state: f('string'), createFiletime: f('filetime'),
      image: f('localPath'), tokenOpened: f('bool'), integritySid: f('sid'), userSid: f('anySid'),
    },
    invariants: { live_requires_handles: (o) => o.state !== 'live' || (o.opened === true && o.tokenOpened === true) },
  },
  'observe:lockdir.identity': { required: IDENTITY_FIELDS },
  'observe:coordination.identity': { required: IDENTITY_FIELDS },
  'observe:thread.count': {
    required: { count: f('nonNegInt'), entries: f('array') },
    invariants: {
      count_matches_entries: (o) => o.count === o.entries.filter((e) => typeof e === 'string' &&
        e !== '.coordination.lock' && e.toLowerCase().endsWith('.lock')).length,
    },
  },
  'observe:thread.identity': { required: IDENTITY_FIELDS },
  'observe:thread.identity_after': { required: IDENTITY_FIELDS },
  'observe:share.read_rwd': {
    required: { opened: f('bool'), win32: f('nonNegInt'), access: f('string'), share: f('string') },
    invariants: {
      opened_matches_win32: (o) => (o.opened === true) === (o.win32 === 0),
      requested_mode: (o) => o.access === 'read' && o.share === 'rwd',
    },
  },
  'observe:share.delete_rwd': {
    required: { opened: f('bool'), win32: f('nonNegInt'), access: f('string'), share: f('string') },
    invariants: {
      opened_matches_win32: (o) => (o.opened === true) === (o.win32 === 0),
      requested_mode: (o) => o.access === 'delete' && o.share === 'rwd',
    },
  },
  'observe:range.probe': {
    required: {
      state: f('string'),
      dirFileIdBefore: f('fileId'), dirFileIdAfter: f('fileId'),
      guardFileId: f('fileId'), guardFileIdAfter: f('fileId'), guardLinks: f('int'), guardDeletePending: f('bool'),
      threadFileIdBefore: f('fileId'), threadFileIdAfter: f('fileId'), threadLinks: f('int'), threadDeletePending: f('bool'),
      guardAcquired: f('bool'), guardReleased: f('bool'),
    },
    nested: {
      'ranges.rust.win32': f('int'), 'ranges.fsext.win32': f('int'),
      'ranges.beyond_fsext.win32': f('int'), 'ranges.tail.win32': f('int'),
    },
    invariants: {
      ranges_consistent: (o) => rangesConsistent(o.ranges),
      // The guard is taken and released synchronously around the probes; a
      // probed state with an unreleased guard is contradictory.
      guard_taken_and_released: (o) => o.guardAcquired === true && o.guardReleased === true,
      guard_single_regular: (o) => o.guardLinks === 1 && o.guardDeletePending === false,
      thread_single_regular: (o) => o.threadLinks === 1 && o.threadDeletePending === false,
    },
  },
  'observe:openers.rm': {
    required: { complete: f('bool'), count: f('nonNegInt'), processes: f('array'), interpretation: f('string'), files: f('array') },
    invariants: {
      interpretation_exact: (o) => o.interpretation === 'opener_candidates_only',
      processes_consistent: rmProcessesConsistent,
    },
  },
  'observe:process.identity_after': {
    required: {
      pid: f('posInt'), opened: f('bool'), state: f('string'), createFiletime: f('filetime'),
      image: f('localPath'), tokenOpened: f('bool'), integritySid: f('sid'), userSid: f('anySid'),
    },
    invariants: { live_requires_handles: (o) => o.state !== 'live' || (o.opened === true && o.tokenOpened === true) },
  },
})

export const EXPECTATIONS = Object.freeze([
  // ---- preflight: before the operator launches Codex -------------------
  { id: 'PF-harness', mode: 'preflight', step: 'harness', derive: 'harnessBaseline', gates: ['W6', 'W7'],
    basis: 'harness file SHA-256 values recorded for the exact file-name set and equal to the supplied baseline' },
  { id: 'PF-token', mode: 'preflight', step: 'token.self', derive: 'tokenIntegrity', gates: ['W6', 'W7'],
    basis: 'measured token integrity SID equals the label SID; never relabelled' },
  { id: 'PF-binary-sha256', mode: 'preflight', step: 'binary.sha256', derive: 'binarySha256Baseline', gates: ['W7'],
    basis: 'binary bytes equal the recorded expected digest and the supplied baseline before any execution' },
  { id: 'PF-binary-signature', mode: 'preflight', step: 'binary.signature', hypothesis: null, gates: ['W7'],
    basis: 'Authenticode status is recorded, not interpreted' },
  { id: 'PF-binary-pe-version', mode: 'preflight', step: 'binary.pe_version', hypothesis: null, gates: ['W7'],
    basis: 'PE version resource is recorded without executing the binary; an absent resource is declared, not implied' },
  { id: 'PF-home', mode: 'preflight', step: 'home.isolated', derive: 'homeIsolated', gates: ['W7'],
    basis: 'fresh private CODEX_HOME under a validated disposable parent, disjoint from the user and environment Codex homes, with the owner/DACL contract and a plain no-follow ancestry, all recomputed by the evaluator' },
  { id: 'PF-binary-version', mode: 'preflight', step: 'binary.version', derive: 'binaryVersion', gates: ['W7'],
    basis: 'version output of the verified binary equals the baseline version, exits 0, and both streams completed inside the deadline without truncation' },
  { id: 'PF-home-after-version', mode: 'preflight', step: 'home.after_version', hypothesis: null, gates: ['W7'],
    basis: 'entries created by the version command are recorded' },
  { id: 'PF-execution-policy', mode: 'preflight', step: 'host.execution_policy', hypothesis: null, gates: ['W6', 'W7'],
    basis: 'existing policy is recorded; it is never changed' },
  { id: 'PF-defender', mode: 'preflight', step: 'host.defender', hypothesis: { amServiceEnabled: true, realTimeProtectionEnabled: true }, gates: ['W7'],
    basis: 'W7 requires a host where Defender is already enabled; it is never enabled or changed here' },
  { id: 'PF-volume', mode: 'preflight', step: 'host.volume', hypothesis: null, gates: ['W7'],
    basis: 'filesystem of the disposable home is recorded (NTFS or ReFS)' },
  { id: 'PF-os', mode: 'preflight', step: 'host.os', hypothesis: null, gates: ['W6', 'W7'],
    basis: 'OS build, PowerShell version, Administrators membership and SSH session are recorded' },
  { id: 'PF-manifest', mode: 'preflight', step: 'manifest', derive: 'manifestBaseline', gates: ['W7'],
    basis: 'the manifest is complete and reconstructible field by field from the raw preflight observations and the baseline' },

  // ---- observe: while the operator-launched Codex holds one thread -----
  { id: 'OB-harness', mode: 'observe', step: 'harness', derive: 'harnessMatchesManifest', gates: ['W6', 'W7'],
    basis: 'observer files byte-identical to the preflight run, recomputed from the recorded digests' },
  { id: 'OB-token', mode: 'observe', step: 'token.self', derive: 'tokenMatchesManifest', gates: ['W6', 'W7'],
    basis: 'observe integrity SID equals the preflight manifest SID and the label SID' },
  { id: 'OB-home', mode: 'observe', step: 'home.identity', derive: 'homeMatchesManifest', gates: ['W7'],
    basis: 'home and parent paths, file IDs, structure, disjointness, owner/DACL contract and no-follow ancestry all still hold and match the manifest' },
  { id: 'OB-run', mode: 'observe', step: 'run', derive: 'runControl', gates: ['W6', 'W7'],
    basis: 'the control record declares one positive target PID, a different observer PID and a sample count, and every process record binds to it' },
  { id: 'OB-process', mode: 'observe', step: 'process.identity', derive: 'imageLive', gates: ['W3', 'W6', 'W7'],
    basis: 'query-only handle to the declared PID is live, same-user, and its image equals the manifest binary path' },
  { id: 'OB-process-token', mode: 'observe', step: 'process.identity', derive: 'codexToken', gates: ['W6'],
    basis: 'Codex token integrity SID equals the -CodexIntegrityLabel SID; denial is unknown' },
  { id: 'OB-process-sample', mode: 'observe', step: 'process.sample', perSample: true, derive: 'sampleProcess', gates: ['W3', 'W7'],
    basis: 'before each sample\'s active operations the declared PID is re-queried and must still be the same live, same-user instance, at the same creation FILETIME, image and integrity' },
  { id: 'OB-lockdir', mode: 'observe', step: 'lockdir.identity', perSample: true, hypothesis: { directory: true, reparse: false }, gates: ['W7'],
    basis: 'thread-writer-locks is a plain directory inside the disposable home' },
  { id: 'OB-guard', mode: 'observe', step: 'coordination.identity', perSample: true,
    hypothesis: { directory: false, reparse: false, links: 1, deletePending: false }, gates: ['W7'],
    basis: '.coordination.lock exists as a single-link regular file, not pending delete' },
  { id: 'OB-thread-count', mode: 'observe', step: 'thread.count', perSample: true, hypothesis: { count: 1 }, gates: ['W7'],
    basis: 'exactly one thread lock; zero or several makes per-thread probes inapplicable' },
  { id: 'OB-thread-identity', mode: 'observe', step: 'thread.identity', perSample: true,
    hypothesis: { directory: false, reparse: false, links: 1, deletePending: false }, gates: ['W7'],
    basis: 'single-link regular lock file, not pending delete' },
  { id: 'OB-share-read-rwd', mode: 'observe', step: 'share.read_rwd', perSample: true, hypothesis: { opened: true }, gates: ['W7'],
    basis: 'full-sharing read open succeeds; it withholds no sharing mode the holder relies on' },
  { id: 'OB-share-delete-rwd', mode: 'observe', step: 'share.delete_rwd', perSample: true, hypothesis: { opened: true }, gates: ['W7'],
    basis: 'full-sharing DELETE-access open; the holder shares delete and no delete is issued' },
  { id: 'OB-range-rust', mode: 'observe', step: 'range.probe', perSample: true, hypothesis: { state: 'probed', 'ranges.rust.win32': 33 }, gates: ['W7'],
    basis: 'Rust std range probe conflicts with the live holder (ERROR_LOCK_VIOLATION)' },
  { id: 'OB-range-fsext', mode: 'observe', step: 'range.probe', perSample: true, hypothesis: { state: 'probed', 'ranges.fsext.win32': 33 }, gates: ['W7'],
    basis: 'fs-ext 0..0xffff0000 emulation conflicts with the holder' },
  { id: 'OB-range-beyond-fsext', mode: 'observe', step: 'range.probe', perSample: true, hypothesis: { state: 'probed', 'ranges.beyond_fsext.win32': 33 }, gates: ['W7'],
    basis: 'holder range extends past 0xffff0000, consistent with Rust std and not with fs-ext' },
  { id: 'OB-range-tail', mode: 'observe', step: 'range.probe', perSample: true, hypothesis: null, gates: ['W7'],
    basis: 'last-offset probe outside the Rust range; Windows acceptance of that offset is not established' },
  { id: 'OB-range-guard', mode: 'observe', step: 'range.probe', perSample: true, derive: 'rangeGuardBinding', gates: ['W7'],
    basis: 'the probe ran under the expected coordination guard and lock directory, and every identity it verified matches that sample\'s identity records before and after' },
  { id: 'OB-thread-stable', mode: 'observe', step: 'thread.identity_after', perSample: true, derive: 'threadStable', gates: ['W7'],
    basis: 'thread lock identity is unchanged across the probes of a sample, recomputed from both identity records' },
  { id: 'OB-openers', mode: 'observe', step: 'openers.rm', perSample: true, derive: 'openersRm', compare: ['count', 'roles'], gates: ['W4', 'W6', 'W7'],
    basis: 'Restart Manager opener candidates only, with every role recomputed from the control record; never holder evidence' },
  { id: 'OB-coordination-range', mode: 'observe', step: 'coordination.range', measurable: false, hypothesis: { range: 'rust' }, gates: ['W7'],
    basis: 'Codex holds the coordination lock only transiently; a passive observer cannot measure its range' },
  { id: 'OB-process-after', mode: 'observe', step: 'process.identity_after', derive: 'processAfterLive', gates: ['W3', 'W7'],
    basis: 'the same process instance (equal PID and creation FILETIME) is still live after all samples; a failure here cannot undo operations already performed' },
])

// The closed set of record steps each mode may contain. Any other step, or an
// orchestrator_error record, invalidates the file.
export function knownSteps(mode) {
  return new Set(EXPECTATIONS.filter((e) => e.mode === mode && e.measurable !== false).map((e) => e.step))
}

// Steps that must carry a sample index (1..samples); every other known step
// must carry no sample at all. A known step with an invalid sample invalidates
// the whole file.
export function perSampleSteps(mode) {
  return new Set(EXPECTATIONS.filter((e) => e.mode === mode && e.measurable !== false && e.perSample).map((e) => e.step))
}
