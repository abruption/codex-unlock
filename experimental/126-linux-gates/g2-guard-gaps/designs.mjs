// G2: guard-liveness gaps of #137 as pure models (#126 research).
import { Buffer } from 'node:buffer'
//
// Nothing here is product code or a measurement. Each export is a pure
// function over explicit evidence or a schedule, so that counterexamples are
// deterministic. Kernel behaviour is source-derived from pinned Linux v6.17
// (`e5f0a698b34ed76002dc5cff3804a61c80233a7a`): fs/locks.c (`locks_start`,
// `locks_show`, `lock_get_status`, `locks_translate_pid`, flock `flc_pid =
// current->tgid`) and fs/proc/fd.c (`seq_show` calls `f_op->show_fdinfo`).
// It is a targeted reading, not an exhaustive audit, and no claim is made
// for other kernels.

// ---------------------------------------------------------------------------
// Gap 1: in-guard reads and what they can wait on.
//
// Wait classes. `target_*` classes depend on the candidate's memory, file
// type or file system and have no bound the observer controls. `lock_fs` is
// the lock file's own file system, which main's guarded probe already opens
// and flocks (parity). `proc_spin` covers task/files spinlocks and RCU.
// `global_file_rwsem` is /proc/locks: `locks_start` takes
// `percpu_down_write(&file_rwsem)` and `blocked_lock_lock`; readers of that
// rwsem (flock/posix insertion) hold it only around list updates and do not
// sleep there in the read v6.17 paths. That is a source argument, not a bound.
export const UNBOUNDED_TARGET_CLASSES = new Set(['target_task_mm', 'target_file_getattr', 'target_file_show_fdinfo'])

const READS = {
  'b483cd5': [
    ['statfs/stat lock path', 'lock_fs'], ['stat /proc/PID, ns/mnt readlink', 'proc_spin'],
    ['/proc/PID/stat', 'proc_spin'], ['/proc/PID/exe readlink + cmdline', 'target_task_mm'],
    ['/proc/PID/fd list', 'proc_spin'], ['fd/N readlink', 'proc_spin'], ['stat fd/N', 'target_file_getattr'],
    ['fdinfo/N', 'target_file_show_fdinfo'], ['stat fd/N', 'target_file_getattr'], ['fd/N readlink', 'proc_spin'],
  ],
  // F4 proposal (../../126-guard-liveness/f4-guard-scope): cmdline/exe and
  // stat via FD moved out; fdinfo stays.
  f4: [
    ['statfs/stat lock path', 'lock_fs'], ['stat /proc/PID, ns/mnt readlink', 'proc_spin'],
    ['/proc/PID/stat', 'proc_spin'], ['/proc/PID/fd list', 'proc_spin'], ['fd/N readlink', 'proc_spin'],
    ['fdinfo/N', 'target_file_show_fdinfo'], ['fd/N readlink', 'proc_spin'],
  ],
  // G4 proposal below: no per-descriptor fdinfo in the guard; /proc/locks
  // instead. statfs moved before the guard (gap 2).
  g4: [
    ['stat lock path', 'lock_fs'], ['stat /proc/PID, ns/mnt+pid readlink', 'proc_spin'],
    ['/proc/PID/stat', 'proc_spin'], ['/proc/PID/fd list', 'proc_spin'], ['fd/N readlink', 'proc_spin'],
    ['/proc/locks', 'global_file_rwsem'], ['fd/N readlink', 'proc_spin'],
  ],
}

export function inGuardReads(design) {
  const reads = READS[design]
  if (!reads) throw new Error(`unknown design ${design}`)
  return reads.map(([read, waitClass]) => ({ read, waitClass }))
}

// What a design's guard can wait on under a schedule. `fd_reused` models FD
// N being closed and reused by a file whose show_fdinfo takes a sleeping lock
// (for example epoll's `ep->mtx` in ep_show_fdinfo) between the in-guard
// readlink and the fdinfo read. The later readlink refuses the result, but the
// wait has already happened while coordination is held.
export function guardWaits(design, schedule = {}) {
  const waits = []
  for (const { read, waitClass } of inGuardReads(design)) {
    if (waitClass === 'target_file_show_fdinfo') {
      waits.push({ read, waitClass, on: schedule.fdReusedBy ? `${schedule.fdReusedBy}.show_fdinfo` : 'lock file (no show_fdinfo on ext4/tmpfs/xfs regular files)' })
    } else if (waitClass === 'target_task_mm') {
      waits.push({ read, waitClass, on: 'target mmap_lock (access_remote_vm)' })
    } else if (waitClass === 'target_file_getattr') {
      waits.push({ read, waitClass, on: schedule.fdReusedBy ? `${schedule.fdReusedBy}.getattr` : 'lock file getattr' })
    } else {
      waits.push({ read, waitClass, on: waitClass })
    }
  }
  const unbounded = waits.filter((w) => UNBOUNDED_TARGET_CLASSES.has(w.waitClass) &&
    (w.waitClass !== 'target_file_show_fdinfo' || schedule.fdReusedBy))
  return { waits, unboundedTargetWaits: unbounded, lockFsParity: waits.some((w) => w.waitClass === 'lock_fs') }
}

// ---------------------------------------------------------------------------
// /proc/locks parser (G4). Each line: `<id>: [<pad>-> ]<kind> ... <pid>
// <maj>:<min>:<ino> <start> <end>`. Rows on the target inode must be a plain
// granted or blocked FLOCK ADVISORY WRITE/READ; anything else on the target is
// unsupported and refuses. Rows on other inodes are only located, not judged.
// Field widths follow lock_get_status: MAJOR is 12 bits and MINOR 20 bits of
// the kernel dev_t, the inode an unsigned long. Anything wider is overflow.
const TARGET_ROW = /^(\d{1,20}): (?:\s*-> )?FLOCK\s+ADVISORY\s+(WRITE|READ)\s+(-?\d{1,20})\s+([0-9a-f]{1,8}):([0-9a-f]{1,8}):(\d{1,20})\s+0\s+EOF$/i
const ANY_ROW = /^(\d{1,20}): (\s*-> )?.*?\s(-?\d{1,20})\s+(?:([0-9a-f]{1,8}):([0-9a-f]{1,8}):(\d{1,20})|<none>:0)\s+\S+\s+\S+$/i
const MAX_INODE = (1n << 64n) - 1n

export function parseProcLocks(text, target) {
  if (typeof text !== 'string' || (text !== '' && !text.endsWith('\n'))) throw new Error('proc_locks_truncated')
  const rows = []
  for (const line of text.split('\n')) {
    if (line === '') continue
    const any = ANY_ROW.exec(line)
    if (!any) throw new Error('proc_locks_line_unsupported')
    if (any[4] === undefined) continue
    const major = BigInt(`0x${any[4]}`); const minor = BigInt(`0x${any[5]}`); const inode = BigInt(any[6])
    if (major > 0xfffn || minor > 0xfffffn || inode > MAX_INODE) throw new Error('proc_locks_field_overflow')
    if (major !== target.major || minor !== target.minor || inode !== target.inode) continue
    const strict = TARGET_ROW.exec(line)
    if (!strict) throw new Error('proc_locks_target_row_unsupported')
    const pid = Number(strict[3])
    if (!Number.isSafeInteger(pid)) throw new Error('proc_locks_pid_unsafe')
    rows.push({ blocked: Boolean(any[2]), access: strict[2].toUpperCase(), pid })
  }
  return rows
}

// Evidence validation for decideG4. Returns a refusal reason or null. Missing
// or malformed fields refuse; nothing here throws or defaults.
const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v)
const isPid = (v) => Number.isSafeInteger(v) && v > 0
const isFdName = (v) => typeof v === 'string' && /^\d{1,10}$/.test(v)
const isTicks = (v) => typeof v === 'string' && /^\d{1,20}$/.test(v)
const isDevIno = (v) => isObject(v) && typeof v.major === 'bigint' && typeof v.minor === 'bigint' && typeof v.inode === 'bigint' &&
  v.major >= 0n && v.major <= 0xfffn && v.minor >= 0n && v.minor <= 0xfffffn && v.inode > 0n && v.inode <= MAX_INODE
function malformed(e) {
  if (!isObject(e)) return 'evidence'
  if (!isPid(e.candidatePid)) return 'candidatePid'
  if (!isFdName(e.candidateFd)) return 'candidateFd'
  if (!isDevIno(e.target)) return 'target'
  if (!Array.isArray(e.candidates) || !e.candidates.every(isFdName)) return 'candidates'
  for (const name of ['pre', 'guard', 'post']) {
    const sample = e[name]
    if (!isObject(sample)) return name
    if (!Array.isArray(sample.descriptors) || sample.descriptors.length === 0 || !sample.descriptors.every(isFdName) ||
      new Set(sample.descriptors).size !== sample.descriptors.length) return `${name}.descriptors`
    if (!sample.descriptors.includes(e.candidateFd)) return `${name}.descriptors_without_candidate`
    if (typeof sample.readlink !== 'string' || !sample.readlink.startsWith('/') || sample.readlink.endsWith(' (deleted)')) return `${name}.readlink`
    if (!isTicks(sample.startTicks)) return `${name}.startTicks`
  }
  for (const name of ['pre', 'post']) {
    if (!Array.isArray(e[name].fdinfoRows) || !e[name].fdinfoRows.every(isDevIno)) return `${name}.fdinfoRows`
  }
  if (!['held', 'free', 'unknown'].includes(e.guard.probe)) return 'guard.probe'
  if (typeof e.guard.pidNamespaceSame !== 'boolean' || typeof e.guard.mountNamespaceSame !== 'boolean') return 'guard.namespaces'
  if (e.guard.procLocks !== null && typeof e.guard.procLocks !== 'string') return 'guard.procLocks'
  if (typeof e.post.commandUnchanged !== 'boolean') return 'post.commandUnchanged'
  return null
}

// G4 decision for one candidate description. Evidence is three samples:
// `pre` (before the guard), `guard` (inside), `post` (after release).
//
// The result is at best `consistent_unproven`: the samples did not refute
// participation, but they do NOT prove that the candidate's sampled
// description participated inside the guard. The /proc/locks acquirer PID
// names the process that called flock(), not a description, and has no
// instance binding (a historical PID can be reused). The hidden-transfer
// schedule in designs.test.mjs satisfies every check here while the sampled
// description was unlocked inside the guard. G4 therefore stays no-go until
// that binding problem is solved. Never sole control.
export function decideG4(e) {
  const refuse = (reason) => ({ decision: 'refuse', reason })
  const bad = malformed(e)
  if (bad) return refuse(`evidence_malformed:${bad}`)
  if (e.candidates.length !== 1 || e.candidates[0] !== e.candidateFd) return refuse('candidate_descriptor_not_unique')
  if (e.guard.pidNamespaceSame !== true || e.guard.mountNamespaceSame !== true) return refuse('namespace_mismatch')
  for (const name of ['pre', 'post']) {
    const rows = e[name].fdinfoRows
    if (rows.length === 0) return refuse(`fdinfo_row_absent_${name}`)
    if (rows.length !== 1) return refuse(`fdinfo_rows_ambiguous_${name}`)
    if (rows[0].major !== e.target.major || rows[0].minor !== e.target.minor || rows[0].inode !== e.target.inode) return refuse(`fdinfo_row_mismatch_${name}`)
  }
  const same = (key) => JSON.stringify(e.pre[key]) === JSON.stringify(e.guard[key]) && JSON.stringify(e.guard[key]) === JSON.stringify(e.post[key])
  for (const key of ['descriptors', 'readlink', 'startTicks']) if (!same(key)) return refuse(`identity_changed:${key}`)
  if (e.guard.probe !== 'held') return refuse(`probe_${e.guard.probe}`)
  if (e.guard.procLocks === null) return refuse('proc_locks_unavailable')
  if (Buffer.byteLength(e.guard.procLocks) > 65536) return refuse('proc_locks_over_limit')
  let rows
  try { rows = parseProcLocks(e.guard.procLocks, e.target) } catch (error) { return refuse(error.message) }
  const granted = rows.filter((r) => !r.blocked)
  if (granted.length === 0) return refuse('proc_locks_no_granted_row')
  if (granted.length !== 1 || granted[0].access !== 'WRITE') return refuse('proc_locks_rows_ambiguous')
  if (granted[0].pid <= 0) return refuse('acquirer_not_visible')
  // flc_pid is the tgid that called flock(). A different acquirer refuses;
  // an equal one is not proof (see above).
  if (granted[0].pid !== e.candidatePid) return refuse('acquirer_pid_mismatch')
  if (e.post.commandUnchanged !== true) return refuse('command_changed_after_guard')
  return { decision: 'consistent_unproven', participationProven: false, soleControl: false,
    gaps: ['sampled_description_not_bound_inside_guard', 'acquirer_pid_has_no_instance_binding'],
    waiters: rows.filter((r) => r.blocked).length }
}

// Model of the hidden-transfer schedule (designs.test.mjs). Returns the three
// samples a G4 observer would collect and the model's ground truth. It is a
// model schedule, not a claim about any Codex runtime path.
export function hiddenTransferSchedule({ candidatePid = 42, fd = '7', target, readlink = '/h/thread-writer-locks/x.lock', startTicks = '900' }) {
  const descriptors = ['0', '1', '2', fd]
  const base = { descriptors, readlink, startTicks }
  const row = (pid) => `1: FLOCK  ADVISORY  WRITE ${pid} ${target.major.toString(16).padStart(2, '0')}:${target.minor.toString(16).padStart(2, '0')}:${target.inode} 0 EOF\n`
  return {
    steps: [
      'pre: P holds description A at FD7',
      'P unlocks A, flocks description B at a temporary FD, passes B to a hidden recipient, closes the temporary FD',
      'guard: FD7 (A) is unlocked; the recipient alone holds B; /proc/locks shows B with acquirer P',
      'the recipient releases B; P flocks A again',
      'post: P holds A at FD7',
    ],
    truth: { sampledDescriptionParticipatedInGuard: false, guardHolder: 'hidden_recipient' },
    evidence: {
      candidatePid, candidateFd: fd, candidates: [fd], target,
      pre: { ...base, fdinfoRows: [{ ...target }] },
      guard: { ...base, probe: 'held', pidNamespaceSame: true, mountNamespaceSame: true, procLocks: row(candidatePid) },
      post: { ...base, fdinfoRows: [{ ...target }], commandUnchanged: true },
    },
  }
}

// The #137 b483cd5 / F4 acceptance, modelled with the same evidence shape:
// one in-guard fdinfo row on the candidate description, without an acquirer
// check. Used only to show counterexamples.
export function decideB483(e) {
  if (e.candidates.length < 1) return { decision: 'refuse', reason: 'no_candidate' }
  if (e.guard.probe !== 'held') return { decision: 'refuse', reason: `probe_${e.guard.probe}` }
  const rows = e.guard.fdinfoRows ?? []
  if (rows.length !== 1) return { decision: 'refuse', reason: rows.length ? 'linux_rows_ambiguous' : 'linux_participation_unproven' }
  return { decision: 'participation', soleControl: false }
}

// ---------------------------------------------------------------------------
// Gap 2: lock file system stalls under the native guard.
export const ALLOWLISTED_FS = new Set([0xef53n, 0x01021994n, 0x58465342n]) // ext, tmpfs, XFS

// Ordered plan for one Linux participation attempt. `fs-gate` checks statfs
// before any participation guard and refuses non-allowlisted file systems
// without taking it. The main probe's own guarded open/flock (`mainProbe`)
// is unchanged by both: refusing that too is a separate policy choice
// (`refuse-before-any-guard`), which also changes diagnostics on such homes.
export function participationPlan(design, lockFsType) {
  const allowed = ALLOWLISTED_FS.has(lockFsType)
  const mainProbe = { guarded: true, touchesLockFs: true }
  if (design === 'b483cd5') {
    return { mainProbe, participationGuardTaken: true, inGuardLockFsOps: ['statfs', 'stat', 'stat'],
      refusedBeforeGuard: false, refusedInGuard: !allowed }
  }
  if (design === 'fs-gate') {
    if (!allowed) return { mainProbe, participationGuardTaken: false, inGuardLockFsOps: [], refusedBeforeGuard: true, refusedInGuard: false }
    return { mainProbe, participationGuardTaken: true, inGuardLockFsOps: ['stat', 'stat'], refusedBeforeGuard: false, refusedInGuard: false }
  }
  if (design === 'refuse-before-any-guard') {
    if (!allowed) return { mainProbe: { guarded: false, touchesLockFs: false, probe: 'unknown' }, participationGuardTaken: false,
      inGuardLockFsOps: [], refusedBeforeGuard: true, refusedInGuard: false }
    return { mainProbe, participationGuardTaken: true, inGuardLockFsOps: ['stat', 'stat'], refusedBeforeGuard: false, refusedInGuard: false }
  }
  throw new Error(`unknown design ${design}`)
}

// ---------------------------------------------------------------------------
// Gap 3: evidence aging between the in-guard observation and the signal.
//
// The decision runs at `checkAt`. The signal happens at `killAt`, which the
// decision cannot observe or bound: between the check and `process.kill` the
// thread can be descheduled, and Node exposes no pidfd. A soft check refuses
// slow paths it can see; it never yields a hard bound. F4's 25 ms check is
// `confirmMs` only.
const TIME_ORDER = ['guardObservedAt', 'guardReleasedAt', 'probeReturnedAt', 'confirmEndedAt', 'checkAt']
export function finalBoundary(t, { softLimitMs = 25 } = {}) {
  const refuse = (reason) => ({ allowed: false, reason, hardBound: false })
  if (t === null || typeof t !== 'object') return refuse('timestamps_missing')
  if (typeof softLimitMs !== 'number' || !Number.isFinite(softLimitMs) || softLimitMs < 0) return refuse('soft_limit_invalid')
  for (const key of TIME_ORDER) if (typeof t[key] !== 'number' || !Number.isFinite(t[key])) return refuse(`timestamp_missing:${key}`)
  // Monotonic clock readings must be ordered; anything else is a broken
  // observation, never a fast one.
  for (let i = 1; i < TIME_ORDER.length; i += 1) {
    if (t[TIME_ORDER[i]] < t[TIME_ORDER[i - 1]]) return refuse(`timestamps_not_monotonic:${TIME_ORDER[i]}`)
  }
  if (t.killAt !== undefined && (typeof t.killAt !== 'number' || !Number.isFinite(t.killAt) || t.killAt < t.checkAt)) {
    return refuse('kill_timestamp_invalid')
  }
  const confirmMs = t.confirmEndedAt - t.probeReturnedAt
  const evidenceAgeAtCheckMs = t.checkAt - t.guardObservedAt
  const allowed = confirmMs <= softLimitMs && evidenceAgeAtCheckMs <= softLimitMs
  return {
    allowed, reason: allowed ? null : 'soft_freshness_exceeded', confirmMs, evidenceAgeAtCheckMs,
    // Observed only after the fact, never an input to the decision.
    evidenceAgeAtSignalMs: t.killAt === undefined ? null : t.killAt - t.guardObservedAt,
    hardBound: false,
    requires: ['post_signal_exit_verification', 'post_signal_lock_release_verification', 'transcript_hash_invariance'],
  }
}

// ---------------------------------------------------------------------------
// Gap 4: inherited-description participation versus sole control.
//
// A granted row proves that one open file description participates in the
// lock. It does not prove that SIGTERM to the candidate releases it: a
// fork-without-exec child or an SCM_RIGHTS recipient shares the description
// (O_CLOEXEC affects exec only). `standard` refuses everything observable;
// `strict` also refuses when any same-user process is unobservable (its
// /proc/PID/fd is unreadable, for example a non-dumpable agent), because such a
// process could hold the description. Neither mode proves sole control.
const pidList = (v) => Array.isArray(v) && v.every((x) => Number.isSafeInteger(x) && x > 0) && new Set(v).size === v.length
export const SOLE_CONTROL_MODES = new Set(['standard', 'strict'])
export function soleControlDecision(e, mode = 'standard') {
  const refuse = (reason) => ({ decision: 'refuse', reason, soleControlProven: false })
  if (!SOLE_CONTROL_MODES.has(mode)) return refuse(`mode_unknown:${String(mode)}`)
  if (e === null || typeof e !== 'object') return refuse('evidence_malformed')
  if (!Number.isSafeInteger(e.candidatePid) || e.candidatePid <= 0) return refuse('evidence_malformed:candidatePid')
  if (e.lsofError !== null && typeof e.lsofError !== 'string') return refuse('evidence_malformed:lsofError')
  if (!pidList(e.openers)) return refuse('evidence_malformed:openers')
  if (!Number.isSafeInteger(e.acquirerPid) || e.acquirerPid <= 0) return refuse('evidence_malformed:acquirerPid')
  if (e.descendants !== null && !pidList(e.descendants)) return refuse('evidence_malformed:descendants')
  if (e.unobservableSameUser !== null && !pidList(e.unobservableSameUser)) return refuse('evidence_malformed:unobservableSameUser')
  if (e.lsofError !== null) return refuse('opener_lookup_incomplete')
  if (e.openers.length !== 1 || e.openers[0] !== e.candidatePid) return refuse('opener_set_not_candidate_only')
  // Necessary, not sufficient: an equal acquirer PID does not bind the
  // description (see decideG4).
  if (e.acquirerPid !== e.candidatePid) return refuse('description_acquired_by_other_process')
  if (e.descendants === null) return refuse('descendants_unavailable')
  if (e.descendants.length > 0) return refuse('descendants_may_share_description')
  const residuals = ['description_binding_unproven', 'post_signal_release_verification_required']
  if (mode === 'strict') {
    if (e.unobservableSameUser === null) return refuse('unobservable_scan_unavailable')
    if (e.unobservableSameUser.length > 0) return refuse('unobservable_same_user_process')
  } else {
    residuals.unshift('hidden_sharer_not_excluded')
  }
  return { decision: 'not_refused', soleControlProven: false, residuals }
}

// #137 b483cd5 policy for the same facts: descendants are a warning only and
// the acquirer is not checked. Used to show the counterexample.
export function soleControlB483(e) {
  if (e.lsofError) return { decision: 'refuse', reason: 'lock_opener_lookup_failed' }
  if (e.openers.length !== 1 || e.openers[0] !== e.candidatePid) return { decision: 'refuse', reason: 'lock_owner_not_unique' }
  const warnings = e.descendants === null ? ['owner_descendants_unavailable']
    : e.descendants.length ? [`owner_has_descendants:${e.descendants.join(',')}`] : []
  return { decision: 'eligible', warnings }
}
