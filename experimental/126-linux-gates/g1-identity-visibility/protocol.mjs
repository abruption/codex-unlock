// G1 stage protocol (#126 research), on top of
// ../../126-guard-liveness/lib/isolated-observer.mjs.
//
// Exactly these stages, once each, in this order, each with a typed result.
// Cross-stage consistency is checked here too. A protocol fault is a
// collection failure; it is never read as a product outcome.
export const G1_STAGES = ['dist_identity', 'module_load', 'lsof_control', 'openers', 'identity_direct',
  'prepare', 'guarded_verify', 'held_probe', 'inspect_thread']
// Only `prepare` may end in an error that counts as an observed product
// outcome (R1). Every other stage error is a collection fault.
const ERROR_ALLOWED = new Set(['prepare'])
const PROBE_STATUS = new Set(['held', 'free', 'unknown'])
const GUARD_STATUS = new Set(['acquired', 'busy', 'absent', 'unsafe', 'changed'])

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v)
export const isTicks = (v) => typeof v === 'string' && /^\d{1,20}$/.test(v)
const isStrings = (v) => Array.isArray(v) && v.every((x) => typeof x === 'string')
const isFdNames = (v) => Array.isArray(v) && v.every((x) => typeof x === 'string' && /^\d{1,10}$/.test(x))
export const isPid = (v) => Number.isSafeInteger(v) && v > 0
const isHash = (v) => typeof v === 'string' && /^[0-9a-f]{64}$/.test(v)
const isError = (v) => v === null || typeof v === 'string'
const isIdentity = (p) => isObject(p) && isPid(p.pid) && typeof p.isCodex === 'boolean' && typeof p.isSharedService === 'boolean' &&
  typeof p.identityComplete === 'boolean' && isStrings(p.errors) && (p.startTicks === null || isTicks(p.startTicks)) &&
  (p.commandFingerprint === null || isHash(p.commandFingerprint))
export const isParticipation = (p) => isObject(p) && isPid(p.pid) && isTicks(p.startTicks) && typeof p.descriptor === 'string' &&
  /^\d{1,10}$/.test(p.descriptor)
// LockProbe as #137 types.ts defines it. `held` requires an acquired guard.
export function isProbe(p) {
  if (!isObject(p) || !PROBE_STATUS.has(p.status) || p.method !== 'flock_exclusive_nonblocking') return false
  if (p.error !== undefined && typeof p.error !== 'string') return false
  if (p.guard !== undefined && !(isObject(p.guard) && GUARD_STATUS.has(p.guard.status) &&
    (p.guard.attempts === undefined || (Number.isSafeInteger(p.guard.attempts) && p.guard.attempts > 0)))) return false
  if (p.participation !== undefined && !isParticipation(p.participation)) return false
  if (p.status === 'held' && p.guard?.status !== 'acquired') return false
  if (p.participation !== undefined && p.status !== 'held') return false
  return true
}

const RESULT_SHAPES = {
  dist_identity: (r) => isObject(r) && r.ok === true && isHash(r.manifestSha256) && r.manifestMatchesExpected === true &&
    r.expectedManifestSha256 === r.manifestSha256 && Array.isArray(r.faults) && r.faults.length === 0,
  module_load: (r) => isObject(r) && isStrings(r.modules) && r.unlockReachable === false,
  lsof_control: (r) => isObject(r) && isError(r.error) && Number.isSafeInteger(r.processCount) && r.processCount >= 0,
  openers: (r) => isObject(r) && isError(r.error) && Array.isArray(r.processes) && r.processes.every(isIdentity),
  identity_direct: (r) => isIdentity(r),
  prepare: (r) => isObject(r) && isPid(r.pid) && isTicks(r.startTicks) && isFdNames(r.candidates) && isFdNames(r.descriptors),
  guarded_verify: (r) => isObject(r) && (r.skipped === 'prepare_failed' || isProbe(r)),
  held_probe: (r) => isProbe(r) && r.participation === undefined,
  inspect_thread: (r) => isObject(r) && typeof r.safeToUnlock === 'boolean' && isStrings(r.blockers) &&
    (r.ownerLockFiles === null || isStrings(r.ownerLockFiles)) &&
    isStrings(r.warnings) && isProbe(r.probe) && typeof r.classification === 'string' && Number.isSafeInteger(r.openers) &&
    (r.owner === null || (isObject(r.owner) && isPid(r.owner.pid) && isStrings(r.owner.errors) &&
      (r.owner.startTicks === null || isTicks(r.owner.startTicks)))),
}
const ERROR_SHAPE = (e) => isObject(e) && (e.code === null || typeof e.code === 'string') && typeof e.message === 'string'

// `context.expectedManifestSha256` and `context.holderPid` are the runner's
// own values, never the child's.
export function validateG1(observation, context = {}) {
  const faults = []
  const byStage = {}
  for (const [index, name] of (observation.begun ?? []).entries()) {
    if (G1_STAGES[index] !== name) faults.push(`stage_order:${index}:${name}`)
  }
  for (const s of observation.stages ?? []) {
    if (Object.hasOwn(byStage, s.stage)) { faults.push(`stage_duplicate:${s.stage}`); continue }
    byStage[s.stage] = s
    if (!G1_STAGES.includes(s.stage)) { faults.push(`stage_unknown:${s.stage}`); continue }
    if (Object.hasOwn(s, 'error')) {
      if (!ERROR_ALLOWED.has(s.stage)) faults.push(`stage_failed:${s.stage}`)
      else if (!ERROR_SHAPE(s.error)) faults.push(`stage_error_malformed:${s.stage}`)
    } else if (!RESULT_SHAPES[s.stage](s.result)) {
      faults.push(`stage_result_malformed:${s.stage}`)
    }
  }
  const missing = G1_STAGES.filter((name) => !Object.hasOwn(byStage, name))
  if (missing.length) faults.push(`stages_missing:${missing.join(',')}`)
  if (faults.length === 0) {
    if (!isHash(context.expectedManifestSha256)) faults.push('expected_manifest_missing')
    else if (byStage.dist_identity.result.manifestSha256 !== context.expectedManifestSha256) faults.push('build_manifest_mismatch')
    if (!isPid(context.holderPid)) faults.push('holder_pid_missing')
    else {
      if (byStage.identity_direct.result.pid !== context.holderPid) faults.push('identity_direct_pid_mismatch')
      if (byStage.prepare.result && byStage.prepare.result.pid !== context.holderPid) faults.push('prepare_pid_mismatch')
    }
    // A failed prepare must be followed by the harness skip, and only then.
    const prepareFailed = Object.hasOwn(byStage.prepare, 'error')
    const skipped = byStage.guarded_verify.result.skipped === 'prepare_failed'
    if (prepareFailed !== skipped) faults.push('prepare_guarded_inconsistent')
  }
  return { ok: faults.length === 0, faults, byStage, missing }
}

export const CHILD_FAULTS = new Set(G1_STAGES.map((s) => `stall:${s}`))

export function parseChildFault(value) {
  if (value === undefined || value === '') return null
  if (!CHILD_FAULTS.has(value)) throw new Error(`G1_CHILD_FAULT must be one of ${[...CHILD_FAULTS].join(', ')}`)
  return value
}
