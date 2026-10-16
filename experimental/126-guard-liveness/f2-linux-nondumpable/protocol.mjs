// F2 stage protocol (#126 research), on top of lib/isolated-observer.mjs.
//
// The inspector must report exactly these stages, once each, in this order.
// Each stage's result or error must have the shape below. A shape fault means
// collection failed; it is never read as a product refusal.
// Build content is verified before any product module is imported.
export const F2_STAGES = ['dist_identity', 'module_load', 'openers', 'prepare', 'guarded_verify', 'inspect_thread']
// Only `prepare` may end in an error that counts as an observed product
// outcome. Every other stage error is a collection fault.
const ERROR_ALLOWED = new Set(['prepare'])

const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v)
const isTicks = (v) => typeof v === 'string' && /^\d+$/.test(v)
const isStrings = (v) => Array.isArray(v) && v.every((x) => typeof x === 'string')
const isPid = (v) => Number.isSafeInteger(v) && v > 0

const RESULT_SHAPES = {
  module_load: (r) => isObject(r) && isStrings(r.modules) && r.unlockReachable === false,
  dist_identity: (r) => isObject(r) && r.ok === true && /^[0-9a-f]{64}$/.test(r.manifestSha256 ?? '') &&
    Array.isArray(r.faults) && r.faults.length === 0,
  openers: (r) => isObject(r) && (r.error === null || typeof r.error === 'string') && Array.isArray(r.processes) &&
    r.processes.every((p) => isObject(p) && isPid(p.pid) && typeof p.isCodex === 'boolean' &&
      typeof p.identityComplete === 'boolean' && isStrings(p.errors) && (p.startTicks === null || isTicks(p.startTicks))),
  prepare: (r) => isObject(r) && isPid(r.pid) && isTicks(r.startTicks) && isStrings(r.candidates) && isStrings(r.descriptors),
  guarded_verify: (r) => isObject(r) && (r.skipped === 'prepare_failed' ||
    (['held', 'free', 'unknown'].includes(r.status) && (r.participation === undefined ||
      (isObject(r.participation) && isPid(r.participation.pid) && isTicks(r.participation.startTicks) &&
        typeof r.participation.descriptor === 'string')))),
  inspect_thread: (r) => isObject(r) && typeof r.safeToUnlock === 'boolean' && isStrings(r.blockers) &&
    isStrings(r.warnings) && isObject(r.probe) && typeof r.classification === 'string',
}
const ERROR_SHAPE = (e) => isObject(e) && (e.code === null || typeof e.code === 'string') && typeof e.message === 'string'

export function validateF2(observation) {
  const faults = []
  const byStage = {}
  const begun = observation.begun ?? []
  begun.forEach((name, index) => {
    if (F2_STAGES[index] !== name) faults.push(`stage_order:${index}:${name}`)
  })
  for (const s of observation.stages ?? []) {
    if (Object.hasOwn(byStage, s.stage)) { faults.push(`stage_duplicate:${s.stage}`); continue }
    byStage[s.stage] = s
    if (!F2_STAGES.includes(s.stage)) { faults.push(`stage_unknown:${s.stage}`); continue }
    if (Object.hasOwn(s, 'error')) {
      if (!ERROR_ALLOWED.has(s.stage)) faults.push(`stage_failed:${s.stage}`)
      else if (!ERROR_SHAPE(s.error)) faults.push(`stage_error_malformed:${s.stage}`)
    } else if (!RESULT_SHAPES[s.stage](s.result)) {
      faults.push(`stage_result_malformed:${s.stage}`)
    }
  }
  const missing = F2_STAGES.filter((name) => !Object.hasOwn(byStage, name))
  if (missing.length) faults.push(`stages_missing:${missing.join(',')}`)
  return { ok: faults.length === 0, faults, byStage, missing }
}

// Accepted F2_CHILD_FAULT values; anything else is refused before any child runs.
export const CHILD_FAULTS = new Set(F2_STAGES.map((s) => `stall:${s}`))

export function parseChildFault(value) {
  if (value === undefined || value === '') return null
  if (!CHILD_FAULTS.has(value)) throw new Error(`F2_CHILD_FAULT must be one of ${[...CHILD_FAULTS].join(', ')}`)
  return value
}
