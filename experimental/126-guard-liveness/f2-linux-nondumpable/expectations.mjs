// Expected-table evaluation for the isolated F2 inspector (#126 research).
//
// Three separate results per run:
// - `collected`: the child completed the F2 protocol (protocol.mjs) without
//   faults and the holder stayed the same live instance throughout.
// - `rows`: whether observed product stages match the table below.
// - `recorded`: values kept for review and never asserted, such as the
//   fixture's isCodex result and final eligibility.
// None of this is a fail-closed proof, a native Codex result or a signal
// decision. A dumpable=0 refusal counts only when the dumpable=0 run's own
// rows pass and the same report's dumpable=1 control passed.
const isTicks = (v) => typeof v === 'string' && /^\d+$/.test(v)
export const sameTicks = (a, b) => isTicks(a) && isTicks(b) && BigInt(a) === BigInt(b)

// Errors that a same-user observer gets from procfs access checks. Anything
// else (ENOENT, a TypeError from a wrong build, the product's budget error)
// is not evidence of a permission refusal.
export const PERMISSION_CODES = new Set(['EACCES', 'EPERM'])
// The #137 `b483cd5` policy adds this blocker when owner start ticks or a
// matching participation are absent (src/policy.ts, evaluateSafety). It is
// the only refusal reason this table attributes to missing participation.
export const PARTICIPATION_BLOCKER = 'linux_participation_unproven'

function firstObservedError(byStage) {
  for (const [name, s] of Object.entries(byStage)) {
    if (s.error) return { stage: name, code: s.error.code, message: s.error.message }
    const r = s.result
    if (name === 'openers' && (r?.error || r?.processes?.some((p) => p.errors.length))) {
      return { stage: name, opener: r.error, errors: r.processes.flatMap((p) => p.errors) }
    }
  }
  return null
}

export function evaluateRun({ dumpable, holder, ticks, observation, protocol }) {
  const rows = []
  const row = (id, ok, detail) => { rows.push({ id, ok: Boolean(ok), ...(ok ? {} : { detail }) }) }
  const collectedFaults = [...(observation.incomplete ? [`incomplete:${observation.incompletePhase}`] : []),
    ...observation.faults, ...protocol.faults]
  // The holder must be one live instance from ready to after inspection.
  if (!isTicks(ticks.ready)) collectedFaults.push('holder_ticks_unavailable')
  if (!sameTicks(ticks.ready, ticks.afterInspect)) collectedFaults.push('holder_instance_changed_or_gone')
  if (ticks.holderExitedDuringInspection) collectedFaults.push('holder_exited_during_inspection')
  const collected = collectedFaults.length === 0
  // Stage shapes are trusted only after protocol validation. A malformed
  // result must remain a structured collection failure, not throw while
  // reading payload fields (or accidentally satisfy an expectation).
  if (protocol.faults.length > 0) return {
    dumpable, collected: false, collectedFaults, rows, ok: false,
    recorded: { firstObservedError: null, guardedAttempted: null, participation: null,
      fixtureIsCodex: null, eligibility: null, owner: null, probe: null },
  }
  const s = protocol.byStage
  const openers = s.openers?.result
  const prepare = s.prepare
  const verify = s.guarded_verify?.result
  const inspect = s.inspect_thread?.result
  const fd = String(holder.fd)
  const only = openers?.processes?.length === 1 ? openers.processes[0] : null
  row('V_owner_visible', openers && openers.error === null && only?.pid === holder.pid, openers)
  if (dumpable === 1) {
    row('E1_owner_identity', only && only.identityComplete === true && only.errors.length === 0 &&
      sameTicks(only.startTicks, ticks.ready), only)
    row('E2_prepare_candidate', prepare?.result && prepare.result.pid === holder.pid && sameTicks(prepare.result.startTicks, ticks.ready) &&
      prepare.result.descriptors.includes(fd) && prepare.result.candidates.includes(fd), prepare)
    row('E3_guarded_participation', verify?.status === 'held' && verify.guard?.status === 'acquired' &&
      verify.participation?.pid === holder.pid && verify.participation.descriptor === fd &&
      sameTicks(verify.participation.startTicks, ticks.ready), verify)
    row('E4_inspection_participation', inspect && inspect.probe.status === 'held' &&
      inspect.probe.participation?.pid === holder.pid && inspect.probe.participation.descriptor === fd &&
      sameTicks(inspect.probe.participation.startTicks, ticks.ready) && inspect.owner?.pid === holder.pid &&
      sameTicks(inspect.owner.startTicks, ticks.ready) && !inspect.blockers.includes(PARTICIPATION_BLOCKER), inspect)
  } else {
    row('R1_prepare_permission_denied', prepare?.error && PERMISSION_CODES.has(prepare.error.code), prepare)
    row('R2_inspection_refused_for_participation', inspect && inspect.safeToUnlock === false &&
      inspect.blockers.includes(PARTICIPATION_BLOCKER) && inspect.probe.participation === undefined, inspect)
  }
  const rowsOk = rows.every((r) => r.ok)
  return {
    dumpable, collected, collectedFaults, rows, ok: collected && rowsOk,
    recorded: {
      firstObservedError: firstObservedError(s),
      guardedAttempted: verify ? verify.skipped !== 'prepare_failed' : null,
      participation: inspect?.probe?.participation ?? null,
      // A Python script path ending in `codex`; not a native Codex result.
      fixtureIsCodex: only?.isCodex ?? null,
      eligibility: inspect ? { safeToUnlock: inspect.safeToUnlock, blockers: inspect.blockers } : null,
      owner: inspect?.owner ?? null,
      probe: inspect?.probe ?? null,
    },
  }
}

export function evaluateReport(runs) {
  const control = runs.find((r) => r.dumpable === 1)
  const refusal = runs.find((r) => r.dumpable === 0)
  const failures = []
  if (!control?.ok) failures.push('control_dumpable1_not_passed')
  if (!refusal?.ok) failures.push('refusal_dumpable0_not_passed')
  // A refusal without a passing control in the same report says nothing.
  return { ok: failures.length === 0 && runs.length === 2, failures,
    refusalCounted: Boolean(control?.ok && refusal?.ok) }
}
