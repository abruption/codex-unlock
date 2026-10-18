// G1 expected-table evaluation (#126 research). Pure functions only.
//
// Results that are reported separately and never merged:
// - `collected`: the inspector completed the G1 protocol (typed stages,
//   matching build manifest, holder PID) without faults, and every sampled
//   start-tick value claimed for the holder equals the runner's own samples.
//   Unavailable evidence stays unavailable; it never matches.
// - `rows`: MEASURED status per row: 'pass', 'fail' or 'blocked' (a stated
//   precondition did not hold, so the row is not evaluable), with causes
//   attributed from the same run. Only 'pass' satisfies a row.
// - `comparison`: measured rows against the SOURCE PREDICTION
//   (variants.mjs) for the measured host class. An unclassified host has no
//   prediction and never matches.
// - report-level `controlPassed`/`refusalCounted`, computed only after exact
//   run coverage is validated. A matched prediction of a failure is not a
//   passing control and is never counted as success.
// Nothing here is a native Codex result, a fail-closed proof or a signal
// decision. Raw lsof text stays in the private result; only its class is
// used here.
import { isTicks } from './protocol.mjs'
import { HOST_CLASSES, predict, VARIANT_ORDER, VARIANTS } from './variants.mjs'

export const sameTicks = (a, b) => isTicks(a) && isTicks(b) && BigInt(a) === BigInt(b)
export const PERMISSION_CODES = new Set(['EACCES', 'EPERM'])
export const PARTICIPATION_BLOCKER = 'linux_participation_unproven'
const sorted = (values) => [...new Set(values.filter(Boolean))].sort()

// The only lsof stderr treated as mount-visibility evidence: one or more
// pairs of `lsof: WARNING: can't stat() <type> file system <absolute path>`
// followed by the indented `Output information may be incomplete.` line, as
// lsof 4.9x prints them. The product's own failure texts (missing tool,
// timeout, output limit, exit status) and anything else are `other`.
const STAT_WARNING = /^lsof: WARNING: can't stat\(\) [A-Za-z0-9_.+-]{1,64} file system \/\S.{0,4095}$/
const INCOMPLETE = /^\s+Output information may be incomplete\.$/
export function classifyLsofError(text) {
  if (text === null) return { kind: 'none' }
  if (typeof text !== 'string' || text === '') return { kind: 'other' }
  const lines = text.split('\n')
  if (lines.length % 2 !== 0) return { kind: 'other' }
  for (let i = 0; i < lines.length; i += 2) {
    if (!STAT_WARNING.test(lines[i]) || !INCOMPLETE.test(lines[i + 1])) return { kind: 'other' }
  }
  return { kind: 'mount_warning', warnings: lines.length / 2 }
}

export function hostClassOf(control) {
  if (control.processCount !== 0) return { hostClass: 'unclassified', reason: 'lsof_control_has_openers' }
  const kind = classifyLsofError(control.error).kind
  if (kind === 'none') return { hostClass: 'clean' }
  if (kind === 'mount_warning') return { hostClass: 'mount_warning' }
  return { hostClass: 'unclassified', reason: 'lsof_control_infrastructure' }
}

export function lsofCauseOf(openerError, control) {
  const kind = classifyLsofError(openerError).kind
  if (kind === 'none') return null
  if (kind === 'other') return 'lsof_infrastructure_error'
  return classifyLsofError(control.error).kind === 'mount_warning' && control.error === openerError
    ? 'lsof_mount_warning' : 'unexplained:lsof_mount_warning_differs'
}

export function identityCauses(identity, readyTicks) {
  const causes = []
  for (const error of identity.errors) {
    if (error.startsWith('arguments_unverified:') || error.startsWith('arguments_truncated:')) causes.push('argv_identity')
    else if (error === 'linux_process_instance_unverified') causes.push('instance_unverified')
    // Only the error code; raw diagnostic text stays in the private record.
    else causes.push(`unexplained:${error.split(':')[0]}`)
  }
  if (!identity.identityComplete && !causes.includes('argv_identity')) causes.push('unexplained:identity_incomplete')
  if (identity.startTicks !== null && !sameTicks(identity.startTicks, readyTicks)) causes.push('unexplained:start_ticks_differ')
  if (identity.errors.length === 0 && (identity.startTicks === null || identity.commandFingerprint === null)) {
    causes.push('unexplained:instance_evidence_missing')
  }
  return sorted(causes)
}

// Maps each eligibility blocker to causes already measured in this run.
export function blockerCauses(blockers, measured) {
  const present = (names) => names.filter((n) => measured.includes(n))
  const lsof = present(['lsof_mount_warning', 'lsof_infrastructure_error'])
  const explain = {
    lock_opener_lookup_failed: lsof,
    owner_lock_file_lookup_failed: present(['owner_lockset_unavailable']),
    owner_holds_other_thread_locks: present(['owner_lockset_unavailable']),
    classification_unknown: present(['lsof_mount_warning', 'lsof_infrastructure_error', 'argv_identity', 'owner_hidden', 'instance_unverified']),
    [PARTICIPATION_BLOCKER]: present(['lsof_mount_warning', 'lsof_infrastructure_error', 'owner_hidden', 'instance_unverified']),
    lock_owner_identity_incomplete: present(['argv_identity']),
    lock_owner_is_not_codex: present(['argv_identity']),
    lock_owner_unavailable: present(['owner_hidden']),
    lock_owner_not_unique: present(['owner_hidden']),
    owner_lock_files_unavailable: present(['owner_hidden']),
    lock_owner_identity_not_stable: present(['owner_hidden', 'instance_unverified']),
  }
  const causes = []
  for (const blocker of blockers) {
    const found = explain[blocker] ?? []
    if (found.length) causes.push(...found)
    else causes.push(`unexplained:${blocker}`)
  }
  return sorted(causes)
}

// Every start-ticks sample attributed to the holder PID must equal the
// runner's readiness sample. Null samples are unavailable, not equal.
export function holderBinding(s, holder, readyTicks) {
  const samples = []
  const add = (where, pid, ticks) => { if (pid === holder.pid) samples.push({ where, ticks: ticks ?? null }) }
  for (const p of s.openers.result.processes) add('openers', p.pid, p.startTicks)
  add('identity_direct', s.identity_direct.result.pid, s.identity_direct.result.startTicks)
  if (s.prepare.result) add('prepare', s.prepare.result.pid, s.prepare.result.startTicks)
  const verify = s.guarded_verify.result
  if (verify.participation) add('guarded_participation', verify.participation.pid, verify.participation.startTicks)
  const inspect = s.inspect_thread.result
  if (inspect.owner) add('inspect_owner', inspect.owner.pid, inspect.owner.startTicks)
  if (inspect.probe.participation) add('inspect_participation', inspect.probe.participation.pid, inspect.probe.participation.startTicks)
  const faults = samples.filter((x) => x.ticks !== null && !sameTicks(x.ticks, readyTicks)).map((x) => `holder_ticks_differ:${x.where}`)
  return { samples, faults, unavailable: samples.filter((x) => x.ticks === null).map((x) => x.where) }
}

export function evaluateRun({ variant, dumpable, holder, ticks, observation, protocol }) {
  const collectedFaults = [...(observation.incomplete ? [`incomplete:${observation.incompletePhase}`] : []),
    ...observation.faults, ...protocol.faults]
  if (!isTicks(ticks.ready)) collectedFaults.push('holder_ticks_unavailable')
  if (!sameTicks(ticks.ready, ticks.afterInspect)) collectedFaults.push('holder_instance_changed_or_gone')
  if (ticks.holderExitedDuringInspection) collectedFaults.push('holder_exited_during_inspection')
  const base = { variant, dumpable, collectedFaults }
  // Payload fields are read only after protocol validation.
  if (protocol.faults.length > 0) return { ...base, collected: false, hostClass: null, rows: {}, recorded: null, manifestSha256: null }
  const s = protocol.byStage
  const binding = holderBinding(s, holder, ticks.ready)
  collectedFaults.push(...binding.faults)
  const collected = collectedFaults.length === 0
  const control = s.lsof_control.result
  const openers = s.openers.result
  const identity = s.identity_direct.result
  const prepare = s.prepare
  const verify = s.guarded_verify.result
  const held = s.held_probe.result
  const inspect = s.inspect_thread.result
  const fd = String(holder.fd)
  const host = hostClassOf(control)
  const lsofCause = lsofCauseOf(openers.error, control)
  const listed = openers.processes.filter((p) => p.pid === holder.pid)
  const onlyHolder = openers.processes.length === 1 && listed.length === 1
  const hiddenCause = listed.length === 0 ? 'owner_hidden' : null
  const idCauses = identityCauses(identity, ticks.ready)
  const heldOk = held.status === 'held' && held.guard?.status === 'acquired' && held.participation === undefined
  const rows = {}
  const row = (id, status, causes = [], detail) => {
    rows[id] = { basis: 'measured', status, causes: status === 'pass' ? [] : sorted(causes),
      ...(status === 'pass' || detail === undefined ? {} : { detail }) }
  }
  row('H0_held_observed', heldOk ? 'pass' : 'fail', ['held_observation_missing'], { status: held.status, guard: held.guard?.status ?? null })
  row('V1_owner_listed', onlyHolder ? 'pass' : 'fail', [hiddenCause ?? 'unexplained:other_openers'],
    openers.processes.map((p) => p.pid === holder.pid ? 'holder' : 'other'))
  row('V2_opener_clean', openers.error === null ? 'pass' : 'fail', [lsofCause])
  const identityOk = idCauses.length === 0 && identity.identityComplete
  row('I1_identity_direct', identityOk ? 'pass' : 'fail', idCauses.length ? idCauses : ['unexplained:identity'])
  const ownerLocksetUnavailable = inspect.blockers.includes('owner_lock_file_lookup_failed') &&
    Array.isArray(inspect.ownerLockFiles) && inspect.ownerLockFiles.length === 0
  const measured = sorted([lsofCause, hiddenCause, ...idCauses, ownerLocksetUnavailable ? 'owner_lockset_unavailable' : null])
  const blocked = (id, causes) => row(id, 'blocked', causes)
  if (dumpable === 1) {
    row('I2_is_codex', identity.isCodex ? 'pass' : 'fail',
      idCauses.includes('argv_identity') ? ['argv_identity'] : ['unexplained:not_codex'])
    const p = prepare.result
    row('E2_prepare_candidate', p && p.pid === holder.pid && sameTicks(p.startTicks, ticks.ready) &&
      p.descriptors.includes(fd) && p.candidates.includes(fd) ? 'pass' : 'fail', ['unexplained:prepare'])
    row('E3_guarded_participation', verify.status === 'held' && verify.guard?.status === 'acquired' &&
      verify.participation?.pid === holder.pid && verify.participation.descriptor === fd &&
      sameTicks(verify.participation.startTicks, ticks.ready) ? 'pass' : 'fail', ['unexplained:guarded_participation'])
    // inspectThread attempts participation only with a clean, unique opener set.
    if (lsofCause || !onlyHolder) {
      blocked('E4_inspection_participation', [lsofCause, hiddenCause ?? (onlyHolder ? null : 'unexplained:other_openers')])
    } else {
      const part = inspect.probe.participation
      row('E4_inspection_participation', inspect.probe.status === 'held' && part?.pid === holder.pid &&
        part.descriptor === fd && sameTicks(part.startTicks, ticks.ready) && inspect.owner?.pid === holder.pid &&
        sameTicks(inspect.owner.startTicks, ticks.ready) && !inspect.blockers.includes(PARTICIPATION_BLOCKER)
        ? 'pass' : 'fail', ['unexplained:inspection_participation'])
    }
    row('E5_eligible', inspect.safeToUnlock && inspect.blockers.length === 0 ? 'pass' : 'fail',
      blockerCauses(inspect.blockers, measured), inspect.blockers)
  } else if (!heldOk) {
    // A denial is reproduced only for a lock observed held in this inspector.
    for (const id of ['R1_prepare_permission_denied', 'R2_refused_with_participation_blocker', 'R3_refusal_attributed_to_denial']) {
      blocked(id, ['held_observation_missing'])
    }
  } else {
    row('R1_prepare_permission_denied', prepare.error && PERMISSION_CODES.has(prepare.error.code) && verify.skipped === 'prepare_failed'
      ? 'pass' : 'fail', ['unexplained:prepare_not_denied'], prepare.error?.code ?? 'no_error')
    const refusalProbe = inspect.probe.status === 'held' ||
      (inspect.probe.status === 'unknown' && inspect.probe.error === PARTICIPATION_BLOCKER &&
        inspect.probe.guard?.status === 'acquired')
    row('R2_refused_with_participation_blocker', !inspect.safeToUnlock && inspect.blockers.includes(PARTICIPATION_BLOCKER) &&
      refusalProbe && inspect.probe.participation === undefined ? 'pass' : 'fail',
    ['unexplained:refusal'], { probe: inspect.probe.status })
    // Denial is the attributed reason only if the owner was visible without
    // an opener error, so that inspectThread reached participation and
    // reported the product's typed participation refusal.
    if (lsofCause || !onlyHolder) {
      blocked('R3_refusal_attributed_to_denial', [lsofCause, hiddenCause ?? (onlyHolder ? null : 'unexplained:other_openers')])
    } else {
      row('R3_refusal_attributed_to_denial', inspect.probe.status === 'unknown' && inspect.probe.error === PARTICIPATION_BLOCKER &&
        inspect.probe.guard?.status === 'acquired' && inspect.owner?.pid === holder.pid &&
        inspect.owner.errors.includes('linux_process_instance_unverified') && inspect.blockers.includes(PARTICIPATION_BLOCKER)
        ? 'pass' : 'fail', ['unexplained:refusal_not_attributed'])
    }
  }
  return {
    ...base, collected, hostClass: host.hostClass, hostReason: host.reason ?? null, rows,
    manifestSha256: s.dist_identity.result.manifestSha256,
    recorded: {
      lsofControlClass: classifyLsofError(control.error).kind, openerErrorClass: classifyLsofError(openers.error).kind,
      identityErrors: identity.errors, isCodex: identity.isCodex, binding,
      eligibility: { safeToUnlock: inspect.safeToUnlock, blockers: inspect.blockers },
      classification: inspect.classification, probe: inspect.probe, heldProbe: held, ownerLockFiles: inspect.ownerLockFiles,
      prepareErrorCode: prepare.error?.code ?? null, guardedAttempted: verify.skipped !== 'prepare_failed',
    },
  }
}

export function compareRun(run) {
  if (!run.collected) return { matched: false, rows: [], reason: 'not_collected' }
  if (!HOST_CLASSES.includes(run.hostClass)) return { matched: false, rows: [], reason: `host_${run.hostClass}` }
  const expected = predict(run.variant, run.dumpable, run.hostClass)
  const rows = Object.entries(expected).map(([id, want]) => {
    const got = run.rows[id]
    const matched = Boolean(got) && got.status === want.status && JSON.stringify(got.causes) === JSON.stringify(want.causes)
    return { id, matched, expected: want, measured: got ?? null }
  })
  const extra = Object.keys(run.rows).filter((id) => !Object.hasOwn(expected, id))
  return { matched: rows.every((r) => r.matched) && extra.length === 0, rows, extra }
}

// Exact coverage: every variant is either in `notExecuted` exactly once (with
// no runs) or has exactly one run per required dumpable value, and nothing
// else. `selected` is the runner's parsed selection.
export function checkCoverage(runs, { selected, notExecuted }) {
  const faults = []
  if (!Array.isArray(selected) || selected.length === 0) faults.push('selection_empty')
  else {
    if (new Set(selected).size !== selected.length) faults.push('selection_duplicate')
    for (const v of selected) if (!Object.hasOwn(VARIANTS, v)) faults.push(`selection_unknown:${v}`)
  }
  const skipped = new Map()
  for (const n of notExecuted ?? []) {
    if (!n || !Object.hasOwn(VARIANTS, n.variant) || typeof n.reason !== 'string' || n.reason === '') { faults.push('not_executed_malformed'); continue }
    if (skipped.has(n.variant)) faults.push(`not_executed_duplicate:${n.variant}`)
    skipped.set(n.variant, n.reason)
    const selectedHere = Array.isArray(selected) && selected.includes(n.variant)
    if ((n.reason === 'not_selected') === selectedHere) faults.push(`not_executed_inconsistent:${n.variant}`)
  }
  const seen = new Map()
  for (const r of runs) {
    const key = `${r?.variant}:${r?.dumpable}`
    seen.set(key, (seen.get(key) ?? 0) + 1)
    if (!r || !Object.hasOwn(VARIANTS, r.variant) || !VARIANTS[r.variant].dumpables.includes(r.dumpable)) faults.push(`run_unexpected:${key}`)
    else if (skipped.has(r.variant)) faults.push(`run_for_not_executed:${key}`)
  }
  for (const [key, count] of seen) if (count > 1) faults.push(`run_duplicate:${key}`)
  for (const v of VARIANT_ORDER) {
    if (!selected?.includes(v) && !skipped.has(v)) faults.push(`not_selected_missing:${v}`)
    if (skipped.has(v)) continue
    for (const d of VARIANTS[v].dumpables) if (!seen.has(`${v}:${d}`)) faults.push(`run_missing:${v}:${d}`)
  }
  return { ok: faults.length === 0, faults, skipped }
}

export function evaluateReport(runs, { selected = VARIANT_ORDER, notExecuted = [], expectedManifestSha256, collectionValid = true } = {}) {
  const coverage = checkCoverage(runs, { selected, notExecuted })
  const failures = [...coverage.faults]
  if (!collectionValid) failures.push('collection_invalid')
  const controlPassed = {}
  const refusalCounted = {}
  const comparisons = []
  const unavailable = (value) => Object.fromEntries(VARIANT_ORDER.map((v) => [v, value]))
  if (!coverage.ok) {
    return { coverageValid: false, predictionsMatched: false, complete: false, failures, notExecuted, hostClass: null,
      controlPassed: unavailable(false), refusalCounted: unavailable(false), comparisons,
      nativeCodexEvidence: 'absent: every variant is synthetic; native Codex argv, image and dumpability are unmeasured' }
  }
  const byKey = new Map(runs.map((r) => [`${r.variant}:${r.dumpable}`, r]))
  const validRun = (run) => Boolean(collectionValid && run?.collected && run.manifestSha256 === expectedManifestSha256)
  for (const r of runs) {
    if (r.manifestSha256 !== expectedManifestSha256) failures.push(`build_manifest_mismatch:${r.variant}:${r.dumpable}`)
  }
  for (const variant of VARIANT_ORDER) {
    if (coverage.skipped.has(variant)) {
      controlPassed[variant] = 'not_executed'; refusalCounted[variant] = 'not_executed'; continue
    }
    for (const dumpable of VARIANTS[variant].dumpables) {
      const run = byKey.get(`${variant}:${dumpable}`)
      if (!run.collected) failures.push(`not_collected:${variant}:${dumpable}`)
      const comparison = compareRun(run)
      comparisons.push({ variant, dumpable, hostClass: run.hostClass, ...comparison })
      if (!comparison.matched) failures.push(`prediction_unmatched:${variant}:${dumpable}`)
    }
    const control = byKey.get(`${variant}:1`)
    const refusal = byKey.get(`${variant}:0`)
    controlPassed[variant] = Boolean(validRun(control) && Object.keys(control.rows).length > 0 &&
      Object.values(control.rows).every((r) => r.status === 'pass'))
    refusalCounted[variant] = VARIANTS[variant].dumpables.includes(0)
      ? Boolean(controlPassed[variant] === true && validRun(refusal) &&
        ['H0_held_observed', 'R1_prepare_permission_denied', 'R2_refused_with_participation_blocker', 'R3_refusal_attributed_to_denial']
          .every((id) => refusal.rows[id]?.status === 'pass'))
      : 'not_applicable'
  }
  const hostClasses = sorted(runs.map((r) => r.hostClass))
  if (hostClasses.length > 1) failures.push(`host_class_changed:${hostClasses.join(',')}`)
  return {
    // `predictionsMatched` means the cause separation reproduced as predicted.
    // It is not a product success and not a passing control.
    coverageValid: true, predictionsMatched: failures.length === 0, complete: coverage.skipped.size === 0, failures, notExecuted,
    hostClass: hostClasses.length === 1 ? hostClasses[0] : null, controlPassed, refusalCounted, comparisons,
    nativeCodexEvidence: 'absent: every variant is synthetic; native Codex argv, image and dumpability are unmeasured',
  }
}
