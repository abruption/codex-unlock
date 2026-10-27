// Pure tests for the G1 expected table: typed collection, build binding,
// holder binding, narrow lsof classification, denial preconditions, exact
// coverage, and that no failure, block, skip or matched failure prediction is
// ever counted as a passing control.
import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  blockerCauses, checkCoverage, classifyLsofError, compareRun, evaluateReport, evaluateRun, hostClassOf, identityCauses, lsofCauseOf,
} from './expectations.mjs'
import { G1_STAGES, isProbe, parseChildFault, validateG1 } from './protocol.mjs'
import { assertPinnedBuildSource, assertPinnedUnpatchedBuild, parseVariantSelection, PINNED_SOURCE_COMMIT, predict, PRODUCT_ARGV_ERROR, VARIANT_ORDER } from './variants.mjs'

const MANIFEST = 'a'.repeat(64)
test('build source identity must equal the pinned full commit', () => {
  assert.doesNotThrow(() => assertPinnedBuildSource({ commit: PINNED_SOURCE_COMMIT }))
  for (const source of [null, {}, { commit: 'b483cd5' }, { commit: 'f'.repeat(40) }]) {
    assert.throws(() => assertPinnedBuildSource(source), /G1 build source must be/)
  }
})
test('G1 build gate requires verified pinned source and an explicit valid unpatched record', () => {
  const verified = { ok: true, source: { commit: PINNED_SOURCE_COMMIT }, patch: { applied: false } }
  assert.doesNotThrow(() => assertPinnedUnpatchedBuild(verified))
  for (const patch of [undefined, null, true, false, 'false', [], {}, { applied: true }, { applied: 'false' }, { applied: 0 }]) {
    assert.throws(() => assertPinnedUnpatchedBuild({ ...verified, patch }), /explicitly record an unpatched build/)
  }
  assert.throws(() => assertPinnedUnpatchedBuild({ ...verified, source: { commit: 'f'.repeat(40) } }), /G1 build source must be/)
  for (const invalid of [undefined, null, {}, { ...verified, ok: false }]) {
    assert.throws(() => assertPinnedUnpatchedBuild(invalid), /G1 build must be verified/)
  }
})
const holder = { pid: 42, fd: 5 }
const ticks = { ready: '900', afterInspect: '900', holderExitedDuringInspection: false }
const FP = 'f'.repeat(64)
const WARN = 'lsof: WARNING: can\'t stat() overlay file system /var/lib/x/merged\n      Output information may be incomplete.\n' +
  'lsof: WARNING: can\'t stat() nsfs file system /run/x/netns/y\n      Output information may be incomplete.'
const M = 'flock_exclusive_nonblocking'
const HELD = { status: 'held', method: M, guard: { status: 'acquired', attempts: 1 } }
const PART = { pid: 42, startTicks: '900', descriptor: '5' }
const identity = (over = {}) => ({ pid: 42, isCodex: true, isSharedService: false, identityComplete: true, errors: [],
  startTicks: '900', commandFingerprint: FP, command: 'codex', arguments: 'codex', lsofCommand: 'codex', ...over })
const argvBad = { isCodex: false, identityComplete: false, errors: [PRODUCT_ARGV_ERROR], arguments: null }

// Builds the nine stage records for one synthetic run, following #137 source.
function stages({ host = 'clean', dumpable = 1, argv = true, listed = dumpable === 1, blockers, held = HELD, inspectProbe }) {
  const warn = host === 'mount_warning' ? WARN : host === 'infra' ? 'lsof timed out after 10000 ms' : null
  const errors = [...(argv ? [] : [PRODUCT_ARGV_ERROR]), ...(dumpable === 0 ? ['linux_process_instance_unverified'] : [])]
  const id = identity({ ...(argv ? {} : argvBad), errors,
    ...(dumpable === 0 ? { startTicks: null, commandFingerprint: null } : {}) })
  const result = (stage, value) => ({ stage, result: value })
  const list = [
    result('dist_identity', { ok: true, faults: [], manifestSha256: MANIFEST, expectedManifestSha256: MANIFEST, manifestMatchesExpected: true }),
    result('module_load', { modules: ['inspection.js'], unlockReachable: false }),
    result('lsof_control', { error: warn, processCount: 0 }),
    result('openers', { error: warn, processes: listed ? [id] : [] }),
    result('identity_direct', id),
  ]
  if (dumpable === 1) {
    list.push(result('prepare', { pid: 42, startTicks: '900', candidates: ['5'], descriptors: ['0', '5'] }))
    list.push(result('guarded_verify', { ...HELD, participation: PART }))
  } else {
    list.push({ stage: 'prepare', error: { code: 'EACCES', name: 'Error', message: 'denied' } })
    list.push(result('guarded_verify', { skipped: 'prepare_failed' }))
  }
  list.push(result('held_probe', held))
  const reached = (host === 'clean') && listed
  const clean = reached && argv && dumpable === 1
  const computed = blockers ?? (clean ? [] : [
    ...(dumpable === 1 && reached ? [] : ['linux_participation_unproven']),
    ...(host !== 'clean' || !argv || !listed ? ['classification_unknown'] : []),
    ...(host !== 'clean' ? ['lock_opener_lookup_failed', ...(listed ? ['owner_lock_file_lookup_failed', 'owner_holds_other_thread_locks'] : [])] : []),
    ...(listed && !argv ? ['lock_owner_identity_incomplete', 'lock_owner_is_not_codex'] : []),
    ...(!listed ? ['lock_owner_not_unique', 'lock_owner_identity_not_stable', 'lock_owner_unavailable', 'owner_lock_files_unavailable'] : []),
  ])
  // inspectThread attempts participation whenever openers are clean and unique.
  const probe = inspectProbe ?? (reached && dumpable === 1 ? { ...HELD, participation: PART }
    : reached ? { status: 'unknown', method: M, guard: { status: 'acquired', attempts: 1 }, error: 'linux_participation_unproven' } : HELD)
  list.push(result('inspect_thread', { classification: clean ? 'live_owner' : 'unknown', safeToUnlock: computed.length === 0,
    blockers: computed, warnings: [], probe, openers: listed ? 1 : 0,
    owner: listed ? { pid: 42, isCodex: id.isCodex, identityComplete: id.identityComplete, errors: id.errors, startTicks: id.startTicks } : null,
    transcript: 'found', ownerLockFiles: listed ? host === 'clean' ? ['/fixture/thread.lock'] : [] : null }))
  return list
}
const observe = (list, extra = {}) => ({ incomplete: false, faults: [], stages: list, begun: list.map((s) => s.stage), ...extra })
const context = { expectedManifestSha256: MANIFEST, holderPid: 42 }
const evaluate = (variant, dumpable, list, t = ticks, extra = {}) => {
  const observation = observe(list, extra)
  return evaluateRun({ variant, dumpable, holder, ticks: t, observation, protocol: validateG1(observation, context) })
}
const run = (variant, dumpable, opts = {}, t = ticks, extra = {}) =>
  evaluate(variant, dumpable, stages({ dumpable, argv: variant !== 'script', ...opts }), t, extra)
const allRuns = (host, skip = []) => VARIANT_ORDER.filter((v) => !skip.includes(v))
  .flatMap((v) => (v === 'node' ? [1] : [1, 0]).map((d) => run(v, d, { host })))
const report = (runs, options = {}) => evaluateReport(runs, { expectedManifestSha256: MANIFEST, ...options })

test('eligible inspection must agree with its exposed policy evidence', () => {
  const mutations = [
    (r) => { r.classification = 'unknown' },
    (r) => { r.openers = 0 },
    (r) => { r.ownerLockFiles = [] },
    (r) => { r.transcript = 'missing' },
    (r) => { r.owner.isCodex = false },
    (r) => { r.owner.identityComplete = false },
    (r) => { r.ownerLockFiles = null },
    (r) => { r.ownerLockFiles = ['/first.lock', '/second.lock'] },
    (r) => { r.owner = null },
    (r) => { r.blockers = ['classification_unknown'] },
    (r) => { r.probe = { status: 'free', method: M } },
    (r) => { delete r.probe.participation },
    (r) => { r.probe = { ...r.probe, participation: { ...PART, pid: 99 } } },
  ]
  for (const mutate of mutations) {
    const list = stages({})
    mutate(list[8].result)
    const protocol = validateG1(observe(list), context)
    assert.ok(protocol.faults.includes('stage_result_malformed:inspect_thread'))
    const measured = evaluate('native', 1, list)
    assert.equal(measured.collected, false)
    const runs = allRuns('clean')
    runs[runs.findIndex((r) => r.variant === 'native' && r.dumpable === 1)] = measured
    assert.equal(report(runs).controlPassed.native, false)
    assert.equal(report(runs).refusalCounted.native, false)
  }
})

test('inspection fields are typed even when the product refused', () => {
  const mutations = [
    (r) => { r.classification = 'not-a-classification' },
    (r) => { r.openers = -1 },
    (r) => { r.openers = '1' },
    (r) => { delete r.openers },
    (r) => { delete r.transcript },
    (r) => { r.transcript = 'invalid' },
    (r) => { delete r.owner.isCodex },
    (r) => { delete r.owner.identityComplete },
    (r) => { r.owner.identityComplete = 'false' },
  ]
  for (const mutate of mutations) {
    const list = stages({ host: 'mount_warning', dumpable: 1 })
    mutate(list[8].result)
    assert.ok(validateG1(observe(list), context).faults.includes('stage_result_malformed:inspect_thread'))
  }
  // Typed refusal evidence remains collectible: missing transcript or
  // incomplete owner identity is a product outcome, not a broken protocol.
  for (const host of ['clean', 'mount_warning']) {
    for (const dumpable of [1, 0]) {
      const list = stages({ host, dumpable, argv: false })
      assert.equal(validateG1(observe(list), context).ok, true)
      list[8].result.transcript = 'missing'
      list[8].result.blockers.push('transcript_missing')
      assert.equal(validateG1(observe(list), context).ok, true)
    }
  }
})

test('protocol: exact order, typed probes, manifest and PID binding, prepare/skip consistency', () => {
  assert.equal(G1_STAGES.length, 9)
  assert.equal(validateG1(observe(stages({})), context).ok, true)
  const swapped = stages({}); [swapped[2], swapped[3]] = [swapped[3], swapped[2]]
  assert.ok(validateG1(observe(swapped), context).faults.some((f) => f.startsWith('stage_order:')))
  assert.ok(validateG1(observe(stages({})), { ...context, expectedManifestSha256: 'b'.repeat(64) }).faults.includes('build_manifest_mismatch'))
  assert.ok(validateG1(observe(stages({})), { holderPid: 42 }).faults.includes('expected_manifest_missing'))
  assert.ok(validateG1(observe(stages({})), { ...context, holderPid: 43 }).faults.includes('identity_direct_pid_mismatch'))
  const childClaims = stages({}); childClaims[0].result.manifestMatchesExpected = false
  assert.ok(validateG1(observe(childClaims), context).faults.includes('stage_result_malformed:dist_identity'))
  const inconsistent = stages({ dumpable: 0 }); inconsistent[6] = { stage: 'guarded_verify', result: HELD }
  assert.ok(validateG1(observe(inconsistent), context).faults.includes('prepare_guarded_inconsistent'))
  const control = stages({}); control[2].result.processCount = -1
  assert.ok(validateG1(observe(control), context).faults.includes('stage_result_malformed:lsof_control'))
  assert.equal(parseChildFault('stall:held_probe'), 'stall:held_probe')
  assert.throws(() => parseChildFault('stall:nope'), /G1_CHILD_FAULT/)
})

test('typed probes: empty, free-with-guard, held-without-guard and stray participation are rejected', () => {
  assert.equal(isProbe(HELD), true)
  assert.equal(isProbe({}), false)
  assert.equal(isProbe({ status: 'held', method: M }), false)
  assert.equal(isProbe({ status: 'held', method: M, guard: { status: 'busy' } }), false)
  assert.equal(isProbe({ status: 'free', method: M, participation: PART }), false)
  assert.equal(isProbe({ status: 'held', method: 'other', guard: { status: 'acquired' } }), false)
  assert.equal(isProbe({ status: 'free', method: M }), true)
  const empty = stages({ dumpable: 0, inspectProbe: {} })
  assert.ok(validateG1(observe(empty), context).faults.includes('stage_result_malformed:inspect_thread'))
})

test('denial needs a held observation: free, unknown or missing held evidence blocks R1-R3', () => {
  for (const held of [{ status: 'free', method: M }, { status: 'unknown', method: M, guard: { status: 'busy', attempts: 1 }, error: 'x' }]) {
    const r = run('native', 0, { host: 'mount_warning', held })
    assert.equal(r.collected, true)
    assert.equal(r.rows.H0_held_observed.status, 'fail')
    for (const id of ['R1_prepare_permission_denied', 'R2_refused_with_participation_blocker', 'R3_refusal_attributed_to_denial']) {
      assert.deepEqual([r.rows[id].status, r.rows[id].causes], ['blocked', ['held_observation_missing']], id)
    }
    assert.equal(compareRun(r).matched, false)
  }
  // A free inspection probe next to a held H0 is a contradiction: R2 fails.
  const contradiction = run('native', 0, { host: 'mount_warning', inspectProbe: { status: 'free', method: M } })
  assert.equal(contradiction.rows.R2_refused_with_participation_blocker.status, 'fail')
  assert.equal(compareRun(contradiction).matched, false)
})

test('holder binding: any claimed holder tick sample that differs is a collection fault; null stays unavailable', () => {
  const list = stages({}); list[5].result.startTicks = '901'
  const r = evaluate('native', 1, list)
  assert.equal(r.collected, false)
  assert.ok(r.collectedFaults.includes('holder_ticks_differ:prepare'))
  const d0 = run('native', 0, { host: 'mount_warning' })
  assert.equal(d0.collected, true)
  assert.deepEqual(d0.recorded.binding.unavailable, ['identity_direct'])
  const owner = stages({ dumpable: 0, host: 'clean', listed: true }); owner[8].result.owner.startTicks = '1'
  assert.ok(evaluate('native', 0, owner).collectedFaults.includes('holder_ticks_differ:inspect_owner'))
})

test('narrow lsof classification: only paired mount warnings count; tool, timeout and other text are infrastructure', () => {
  assert.deepEqual(classifyLsofError(WARN), { kind: 'mount_warning', warnings: 2 })
  assert.deepEqual(classifyLsofError(null), { kind: 'none' })
  for (const text of ['lsof is not installed at /usr/sbin/lsof or /usr/bin/lsof', 'lsof timed out after 10000 ms', 'lsof exited with status 2',
    'lsof: WARNING: can\'t stat() overlay file system /x', `${WARN}\nextra`, 'lsof: WARNING: something else\n      Output information may be incomplete.', '']) {
    assert.equal(classifyLsofError(text).kind, 'other', text)
  }
  assert.deepEqual(hostClassOf({ error: WARN, processCount: 0 }), { hostClass: 'mount_warning' })
  assert.deepEqual(hostClassOf({ error: WARN, processCount: 1 }), { hostClass: 'unclassified', reason: 'lsof_control_has_openers' })
  assert.deepEqual(hostClassOf({ error: 'lsof timed out', processCount: 0 }), { hostClass: 'unclassified', reason: 'lsof_control_infrastructure' })
  const control = { error: WARN, processCount: 0 }
  assert.equal(lsofCauseOf(WARN, control), 'lsof_mount_warning')
  assert.equal(lsofCauseOf('lsof timed out', control), 'lsof_infrastructure_error')
  assert.equal(lsofCauseOf(WARN.split('\n').slice(0, 2).join('\n'), control), 'unexplained:lsof_mount_warning_differs')
  // Equal arbitrary errors on the lock path and the control are not a mount warning.
  assert.equal(lsofCauseOf('lsof timed out', { error: 'lsof timed out', processCount: 0 }), 'lsof_infrastructure_error')
  const infra = run('native', 1, { host: 'infra' })
  assert.equal(infra.hostClass, 'unclassified')
  assert.deepEqual(compareRun(infra), { matched: false, rows: [], reason: 'host_unclassified' })
})

test('cause attribution from identity errors and blockers keeps codes only', () => {
  assert.deepEqual(identityCauses(identity({ ...argvBad }), '900'), ['argv_identity'])
  assert.deepEqual(identityCauses(identity({ errors: ['linux_process_instance_unverified'], startTicks: null, commandFingerprint: null }), '900'), ['instance_unverified'])
  assert.deepEqual(identityCauses(identity({ errors: ['ppid_unknown:ps failed at /some/path'] }), '900'), ['unexplained:ppid_unknown'])
  assert.deepEqual(blockerCauses(['lock_opener_lookup_failed'], []), ['unexplained:lock_opener_lookup_failed'])
  assert.deepEqual(blockerCauses(['transcript_missing', 'lock_opener_lookup_failed'], ['lsof_mount_warning']),
    ['lsof_mount_warning', 'unexplained:transcript_missing'])
})

test('clean host, argv-clean variant: every measured row passes and matches the source prediction', () => {
  const r = run('native', 1, { host: 'clean' })
  assert.equal(r.collected, true)
  assert.ok(Object.values(r.rows).every((x) => x.status === 'pass' && x.basis === 'measured'), JSON.stringify(r.rows))
  const c = compareRun(r)
  assert.equal(c.matched, true)
  assert.ok(c.rows.every((x) => x.expected.basis === 'source_prediction'))
})

test('mount-warning host separates causes; script adds argv identity; clean host script fails only on argv', () => {
  const clean = run('argv0', 1, { host: 'mount_warning' })
  assert.deepEqual(clean.rows.V2_opener_clean.causes, ['lsof_mount_warning'])
  assert.equal(clean.rows.I1_identity_direct.status, 'pass')
  assert.deepEqual([clean.rows.E4_inspection_participation.status, clean.rows.E4_inspection_participation.causes], ['blocked', ['lsof_mount_warning']])
  assert.equal(compareRun(clean).matched, true)
  const script = run('script', 1, { host: 'mount_warning' })
  assert.deepEqual(script.rows.E5_eligible.causes, ['argv_identity', 'lsof_mount_warning', 'owner_lockset_unavailable'])
  assert.equal(compareRun(script).matched, true)
  const scriptClean = run('script', 1, { host: 'clean' })
  assert.equal(scriptClean.rows.E4_inspection_participation.status, 'pass')
  assert.equal(compareRun(scriptClean).matched, true)
  const otherLocks = stages({ host: 'mount_warning' })
  otherLocks[8].result.ownerLockFiles = ['/fixture/one.lock', '/fixture/two.lock']
  const unprovenCause = evaluate('native', 1, otherLocks)
  assert.ok(unprovenCause.rows.E5_eligible.causes.includes('unexplained:owner_holds_other_thread_locks'))
  assert.equal(compareRun(unprovenCause).matched, false)
})

test('dumpable=0: hidden owner blocks R3; a listed owner with the typed participation refusal passes R3 but contradicts the prediction', () => {
  const r = run('native', 0, { host: 'mount_warning' })
  assert.equal(r.rows.R1_prepare_permission_denied.status, 'pass')
  assert.equal(r.rows.R2_refused_with_participation_blocker.status, 'pass')
  assert.deepEqual(r.rows.R3_refusal_attributed_to_denial.causes, ['lsof_mount_warning', 'owner_hidden'])
  assert.equal(compareRun(r).matched, true)
  const listed = run('native', 0, { host: 'clean', listed: true })
  for (const id of ['R1_prepare_permission_denied', 'R2_refused_with_participation_blocker', 'R3_refusal_attributed_to_denial']) {
    assert.equal(listed.rows[id].status, 'pass', id)
  }
  assert.equal(compareRun(listed).matched, false)
})

test('full reports: predictions matched, controls only on a clean host, no refusal counted', () => {
  const warning = report(allRuns('mount_warning'))
  assert.equal(warning.predictionsMatched, true, JSON.stringify(warning.failures))
  assert.equal(warning.hostClass, 'mount_warning')
  for (const v of VARIANT_ORDER) assert.equal(warning.controlPassed[v], false, v)
  assert.deepEqual(warning.refusalCounted, { script: false, argv0: false, native: false, node: 'not_applicable' })
  const clean = report(allRuns('clean'))
  assert.equal(clean.predictionsMatched, true, JSON.stringify(clean.failures))
  assert.deepEqual(clean.controlPassed, { script: false, argv0: true, native: true, node: true })
  assert.deepEqual(clean.refusalCounted, { script: false, argv0: false, native: false, node: 'not_applicable' })
  assert.match(clean.nativeCodexEvidence, /^absent/)
})

test('coverage: duplicate, extra, missing and inconsistent runs invalidate the report before any control is computed', () => {
  const runs = allRuns('clean')
  const dup = report([...runs, runs[2]])
  assert.equal(dup.coverageValid, false)
  assert.ok(dup.failures.includes('run_duplicate:argv0:1'))
  assert.deepEqual(dup.controlPassed, { script: false, argv0: false, native: false, node: false })
  const extra = report([...runs, { ...runs[6], dumpable: 0 }])
  assert.ok(extra.failures.includes('run_unexpected:node:0'))
  assert.ok(report(runs.slice(1)).failures.includes('run_missing:script:1'))
  const skipped = report(allRuns('clean', ['native']), { notExecuted: [{ variant: 'native', reason: 'no_compiler' }] })
  assert.equal(skipped.coverageValid, true)
  assert.equal(skipped.complete, false)
  assert.equal(skipped.controlPassed.native, 'not_executed')
  assert.ok(report(runs, { notExecuted: [{ variant: 'native', reason: 'no_compiler' }] }).failures.includes('run_for_not_executed:native:1'))
  assert.ok(checkCoverage(runs, { selected: VARIANT_ORDER, notExecuted: [{ variant: 'native', reason: 'not_selected' }] }).faults
    .includes('not_executed_inconsistent:native'))
  assert.ok(checkCoverage([], { selected: [], notExecuted: [] }).faults.includes('selection_empty'))
  assert.ok(checkCoverage([], { selected: ['native', 'native'], notExecuted: [] }).faults.includes('selection_duplicate'))
  const wrongBuild = report(runs.map((r, i) => (i === 0 ? { ...r, manifestSha256: 'c'.repeat(64) } : r)))
  assert.ok(wrongBuild.failures.includes('build_manifest_mismatch:script:1'))
  assert.equal(wrongBuild.predictionsMatched, false)
  assert.ok(checkCoverage(runs, { selected: ['native'], notExecuted: [] }).faults.includes('not_selected_missing:script'))
  const argvBuildDrift = report(runs.map((r) => r.variant === 'argv0' ? { ...r, manifestSha256: 'c'.repeat(64) } : r))
  assert.equal(argvBuildDrift.controlPassed.argv0, false)
  const cleanupFailed = report(runs, { collectionValid: false })
  assert.equal(cleanupFailed.predictionsMatched, false)
  assert.ok(Object.values(cleanupFailed.controlPassed).every((v) => v === false))
})

test('variant selection is strict', () => {
  assert.deepEqual(parseVariantSelection(undefined), VARIANT_ORDER)
  assert.deepEqual(parseVariantSelection('node,script'), ['script', 'node'])
  for (const bad of ['', ' ', 'native,native', 'native,', 'nativ', 'script,,node']) assert.throws(() => parseVariantSelection(bad), /G1_VARIANTS/, bad)
})

test('uncollected, incomplete and unmatched runs never count; a matched failure is not a control', () => {
  const changed = run('native', 1, { host: 'clean' }, { ...ticks, afterInspect: '901' })
  assert.equal(changed.collected, false)
  assert.equal(compareRun(changed).matched, false)
  assert.equal(run('native', 1, { host: 'clean' }, ticks, { incomplete: true, incompletePhase: 'stages' }).collected, false)
  const extra = run('native', 1, { host: 'mount_warning', blockers: ['lock_opener_lookup_failed', 'transcript_missing'] })
  assert.ok(extra.rows.E5_eligible.causes.includes('unexplained:transcript_missing'))
  assert.equal(compareRun(extra).matched, false)
  const malformed = stages({}); malformed[8].result.blockers = 'x'
  const bad = evaluate('native', 1, malformed)
  assert.equal(bad.collected, false)
  assert.deepEqual(bad.rows, {})
  const script = run('script', 1, { host: 'mount_warning' })
  assert.equal(compareRun(script).matched, true)
  assert.equal(Object.values(script.rows).every((x) => x.status === 'pass'), false)
  assert.equal(predict('native', 1, 'clean').E5_eligible.basis, 'source_prediction')
  assert.throws(() => predict('native', 1, 'unclassified'), /no prediction/)
})
