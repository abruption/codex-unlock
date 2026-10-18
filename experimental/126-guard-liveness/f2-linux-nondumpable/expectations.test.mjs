import assert from 'node:assert/strict'
import { test } from 'node:test'
import { evaluateReport, evaluateRun, sameTicks } from './expectations.mjs'
import { parseChildFault, validateF2 } from './protocol.mjs'

const holder = { pid: 42, fd: 5 }
const ticks = { ready: '900', afterInspect: '900', holderExitedDuringInspection: false }
const startupManifest = 'a'.repeat(64)
const probe = (status, extra = {}) => ({ status, method: 'flock_exclusive_nonblocking', ...extra })
const clone = (v) => JSON.parse(JSON.stringify(v))
const stage = (name, outcome) => ({ stage: name, ...outcome })
const base = () => [
  stage('dist_identity', { result: { ok: true, faults: [], manifestSha256: 'a'.repeat(64) } }),
  stage('module_load', { result: { modules: ['inspection.js'], unlockReachable: false } }),
]
const positive = () => [...base(),
  stage('openers', { result: { error: null, processes: [{ pid: 42, startTicks: '900', errors: [], isCodex: true, identityComplete: true }] } }),
  stage('prepare', { result: { pid: 42, startTicks: '900', candidates: ['5'], descriptors: ['0', '5'] } }),
  stage('guarded_verify', { result: probe('held', { guard: { status: 'acquired' }, participation: { pid: 42, startTicks: '900', descriptor: '5' } }) }),
  stage('inspect_thread', { result: { classification: 'live_owner', safeToUnlock: true, blockers: [], warnings: [],
    owner: { pid: 42, startTicks: '900' }, probe: probe('held', { guard: { status: 'acquired' }, participation: { pid: 42, startTicks: '900', descriptor: '5' } }) } }),
]
const refused = () => [...base(),
  stage('openers', { result: { error: null, processes: [{ pid: 42, startTicks: null, errors: ['linux_process_instance_unverified'], isCodex: true, identityComplete: true }] } }),
  stage('prepare', { error: { code: 'EACCES', name: 'Error', message: 'denied' } }),
  stage('guarded_verify', { result: { skipped: 'prepare_failed' } }),
  stage('inspect_thread', { result: { classification: 'live_owner', safeToUnlock: false, blockers: ['linux_participation_unproven'],
    warnings: [], owner: { pid: 42, startTicks: null }, probe: probe('unknown') } }),
]
const observe = (stages, extra = {}) => ({ incomplete: false, faults: [], stages, begun: stages.map((s) => s.stage), ...extra })
const run = (dumpable, stages, extra = {}, t = ticks) => {
  const observation = observe(stages, extra)
  return evaluateRun({ dumpable, holder, ticks: t, observation, protocol: validateF2(observation), expectedManifestSha256: startupManifest })
}
const failed = (r) => r.rows.filter((x) => !x.ok).map((x) => x.id)

test('ticks compare as decimal strings only', () => {
  assert.equal(sameTicks('0900', '900'), true)
  assert.equal(sameTicks('900', 900), false)
  assert.equal(sameTicks('9e2', '900'), false)
  assert.equal(sameTicks(null, null), false)
  assert.equal(sameTicks('', ''), false)
  assert.equal(sameTicks('unknown', 'unknown'), false)
})

test('F2 protocol requires exact order, uniqueness and result shapes', () => {
  assert.equal(validateF2(observe(positive())).ok, true)
  assert.deepEqual(validateF2(observe([])).faults, ['stages_missing:dist_identity,module_load,openers,prepare,guarded_verify,inspect_thread'])
  const swapped = positive(); [swapped[2], swapped[3]] = [swapped[3], swapped[2]]
  assert.ok(validateF2(observe(swapped)).faults.some((f) => f.startsWith('stage_order:')))
  const dup = positive(); dup.push(clone(dup[5]))
  assert.ok(validateF2(observe(dup)).faults.includes('stage_duplicate:inspect_thread'))
  const badIdentity = positive(); badIdentity[0].result.ok = false
  assert.ok(validateF2(observe(badIdentity)).faults.includes('stage_result_malformed:dist_identity'))
  const threw = positive(); threw[5] = stage('inspect_thread', { error: { code: null, message: 'stale_residue' } })
  assert.ok(validateF2(observe(threw)).faults.includes('stage_failed:inspect_thread'))
  const notArray = positive(); notArray[5].result.blockers = 'linux_participation_unproven'
  assert.ok(validateF2(observe(notArray)).faults.includes('stage_result_malformed:inspect_thread'))
  const badTicks = positive(); badTicks[3].result.startTicks = 900
  assert.ok(validateF2(observe(badTicks)).faults.includes('stage_result_malformed:prepare'))
})

test('child fault values are an explicit allowlist', () => {
  assert.equal(parseChildFault(undefined), null)
  assert.equal(parseChildFault('stall:prepare'), 'stall:prepare')
  assert.throws(() => parseChildFault('stall:prepar'), /F2_CHILD_FAULT/)
  assert.throws(() => parseChildFault('stall'), /F2_CHILD_FAULT/)
})

test('dumpable=1 control requires identity, held guard, FD and ticks', () => {
  const r = run(1, positive())
  assert.equal(r.ok, true)
  assert.equal(r.recorded.fixtureIsCodex, true)
  assert.deepEqual(r.recorded.eligibility, { safeToUnlock: true, blockers: [] })
  const wrongFd = positive(); wrongFd[4].result.participation.descriptor = '6'
  assert.deepEqual(failed(run(1, wrongFd)), ['E3_guarded_participation'])
  const forged = positive(); forged[3].result.startTicks = '901'
  assert.deepEqual(failed(run(1, forged)), ['E2_prepare_candidate'])
  const incompleteId = positive(); incompleteId[2].result.processes[0].identityComplete = false
  assert.deepEqual(failed(run(1, incompleteId)), ['E1_owner_identity'])
  const freeGuard = positive(); freeGuard[4].result.guard.status = 'busy'
  assert.deepEqual(failed(run(1, freeGuard)), ['E3_guarded_participation'])
  // A refusal is not a pass for the positive control.
  assert.equal(run(1, refused()).ok, false)
})

test('holder instance must stay the same live process', () => {
  assert.ok(run(1, positive(), {}, { ...ticks, afterInspect: '901' }).collectedFaults.includes('holder_instance_changed_or_gone'))
  assert.ok(run(1, positive(), {}, { ...ticks, afterInspect: null }).collectedFaults.includes('holder_instance_changed_or_gone'))
  const exited = run(0, refused(), {}, { ...ticks, holderExitedDuringInspection: true })
  assert.equal(exited.collected, false)
  assert.equal(exited.ok, false)
})

test('inspection needs its own acquired guard even when direct guarded verification passed', () => {
  for (const guard of [undefined, { status: 'busy' }, { status: 'unsafe' }]) {
    const stages = positive()
    if (guard === undefined) delete stages[5].result.probe.guard
    else stages[5].result.probe.guard = guard
    const result = run(1, stages)
    assert.equal(result.collected, true)
    assert.equal(result.rows.find((r) => r.id === 'E3_guarded_participation').ok, true)
    assert.deepEqual(failed(result), ['E4_inspection_participation'])
    assert.equal(result.ok, false)
    const report = evaluateReport([result, run(0, refused())])
    assert.equal(report.ok, false)
    assert.equal(report.refusalCounted, false)
  }
})

test('dumpable=0 counts only a permission refusal with the participation blocker', () => {
  assert.equal(run(0, refused()).ok, true)
  for (const error of [{ code: 'ENOENT', message: 'gone' }, { code: null, name: 'TypeError', message: 'wrong build' },
    { code: null, name: 'Error', message: 'linux_attribution_budget' }]) {
    const s = refused(); s[3] = stage('prepare', { error })
    assert.deepEqual(failed(run(0, s)), ['R1_prepare_permission_denied'], error.message)
  }
  const unrelated = refused(); unrelated[5].result.blockers = ['transcript_missing']
  assert.deepEqual(failed(run(0, unrelated)), ['R2_inspection_refused_for_participation'])
  const hidden = refused(); hidden[2].result.processes = []
  assert.deepEqual(failed(run(0, hidden)), ['V_owner_visible'])
  assert.equal(run(0, positive()).ok, false)
  assert.equal(run(0, refused()).recorded.guardedAttempted, false)
})

test('R2 permits additional blockers and records them without claiming sole causation', () => {
  const stages = refused()
  const inspection = stages[5].result
  inspection.blockers.push('lock_owner_identity_incomplete')
  inspection.owner.errors = ['linux_process_instance_unverified']
  inspection.probe.error = 'permission evidence unavailable'
  const result = run(0, stages)
  assert.equal(result.ok, true)
  assert.deepEqual(result.recorded.eligibility.blockers, inspection.blockers)
  assert.deepEqual(result.recorded.owner.errors, inspection.owner.errors)
  assert.equal(result.recorded.probe.error, inspection.probe.error)
})

test('incomplete or faulted collection never satisfies the table', () => {
  assert.ok(run(0, refused(), { incomplete: true, incompletePhase: 'stages' }).collectedFaults.includes('incomplete:stages'))
  assert.equal(run(1, positive(), { faults: ['malformed_line:3'] }).ok, false)
  assert.equal(run(1, positive().slice(0, 3), { incomplete: true, incompletePhase: 'stages' }).ok, false)
})

test('malformed stage payloads return collection failures instead of throwing', () => {
  for (const dumpable of [1, 0]) {
    for (let at = 0; at < positive().length; at++) {
      for (const payload of [null, {}, { processes: 'malformed' }, { probe: null, blockers: null }]) {
        const stages = positive()
        stages[at].result = payload
        const r = run(dumpable, stages)
        assert.equal(r.collected, false, `dumpable=${dumpable} stage=${at}`)
        assert.equal(r.ok, false)
        assert.deepEqual(r.rows, [])
        assert.ok(r.collectedFaults.some((f) => f.startsWith('stage_result_malformed:')))
      }
    }
  }
})

test('a refusal counts only with a passing control in the same report', () => {
  assert.deepEqual(evaluateReport([run(1, positive()), run(0, refused())]), { ok: true, failures: [], refusalCounted: true })
  const r = evaluateReport([run(1, refused()), run(0, refused())])
  assert.equal(r.refusalCounted, false)
  assert.deepEqual(r.failures, ['control_dumpable1_not_passed'])
  assert.equal(evaluateReport([run(0, refused())]).ok, false)
})

test('refusal cannot pass with an absent, malformed or invalid nested lock probe', () => {
  const malformed = [undefined, null, {}, { status: 'unknown' }, probe('invalid'),
    { ...probe('unknown'), method: 'unverified' }, probe('unknown', { guard: { status: 'invalid' } }),
    probe('unknown', { guard: { status: 'busy', attempts: 0 } }), probe('unknown', { participation: null }),
    probe('unknown', { participation: {} }), probe('held', { participation: { pid: '42', startTicks: '900', descriptor: '5' } }),
    probe('held', { participation: { pid: 42, startTicks: 900, descriptor: '5' } }),
    probe('held', { participation: { pid: 42, startTicks: '900', descriptor: '' } })]
  for (const value of malformed) {
    const stages = refused()
    stages[5].result.probe = value
    const result = run(0, stages)
    assert.equal(result.collected, false)
    assert.equal(result.ok, false)
    assert.deepEqual(result.rows, [])
    assert.ok(result.collectedFaults.includes('stage_result_malformed:inspect_thread'))
    assert.equal(evaluateReport([run(1, positive()), result]).refusalCounted, false)
  }
})

test('each dumpability run must match the same startup build manifest', () => {
  for (const dumpable of [1, 0]) {
    const stages = dumpable ? positive() : refused()
    stages[0].result.manifestSha256 = 'b'.repeat(64)
    // A replacement build can be internally coherent and pass the stage
    // protocol, but cannot be attributed to the parent's startup identity.
    assert.equal(validateF2(observe(stages)).ok, true)
    const result = run(dumpable, stages)
    assert.equal(result.collected, false)
    assert.equal(result.ok, false)
    assert.deepEqual(result.rows, [])
    assert.ok(result.collectedFaults.includes('startup_manifest_sha256_changed'))
  }
  const observation = observe(positive())
  const result = evaluateRun({ dumpable: 1, holder, ticks, observation, protocol: validateF2(observation) })
  assert.equal(result.ok, false)
  assert.ok(result.collectedFaults.includes('startup_manifest_sha256_invalid'))
})
