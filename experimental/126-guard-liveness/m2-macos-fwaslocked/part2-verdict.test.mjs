import assert from 'node:assert/strict'
import { Buffer } from 'node:buffer'
import { test } from 'node:test'
import { assertDarwin } from './options.mjs'
import { evaluateFilterMeasurement } from './filter-measurement.mjs'
import { barrierEventFailed, diagnosticEvidence, evaluatePart2Scenario } from './part2-verdict.mjs'

test('barrier completion rejects nonzero exit, noise, signals, spawn errors and missing stderr', () => {
  const success = { status: 0, signal: null, stderr: Buffer.from('') }
  const done = (result) => ({ event: 'done', ...diagnosticEvidence(result) })
  assert.equal(barrierEventFailed(done(success)), false)
  for (const result of [
    { ...success, status: 1 }, { ...success, status: 2 }, { ...success, status: null },
    { ...success, stderr: Buffer.from('warning: incomplete visibility\n') },
    { ...success, stderr: Buffer.from(' ') }, { ...success, signal: 'SIGTERM' },
    { ...success, error: new Error('synthetic spawn failure') },
  ]) assert.equal(barrierEventFailed(done(result)), true)
  const evidence = done({ ...success, stderr: Buffer.from('synthetic stderr') })
  assert.equal(evidence.stderr, 'synthetic stderr')
  assert.equal(barrierEventFailed({ event: 'done', exitCode: 0 }), true)
})

test('barrier handshake and release failures remain failures', () => {
  for (const event of ['barrier_failed', 'barrier_release_failed', 'fatal']) assert.equal(barrierEventFailed({ event }), true)
  assert.equal(barrierEventFailed({ event: 'barrier_entered', reply: 'busy' }), true)
  assert.equal(barrierEventFailed({ event: 'barrier_entered', reply: 'inside' }), false)
})

function observation(scenario) {
  const holder = 101
  const visible = scenario === 'control_visible_holder' ? holder : 102
  const blocked = scenario === 'B_failed'
  const decision = scenario.startsWith('B_failed') ? 'reject' : 'not_excluded'
  return {
    holder, visible,
    inspection: { classification: 'live_owner', safeToUnlock: !blocked, owner: { pid: visible },
      openers: [{ pid: visible }], blockers: blocked ? ['owner_holds_other_thread_locks'] : [] },
    measurement: evaluateFilterMeasurement([{ valid: true, owner: { decision } }]),
  }
}

const scenarios = ['B_failed', 'B_failed_all_scans', 'B_former', 'control_visible_holder']
const verdict = (scenario, sample) => evaluatePart2Scenario(scenario, sample.inspection, sample.holder, sample.visible, sample.measurement)

test('all four documented M2 scenarios match their independent expected outcomes', () => {
  for (const scenario of scenarios) assert.deepEqual(verdict(scenario, observation(scenario)), [])
})

test('a missing reproduction or failed visible-holder control cannot pass the scenario', () => {
  const changes = [
    (sample) => { sample.inspection.classification = 'unknown' },
    (sample) => { sample.inspection.safeToUnlock = !sample.inspection.safeToUnlock },
    (sample) => { sample.inspection.owner = null },
    (sample) => { sample.inspection.owner.pid = 999 },
    (sample) => { sample.inspection.openers = [] },
    (sample) => { sample.inspection.openers.push({ pid: 999 }) },
    (sample) => { sample.inspection.blockers = ['lock_probe_unknown'] },
    (sample) => { sample.measurement = evaluateFilterMeasurement([{ valid: true, owner: { decision: 'unknown' } }]) },
    (sample) => { sample.measurement.filterWouldRefuse = !sample.measurement.filterWouldRefuse },
  ]
  for (const scenario of scenarios) {
    for (const change of changes) {
      const sample = observation(scenario)
      change(sample)
      assert.notEqual(verdict(scenario, sample).length, 0, scenario)
    }
  }
})

test('owner relations and all sampled filter decisions must match the scenario', () => {
  for (const scenario of scenarios) {
    const sample = observation(scenario)
    sample.inspection.owner.pid = scenario === 'control_visible_holder' ? 102 : sample.holder
    assert.ok(verdict(scenario, sample).includes('owner_relation'))
    const mixed = observation(scenario)
    mixed.measurement = evaluateFilterMeasurement([
      { valid: true, owner: { decision: 'reject' } }, { valid: true, owner: { decision: 'not_excluded' } },
    ])
    assert.ok(verdict(scenario, mixed).includes('filter_result'))
  }
  const sample = observation('B_former')
  assert.deepEqual(verdict('unknown_scenario', sample), ['unknown_scenario'])
})

test('M2 rejects every non-Darwin platform before measurement setup', () => {
  assert.doesNotThrow(() => assertDarwin('darwin'))
  for (const platform of ['linux', 'win32', 'freebsd', 'Darwin', '', undefined, null]) {
    assert.throws(() => assertDarwin(platform), /M2 requires Darwin/)
  }
})
