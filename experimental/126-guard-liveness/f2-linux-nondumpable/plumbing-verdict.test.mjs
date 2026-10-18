import assert from 'node:assert/strict'
import { test } from 'node:test'
import { F2_STAGES } from './protocol.mjs'
import { evaluateNominalPlumbing } from './plumbing-verdict.mjs'

function nominal() {
  const results = {
    dist_identity: { ok: true, manifestSha256: 'a'.repeat(64), faults: [] },
    module_load: { modules: ['inspection.js'], unlockReachable: false },
    openers: { error: null, processes: [] },
    prepare: { pid: 123, startTicks: '456', candidates: ['4'], descriptors: ['4'] },
    guarded_verify: { status: 'held' },
    inspect_thread: { safeToUnlock: false, blockers: ['unproven'], warnings: [], probe: {}, classification: 'unknown' },
  }
  return { begun: [...F2_STAGES], stages: F2_STAGES.map((stage) => ({ stage, result: results[stage] })), incomplete: false, faults: [] }
}

test('nominal plumbing and the protocol-allowed platform prepare error pass', () => {
  assert.equal(evaluateNominalPlumbing(nominal()).ok, true)
  const observed = nominal()
  observed.stages[3] = { stage: 'prepare', error: { code: 'ENOENT', message: '/proc unavailable' } }
  observed.stages[4] = { stage: 'guarded_verify', result: { skipped: 'prepare_failed' } }
  const verdict = evaluateNominalPlumbing(observed)
  assert.equal(verdict.ok, true)
  assert.deepEqual(verdict.failures, [])
})

test('stream-valid stage errors outside prepare always fail nominal plumbing', () => {
  for (const stage of ['openers', 'guarded_verify', 'inspect_thread']) {
    const observed = nominal()
    observed.stages[F2_STAGES.indexOf(stage)] = { stage, error: { code: 'EIO', message: 'synthetic error' } }
    assert.deepEqual(observed.faults, [])
    const verdict = evaluateNominalPlumbing(observed)
    assert.equal(verdict.ok, false, stage)
    assert.ok(verdict.protocol.faults.includes(`stage_failed:${stage}`))
    assert.ok(verdict.failures.some((f) => f.includes(`stage_failed:${stage}`)))
  }
})

test('stream-valid malformed stage payloads and malformed prepare errors fail', () => {
  for (const stage of F2_STAGES) {
    const observed = nominal()
    observed.stages[F2_STAGES.indexOf(stage)] = { stage, result: {} }
    const verdict = evaluateNominalPlumbing(observed)
    assert.equal(verdict.ok, false, stage)
    assert.ok(verdict.protocol.faults.includes(`stage_result_malformed:${stage}`))
  }
  const observed = nominal()
  observed.stages[3] = { stage: 'prepare', error: {} }
  const verdict = evaluateNominalPlumbing(observed)
  assert.equal(verdict.ok, false)
  assert.ok(verdict.protocol.faults.includes('stage_error_malformed:prepare'))
})

test('missing, reordered or duplicate stages and observer failures stay failed', () => {
  const missing = nominal()
  missing.stages.pop()
  const reordered = nominal()
  reordered.begun.reverse()
  const duplicate = nominal()
  duplicate.stages.push(duplicate.stages[0])
  for (const observed of [missing, reordered, duplicate, { ...nominal(), incomplete: true },
    { ...nominal(), faults: ['stdout_limit'] }, { ...nominal(), faults: undefined }]) {
    assert.equal(evaluateNominalPlumbing(observed).ok, false)
  }
})
