import assert from 'node:assert/strict'
import { test } from 'node:test'
import { evaluateFilterMeasurement } from './filter-measurement.mjs'

const scan = (decision) => ({ valid: true, owner: { decision } })

test('missing owner and unknown evidence fail a completed part-2 scenario', () => {
  for (const scans of [[], [{ valid: true, owner: null }], [{ valid: true }], [scan('unknown')],
    [scan('not_excluded'), scan('unknown')], [scan('reject'), { valid: true, owner: null }]]) {
    const measurement = evaluateFilterMeasurement(scans)
    assert.equal(measurement.filterMeasurementValid, false)
    assert.equal(measurement.filterWouldRefuse, null)
    assert.equal(measurement.failure, 'filter_measurement_unavailable')
  }
})

test('invalid scans and unexpected decisions cannot certify a filter measurement', () => {
  for (const scans of [null, {}, [null], [{ valid: false, owner: { decision: 'reject' } }],
    [{ valid: 'true', owner: { decision: 'reject' } }], [scan('holder')], [scan('')]]) {
    const measurement = evaluateFilterMeasurement(scans)
    assert.equal(measurement.filterMeasurementValid, false)
    assert.equal(measurement.filterWouldRefuse, null)
    assert.notEqual(measurement.failure, null)
  }
})

test('usable not-excluded and refusal measurements retain their distinct results', () => {
  const visible = evaluateFilterMeasurement([scan('not_excluded'), scan('not_excluded')])
  assert.equal(visible.filterMeasurementValid, true)
  assert.equal(visible.filterWouldRefuse, false)
  assert.equal(visible.failure, null)
  const rejected = evaluateFilterMeasurement([scan('not_excluded'), scan('reject')])
  assert.equal(rejected.filterMeasurementValid, true)
  assert.equal(rejected.filterWouldRefuse, true)
  assert.equal(rejected.failure, null)
})
