import assert from 'node:assert/strict'
import { test } from 'node:test'
import { parseF1Fault } from './f1-options.mjs'

test('F1 selects nominal only when the fault setting is absent or empty', () => {
  assert.equal(parseF1Fault(undefined), null)
  assert.equal(parseF1Fault(''), null)
})

test('F1 accepts only the two exact fault names', () => {
  assert.equal(parseF1Fault('skip_round'), 'skip_round')
  assert.equal(parseF1Fault('waiter_lifetime'), 'waiter_lifetime')
})

test('F1 rejects unknown, misspelled, padded and non-string fault settings', () => {
  for (const value of ['skip_roudn', 'waiter_lifetim', 'unknown', 'nominal', ' ', '\t', '\n',
    'skip_round ', ' skip_round', 'waiter_lifetime\n', 'SKIP_ROUND', 'false', '0', null, false, 0, {}]) {
    assert.throws(() => parseF1Fault(value), /^Error: F1_FAULT must be empty, skip_round or waiter_lifetime$/)
  }
})
