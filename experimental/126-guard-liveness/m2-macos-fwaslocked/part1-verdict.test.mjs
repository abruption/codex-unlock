import assert from 'node:assert/strict'
import { test } from 'node:test'
import { evaluatePart1Scenario } from './part1-verdict.mjs'

const role = (decision, pid = 100) => ({ decision, pid, flags: [decision === 'reject' ? '5:0x3' : '5:0x4003'] })
const cases = [
  ['holder', 'held', { holder: role('not_excluded') }],
  ['holder_multi_opener', 'held', { holder: { ...role('not_excluded'), flags: ['4:0x4003', '9:0x1'] }, opener: role('reject', 101) }],
  ['holder_opener', 'held', { holder: role('not_excluded'), opener: role('reject', 101) }],
  ['holder_failed', 'held', { holder: role('not_excluded'), failed: role('reject', 101) }],
  ['former_holder', 'held', { former: role('not_excluded'), holder: role('not_excluded', 101) }],
  ['former_only', 'free', { former: role('not_excluded') }],
  ['failed_after_holder_exit', 'free', { failed: role('reject') }],
]

test('all seven descriptor-lifetime scenarios require their fixed expected outcomes', () => {
  for (const [name, probe, roles] of cases) assert.deepEqual(evaluatePart1Scenario(name, probe, { valid: true }, roles), [], name)
})

test('contrary but well-formed probe and flag decisions invalidate each scenario', () => {
  for (const [name, probe, roles] of cases) {
    assert.ok(evaluatePart1Scenario(name, probe === 'held' ? 'free' : 'held', { valid: true }, roles).includes('probe'), name)
    for (const [label, observation] of Object.entries(roles)) {
      const opposite = role(observation.decision === 'reject' ? 'not_excluded' : 'reject', observation.pid)
      assert.ok(evaluatePart1Scenario(name, probe, { valid: true }, { ...roles, [label]: opposite }).includes(`decision:${label}`), `${name}/${label}`)
    }
  }
})

test('missing or extra roles, unknown decisions and absent descriptor evidence never pass', () => {
  const normal = { holder: role('not_excluded'), opener: role('reject', 101) }
  for (const roles of [null, {}, [], { holder: normal.holder }, { ...normal, unexpected: role('reject', 102) },
    { ...normal, opener: role('unknown', 101) }, { ...normal, opener: { ...normal.opener, flags: [] } },
    { ...normal, holder: { ...normal.holder, pid: null } }]) {
    assert.notEqual(evaluatePart1Scenario('holder_opener', 'held', { valid: true }, roles).length, 0)
  }
})

test('invalid scans and unrecognized cases do not acquire a success interpretation', () => {
  for (const scan of [null, {}, { valid: false }, { valid: 'true' }]) {
    assert.ok(evaluatePart1Scenario('holder', 'held', scan, { holder: role('not_excluded') }).includes('invalid_scan'))
  }
  for (const name of ['unknown', 'toString', '__proto__']) assert.deepEqual(evaluatePart1Scenario(name, 'held', { valid: true }, {}), ['unknown_scenario'])
})

test('additional descriptors do not imply an unexpected role or fixed FD count', () => {
  const roles = { holder: { ...role('not_excluded'), flags: ['7:0x1', '22:0x4003', '41:0x1'] }, opener: role('reject', 101) }
  assert.deepEqual(evaluatePart1Scenario('holder_multi_opener', 'held', { valid: true }, roles), [])
})
