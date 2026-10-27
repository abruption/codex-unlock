// Deterministic checks of the M2 parser and refusal-side decision.
// Run: node --test experimental/126-guard-liveness/m2-macos-fwaslocked/fg-scan.test.mjs
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { filterDecision, interpretScan, withoutPid } from './fg-scan.mjs'

const rec = (...fields) => fields.map((f) => `${f}\0`).join('') + '\n'
const ok = (stdout) => interpretScan({ status: 0, stdout })

test('multi-FD holder is not excluded; mixed nonholder is rejected', () => {
  const scan = ok(rec('p100') + rec('f3', 'G0x3;0x2') + rec('f4', 'G0x4003;0x2') + rec('p200') + rec('f5', 'G0x3;0x2') + rec('f6', 'G0x1;0x0'))
  assert.equal(scan.valid, true)
  assert.equal(filterDecision(scan, 100).decision, 'not_excluded')
  assert.equal(filterDecision(scan, 100).descriptors.length, 2)
  assert.equal(filterDecision(scan, 200).decision, 'reject')
  assert.equal(filterDecision(scan, 200).descriptors.length, 2)
})

test('the first descriptor alone does not decide', () => {
  const scan = ok(rec('p100') + rec('f3', 'G0x3;0x2') + rec('f9', 'G0x4002;0x2'))
  assert.equal(filterDecision(scan, 100).decision, 'not_excluded')
})

test('absent PID is unknown, also after a modelled omission', () => {
  const scan = ok(rec('p100') + rec('f3', 'G0x4003;0x2'))
  assert.equal(filterDecision(scan, 300).reason, 'pid_absent')
  assert.equal(filterDecision(withoutPid(scan, 100), 100).decision, 'unknown')
})

test('failed, signalled, errored or noisy scans are unknown', () => {
  const stdout = rec('p100') + rec('f3', 'G0x3;0x2')
  for (const input of [
    { status: 1, stdout },
    { status: null, signal: 'SIGTERM', stdout },
    { status: null, error: 'spawnSync ETIMEDOUT', stdout },
    { status: 0, stderr: 'lsof: WARNING', stdout },
  ]) {
    const scan = interpretScan(input)
    assert.equal(scan.valid, false)
    assert.equal(filterDecision(scan, 100).decision, 'unknown')
  }
})

test('partial or malformed output is unknown for every PID', () => {
  for (const stdout of [
    rec('p100') + rec('f3'),
    rec('p100') + rec('f3', 'Gzz'),
    rec('f3', 'G0x3;0x2'),
    rec('p100') + rec('G0x3;0x2'),
    rec('px') + rec('f3', 'G0x3;0x2'),
    rec('p100') + rec('f3', 'G0x3;0x2', 'n/x'),
    rec('p100') + rec('f3', 'G0x3;0x2') + rec('p200') + rec('f4'),
    rec('p100') + 'f3\0G0x3;0x2',
    rec('p100') + 'f3\0G0x3;0x2\0',
    rec('p100') + 'f3\0G0x3;0x2\n',
    rec('p100') + rec('f3', 'G0x4003;0x2', 'G0x3;0x2'),
    rec('p100') + rec('f', 'G0x3;0x2'),
    rec('p9007199254740993') + rec('f3', 'G0x3;0x2'),
    rec('p0') + rec('f3', 'G0x3;0x2'),
  ]) {
    const scan = ok(stdout)
    assert.equal(scan.valid, false, JSON.stringify(stdout))
    assert.equal(filterDecision(scan, 100).decision, 'unknown')
  }
})

test('empty successful scan has no positive outcome', () => {
  const scan = ok('')
  assert.equal(scan.valid, true)
  assert.equal(filterDecision(scan, 100).decision, 'unknown')
})
