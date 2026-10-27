// Runner-level negative tests for holder supervision (cross-platform).
// The children are tiny Node scripts that end on their own; none is
// signalled. Each test waits for every child's exit with a bound.
import assert from 'node:assert/strict'
import process from 'node:process'
import { setTimeout as delay } from 'node:timers/promises'
import { test } from 'node:test'
import { createSupervisor, stopFaults, superviseOnce } from './lifecycle.mjs'

const node = (source) => ({ command: process.execPath, args: ['-e', source], options: { env: {} } })
const READY = 'process.stdout.write(JSON.stringify({ ready: true, pid: process.pid }) + "\\n");'
// Exits 0 on stdin EOF; a 5 s lifetime guards against a stuck test.
const ON_EOF = (code) => `${READY} process.stdin.on("end", () => process.exit(${code})); process.stdin.resume(); setTimeout(() => process.exit(3), 5000).unref()`
const settled = async (handleExit, ms = 6000) => Promise.race([handleExit, delay(ms).then(() => 'unconfirmed')])

test('good holder: ready, during, exit 0 on EOF, no faults, stopped once', async () => {
  const s = createSupervisor()
  const r = await superviseOnce(s, { ...node(ON_EOF(0)), during: async (ready) => ready.pid })
  assert.deepEqual(r.faults, [])
  assert.equal(r.duringResult, r.pid)
  assert.equal(r.outcome.exitCode, 0)
  assert.deepEqual(await s.sweep(1000), [])
  assert.equal(s.started(), 1)
  assert.equal(s.stopped(), 1)
})

test('readiness timeout is a fault and the holder is still stopped', async () => {
  const s = createSupervisor()
  const r = await superviseOnce(s, { ...node('process.stdin.on("end", () => process.exit(0)); process.stdin.resume(); setTimeout(() => process.exit(3), 5000).unref()'), readyMs: 200 })
  assert.deepEqual(r.faults, ['holder:ready_failed:timeout'])
  assert.equal(r.outcome.exitCode, 0)
})

test('early exit before readiness is a fault, and its nonzero exit is a separate fault', async () => {
  const s = createSupervisor()
  const r = await superviseOnce(s, node('process.exit(1)'))
  assert.equal(r.faults.length, 2, JSON.stringify(r.faults))
  assert.match(r.faults[0], /^holder:ready_failed:(exited|stdout_ended)$/)
  assert.equal(r.faults[1], 'holder:exit:1')
})

test('invalid or unparseable ready records are faults', async () => {
  const s = createSupervisor()
  const bad = await superviseOnce(s, { ...node(ON_EOF(0)), validateReady: (ready) => (ready.pid === -1 ? null : 'pid_mismatch') })
  assert.deepEqual(bad.faults, ['holder:ready_invalid:pid_mismatch'])
  const text = await superviseOnce(s, node('process.stdout.write("not json\\n"); process.stdin.on("end", () => process.exit(0)); process.stdin.resume(); setTimeout(() => process.exit(3), 5000).unref()'))
  assert.deepEqual(text.faults, ['holder:ready_unparseable'])
})

test('EOF failure: a holder that ignores EOF is incomplete, never signalled, and exits on its own lifetime', async () => {
  const s = createSupervisor()
  let handle
  const r = await superviseOnce(s, { ...node(`${READY} process.stdin.resume(); setTimeout(() => process.exit(0), 1200)`), stopMs: 200,
    during: async (_ready, h) => { handle = h } })
  assert.deepEqual(r.faults, ['holder:incomplete'])
  assert.deepEqual(await settled(handle.exited), { exitCode: 0, signal: null })
})

test('a nonzero exit on EOF and a failing `during` are faults', async () => {
  const s = createSupervisor()
  const r = await superviseOnce(s, node(ON_EOF(2)))
  assert.deepEqual(r.faults, ['holder:exit:2'])
  const d = await superviseOnce(s, { ...node(ON_EOF(0)), during: async () => { throw new Error('inspection failed') } })
  assert.deepEqual(d.faults, ['holder:during_failed'])
  assert.equal(d.error, 'inspection failed')
})

test('stop outcomes: every error field becomes a fault', () => {
  assert.deepEqual(stopFaults('h', { exitCode: 0, signal: null, stdinErrors: [] }), [])
  assert.deepEqual(stopFaults('h', { exitCode: 0, signal: null, stdinErrors: ['EPIPE'], error: 'stdin_io_failed' }),
    ['h:error:stdin_io_failed', 'h:stdin_errors:1'])
  assert.deepEqual(stopFaults('h', { exitCode: null, signal: 'SIGTERM', stdinErrors: [] }), ['h:signal:SIGTERM', 'h:exit:null'])
  assert.deepEqual(stopFaults('h', { incomplete: true, pid: 1, stdinErrors: [] }), ['h:incomplete'])
  assert.deepEqual(stopFaults('h', undefined), ['h:stop_outcome_missing'])
})
