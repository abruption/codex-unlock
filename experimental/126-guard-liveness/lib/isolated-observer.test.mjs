import assert from 'node:assert/strict'
import { Buffer } from 'node:buffer'
import { test } from 'node:test'
import process from 'node:process'
import { performance } from 'node:perf_hooks'
import { setTimeout } from 'node:timers'
import { URL } from 'node:url'
import { LineCollector, lateExitStatus, runIsolated, summarizeStages } from './isolated-observer.mjs'

const LIB = new URL('./isolated-observer.mjs', import.meta.url).href
// Child bodies import the generic layer and stop cleanly on StopStages.
const child = (body) => [process.execPath, ['--input-type=module', '-e',
  `import { childStages, StopStages } from '${LIB}'\ntry {\n${body}\n} catch (error) { if (!(error instanceof StopStages)) throw error }`]]
const opts = { startupBudgetMs: 10000, budgetMs: 5000 }
const hello = '{"hello":true,"pid":1}'
const stall = (ms) => `Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ${ms})`

test('stage stream requires the handshake, paired stages and one outcome per end', () => {
  const ok = summarizeStages([hello, '{"stage":"a","phase":"begin"}', '{"stage":"a","phase":"end","result":1}', '{"final":true}'])
  assert.deepEqual(ok.faults, [])
  assert.deepEqual(ok.stages, [{ stage: 'a', result: 1 }])
  assert.deepEqual(summarizeStages(['{"final":true}']).faults, ['missing_hello'])
  assert.deepEqual(summarizeStages([]).faults, ['missing_hello'])
  assert.deepEqual(summarizeStages([hello, '{"stage":"a","phase":"begin"}', '{"stage":"a","phase":"end","result":1,"error":{}}']).faults,
    ['end_outcome_invalid:a'])
  assert.deepEqual(summarizeStages([hello, '{"stage":"a","phase":"begin"}', '{"stage":"a","phase":"end"}']).faults, ['end_outcome_invalid:a'])
  const bad = summarizeStages([hello, 'nope', '{"stage":"a","phase":"begin"}', '{"stage":"b","phase":"end","result":1}', '{"stage":"c","phase":"begin"}'])
  assert.deepEqual(bad.faults, ['malformed_line:1', 'unmatched_end:b'])
  assert.equal(bad.openStage, 'c')
  assert.deepEqual(summarizeStages([hello, '{"final":true}', '{"final":true}']).faults, ['record_after_terminal:2'])
  assert.deepEqual(summarizeStages([hello, '{"stage":"x","phase":"begin"}', '{"final":true}']).faults, ['terminal_inside_stage:x'])
  assert.deepEqual(summarizeStages([hello, '42', '[1]', '{"what":1}', hello]).faults,
    ['malformed_line:1', 'malformed_line:2', 'unknown_record:3', 'unexpected_hello:4'])
  assert.deepEqual(summarizeStages([hello, '{"stop":"lifetime"}']).faults, ['stopped:lifetime'])
})

test('line collector bounds bytes, keeps split multibyte characters and flags partial lines', () => {
  const c = new LineCollector(64)
  const text = Buffer.from('한글 line\n')
  c.push(text.subarray(0, 1))
  c.push(text.subarray(1, 4))
  c.push(text.subarray(4))
  assert.deepEqual(c.lines, ['한글 line'])
  assert.deepEqual(c.faults('stdout'), [])
  c.push(Buffer.alloc(200, 0x61))
  assert.equal(c.lines.length, 1)
  assert.ok(c.pendingBytes <= 64)
  assert.deepEqual(c.faults('stdout'), [`stdout_limit:${text.length + 200}`, 'stdout_unterminated_line'])
})

test('nominal child completes every stage', async () => {
  const [cmd, args] = child(`const c = childStages({ lifetimeMs: 5000 })
await c.stage('one', () => 1)
await c.stage('two', () => { throw Object.assign(new Error('denied'), { code: 'EACCES' }) })
await c.finish({ done: true })`)
  const r = await runIsolated(cmd, args, opts)
  assert.equal(r.incomplete, false)
  assert.deepEqual(r.faults, [])
  assert.deepEqual(r.stages.map((s) => s.stage), ['one', 'two'])
  assert.equal(r.stages[1].error.code, 'EACCES')
  assert.equal(r.final.done, true)
  assert.equal(r.hello.pid, r.instance.pid)
})

test('a synchronous stall after the handshake is bounded by the stage budget', async () => {
  // The stage budget starts at the handshake, so startup latency is excluded.
  const [cmd, args] = child(`const c = childStages({ lifetimeMs: 30000 })
await c.stage('fast', () => 1)
await c.stage('stall', () => { ${stall(3000)}; return 'late' })
await c.finish()`)
  const r = await runIsolated(cmd, args, { startupBudgetMs: 10000, budgetMs: 300 })
  assert.equal(r.incomplete, true)
  assert.equal(r.incompletePhase, 'stages')
  assert.equal(r.openStage, 'stall')
  assert.deepEqual(r.stages.map((s) => s.stage), ['fast'])
  assert.ok(r.elapsedMs - r.helloMs < 2000, `stage wait ${r.elapsedMs - r.helloMs} ms`)
  // stdin was closed: the child stops at its next boundary with code 4, no signal.
  const [late] = await lateExitStatus([{ label: { id: 'stall' }, instance: r.instance, lateExit: r.lateExit }], 10000)
  assert.deepEqual({ status: late.status, exit: late.exit }, { status: 'exited', exit: { code: 4, signal: null } })
})

test('a stall before the handshake is a startup timeout', async () => {
  const [cmd, args] = child(`${stall(2000)}
const c = childStages({ lifetimeMs: 5000 })
await c.finish()`)
  const r = await runIsolated(cmd, args, { startupBudgetMs: 300, budgetMs: 5000 })
  assert.equal(r.incomplete, true)
  assert.equal(r.incompletePhase, 'startup')
  assert.ok(r.faults.includes('missing_hello'))
  const [late] = await lateExitStatus([{ label: {}, instance: r.instance, lateExit: r.lateExit }], 10000)
  assert.equal(late.status, 'exited')
})

test('late exit status stays per instance and reports unconfirmed exits', async () => {
  const never = new Promise(() => {})
  const statuses = await lateExitStatus([
    { label: { id: 'a' }, instance: { pid: 1 }, lateExit: Promise.resolve({ code: 0, signal: null }) },
    { label: { id: 'b' }, instance: { pid: 2 }, lateExit: never },
  ], 50)
  assert.deepEqual(statuses.map((s) => [s.id, s.instance.pid, s.status]), [['a', 1, 'exited'], ['b', 2, 'unconfirmed']])
})

test('long output without a newline is bounded and faulted', async () => {
  const [cmd, args] = child(`const c = childStages({ lifetimeMs: 5000 })
await c.stage('spam', () => { process.stdout.write('x'.repeat(1 << 21)); return 1 })
await c.finish()`)
  const started = performance.now()
  const r = await runIsolated(cmd, args, { ...opts, maxStdoutBytes: 64 << 10 })
  assert.ok(performance.now() - started < 10000)
  assert.ok(r.faults.some((f) => f.startsWith('stdout_limit:')), r.faults.join(','))
  assert.ok(r.faults.includes('no_final_record') || r.faults.some((f) => f.startsWith('malformed_line')), r.faults.join(','))
})

test('stderr is bounded by bytes', async () => {
  const [cmd, args] = child(`const c = childStages({ lifetimeMs: 5000 })
process.stderr.write('한'.repeat(40000))
await c.finish()`)
  const r = await runIsolated(cmd, args, { ...opts, maxStderrBytes: 1024 })
  assert.ok(r.faults.some((f) => f.startsWith('stderr_limit:')), r.faults.join(','))
  // A cut inside a character decodes to one U+FFFD (3 bytes).
  assert.ok(Buffer.byteLength(r.stderr) <= 1024 + 3, String(Buffer.byteLength(r.stderr)))
})

test('collection waits for finite inherited stderr after the direct child exits', async () => {
  const grandchild = `process.stderr.on('error', () => {}); setTimeout(() => process.stderr.write('late stderr'), 200)`
  const [cmd, args] = child(`const c = childStages({ lifetimeMs: 5000 })
const { spawn } = await import('node:child_process')
const descendant = spawn(process.execPath, ['-e', ${JSON.stringify(grandchild)}], { stdio: ['ignore', 'ignore', 'inherit'] })
descendant.unref()
await c.finish()`)
  const r = await runIsolated(cmd, args, opts)
  assert.equal(r.incomplete, false)
  assert.equal(r.stderr, 'late stderr')
  assert.ok(r.faults.includes('stderr_unterminated_line'))
})

test('inherited stderr still open at the stage bound is incomplete', async () => {
  const [cmd, args] = child(`const c = childStages({ lifetimeMs: 5000 })
const { spawn } = await import('node:child_process')
const descendant = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 700)'], { stdio: ['ignore', 'ignore', 'inherit'] })
descendant.unref()
await c.finish()`)
  const r = await runIsolated(cmd, args, { startupBudgetMs: 10000, budgetMs: 100 })
  assert.equal(r.incomplete, true)
  assert.equal(r.incompletePhase, 'stages')
  const [late] = await lateExitStatus([{ label: {}, instance: r.instance, lateExit: r.lateExit }], 10000)
  assert.equal(late.status, 'exited')
  // The finite descendant exits itself; do not leave a live fixture behind.
  await new Promise((resolve) => setTimeout(resolve, 1000))
})

test('lifetime is checked at boundaries only and never interrupts an async stage', async () => {
  const [cmd, args] = child(`const c = childStages({ lifetimeMs: 100 })
await c.stage('async', () => new Promise((resolve) => setTimeout(() => resolve('done'), 400)))
await c.stage('never', () => 1)
await c.finish()`)
  const r = await runIsolated(cmd, args, opts)
  assert.deepEqual(r.exit, { code: 3, signal: null })
  assert.deepEqual(r.stages, [{ stage: 'async', result: 'done' }])
  assert.equal(r.stop, 'lifetime')
  assert.ok(r.faults.includes('stopped:lifetime'))
  assert.ok(r.faults.includes('no_final_record'))
})

test('early exit, malformed output and nonzero exit are faults', async () => {
  let [cmd, args] = child(`const c = childStages({ lifetimeMs: 5000 })
process.stdout.write(JSON.stringify({ stage: 'x', phase: 'begin' }) + '\\n'); process.exit(0)`)
  let r = await runIsolated(cmd, args, opts)
  assert.equal(r.incomplete, false)
  assert.ok(r.faults.includes('no_final_record'))
  assert.ok(r.faults.includes('stage_not_ended:x'))
  ;[cmd, args] = child(`const c = childStages({ lifetimeMs: 5000 })
await c.stage('a', () => 1); process.stdout.write('{broken\\n'); await c.finish(); process.exitCode = 2`)
  r = await runIsolated(cmd, args, opts)
  assert.ok(r.faults.some((f) => f.startsWith('malformed_line')))
  assert.ok(r.faults.includes('exit:2:null'))
})

test('spawn failure is a fault, not a result', async () => {
  const r = await runIsolated('/nonexistent-codex-research-observer', [], opts)
  assert.equal(r.incomplete, false)
  assert.ok(r.faults.some((f) => f.startsWith('spawn:')))
})
