// Separate-process observation for research inspection (#126 F2).
//
// Generic layer only: process lifecycle, bounded output and the stage-record
// protocol. Which stages must appear is decided by a caller's protocol layer
// (for F2: ../f2-linux-nondumpable/protocol.mjs).
//
// The parent never imports product modules. Product code runs in a child that
// first writes a `hello` handshake, then one JSON line per stage boundary. A
// synchronous call that stalls blocks only the child's event loop; the parent
// keeps its own timers and returns `incomplete` with the open stage.
//
// No cancellation guarantee. The parent sends no signal. On an exceeded bound
// it closes the child's stdin, destroys the pipes, unrefs the child and keeps
// a `lateExit` promise for that instance. The child has no lifetime timer: it
// checks its deadline and stdin EOF only between stages, then stops scheduling
// stages and lets pending work drain instead of calling process.exit. A child
// stuck in a syscall, or awaiting work that never settles, can outlive the
// runner.
import { Buffer } from 'node:buffer'
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import { performance } from 'node:perf_hooks'
import process from 'node:process'
import { clearTimeout, setImmediate, setTimeout } from 'node:timers'

const DEFAULT_STDOUT_BYTES = 1 << 20
const DEFAULT_STDERR_BYTES = 64 << 10

// Linux start ticks of a running process, as a decimal string. Elsewhere the
// instance is recorded as unavailable, not assumed.
export function processInstance(pid) {
  if (process.platform !== 'linux') return { pid, startTicks: null, reason: 'not_linux' }
  try {
    const text = fs.readFileSync(`/proc/${pid}/stat`, 'utf8')
    const fields = text.slice(text.lastIndexOf(') ') + 2).trim().split(/\s+/)
    if (!text.startsWith(`${pid} (`) || fields[0] === 'Z' || fields[0] === 'X') return { pid, startTicks: null, reason: 'not_running' }
    return /^\d+$/.test(fields[19] ?? '') ? { pid, startTicks: fields[19] } : { pid, startTicks: null, reason: 'malformed' }
  } catch (error) {
    return { pid, startTicks: null, reason: error.code ?? String(error) }
  }
}

// Splits a byte stream into complete lines under a total byte limit. Lines are
// decoded only when complete, so a multibyte character split across chunks is
// preserved. Bytes past the limit are counted and dropped, never buffered.
export class LineCollector {
  constructor(limit) {
    this.limit = limit
    this.bytes = 0
    this.pending = []
    this.pendingBytes = 0
    this.lines = []
    this.overflow = false
  }

  push(chunk) {
    const room = Math.max(0, this.limit - this.bytes)
    this.bytes += chunk.length
    if (chunk.length > room) this.overflow = true
    let part = chunk.subarray(0, room)
    for (let at = part.indexOf(10); at >= 0; at = part.indexOf(10)) {
      this.pending.push(part.subarray(0, at))
      this.lines.push(Buffer.concat(this.pending).toString('utf8'))
      this.pending = []
      this.pendingBytes = 0
      part = part.subarray(at + 1)
    }
    if (part.length) { this.pending.push(part); this.pendingBytes += part.length }
  }

  text() {
    return Buffer.concat([...this.lines.map((line) => Buffer.from(line + '\n')), ...this.pending]).toString('utf8')
  }

  faults(name) {
    const out = []
    if (this.overflow) out.push(`${name}_limit:${this.bytes}`)
    if (this.pendingBytes) out.push(`${name}_unterminated_line`)
    return out
  }
}

// Pure stage-stream validation. The first record must be the handshake; each
// `end` carries exactly one of `result`/`error`; at most one terminal record
// (`final` or `stop`), and nothing after it.
export function summarizeStages(lines) {
  const stages = []
  const begun = []
  const faults = []
  let open = null
  let terminal = null
  let hello = null
  if (lines.length === 0) faults.push('missing_hello')
  lines.forEach((line, index) => {
    let record
    try { record = JSON.parse(line) } catch { faults.push(`malformed_line:${index}`); return }
    if (record === null || typeof record !== 'object' || Array.isArray(record)) { faults.push(`malformed_line:${index}`); return }
    if (index === 0) {
      if (record.hello === true && Number.isInteger(record.pid)) { hello = record; return }
      faults.push('missing_hello')
    } else if (Object.hasOwn(record, 'hello')) {
      faults.push(`unexpected_hello:${index}`); return
    }
    if (terminal) { faults.push(`record_after_terminal:${index}`); return }
    if (record.final === true || typeof record.stop === 'string') {
      if (open) faults.push(`terminal_inside_stage:${open}`)
      terminal = record
      if (record.stop) faults.push(`stopped:${record.stop}`)
    } else if (record.phase === 'begin' && typeof record.stage === 'string') {
      if (open) faults.push(`nested_stage:${record.stage}`)
      open = record.stage
      begun.push(record.stage)
    } else if (record.phase === 'end' && typeof record.stage === 'string') {
      const hasResult = Object.hasOwn(record, 'result')
      const hasError = Object.hasOwn(record, 'error')
      if (open !== record.stage) faults.push(`unmatched_end:${record.stage}`)
      else if (hasResult === hasError) faults.push(`end_outcome_invalid:${record.stage}`)
      else stages.push(hasResult ? { stage: record.stage, result: record.result } : { stage: record.stage, error: record.error })
      open = null
    } else {
      faults.push(`unknown_record:${index}`)
    }
  })
  return { hello, stages, begun, openStage: open, final: terminal?.final === true ? terminal : null,
    stop: terminal?.stop ?? null, faults }
}

// Two bounds: `startupBudgetMs` until the handshake line, then `budgetMs` for
// the stages. The second bound starts at the handshake, so child startup
// latency does not consume the stage budget.
export function runIsolated(command, args, { startupBudgetMs, budgetMs, env,
  maxStdoutBytes = DEFAULT_STDOUT_BYTES, maxStderrBytes = DEFAULT_STDERR_BYTES } = {}) {
  for (const [name, value] of Object.entries({ startupBudgetMs, budgetMs })) {
    if (!Number.isInteger(value) || value <= 0) throw new Error(`${name} must be a positive integer`)
  }
  const child = spawn(command, args, { env, stdio: ['pipe', 'pipe', 'pipe'] })
  const instance = Number.isInteger(child.pid) ? processInstance(child.pid) : null
  const stdout = new LineCollector(maxStdoutBytes)
  const stderr = new LineCollector(maxStderrBytes)
  const faults = []
  child.stdin.on('error', (error) => { faults.push(`stdin:${error.code ?? error.message}`) })
  const startedAt = performance.now()
  let helloAt = null
  let onHello
  const sawHello = new Promise((resolve) => { onHello = resolve })
  child.stdout.on('data', (chunk) => {
    stdout.push(chunk)
    if (helloAt === null && stdout.lines.length > 0) { helloAt = performance.now(); onHello('hello') }
  })
  child.stderr.on('data', (chunk) => { stderr.push(chunk) })
  // A descendant may inherit stderr after the direct child exits and closes
  // stdout. Do not certify collection until both captured streams close.
  const closed = Promise.all([child.stdout, child.stderr].map((stream) =>
    new Promise((resolve) => { stream.once('close', resolve) })))
  const exited = new Promise((resolve) => {
    child.once('exit', (code, signal) => resolve({ code, signal }))
    child.once('error', (error) => resolve({ code: null, signal: null, error: error.message }))
  })
  const done = exited.then(async (result) => { await closed; return result })
  let timer
  const bound = (ms, phase) => new Promise((resolve) => { timer = setTimeout(() => resolve({ timeout: phase }), ms) })
  const finish = (result) => {
    clearTimeout(timer)
    const summary = summarizeStages(stdout.lines)
    const all = [...faults, ...stdout.faults('stdout'), ...stderr.faults('stderr'), ...summary.faults]
    try { child.stdin.end() } catch { /* already closed */ }
    child.stdin.destroy()
    child.stdout.destroy()
    child.stderr.destroy()
    const base = { instance, elapsedMs: performance.now() - startedAt,
      helloMs: helloAt === null ? null : helloAt - startedAt, ...summary, stderr: stderr.text() }
    if (result.timeout) {
      child.unref()
      return { ...base, incomplete: true, incompletePhase: result.timeout, faults: all, lateExit: exited }
    }
    if (result.error) all.push(`spawn:${result.error}`)
    if (result.code !== 0 || result.signal) all.push(`exit:${result.code}:${result.signal}`)
    if (!summary.final) all.push('no_final_record')
    if (summary.openStage) all.push(`stage_not_ended:${summary.openStage}`)
    return { ...base, incomplete: false, exit: result, faults: all }
  }
  return Promise.race([done, sawHello, bound(startupBudgetMs, 'startup')]).then((first) => {
    if (first !== 'hello') return finish(first)
    clearTimeout(timer)
    return Promise.race([done, bound(budgetMs, 'stages')]).then(finish)
  })
}

// Bounded look at late exits, one status per instance.
export async function lateExitStatus(entries, budgetMs) {
  let timer
  const expired = new Promise((resolve) => { timer = setTimeout(() => resolve(null), budgetMs) })
  const statuses = await Promise.all(entries.map(async (entry) => {
    const exit = await Promise.race([entry.lateExit, expired])
    return { ...entry.label, instance: entry.instance, ...(exit ? { status: 'exited', exit } : { status: 'unconfirmed' }) }
  }))
  clearTimeout(timer)
  return statuses
}

export class StopStages extends Error {
  constructor(reason) { super(`stopped:${reason}`); this.reason = reason }
}

// Child side. Writes the handshake at once. Each stage writes `begin` before it
// runs and `end` after. Deadline and stdin EOF are checked only at stage
// boundaries; a stop writes a `stop` record, sets the exit code and throws
// StopStages. The caller should catch it and return so pending handles drain.
export function childStages({ lifetimeMs }) {
  const deadline = performance.now() + lifetimeMs
  let parentGone = false
  process.stdin.on('end', () => { parentGone = true })
  process.stdin.on('error', () => { parentGone = true })
  process.stdin.resume()
  // Synchronous writes; a closed parent pipe is the same as stdin EOF.
  const write = (record) => {
    if (parentGone) return
    const bytes = Buffer.from(JSON.stringify(record) + '\n')
    let offset = 0
    while (offset < bytes.length) {
      try {
        offset += fs.writeSync(1, bytes, offset)
      } catch (error) {
        if (error.code === 'EAGAIN' && performance.now() <= deadline) continue
        parentGone = true
        return
      }
    }
  }
  const release = () => { process.stdin.pause(); process.stdin.destroy() }
  // Yield one macrotask so EOF seen during a synchronous stall is processed.
  const boundary = async () => {
    await new Promise((resolve) => { setImmediate(resolve) })
    const reason = parentGone ? 'parent_gone' : performance.now() > deadline ? 'lifetime' : null
    if (reason) {
      write({ stop: reason })
      release()
      process.exitCode = reason === 'parent_gone' ? 4 : 3
      throw new StopStages(reason)
    }
  }
  write({ hello: true, pid: process.pid })
  return {
    async stage(name, fn) {
      await boundary()
      write({ stage: name, phase: 'begin', at: performance.now() })
      let record
      try {
        const result = await fn()
        record = { stage: name, phase: 'end', at: performance.now(), result: result === undefined ? null : result }
      } catch (error) {
        record = { stage: name, phase: 'end', at: performance.now(),
          error: { code: error?.code ?? null, name: error?.name ?? null, message: String(error?.message ?? error) } }
      }
      write(record)
      return record
    },
    async finish(extra = {}) {
      await boundary()
      write({ final: true, ...extra })
      release()
    },
  }
}
