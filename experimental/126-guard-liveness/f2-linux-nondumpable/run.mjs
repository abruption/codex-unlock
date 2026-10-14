#!/usr/bin/env node
// F2 runner (#126 research). NOT RUN YET: prepared for a Linux host chosen by
// the integrating session. Refuses to run anywhere else, as root, or with
// differing real and effective UIDs.
//
// For FIXTURE_DUMPABLE in [1, 0]: start the synthetic `codex` holder in a
// fresh private scratch directory, validate its ready record, record the
// same-user /proc access matrix, and, when F2_DIST names a trusted review
// build, record `inspectThread` for that build. `unlockInspectedThread` is
// never called.
//
// Signals: this runner signals neither the holder nor the observer. The holder
// ends on stdin EOF or its own 20 s lifetime; the observer is waited for with
// a bound and, if it has not exited, is recorded as incomplete and left
// running (a /proc read in a killable kernel wait cannot be interrupted by a
// handled signal anyway). Code loaded from F2_DIST runs in this process and
// is not covered by that statement: the product's own diagnostics may signal
// their timed-out children.
//
// Any validation failure, error or unconfirmed exit makes the run exit
// nonzero. Scratch is always kept.
import { spawn } from 'node:child_process'
import { createHash } from 'node:crypto'
import { log } from 'node:console'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import process from 'node:process'
import { setTimeout as delay } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'
import { freshPrivateDir, startChild, stopAll, stopChild, writeNew } from '../lib/common.mjs'

if (process.platform !== 'linux') throw new Error('F2 runs on Linux only')
if (process.getuid() === 0 || process.getuid() !== process.geteuid()) throw new Error('F2 requires an unprivileged same-UID runner')
const DIR = path.dirname(fileURLToPath(import.meta.url))
const THREAD_ID = '01a089e8-3731-7202-ba68-0f4b0a3b2711'
const OBSERVER_BUDGET_MS = 10000
const INSPECT_BUDGET_MS = 15000

let inspectThread = null
let build = null
if (process.env.F2_DIST) {
  // Only a build the integrating session reviewed: importing it runs its code.
  if (!process.env.F2_DIST_COMMIT) throw new Error('F2_DIST requires F2_DIST_COMMIT')
  const entry = path.join(path.resolve(process.env.F2_DIST), 'inspection.js')
  build = { commit: process.env.F2_DIST_COMMIT, entry, sha256: createHash('sha256').update(fs.readFileSync(entry)).digest('hex') }
  inspectThread = (await import(entry)).inspectThread
}

const out = freshPrivateDir('126-f2')
const live = new Set()
const failures = []
const incomplete = []
const read = (file) => (fs.existsSync(file) ? fs.readFileSync(file, 'utf8').trim() : null)
const report = {
  environment: {
    kernel: os.release(), node: process.version, uid: process.getuid(),
    ptraceScope: read('/proc/sys/kernel/yama/ptrace_scope'),
    procMount: fs.readFileSync('/proc/self/mountinfo', 'utf8').split('\n').find((l) => / \/proc /.test(l)) ?? null,
    build,
  },
  runs: [],
}

function observe(pid, fd, lockPath) {
  const child = spawn('python3', ['-I', path.join(DIR, 'observe.py'), String(pid), String(fd), lockPath], { stdio: ['ignore', 'pipe', 'pipe'] })
  let stdout = ''
  let stderr = ''
  child.stdout.on('data', (chunk) => { stdout += chunk })
  child.stderr.on('data', (chunk) => { stderr += chunk })
  const exited = new Promise((resolve) => {
    child.once('exit', (code, signal) => resolve({ code, signal }))
    child.once('error', (error) => resolve({ code: null, error: error.message }))
  })
  return Promise.race([exited, delay(OBSERVER_BUDGET_MS).then(() => null)]).then((result) => {
    if (result === null) {
      // Leave it running; do not let it hold this process open.
      child.unref(); child.stdout.destroy(); child.stderr.destroy()
      return { incomplete: true, pid: child.pid }
    }
    if (result.code !== 0) return { failed: result, stderr }
    try { return { result: JSON.parse(stdout) } } catch { return { failed: 'unparseable', stdout, stderr } }
  })
}

for (const dumpable of [1, 0]) {
  const home = path.join(out, `home-${dumpable}`)
  const lockDir = path.join(home, 'thread-writer-locks')
  const sessions = path.join(home, 'sessions', '2026', '10', '14')
  fs.mkdirSync(lockDir, { recursive: true, mode: 0o700 })
  fs.mkdirSync(sessions, { recursive: true, mode: 0o700 })
  writeNew(path.join(lockDir, '.coordination.lock'), '')
  const lockPath = path.join(lockDir, `${THREAD_ID}.lock`)
  writeNew(lockPath, '')
  writeNew(path.join(sessions, `rollout-2026-10-14T00-00-00-${THREAD_ID}.jsonl`),
    JSON.stringify({ timestamp: '2026-10-14T00:00:00.000Z', type: 'event_msg', payload: { type: 'task_complete' } }) + '\n')
  const run = { requestedDumpable: dumpable }
  const holder = startChild(path.join(DIR, 'codex'), [], {
    env: { PATH: '/usr/bin:/bin', FIXTURE_LOCK_PATH: lockPath, FIXTURE_DUMPABLE: String(dumpable) },
  }, live)
  try {
    const ready = JSON.parse(await holder.ready)
    run.holder = ready
    if (ready.ready !== true || ready.pid !== holder.pid || !Number.isInteger(ready.fd) || ready.fd < 3 ||
      ready.dumpable !== dumpable || ready.uid !== process.getuid() || ready.euid !== process.getuid()) {
      throw new Error(`holder ready record invalid: ${JSON.stringify(ready)}`)
    }
    const observed = await observe(ready.pid, ready.fd, lockPath)
    run.observe = observed
    if (observed.incomplete) incomplete.push({ role: 'observer', ...observed })
    else if (!observed.result) failures.push(`observer dumpable=${dumpable}: ${JSON.stringify(observed)}`)
    if (inspectThread) {
      const settled = await Promise.race([
        inspectThread(THREAD_ID, { codexHome: home, stabilityMs: 50, terminationTimeoutMs: 3000 }).then((value) => ({ value }), (error) => ({ error: String(error) })),
        delay(INSPECT_BUDGET_MS).then(() => null),
      ])
      if (settled === null) {
        // The pending call cannot be cancelled; the holder still gets EOF below.
        run.inspect = { incomplete: true }
        incomplete.push({ role: 'inspect', dumpable })
      } else if (settled.error) {
        run.inspect = { error: settled.error }
        failures.push(`inspect dumpable=${dumpable}: ${settled.error}`)
      } else {
        const inspection = settled.value
        run.inspect = {
          classification: inspection.classification, safeToUnlock: inspection.safeToUnlock,
          blockers: inspection.blockers, ownerPid: inspection.owner?.pid ?? null,
          attribution: inspection.attribution ?? null,
        }
      }
    }
  } catch (error) {
    run.error = String(error?.stack ?? error)
    failures.push(`dumpable=${dumpable}: ${run.error}`)
  } finally {
    run.holderExit = await stopChild(holder, 5000)
    if (run.holderExit.incomplete) incomplete.push({ role: 'holder', ...run.holderExit })
    else if (run.holderExit.exitCode !== 0 && !run.error) failures.push(`holder dumpable=${dumpable} exit ${JSON.stringify(run.holderExit)} ${holder.stderr}`)
  }
  report.runs.push(run)
}
for (const result of await stopAll(live, 5000)) if (result.incomplete) incomplete.push({ role: 'holder', ...result })
if (report.runs.length !== 2) failures.push(`runs ${report.runs.length}/2`)
const ok = failures.length === 0 && incomplete.length === 0
Object.assign(report, { ok, failures, incomplete })
writeNew(path.join(out, 'f2-results.json'), JSON.stringify(report, null, 2) + '\n')
log(JSON.stringify({ out, ok, failures, incomplete, runs: report.runs.map((r) => ({ d: r.requestedDumpable, holder: r.holder, exit: r.holderExit, inspect: r.inspect })) }, null, 2))
process.exitCode = ok ? 0 : 1
