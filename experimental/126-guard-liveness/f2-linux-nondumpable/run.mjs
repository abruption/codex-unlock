#!/usr/bin/env node
// F2 access-matrix runner (#126 research). Refuses to run off Linux, as root, or with
// differing real and effective UIDs.
//
// For FIXTURE_DUMPABLE in [1, 0]: start the synthetic `codex` holder in a
// fresh private scratch directory, validate its ready record, record the
// same-user /proc access matrix. With F2_BUILD set to a directory made by
// build.mjs, the runner verifies that build against its manifest, then runs
// inspect-child.mjs in a separate process (lib/isolated-observer.mjs). The
// stages are checked by protocol.mjs and evaluated by expectations.mjs. This
// runner never imports a product module: a synchronous product stall blocks
// only that child, and this process records it as incomplete. No unlock
// method is called.
//
// Signals: this runner signals neither the holder, the observer nor the
// inspector child. An inspector past its bound gets stdin EOF and is left
// running; it stops at its next stage boundary, and a child stuck inside a
// syscall has no exit guarantee. The holder ends on stdin EOF or its own
// lifetime (HOLDER_LIFETIME_S). The observer is waited for with a bound and,
// if it has not exited, is recorded as incomplete and left running (a /proc
// read in a killable kernel wait cannot be interrupted by a handled signal
// anyway). Product diagnostics inside the inspector may signal their own
// timed-out diagnostic process groups; see inspect-child.mjs.
//
// Any validation failure, error, unconfirmed exit or observation made without
// the same live holder instance makes the run exit nonzero. Scratch is always
// kept.
import { spawn } from 'node:child_process'
import { log } from 'node:console'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { performance } from 'node:perf_hooks'
import process from 'node:process'
import { setTimeout as delay } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'
import { freshPrivateDir, startChild, stopAll, stopChild, writeNew } from '../lib/common.mjs'
import { LineCollector, lateExitStatus, processInstance, runIsolated } from '../lib/isolated-observer.mjs'
import { verifyBuild } from './build.mjs'
import { evaluateReport, evaluateRun, sameTicks } from './expectations.mjs'
import { parseChildFault, validateF2 } from './protocol.mjs'
import { validateAccessObservation } from './access-observation.mjs'

if (process.platform !== 'linux') throw new Error('F2 runs on Linux only')
if (process.getuid() === 0 || process.getuid() !== process.geteuid()) throw new Error('F2 requires an unprivileged same-UID runner')
if (process.env.F2_DIST) throw new Error('F2_DIST is replaced by F2_BUILD, a directory made by build.mjs')
const DIR = path.dirname(fileURLToPath(import.meta.url))
const THREAD_ID = '01a089e8-3731-7202-ba68-0f4b0a3b2711'
const OBSERVER_BUDGET_MS = 10000
const OBSERVER_OUTPUT_BYTES = 256 << 10
const INSPECT_STARTUP_MS = 10000
const INSPECT_STAGES_MS = 15000
// Holder lifetime must cover readiness (5 s), observation, inspection and
// cleanup with margin; observations after the holder ends are invalid.
const HOLDER_LIFETIME_S = 60
const NEEDED_MS = OBSERVER_BUDGET_MS + INSPECT_STARTUP_MS + INSPECT_STAGES_MS + 5000
const BUILD = process.env.F2_BUILD ? fs.realpathSync(process.env.F2_BUILD) : null
const CHILD_FAULT = parseChildFault(process.env.F2_CHILD_FAULT)
if (CHILD_FAULT && !BUILD) throw new Error('F2_CHILD_FAULT requires F2_BUILD')
// The runner's own check. inspect-child repeats it before importing.
const buildCheck = BUILD ? verifyBuild(BUILD) : null
if (buildCheck && !buildCheck.ok) throw new Error(`F2_BUILD does not match its manifest: ${buildCheck.faults.join(',')}`)

const out = freshPrivateDir('126-f2')
const live = new Set()
const failures = []
const incomplete = []
const lateExits = []
const read = (file) => (fs.existsSync(file) ? fs.readFileSync(file, 'utf8').trim() : null)
const report = {
  environment: {
    kernel: os.release(), node: process.version, uid: process.getuid(),
    ptraceScope: read('/proc/sys/kernel/yama/ptrace_scope'),
    procMount: fs.readFileSync('/proc/self/mountinfo', 'utf8').split('\n').find((l) => / \/proc /.test(l)) ?? null,
    mode: BUILD ? 'access_matrix_and_isolated_inspection' : 'access_matrix_only',
    build: buildCheck && { dir: BUILD, manifestSha256: buildCheck.manifestSha256, source: buildCheck.source, patch: buildCheck.patch,
      verifiedBy: 'run.mjs re-hash against manifest.json' },
    childFault: CHILD_FAULT,
  },
  runs: [],
}

// Bounded output, parsed only after both captured streams close.
function observe(pid, fd, lockPath) {
  const child = spawn('python3', ['-I', path.join(DIR, 'observe.py'), String(pid), String(fd), lockPath], { stdio: ['ignore', 'pipe', 'pipe'] })
  const stdout = new LineCollector(OBSERVER_OUTPUT_BYTES)
  const stderr = new LineCollector(64 << 10)
  child.stdout.on('data', (chunk) => { stdout.push(chunk) })
  child.stderr.on('data', (chunk) => { stderr.push(chunk) })
  const closed = Promise.all([child.stdout, child.stderr].map((stream) =>
    new Promise((resolve) => { stream.once('close', resolve) })))
  const exited = new Promise((resolve) => {
    child.once('exit', (code, signal) => resolve({ code, signal }))
    child.once('error', (error) => resolve({ code: null, error: error.message }))
  })
  const done = exited.then(async (result) => { await closed; return result })
  return Promise.race([done, delay(OBSERVER_BUDGET_MS).then(() => null)]).then((result) => {
    if (result === null) {
      // Leave it running; do not let it hold this process open.
      child.unref(); child.stdout.destroy(); child.stderr.destroy()
      return { incomplete: true, instance: processInstance(child.pid) }
    }
    const faults = [...stdout.faults('stdout'), ...stderr.faults('stderr')]
    if (result.code !== 0 || faults.length) return { failed: result, faults, stderr: stderr.text() }
    try { return { result: JSON.parse(stdout.text()) } } catch { return { failed: 'unparseable', stderr: stderr.text() } }
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
  const startedAt = performance.now()
  const holder = startChild(path.join(DIR, 'codex'), [], {
    env: { PATH: '/usr/bin:/bin', FIXTURE_LOCK_PATH: lockPath, FIXTURE_DUMPABLE: String(dumpable), FIXTURE_LIFETIME_SECONDS: String(HOLDER_LIFETIME_S) },
  }, live)
  let holderExited = false
  holder.exited.then(() => { holderExited = true })
  try {
    const ready = JSON.parse(await holder.ready)
    run.holder = ready
    // Independent instance sample, taken by this runner at readiness.
    run.holderInstanceAtReady = processInstance(ready.pid)
    if (ready.ready !== true || ready.pid !== holder.pid || !Number.isInteger(ready.fd) || ready.fd < 3 ||
      ready.dumpable !== dumpable || ready.uid !== process.getuid() || ready.euid !== process.getuid() ||
      ready.lifetime_seconds !== HOLDER_LIFETIME_S) {
      throw new Error(`holder ready record invalid: ${JSON.stringify(ready)}`)
    }
    const observed = await observe(ready.pid, ready.fd, lockPath)
    run.observe = observed
    run.holderInstanceAfterObserve = processInstance(ready.pid)
    if (observed.incomplete) incomplete.push({ role: 'observer', dumpable, instance: observed.instance })
    else if (!Object.hasOwn(observed, 'result')) failures.push(`observer dumpable=${dumpable}: ${JSON.stringify(observed)}`)
    else {
      run.accessCollection = validateAccessObservation(observed.result, {
        pid: ready.pid, fd: ready.fd, uid: process.getuid(), kernel: report.environment.kernel,
        startTicks: run.holderInstanceAtReady.startTicks,
      })
      if (!run.accessCollection.collected) failures.push(`observer dumpable=${dumpable}: ${run.accessCollection.faults.join(',')}`)
    }
    if (!sameTicks(run.holderInstanceAtReady.startTicks, run.holderInstanceAfterObserve.startTicks) || holderExited) {
      failures.push(`dumpable=${dumpable}: holder instance changed or ended during observation`)
    }
    if (BUILD) {
      if (performance.now() - startedAt + NEEDED_MS > HOLDER_LIFETIME_S * 1000) throw new Error('holder lifetime insufficient for inspection')
      const inspected = await runIsolated(process.execPath,
        [path.join(DIR, 'inspect-child.mjs'), BUILD, String(ready.pid), String(ready.fd), lockPath, home, THREAD_ID, buildCheck.manifestSha256], {
          startupBudgetMs: INSPECT_STARTUP_MS, budgetMs: INSPECT_STAGES_MS,
          env: { PATH: '/usr/sbin:/usr/bin:/bin',
            ...(process.env.RESEARCH_TMP_ROOT !== undefined ? { RESEARCH_TMP_ROOT: process.env.RESEARCH_TMP_ROOT } : {}),
            ...(CHILD_FAULT ? { F2_CHILD_FAULT: CHILD_FAULT } : {}) },
        })
      const { lateExit, ...record } = inspected
      run.inspect = record
      run.holderInstanceAfterInspect = processInstance(ready.pid)
      if (inspected.incomplete) {
        incomplete.push({ role: 'inspector', dumpable, instance: inspected.instance, phase: inspected.incompletePhase, openStage: inspected.openStage })
        lateExits.push({ label: { dumpable }, instance: inspected.instance, lateExit })
      }
      run.protocol = validateF2(inspected)
      run.evaluation = evaluateRun({
        dumpable, holder: ready, observation: inspected, protocol: run.protocol, expectedManifestSha256: buildCheck.manifestSha256,
        ticks: { ready: run.holderInstanceAtReady.startTicks, afterInspect: run.holderInstanceAfterInspect.startTicks,
          holderExitedDuringInspection: holderExited },
      })
      delete run.protocol.byStage
      if (!run.evaluation.collected) failures.push(`inspector dumpable=${dumpable}: ${run.evaluation.collectedFaults.join(',')}`)
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
// Bounded look for late inspector exits, one status per instance.
report.lateInspectorExits = await lateExitStatus(lateExits, 2000)
const collected = failures.length === 0 && incomplete.length === 0
report.expectations = BUILD ? evaluateReport(report.runs.map((r) => r.evaluation).filter(Boolean)) : null
const ok = collected && (!BUILD || report.expectations.ok)
Object.assign(report, { ok, collected, failures, incomplete })
writeNew(path.join(out, 'f2-results.json'), JSON.stringify(report, null, 2) + '\n')
log(JSON.stringify({ out, ok, collected, failures, incomplete, expectations: report.expectations,
  runs: report.runs.map((r) => ({ d: r.requestedDumpable, holder: r.holder, exit: r.holderExit,
    rows: r.evaluation?.rows.map((x) => `${x.id}:${x.ok}`), recorded: r.evaluation?.recorded })) }, null, 2))
process.exitCode = ok ? 0 : 1
