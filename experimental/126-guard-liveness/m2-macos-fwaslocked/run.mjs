#!/usr/bin/env node
// M2 (#127 research): can an `lsof +fg` FWASLOCKED check serve as a
// refusal-side filter on macOS? Measurement only; no product policy changes.
//
// Part 1 is a flag matrix over descriptor lifetimes. Part 2 re-runs the #100
// wrong-target shape (actual holder hidden from the product's lsof scan) with
// two visible Codex-looking non-holders: a failed acquirer and a former holder
// that released with LOCK_UN but kept its descriptor. The +fg scan is taken in
// the same barrier window, and the modelled omission is applied to it too.
//
// `inspectThread` is called; `unlockInspectedThread` never is, so no owner
// is signalled. This runner sends no signal to its children: it closes their
// stdin and waits with a bound, and each fixture has its own lifetime. Node
// can still SIGTERM a timed-out `lsof` (spawnSync timeout here, and the
// product's own diagnostic timeout); the +fg scans record such signals.
//
// Any error, unconfirmed child exit, missing scan or result count mismatch
// makes the run exit nonzero. Scratch is always kept; the socket directory is
// removed only when every child's exit was observed.
//
// M2_FAULT (fault checks only): `early_exit` (an actor exits before ready),
// `ignore_eof` (an actor ignores EOF, stop budget shorter than its lifetime),
// `long_socket` (socket path over the platform limit, refused before start).
import { log } from 'node:console'
import fs from 'node:fs'
import { createRequire } from 'node:module'
import os from 'node:os'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath } from 'node:url'
import { assertSocketPath, freshPrivateDir, startChild, stopAll, stopChild, writeNew } from '../lib/common.mjs'
import { fgScan, filterDecision, withoutPid } from './fg-scan.mjs'
import { evaluateFilterMeasurement } from './filter-measurement.mjs'
import { assertDarwin, options, wrapperText } from './options.mjs'
import { barrierEventFailed, evaluatePart2Scenario } from './part2-verdict.mjs'
import { evaluatePart1Scenario } from './part1-verdict.mjs'

// Reject unsupported hosts before product/native imports, scratch or children.
assertDarwin(process.platform)
const DIR = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.resolve(DIR, '../../..')
const DIST = path.join(ROOT, 'dist')
const THREAD_ID = '01a089e8-3731-7202-ba68-0f4b0a3b2711'
const { repeats: REPEATS, parts: PARTS } = options(process.env)
const FAULT = process.env.M2_FAULT ?? null
const LIFETIME_MS = 60000
const REQUIRE_FROM = path.join(ROOT, 'node_modules', 'fs-ext-extra-prebuilt', 'package.json')
const { inspectThread } = await import(path.join(DIST, 'inspection.js'))
const { overrideDiagnosticExecutableForTesting } = await import(path.join(DIST, 'process.js'))
const fsExt = createRequire(REQUIRE_FROM)('fs-ext-extra-prebuilt')

const out = freshPrivateDir('127-m2')
const sockets = freshPrivateDir('127-s')
const logFile = path.join(out, 'events.jsonl')
const live = new Set()
const results = []
const failures = []
const incomplete = []
let homeIndex = 0

function createHome() {
  const home = path.join(out, `h${++homeIndex}`)
  const lockDir = path.join(home, 'thread-writer-locks')
  const sessionDir = path.join(home, 'sessions', '2026', '10', '14')
  fs.mkdirSync(lockDir, { recursive: true, mode: 0o700 })
  fs.mkdirSync(sessionDir, { recursive: true, mode: 0o700 })
  writeNew(path.join(lockDir, '.coordination.lock'), '')
  const lockPath = path.join(lockDir, `${THREAD_ID}.lock`)
  writeNew(lockPath, '')
  writeNew(path.join(sessionDir, `rollout-2026-10-14T00-00-00-${THREAD_ID}.jsonl`),
    JSON.stringify({ timestamp: '2026-10-14T00:00:00.000Z', type: 'event_msg', payload: { type: 'task_complete' } }) + '\n')
  return { home, lockPath }
}

async function start(script, env) {
  const node = script.endsWith('.mjs')
  const handle = startChild(node ? process.execPath : script, node ? [script] : [], {
    env: { PATH: process.env.PATH, FIXTURE_REQUIRE_FROM: REQUIRE_FROM, FIXTURE_LIFETIME_MS: String(LIFETIME_MS), ...env },
  }, live)
  const line = await handle.ready
  if (line !== 'ready') throw new Error(`unexpected first line from ${script}: ${line}`)
  return handle
}

async function stop(handle, budgetMs = 10000, expectedExit = 0) {
  const result = await stopChild(handle, budgetMs)
  if (result.incomplete) incomplete.push(result)
  else if (result.exitCode !== expectedExit) failures.push(`pid ${handle.pid} exit ${JSON.stringify(result)} ${handle.stderr}`)
  return result
}

// The observer uses its own descriptor and closes it; its bit never appears
// in a scan because every scan precedes this probe.
function probe(lockPath) {
  const fd = fs.openSync(lockPath, 'r')
  try {
    fsExt.flockSync(fd, 'exnb')
    fsExt.flockSync(fd, 'un')
    return 'free'
  } catch (error) {
    if (error.code === 'EAGAIN' || error.code === 'EWOULDBLOCK') return 'held'
    return `error:${error.code}`
  } finally {
    fs.closeSync(fd)
  }
}

const roleView = (scan, pids) => Object.fromEntries(Object.entries(pids).map(([role, pid]) => {
  const { decision, reason, descriptors } = filterDecision(scan, pid)
  return [role, { pid, decision, reason, flags: descriptors.map((d) => `${d.fd}:${d.flags}`) }]
}))

const ACTOR = path.join(DIR, 'actor.mjs')
const actor = (role, lockPath, extra = {}) => start(ACTOR, { FIXTURE_ROLE: role, FIXTURE_LOCK_PATH: lockPath, ...extra })

const MATRIX = {
  holder: async (p) => ({ holder: await actor('holder', p) }),
  holder_multi_opener: async (p) => ({ holder: await actor('holder_multi', p), opener: await actor('opener', p) }),
  holder_opener: async (p) => ({ holder: await actor('holder', p), opener: await actor('opener', p) }),
  holder_failed: async (p) => ({ holder: await actor('holder', p), failed: await actor('failed', p) }),
  former_holder: async (p) => ({ former: await actor('former', p), holder: await actor('holder', p) }),
  former_only: async (p) => ({ former: await actor('former', p) }),
  failed_after_holder_exit: async (p) => {
    const holder = await actor('holder', p)
    const failed = await actor('failed', p)
    await stop(holder)
    return { failed }
  },
}

async function part1() {
  for (let rep = 0; rep < REPEATS; rep += 1) {
    for (const [name, setup] of Object.entries(MATRIX)) {
      const { lockPath } = createHome()
      const actors = await setup(lockPath)
      const scan = fgScan(lockPath)
      if (!scan.valid) failures.push(`part1 ${rep} ${name}: invalid +fg scan ${scan.problems.join(',')}`)
      const state = probe(lockPath)
      if (state !== 'free' && state !== 'held') failures.push(`part1 ${rep} ${name}: probe ${state}`)
      const pids = Object.fromEntries(Object.entries(actors).map(([k, h]) => [k, h.pid]))
      const roles = roleView(scan, pids)
      if (Object.values(roles).some((r) => r.decision === 'unknown')) failures.push(`part1 ${rep} ${name}: fixture descriptor evidence unknown`)
      const scenarioFailures = evaluatePart1Scenario(name, state, scan, roles)
      for (const reason of scenarioFailures) failures.push(`part1 ${rep} ${name}: expected observation ${reason}`)
      results.push({
        part: 1, rep, case: name, probe: state,
        scenarioMatched: scenarioFailures.length === 0, scenarioFailures,
        scan: { valid: scan.valid, problems: scan.problems, status: scan.status, signal: scan.signal, raw: scan.raw.replace(/\0/g, '|') },
        roles,
      })
      for (const handle of Object.values(actors)) await stop(handle)
    }
  }
}

function writeWrapper() {
  const wrapper = path.join(out, 'lsof-wrapper.sh')
  const configPath = path.join(out, 'barrier-config.json')
  writeNew(wrapper, wrapperText(configPath, process.execPath, path.join(DIR, 'lsof-barrier.mjs')), 0o700)
  return { wrapper, configPath }
}

function eventsSince(offset) {
  const text = fs.existsSync(logFile) ? fs.readFileSync(logFile).subarray(offset).toString('utf8') : ''
  return text.split('\n').filter(Boolean).map((line) => JSON.parse(line))
}

async function part2() {
  const { wrapper, configPath } = writeWrapper()
  const scenarios = ['B_failed', 'B_failed_all_scans', 'B_former', 'control_visible_holder']
  for (let rep = 0; rep < REPEATS; rep += 1) {
    for (const scenario of scenarios) {
      const { home, lockPath } = createHome()
      const env = { FIXTURE_LOCK_PATH: lockPath }
      const config = { log: logFile }
      const handles = []
      let holder
      let visible
      if (scenario === 'B_former') {
        // The former holder releases before the hidden holder acquires.
        visible = await start(path.join(DIR, 'former', 'codex'), env)
        handles.push(visible)
        holder = await start(path.join(DIR, 'holder', 'codex'), env)
        handles.push(holder)
        config.hidePid = holder.pid
      } else {
        holder = await start(path.join(DIR, 'holder', 'codex'), env)
        handles.push(holder)
        visible = holder
        if (scenario.startsWith('B_failed')) {
          const socket = path.join(sockets, `s${homeIndex}.sock`)
          assertSocketPath(socket)
          visible = await start(path.join(DIR, 'transient', 'codex'), { ...env, FIXTURE_SOCKET: socket, FIXTURE_LOG: logFile })
          handles.push(visible)
          Object.assign(config, { socket, hidePid: holder.pid, barrierAll: scenario === 'B_failed_all_scans' })
        }
      }
      fs.writeFileSync(configPath, JSON.stringify(config) + '\n', { mode: 0o600 })
      const offset = fs.existsSync(logFile) ? fs.statSync(logFile).size : 0
      overrideDiagnosticExecutableForTesting('lsof', wrapper)
      let inspection
      try {
        inspection = await inspectThread(THREAD_ID, { codexHome: home, stabilityMs: 50, terminationTimeoutMs: 3000 })
      } finally {
        overrideDiagnosticExecutableForTesting('lsof', null)
      }
      const allEvents = eventsSince(offset)
      const events = allEvents.filter((e) => e.event === 'fg_scan')
      for (const event of allEvents) {
        if (barrierEventFailed(event)) {
          failures.push(`part2 ${rep} ${scenario}: barrier evidence ${JSON.stringify(event)}`)
        }
      }
      if (config.socket) {
        const entered = allEvents.filter((e) => e.event === 'barrier_entered' && e.reply === 'inside').length
        const finished = allEvents.filter((e) => e.role === 'transient' && e.event === 'finish').length
        if (!entered || finished !== entered) failures.push(`part2 ${rep} ${scenario}: barrier windows entered=${entered} finished=${finished}`)
      }
      if (!events.length) failures.push(`part2 ${rep} ${scenario}: no +fg scan recorded`)
      const scans = events.map((e) => {
        if (!e.scan.valid) failures.push(`part2 ${rep} ${scenario}: invalid +fg scan ${e.scan.problems.join(',')}`)
        const hidden = typeof config.hidePid === 'number' ? withoutPid(e.scan, config.hidePid) : e.scan
        return {
          valid: e.scan.valid, problems: e.scan.problems, signal: e.scan.signal, raw: e.scan.raw.replace(/\0/g, '|'),
          owner: inspection.owner ? roleView(hidden, { owner: inspection.owner.pid }).owner : null,
          actualHolderUnfiltered: roleView(e.scan, { holder: holder.pid }).holder,
        }
      })
      const measurement = evaluateFilterMeasurement(scans)
      const { ownerDecisions, filterMeasurementValid, filterWouldRefuse, failure } = measurement
      // A completed scenario without a usable filter observation is still a
      // failed measurement; it cannot leave the final run's failures empty.
      if (failure) failures.push(`part2 ${rep} ${scenario}: ${failure}`)
      const scenarioFailures = evaluatePart2Scenario(scenario, inspection, holder.pid, visible.pid, measurement)
      for (const reason of scenarioFailures) failures.push(`part2 ${rep} ${scenario}: expected observation ${reason}`)
      results.push({
        part: 2, rep, scenario,
        scenarioMatched: scenarioFailures.length === 0, scenarioFailures,
        classification: inspection.classification, safeToUnlock: inspection.safeToUnlock,
        blockers: inspection.blockers, openers: inspection.openers.length,
        ownerPid: inspection.owner?.pid ?? null, actualHolderPid: holder.pid, visiblePid: visible.pid,
        wrongTarget: inspection.safeToUnlock && inspection.owner?.pid !== holder.pid,
        // An unavailable owner or invalid evidence cannot establish a filter
        // measurement. A present flag still never establishes lock ownership.
        filterMeasurementValid,
        filterWouldRefuse,
        ownerDecisions, scans,
      })
      for (const handle of handles) await stop(handle)
    }
  }
}

async function faultCase() {
  const { lockPath } = createHome()
  if (FAULT === 'early_exit') {
    await actor('early_exit', lockPath)
  } else if (FAULT === 'ignore_eof') {
    const handle = await actor('ignore_eof', lockPath, { FIXTURE_LIFETIME_MS: '4000' })
    await stop(handle, 1000)
  } else if (FAULT === 'long_socket') {
    assertSocketPath(path.join(sockets, 'x'.repeat(200) + '.sock'))
    await start(path.join(DIR, 'transient', 'codex'), { FIXTURE_LOCK_PATH: lockPath, FIXTURE_SOCKET: 'unused', FIXTURE_LOG: logFile })
  } else {
    throw new Error(`unknown fault ${FAULT}`)
  }
}

try {
  if (FAULT) await faultCase()
  else {
    if (PARTS.includes('1')) await part1()
    if (PARTS.includes('2')) await part2()
  }
} catch (error) {
  failures.push(String(error?.stack ?? error))
}
for (const result of await stopAll(live)) {
  if (result.incomplete) incomplete.push(result)
  else if (result.exitCode !== 0 || result.signal || result.error) failures.push(`cleanup exit ${JSON.stringify(result)}`)
}
const expected = FAULT ? 0
  : (PARTS.includes('1') ? REPEATS * Object.keys(MATRIX).length : 0) + (PARTS.includes('2') ? REPEATS * 4 : 0)
if (results.length !== expected) failures.push(`results ${results.length}/${expected}`)
const diagnosticSignals = results.flatMap((r) => r.part === 1 ? [r.scan.signal] : r.scans?.map((s) => s.signal) ?? []).filter(Boolean)
const ok = failures.length === 0 && incomplete.length === 0
// Keep the socket directory when any child's exit is unconfirmed.
if (incomplete.length === 0) fs.rmSync(sockets, { recursive: true, force: true })
const report = {
  ok, fault: FAULT, failures, incomplete, socketsKept: incomplete.length ? sockets : null,
  diagnosticSignalsRecorded: diagnosticSignals,
  environment: { platform: process.platform, release: os.release(), arch: process.arch, node: process.version, commit: process.env.M2_COMMIT ?? null },
  results,
}
writeNew(path.join(out, 'm2-results.json'), JSON.stringify(report, null, 2) + '\n')
const brief = results.map((r) => r.part === 1
  ? `P1 ${r.rep} ${r.case} probe=${r.probe} valid=${r.scan.valid} ` + Object.entries(r.roles).map(([k, v]) => `${k}:${v.flags.join('+')}/${v.decision}`).join(' ')
  : `P2 ${r.rep} ${r.scenario} cls=${r.classification} safe=${r.safeToUnlock} wrong=${r.wrongTarget} filter=${r.ownerDecisions.join(',')} refuse=${r.filterWouldRefuse}`)
log([`out=${out}`, `ok=${ok} fault=${FAULT} failures=${failures.length} incomplete=${incomplete.length} diagSignals=${diagnosticSignals.length}`,
  ...failures.map((f) => `FAIL ${f.split('\n')[0]}`), ...brief].join('\n'))
process.exitCode = ok ? 0 : 1
