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

const DIR = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.resolve(DIR, '../../..')
const DIST = path.join(ROOT, 'dist')
const THREAD_ID = '01a089e8-3731-7202-ba68-0f4b0a3b2711'
const REPEATS = Number(process.env.M2_REPEATS ?? 3)
const PARTS = (process.env.M2_PARTS ?? '1,2').split(',')
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
      const pids = Object.fromEntries(Object.entries(actors).map(([k, h]) => [k, h.pid]))
      results.push({
        part: 1, rep, case: name, probe: probe(lockPath),
        scan: { valid: scan.valid, problems: scan.problems, status: scan.status, signal: scan.signal, raw: scan.raw.replace(/\0/g, '|') },
        roles: roleView(scan, pids),
      })
      for (const handle of Object.values(actors)) await stop(handle)
    }
  }
}

function writeWrapper() {
  const wrapper = path.join(out, 'lsof-wrapper.sh')
  const configPath = path.join(out, 'barrier-config.json')
  writeNew(wrapper, '#!/bin/sh\n' +
    `FIXTURE_CONFIG=${JSON.stringify(configPath)} exec ${JSON.stringify(process.execPath)} ${JSON.stringify(path.join(DIR, 'lsof-barrier.mjs'))} "$@"\n`, 0o700)
  return { wrapper, configPath }
}

function scanEventsSince(offset) {
  const text = fs.existsSync(logFile) ? fs.readFileSync(logFile, 'utf8').slice(offset) : ''
  return text.split('\n').filter(Boolean).map((line) => JSON.parse(line)).filter((e) => e.event === 'fg_scan')
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
      const events = scanEventsSince(offset)
      if (!events.length) failures.push(`part2 ${rep} ${scenario}: no +fg scan recorded`)
      const scans = events.map((e) => {
        const hidden = typeof config.hidePid === 'number' ? withoutPid(e.scan, config.hidePid) : e.scan
        return {
          valid: e.scan.valid, problems: e.scan.problems, signal: e.scan.signal, raw: e.scan.raw.replace(/\0/g, '|'),
          owner: inspection.owner ? roleView(hidden, { owner: inspection.owner.pid }).owner : null,
          actualHolderUnfiltered: roleView(e.scan, { holder: holder.pid }).holder,
        }
      })
      const ownerDecisions = scans.map((s) => s.owner?.decision ?? 'no_owner')
      results.push({
        part: 2, rep, scenario,
        classification: inspection.classification, safeToUnlock: inspection.safeToUnlock,
        blockers: inspection.blockers, openers: inspection.openers.length,
        ownerPid: inspection.owner?.pid ?? null, actualHolderPid: holder.pid, visiblePid: visible.pid,
        wrongTarget: inspection.safeToUnlock && inspection.owner?.pid !== holder.pid,
        // Refusal needs a decision other than not_excluded in some scan;
        // unknown counts as refusal, never as a holder.
        filterWouldRefuse: ownerDecisions.length > 0 && ownerDecisions.some((d) => d !== 'not_excluded'),
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
