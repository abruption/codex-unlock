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
// No process is signalled. `inspectThread` is called, `unlockInspectedThread`
// never is. Every child ends on stdin EOF within a bounded wait.
import { spawn } from 'node:child_process'
import { log } from 'node:console'
import { once } from 'node:events'
import fs from 'node:fs'
import { createRequire } from 'node:module'
import os from 'node:os'
import path from 'node:path'
import process from 'node:process'
import { clearTimeout, setTimeout } from 'node:timers'
import { setTimeout as delay } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'
import { fgScan, filterDecision } from './fg-scan.mjs'

const DIR = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.resolve(DIR, '../../..')
const DIST = path.join(ROOT, 'dist')
const THREAD_ID = '01a089e8-3731-7202-ba68-0f4b0a3b2711'
const REPEATS = Number(process.env.M2_REPEATS ?? 3)
const REQUIRE_FROM = path.join(ROOT, 'node_modules', 'fs-ext-extra-prebuilt', 'package.json')
const { inspectThread } = await import(path.join(DIST, 'inspection.js'))
const { overrideDiagnosticExecutableForTesting } = await import(path.join(DIST, 'process.js'))
const fsExt = createRequire(REQUIRE_FROM)('fs-ext-extra-prebuilt')

const out = process.env.M2_OUT ?? fs.mkdtempSync(path.join(os.tmpdir(), 'codex-127-m2-'))
fs.chmodSync(out, 0o700)
const logFile = path.join(out, 'events.jsonl')
// Unix socket paths are limited to 104 bytes on macOS, so sockets live in a
// short private directory supplied by the caller (or os.tmpdir()).
const sockets = fs.mkdtempSync(path.join(process.env.M2_SOCKET_ROOT ?? os.tmpdir(), 'codex-127-'))
fs.chmodSync(sockets, 0o700)
// Every started child, so an error path still ends them by stdin EOF.
const live = new Set()
const results = []
const incomplete = []
let homeIndex = 0

function createHome() {
  const home = path.join(out, `h${++homeIndex}`)
  const lockDir = path.join(home, 'thread-writer-locks')
  const sessionDir = path.join(home, 'sessions', '2026', '10', '14')
  fs.mkdirSync(lockDir, { recursive: true, mode: 0o700 })
  fs.mkdirSync(sessionDir, { recursive: true, mode: 0o700 })
  fs.writeFileSync(path.join(lockDir, '.coordination.lock'), '', { mode: 0o600 })
  const lockPath = path.join(lockDir, `${THREAD_ID}.lock`)
  fs.writeFileSync(lockPath, '', { mode: 0o600 })
  fs.writeFileSync(path.join(sessionDir, `rollout-2026-10-14T00-00-00-${THREAD_ID}.jsonl`),
    JSON.stringify({ timestamp: '2026-10-14T00:00:00.000Z', type: 'event_msg', payload: { type: 'task_complete' } }) + '\n')
  return { home, lockPath }
}

function start(script, env, args = []) {
  return new Promise((resolve, reject) => {
    const child = spawn(script.endsWith('.mjs') ? process.execPath : script,
      script.endsWith('.mjs') ? [script, ...args] : args,
      { env: { PATH: process.env.PATH, FIXTURE_REQUIRE_FROM: REQUIRE_FROM, ...env }, stdio: ['pipe', 'pipe', 'pipe'] })
    live.add(child)
    child.once('exit', () => live.delete(child))
    let stderr = ''
    child.stderr.on('data', (chunk) => { stderr += chunk })
    const timer = setTimeout(() => reject(new Error(`ready timeout ${script}`)), 5000)
    child.stdout.once('data', (chunk) => {
      clearTimeout(timer)
      if (String(chunk).includes('ready')) resolve(child)
      else reject(new Error(`unexpected output ${chunk}`))
    })
    child.once('exit', (code) => { clearTimeout(timer); reject(new Error(`exited early ${code}: ${stderr}`)) })
  })
}

async function stop(child) {
  if (child.exitCode !== null) return child.exitCode
  child.stdin.end()
  const code = await Promise.race([once(child, 'exit').then(([c]) => c), delay(10000).then(() => 'incomplete')])
  if (code === 'incomplete') incomplete.push(child.pid)
  return code
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

function decisions(scan, pids) {
  return Object.fromEntries(Object.entries(pids).map(([role, pid]) => {
    const entry = scan.entries.find((e) => e.pid === pid)
    return [role, { pid, flags: entry?.flags ?? null, wasLocked: entry ? entry.wasLocked : 'absent', decision: filterDecision(entry) }]
  }))
}

const ACTOR = path.join(DIR, 'actor.mjs')
const actor = (role, lockPath) => start(ACTOR, { FIXTURE_ROLE: role, FIXTURE_LOCK_PATH: lockPath })

// Part 1 cases. Each returns { pids, children, after? }.
const MATRIX = {
  holder: async (lockPath) => { const h = await actor('holder', lockPath); return { pids: { holder: h.pid }, children: [h] } },
  holder_opener: async (lockPath) => {
    const h = await actor('holder', lockPath); const o = await actor('opener', lockPath)
    return { pids: { holder: h.pid, opener: o.pid }, children: [h, o] }
  },
  holder_failed: async (lockPath) => {
    const h = await actor('holder', lockPath); const f = await actor('failed', lockPath)
    return { pids: { holder: h.pid, failed: f.pid }, children: [h, f] }
  },
  former_holder: async (lockPath) => {
    const p = await actor('former', lockPath); const h = await actor('holder', lockPath)
    return { pids: { former: p.pid, holder: h.pid }, children: [p, h] }
  },
  former_only: async (lockPath) => { const p = await actor('former', lockPath); return { pids: { former: p.pid }, children: [p] } },
  failed_after_holder_exit: async (lockPath) => {
    const h = await actor('holder', lockPath); const f = await actor('failed', lockPath)
    const code = await stop(h)
    return { pids: { failed: f.pid, exitedHolder: h.pid }, children: [f], note: `holder exit ${code}` }
  },
}

async function part1() {
  for (let rep = 0; rep < REPEATS; rep += 1) {
    for (const [name, setup] of Object.entries(MATRIX)) {
      const { lockPath } = createHome()
      const { pids, children, note } = await setup(lockPath)
      const scan = fgScan(lockPath)
      const state = probe(lockPath)
      results.push({ part: 1, rep, case: name, note, probe: state, scanStatus: scan.status, stderr: scan.stderr, raw: scan.raw.replace(/\0/g, '|'), roles: decisions(scan, pids) })
      for (const child of children) await stop(child)
    }
  }
}

async function writeWrapper() {
  const wrapper = path.join(out, 'lsof-wrapper.sh')
  const configPath = path.join(out, 'barrier-config.json')
  fs.writeFileSync(wrapper, '#!/bin/sh\n' +
    `FIXTURE_CONFIG=${JSON.stringify(configPath)} exec ${JSON.stringify(process.execPath)} ${JSON.stringify(path.join(DIR, 'lsof-barrier.mjs'))} "$@"\n`, { mode: 0o755 })
  return { wrapper, configPath }
}

function scanEventsSince(offset) {
  const text = fs.existsSync(logFile) ? fs.readFileSync(logFile, 'utf8').slice(offset) : ''
  return text.split('\n').filter(Boolean).map((line) => JSON.parse(line)).filter((e) => e.event === 'fg_scan')
}

async function part2() {
  const { wrapper, configPath } = await writeWrapper()
  const scenarios = ['B_failed', 'B_failed_all_scans', 'B_former', 'control_visible_holder']
  for (let rep = 0; rep < REPEATS; rep += 1) {
    for (const scenario of scenarios) {
      const { home, lockPath } = createHome()
      const env = { FIXTURE_LOCK_PATH: lockPath }
      const holder = await start(path.join(DIR, 'holder', 'codex'), env)
      const children = [holder]
      const config = { log: logFile }
      let visible = holder
      if (scenario.startsWith('B_failed')) {
        const socket = path.join(sockets, `s${homeIndex}.sock`)
        visible = await start(path.join(DIR, 'transient', 'codex'), { ...env, FIXTURE_SOCKET: socket, FIXTURE_LOG: logFile })
        Object.assign(config, { socket, hidePid: holder.pid, barrierAll: scenario === 'B_failed_all_scans' })
      } else if (scenario === 'B_former') {
        // The former holder must release before the hidden holder acquires,
        // so start it on a fresh home first and the holder after it.
        await stop(holder)
        children.length = 0
        visible = await start(path.join(DIR, 'former', 'codex'), env)
        const realHolder = await start(path.join(DIR, 'holder', 'codex'), env)
        children.push(visible, realHolder)
        Object.assign(config, { hidePid: realHolder.pid })
        config.realHolder = realHolder.pid
      }
      if (visible !== holder) children.push(visible)
      fs.writeFileSync(configPath, JSON.stringify(config) + '\n')
      const offset = fs.existsSync(logFile) ? fs.statSync(logFile).size : 0
      overrideDiagnosticExecutableForTesting('lsof', wrapper)
      let inspection
      try {
        inspection = await inspectThread(THREAD_ID, { codexHome: home, stabilityMs: 50, terminationTimeoutMs: 3000 })
      } finally {
        overrideDiagnosticExecutableForTesting('lsof', null)
      }
      const actualHolder = config.realHolder ?? holder.pid
      const scans = scanEventsSince(offset).map((e) => {
        // Apply the same modelled omission to the +fg view as to the product
        // scan, then evaluate the filter on the product's selected owner.
        const hidden = { ...e.scan, entries: e.scan.entries.filter((x) => x.pid !== config.hidePid) }
        return {
          raw: e.scan.raw.replace(/\0/g, '|'),
          owner: inspection.owner ? decisions(hidden, { owner: inspection.owner.pid }).owner : null,
          actualHolderUnfiltered: decisions(e.scan, { holder: actualHolder }).holder,
        }
      })
      const ownerDecisions = scans.map((s) => s.owner?.decision ?? 'no_owner')
      results.push({
        part: 2, rep, scenario,
        classification: inspection.classification, safeToUnlock: inspection.safeToUnlock,
        blockers: inspection.blockers, openers: inspection.openers.length,
        ownerPid: inspection.owner?.pid ?? null, actualHolderPid: actualHolder, visiblePid: visible.pid,
        wrongTarget: inspection.safeToUnlock && inspection.owner?.pid !== actualHolder,
        filterWouldRefuse: ownerDecisions.length > 0 && ownerDecisions.some((d) => d !== 'not_excluded'),
        ownerDecisions, scans,
      })
      for (const child of children) await stop(child)
    }
  }
}

try {
  const parts = (process.env.M2_PARTS ?? '1,2').split(',')
  if (parts.includes('1')) await part1()
  if (parts.includes('2')) await part2()
} catch (error) {
  results.push({ error: String(error?.stack ?? error) })
} finally {
  for (const child of [...live]) await stop(child)
  fs.rmSync(sockets, { recursive: true, force: true })
}
const report = {
  environment: { platform: process.platform, release: os.release(), arch: process.arch, node: process.version, commit: process.env.M2_COMMIT ?? null },
  incomplete, results,
}
fs.writeFileSync(path.join(out, 'm2-results.json'), JSON.stringify(report, null, 2) + '\n', { mode: 0o600 })
const brief = results.map((r) => r.part === 1
  ? `P1 ${r.rep} ${r.case} probe=${r.probe} ` + Object.entries(r.roles).map(([k, v]) => `${k}:${v.flags}/${v.decision}`).join(' ')
  : r.part === 2
    ? `P2 ${r.rep} ${r.scenario} cls=${r.classification} safe=${r.safeToUnlock} owner=${r.ownerPid} holder=${r.actualHolderPid} wrong=${r.wrongTarget} filter=${r.ownerDecisions.join(',')} refuse=${r.filterWouldRefuse}`
    : JSON.stringify(r))
log([`out=${out}`, `incomplete=${incomplete.length}`, ...brief].join('\n'))
