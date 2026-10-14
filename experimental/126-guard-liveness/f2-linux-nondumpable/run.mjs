#!/usr/bin/env node
// F2 runner (#126 research). NOT RUN YET: prepared for a Linux host chosen by
// the integrating session. Refuses to run anywhere else.
//
// For FIXTURE_DUMPABLE in [1, 0]: start the synthetic `codex` holder in a
// private scratch home, record the same-user /proc access matrix, and, when
// F2_DIST points at a codex-unlock dist build, record `inspectThread` for that
// build. `unlockInspectedThread` is never called and no signal is sent; the
// holder ends on stdin EOF within a bounded wait.
import { spawn, spawnSync } from 'node:child_process'
import { log } from 'node:console'
import { once } from 'node:events'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import process from 'node:process'
import readline from 'node:readline'
import { setTimeout as delay } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'

if (process.platform !== 'linux') throw new Error('F2 runs on Linux only')
const DIR = path.dirname(fileURLToPath(import.meta.url))
const THREAD_ID = '01a089e8-3731-7202-ba68-0f4b0a3b2711'
const out = process.env.F2_OUT ?? fs.mkdtempSync(path.join(os.tmpdir(), 'codex-126-f2-'))
fs.chmodSync(out, 0o700)
const inspectThread = process.env.F2_DIST
  ? (await import(path.join(path.resolve(process.env.F2_DIST), 'inspection.js'))).inspectThread
  : null

const report = {
  environment: {
    kernel: os.release(), node: process.version,
    ptraceScope: fs.existsSync('/proc/sys/kernel/yama/ptrace_scope') ? fs.readFileSync('/proc/sys/kernel/yama/ptrace_scope', 'utf8').trim() : null,
    procMount: fs.readFileSync('/proc/self/mountinfo', 'utf8').split('\n').find((l) => / \/proc /.test(l)) ?? null,
    dist: process.env.F2_DIST ?? null,
  },
  runs: [],
}

for (const dumpable of ['1', '0']) {
  const home = path.join(out, `home-${dumpable}`)
  const lockDir = path.join(home, 'thread-writer-locks')
  const sessions = path.join(home, 'sessions', '2026', '10', '14')
  fs.mkdirSync(lockDir, { recursive: true, mode: 0o700 })
  fs.mkdirSync(sessions, { recursive: true, mode: 0o700 })
  fs.writeFileSync(path.join(lockDir, '.coordination.lock'), '', { mode: 0o600 })
  const lockPath = path.join(lockDir, `${THREAD_ID}.lock`)
  fs.writeFileSync(lockPath, '', { mode: 0o600 })
  fs.writeFileSync(path.join(sessions, `rollout-2026-10-14T00-00-00-${THREAD_ID}.jsonl`),
    JSON.stringify({ timestamp: '2026-10-14T00:00:00.000Z', type: 'event_msg', payload: { type: 'task_complete' } }) + '\n')
  const holder = spawn(path.join(DIR, 'codex'), [], {
    env: { PATH: '/usr/bin:/bin', FIXTURE_LOCK_PATH: lockPath, FIXTURE_DUMPABLE: dumpable },
    stdio: ['pipe', 'pipe', 'inherit'],
  })
  const run = { requestedDumpable: dumpable }
  try {
    const first = await Promise.race([
      once(readline.createInterface({ input: holder.stdout }), 'line').then(([line]) => JSON.parse(line)),
      delay(5000).then(() => { throw new Error('holder ready timeout') }),
    ])
    run.holder = first
    const observed = spawnSync('python3', ['-I', path.join(DIR, 'observe.py'), String(first.pid), String(first.fd), lockPath],
      { timeout: 5000, encoding: 'utf8' })
    run.observe = observed.status === 0 ? JSON.parse(observed.stdout) : { status: observed.status, stderr: observed.stderr }
    if (inspectThread) {
      const inspection = await inspectThread(THREAD_ID, { codexHome: home, stabilityMs: 50, terminationTimeoutMs: 3000 })
      run.inspect = {
        classification: inspection.classification, safeToUnlock: inspection.safeToUnlock,
        blockers: inspection.blockers, ownerPid: inspection.owner?.pid ?? null,
        attribution: inspection.attribution ?? null,
      }
    }
  } catch (error) {
    run.error = String(error?.stack ?? error)
  } finally {
    holder.stdin.end()
    run.holderExit = await Promise.race([once(holder, 'exit').then(([code]) => code), delay(5000).then(() => 'incomplete')])
  }
  report.runs.push(run)
}
fs.writeFileSync(path.join(out, 'f2-results.json'), JSON.stringify(report, null, 2) + '\n', { mode: 0o600 })
log(JSON.stringify({ out, runs: report.runs.map((r) => ({ d: r.requestedDumpable, holder: r.holder, exit: r.holderExit, inspect: r.inspect, error: r.error })) }, null, 2))
