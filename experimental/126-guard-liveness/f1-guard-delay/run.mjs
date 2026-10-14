#!/usr/bin/env node
// F1 (#126 research): does a finite delay inside codex-unlock's native guard
// propagate to a Codex-like process waiting on the same `.coordination.lock`?
//
// The delay is injected through the existing `afterGuardAcquired` test hook of
// `guardedProbeOnce` (dist build of this checkout; src is unchanged) and is a
// bounded `Atomics.wait`. This measures propagation of an injected delay. It is
// not a reproduction of a /proc cmdline or any other kernel wait.
//
// Rounds alternate per delay: `baseline` writes the marker without holding
// the guard, `guarded` writes it inside the guard and then waits `delayMs`.
// The waiter is stopped by closing its stdin and has its own lifetime; this
// runner sends no signal. Any error, missing or mismatched round, or
// unconfirmed child exit makes the run exit nonzero and keeps its scratch.
//
// F1_FAULT (fault checks only): `skip_round` makes the waiter never answer
// round 3; `waiter_lifetime` gives the waiter a 300 ms lifetime.
import { log } from 'node:console'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import process from 'node:process'
import { setTimeout as delay } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'
import { freshPrivateDir, startChild, stopAll, writeNew } from '../lib/common.mjs'

const DIR = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.resolve(DIR, '../../..')
const THREAD_ID = '01a089e8-3731-7202-ba68-0f4b0a3b2711'
const DELAYS = [0, 10, 50, 200, 1000]
const REPEATS = Number(process.env.F1_REPEATS ?? 5)
const WAITER_DEADLINE_MS = 5000
const REPLY_BUDGET_MS = WAITER_DEADLINE_MS + 2000
const FAULT = process.env.F1_FAULT ?? null

const { guardedProbeOnce } = await import(path.join(ROOT, 'dist', 'native-coordination.js'))
const sleeper = new Int32Array(new SharedArrayBuffer(4))
const now = () => process.hrtime.bigint()
const ms = (a, b) => Number(b - a) / 1e6

const out = freshPrivateDir('126-f1')
const home = path.join(out, 'home')
const lockDir = path.join(home, 'thread-writer-locks')
const markers = path.join(out, 'markers')
fs.mkdirSync(lockDir, { recursive: true, mode: 0o700 })
fs.mkdirSync(markers, { mode: 0o700 })
const guardPath = path.join(lockDir, '.coordination.lock')
const lockPath = path.join(lockDir, `${THREAD_ID}.lock`)
writeNew(guardPath, '')
writeNew(lockPath, '')
const identity = (p) => { const s = fs.statSync(p, { bigint: true }); return `${s.dev}:${s.ino}:${s.size}:${s.mtimeNs}` }
const before = { guard: identity(guardPath), lock: identity(lockPath) }

const live = new Set()
const failures = []
const results = []
const expectedRounds = REPEATS * DELAYS.length * 2
const waiter = startChild(process.execPath, [path.join(DIR, 'waiter.mjs')], {
  env: {
    FIXTURE_GUARD: guardPath, FIXTURE_MARKER_DIR: markers,
    FIXTURE_DEADLINE_MS: String(WAITER_DEADLINE_MS),
    FIXTURE_LIFETIME_MS: FAULT === 'waiter_lifetime' ? '300' : String(expectedRounds * REPLY_BUDGET_MS),
    FIXTURE_FAULT_SKIP_ROUND: FAULT === 'skip_round' ? '3' : '0',
    FIXTURE_REQUIRE_FROM: path.join(ROOT, 'node_modules', 'fs-ext-extra-prebuilt', 'package.json'),
  },
}, live)

const queue = []
let wake = null
async function nextLine() {
  const limit = Date.now() + REPLY_BUDGET_MS
  while (!queue.length) {
    if (Date.now() > limit) throw new Error('waiter reply timeout')
    if (waiter.child.exitCode !== null) throw new Error(`waiter exited ${waiter.child.exitCode}`)
    await Promise.race([new Promise((resolve) => { wake = resolve }), delay(50)])
  }
  return queue.shift()
}

let n = 0
try {
  if (await waiter.ready !== 'ready') throw new Error('waiter not ready')
  waiter.lines.on('line', (line) => { queue.push(line); wake?.() })
  for (let rep = 0; rep < REPEATS; rep += 1) {
    for (const delayMs of DELAYS) {
      for (const mode of ['baseline', 'guarded']) {
        n += 1
        waiter.child.stdin.write(`round ${n}\n`)
        if (await nextLine() !== `armed ${n}`) throw new Error(`waiter not armed for round ${n}`)
        const marker = path.join(markers, `marker-${n}`)
        let guardAcquired = null
        let hookEnd = null
        let probe = null
        const start = now()
        if (mode === 'baseline') {
          writeNew(marker, '')
        } else {
          probe = guardedProbeOnce(lockPath, undefined, {
            afterGuardAcquired: () => {
              guardAcquired = now()
              writeNew(marker, '')
              Atomics.wait(sleeper, 0, 0, delayMs)
              hookEnd = now()
            },
          })
        }
        const returned = now()
        const reply = JSON.parse(await nextLine())
        if (reply.round !== n || reply.outcome !== 'acquired') failures.push(`round ${n}: ${JSON.stringify(reply)}`)
        if (mode === 'guarded' && (probe?.status !== 'free' || probe?.guard?.status !== 'acquired')) {
          failures.push(`round ${n}: probe ${JSON.stringify(probe)}`)
        }
        results.push({
          round: n, rep, mode, delayMs,
          probeStatus: probe?.status ?? null, guardStatus: probe?.guard?.status ?? null,
          hookMs: guardAcquired !== null ? ms(guardAcquired, hookEnd) : null,
          guardHeldUntilReturnMs: guardAcquired !== null ? ms(guardAcquired, returned) : null,
          callMs: ms(start, returned),
          waiter: reply,
          // Waiter acquisition minus this runner's return from the call (or
          // marker write for baseline). The guard's LOCK_UN happens before the
          // return, so this is not a guard-release delay and may be negative.
          acquireMinusReturnMs: reply.acquiredNs ? ms(returned, BigInt(reply.acquiredNs)) : null,
        })
      }
    }
  }
} catch (error) {
  failures.push(String(error?.stack ?? error))
}
const stops = await stopAll(live)
const incomplete = stops.filter((s) => s.incomplete)
for (const stop of stops) if (!stop.incomplete && stop.exitCode !== 0) failures.push(`waiter exit ${JSON.stringify(stop)}`)
if (results.length !== expectedRounds) failures.push(`rounds ${results.length}/${expectedRounds}`)

const after = { guard: identity(guardPath), lock: identity(lockPath) }
if (JSON.stringify(before) !== JSON.stringify(after)) failures.push('native file identity changed')
const grouped = {}
for (const r of results) (grouped[`${r.mode}:${r.delayMs}`] ??= []).push(r)
const stats = Object.fromEntries(Object.entries(grouped).map(([k, rows]) => {
  const blocked = rows.map((r) => r.waiter.blockedMs).filter((x) => typeof x === 'number').sort((a, b) => a - b)
  const deltas = rows.map((r) => r.acquireMinusReturnMs).filter((x) => typeof x === 'number').sort((a, b) => a - b)
  return [k, {
    n: rows.length,
    blockedMs: { min: blocked[0], median: blocked[Math.floor(blocked.length / 2)], max: blocked.at(-1) },
    acquireMinusReturnMs: { min: deltas[0], max: deltas.at(-1), negative: deltas.filter((x) => x < 0).length },
  }]
}))
const ok = failures.length === 0 && incomplete.length === 0
const report = {
  ok, fault: FAULT, failures, incomplete,
  environment: { platform: process.platform, release: os.release(), arch: process.arch, node: process.version, commit: process.env.F1_COMMIT ?? null },
  nativeFilesUnchanged: JSON.stringify(before) === JSON.stringify(after),
  stats, results,
}
writeNew(path.join(out, 'f1-results.json'), JSON.stringify(report, null, 2) + '\n')
log(JSON.stringify({ out, ok, fault: FAULT, failures, incomplete, stats }, null, 2))
// Scratch is always kept: it holds the results and, on failure, the evidence.
process.exitCode = ok ? 0 : 1
