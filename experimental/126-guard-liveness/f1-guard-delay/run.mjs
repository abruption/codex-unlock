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
// The waiter exits on stdin EOF; nothing here sends a signal.
import { spawn } from 'node:child_process'
import { log } from 'node:console'
import { once } from 'node:events'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import process from 'node:process'
import readline from 'node:readline'
import { setTimeout as delay } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'

const DIR = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.resolve(DIR, '../../..')
const THREAD_ID = '01a089e8-3731-7202-ba68-0f4b0a3b2711'
const DELAYS = [0, 10, 50, 200, 1000]
const REPEATS = Number(process.env.F1_REPEATS ?? 5)
const WAITER_DEADLINE_MS = 5000
const REPLY_BUDGET_MS = WAITER_DEADLINE_MS + 2000

const { guardedProbeOnce } = await import(path.join(ROOT, 'dist', 'native-coordination.js'))
const sleeper = new Int32Array(new SharedArrayBuffer(4))
const now = () => process.hrtime.bigint()
const ms = (a, b) => Number(b - a) / 1e6

const out = process.env.F1_OUT ?? fs.mkdtempSync(path.join(os.tmpdir(), 'codex-126-f1-'))
fs.chmodSync(out, 0o700)
const home = path.join(out, 'home')
const lockDir = path.join(home, 'thread-writer-locks')
const markers = path.join(out, 'markers')
fs.mkdirSync(lockDir, { recursive: true, mode: 0o700 })
fs.mkdirSync(markers, { mode: 0o700 })
const guardPath = path.join(lockDir, '.coordination.lock')
const lockPath = path.join(lockDir, `${THREAD_ID}.lock`)
fs.writeFileSync(guardPath, '', { mode: 0o600 })
fs.writeFileSync(lockPath, '', { mode: 0o600 })
const identity = (p) => { const s = fs.statSync(p, { bigint: true }); return `${s.dev}:${s.ino}:${s.size}:${s.mtimeNs}` }
const before = { guard: identity(guardPath), lock: identity(lockPath) }

const waiter = spawn(process.execPath, [path.join(DIR, 'waiter.mjs')], {
  env: {
    FIXTURE_GUARD: guardPath, FIXTURE_MARKER_DIR: markers,
    FIXTURE_DEADLINE_MS: String(WAITER_DEADLINE_MS),
    FIXTURE_REQUIRE_FROM: path.join(ROOT, 'node_modules', 'fs-ext-extra-prebuilt', 'package.json'),
  },
  stdio: ['pipe', 'pipe', 'inherit'],
})
const replies = readline.createInterface({ input: waiter.stdout })
const queue = []
let wake = null
replies.on('line', (line) => { queue.push(line); wake?.() })

async function nextLine() {
  const limit = Date.now() + REPLY_BUDGET_MS
  while (!queue.length) {
    if (Date.now() > limit) throw new Error('waiter reply timeout')
    await Promise.race([new Promise((resolve) => { wake = resolve }), delay(50)])
  }
  return queue.shift()
}

const results = []
let n = 0
try {
  if (await nextLine() !== 'ready') throw new Error('waiter not ready')
  for (let rep = 0; rep < REPEATS; rep += 1) {
    for (const delayMs of DELAYS) {
      for (const mode of ['baseline', 'guarded']) {
        n += 1
        waiter.stdin.write(`round ${n}\n`)
        if (await nextLine() !== `armed ${n}`) throw new Error('waiter not armed')
        const marker = path.join(markers, `marker-${n}`)
        let guardAcquired = null
        let hookEnd = null
        let probe = null
        const start = now()
        if (mode === 'baseline') {
          fs.writeFileSync(marker, '')
        } else {
          probe = guardedProbeOnce(lockPath, undefined, {
            afterGuardAcquired: () => {
              guardAcquired = now()
              fs.writeFileSync(marker, '')
              Atomics.wait(sleeper, 0, 0, delayMs)
              hookEnd = now()
            },
          })
        }
        const returned = now()
        const reply = JSON.parse(await nextLine())
        results.push({
          round: n, rep, mode, delayMs,
          probeStatus: probe?.status ?? null, guardStatus: probe?.guard?.status ?? null,
          hookMs: guardAcquired !== null ? ms(guardAcquired, hookEnd) : null,
          guardHeldMs: guardAcquired !== null ? ms(guardAcquired, returned) : null,
          callMs: ms(start, returned),
          waiter: reply,
          // Cross-process figure: both sides read the same system monotonic
          // clock through process.hrtime.bigint().
          acquireAfterReturnMs: reply.acquiredNs ? ms(returned, BigInt(reply.acquiredNs)) : null,
        })
      }
    }
  }
} catch (error) {
  results.push({ error: String(error?.stack ?? error) })
} finally {
  waiter.stdin.end()
  const exited = await Promise.race([once(waiter, 'exit').then(([code]) => code), delay(5000).then(() => 'incomplete')])
  results.push({ waiterExit: exited })
}

const after = { guard: identity(guardPath), lock: identity(lockPath) }
const summary = {}
for (const r of results.filter((x) => x.mode)) {
  const key = `${r.mode}:${r.delayMs}`
  ;(summary[key] ??= []).push(r.waiter.blockedMs ?? null)
}
const stats = Object.fromEntries(Object.entries(summary).map(([k, v]) => {
  const s = v.filter((x) => x !== null).sort((a, b) => a - b)
  return [k, { n: v.length, ok: s.length, minMs: s[0], medianMs: s[Math.floor(s.length / 2)], maxMs: s.at(-1) }]
}))
const report = {
  environment: {
    platform: process.platform, release: os.release(), arch: process.arch, node: process.version,
    commit: process.env.F1_COMMIT ?? null,
  },
  nativeFilesUnchanged: JSON.stringify(before) === JSON.stringify(after),
  stats, results,
}
fs.writeFileSync(path.join(out, 'f1-results.json'), JSON.stringify(report, null, 2) + '\n', { mode: 0o600 })
log(JSON.stringify({ out, nativeFilesUnchanged: report.nativeFilesUnchanged, stats, waiterExit: results.at(-1) }, null, 2))
