#!/usr/bin/env node
// Codex-like coordination waiter (#126 research, F1). Real Codex waits on
// `.coordination.lock` with a blocking exclusive flock. This fixture polls a
// nonblocking flock instead so that it can enforce its own deadline: a blocking
// wait has no bound of its own and could outlive the experiment.
//
// Per round: read `round N` from stdin, reply `armed N`, wait until the
// orchestrator's marker file exists (written while the orchestrator holds the
// guard), then poll the guard until it is acquired or the deadline passes.
// Release immediately and print one JSON line. stdin EOF ends the process.
import fs from 'node:fs'
import { createRequire } from 'node:module'
import path from 'node:path'
import process from 'node:process'
import readline from 'node:readline'
import { setImmediate } from 'node:timers'

const require = createRequire(process.env.FIXTURE_REQUIRE_FROM)
const { flockSync } = require('fs-ext-extra-prebuilt')

const guardPath = process.env.FIXTURE_GUARD
const markerDir = process.env.FIXTURE_MARKER_DIR
const deadlineMs = Number(process.env.FIXTURE_DEADLINE_MS)
const POLL_MS = 0.1
const sleeper = new Int32Array(new SharedArrayBuffer(4))
const nap = () => Atomics.wait(sleeper, 0, 0, POLL_MS)
const now = () => process.hrtime.bigint()
const ms = (a, b) => Number(b - a) / 1e6

function round(n) {
  const start = now()
  const limit = start + BigInt(Math.round(deadlineMs * 1e6))
  const marker = path.join(markerDir, `marker-${n}`)
  while (!fs.existsSync(marker)) {
    if (now() > limit) return { round: n, outcome: 'marker_timeout' }
    nap()
  }
  const markerSeen = now()
  const fd = fs.openSync(guardPath, 'r')
  let polls = 0
  try {
    while (true) {
      polls += 1
      try {
        flockSync(fd, 'exnb')
        break
      } catch (error) {
        if (error.code !== 'EAGAIN' && error.code !== 'EWOULDBLOCK') throw error
      }
      if (now() > limit) return { round: n, outcome: 'acquire_timeout', polls }
      nap()
    }
    const acquired = now()
    flockSync(fd, 'un')
    return {
      round: n, outcome: 'acquired', polls,
      markerSeenNs: String(markerSeen), acquiredNs: String(acquired),
      blockedMs: ms(markerSeen, acquired),
    }
  } finally {
    fs.closeSync(fd)
  }
}

const lines = readline.createInterface({ input: process.stdin })
lines.on('line', (line) => {
  const match = /^round (\d+)$/.exec(line)
  if (!match) return
  process.stdout.write(`armed ${match[1]}\n`)
  // Let the reply flush before the synchronous wait starts.
  setImmediate(() => process.stdout.write(JSON.stringify(round(Number(match[1]))) + '\n'))
})
lines.on('close', () => process.exit(0))
process.stdout.write('ready\n')
