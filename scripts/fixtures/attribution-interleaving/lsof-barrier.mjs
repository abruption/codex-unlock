#!/usr/bin/env node
// Barrier-equipped lsof wrapper for interleaving experiment (#100).
//
// When FIXTURE_SOCKET is set and FIXTURE_BARRIER is not 'off':
//   1. Connects to the transient fixture socket.
//   2. Sends 'attempt\n' so the transient opens the thread file under coordination.
//   3. Waits for the transient to confirm it is inside the window.
//   4. Runs the real system lsof with the same arguments.
//   5. Sends 'finish\n' so the transient closes its descriptors.
//
// When FIXTURE_HIDE_PID is set, process sets matching that PID in lsof's
// NUL-delimited -F0 output are removed before printing. This models the
// measured clean omission (exit 0, empty stderr) of a holder that lsof
// cannot see due to UID or namespace filtering.
//
// This script is injected only through codex-unlock's in-process diagnostic
// override seam, never through PATH or as a system lsof replacement.
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import net from 'node:net'
import process from 'node:process'
import { clearTimeout, setTimeout } from 'node:timers'

// codex-unlock runs diagnostics with a replaced environment (no PATH to node,
// no inherited variables), so settings arrive through a config file whose path
// a generated shell wrapper injects.
const args = process.argv.slice(2)
const config = JSON.parse(fs.readFileSync(process.env.FIXTURE_CONFIG, 'utf8'))
const logPath = config.log
const socketPath = config.socket
const barrier = config.barrier !== false
const hidePid = typeof config.hidePid === 'number' ? config.hidePid : null
const realLsof = config.realLsof || '/usr/sbin/lsof'

function log(record) {
  if (logPath) {
    fs.appendFileSync(
      logPath,
      JSON.stringify({ role: 'lsof-barrier', pid: process.pid, t: Date.now(), args, ...record }) + '\n'
    )
  }
}

// The timer must be cleared on every path: a pending timer keeps this process
// alive past its reply, and codex-unlock kills a diagnostic that outlives its
// own 5s command budget.
function barrierRequest(command) {
  return new Promise((resolve, reject) => {
    let timer
    const settle = (fn, value) => { clearTimeout(timer); sock.destroy(); fn(value) }
    const sock = net.createConnection(socketPath, () => {
      sock.setEncoding('utf8')
      let buf = ''
      sock.on('data', (chunk) => {
        buf += chunk
        const nl = buf.indexOf('\n')
        if (nl >= 0) settle(resolve, buf.slice(0, nl))
      })
      sock.write(command + '\n')
    })
    sock.on('error', (error) => settle(reject, error))
    timer = setTimeout(() => settle(reject, new Error('barrier timeout')), 2000)
  })
}

function removePidSets(stdout, pid) {
  // lsof -F0 uses NUL as field separator and newline as record terminator.
  // Each process set starts with 'p<pid>\0'. We remove entire process sets
  // whose PID matches.
  const pidPrefix = `p${pid}\0`
  const lines = stdout.split('\n')
  const kept = []
  let skip = false
  for (const line of lines) {
    if (line.startsWith('p')) {
      skip = line.startsWith(pidPrefix)
    }
    if (!skip) kept.push(line)
  }
  return kept.join('\n')
}

async function main() {
  let barrierReply = null
  if (barrier && socketPath) {
    try {
      barrierReply = await barrierRequest('attempt')
      log({ event: 'barrier_entered', reply: barrierReply })
      if (barrierReply === 'busy') barrierReply = null
    } catch (error) {
      log({ event: 'barrier_failed', error: error.message })
    }
  }

  const result = spawnSync(realLsof, args, {
    env: { LC_ALL: 'C', LANG: 'C', PATH: '/usr/bin:/bin:/usr/sbin:/sbin' },
    maxBuffer: 4 * 1024 * 1024,
    timeout: 10000,
  })

  if (barrier && socketPath && barrierReply) {
    try {
      await barrierRequest('finish')
      log({ event: 'barrier_released' })
    } catch (error) {
      log({ event: 'barrier_release_failed', error: error.message })
    }
  }

  let stdout = result.stdout ? result.stdout.toString() : ''
  const stderr = result.stderr ? result.stderr.toString() : ''

  if (hidePid !== null && stdout) {
    const before = stdout
    stdout = removePidSets(stdout, hidePid)
    log({ event: 'filter', hidePid, removed: before !== stdout })
  }

  log({ event: 'done', exitCode: result.status, stderrLen: stderr.length, stdoutLen: stdout.length, stdoutHead: stdout.slice(0, 200).replace(/\0/g, '|') })

  process.stdout.write(stdout)
  process.stderr.write(stderr)
  process.exitCode = result.status ?? 1
}

main().catch((error) => {
  log({ event: 'fatal', error: error.message })
  process.exitCode = 1
})
