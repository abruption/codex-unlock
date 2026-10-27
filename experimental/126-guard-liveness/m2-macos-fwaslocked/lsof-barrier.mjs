#!/usr/bin/env node
// Barrier lsof wrapper for M2 (#127 research). Derived from the #100
// attribution-interleaving wrapper: optional barrier into the transient's
// open window, optional removal of one PID's process sets (modelled clean
// omission), plus an `lsof +fg` scan taken in the same window and logged for
// the hypothetical FWASLOCKED refusal filter. The product's own scan output
// is passed through unchanged apart from the modelled omission. spawnSync's
// timeout makes Node send SIGTERM to a slow lsof; `signal` is logged.
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import net from 'node:net'
import process from 'node:process'
import { clearTimeout, setTimeout } from 'node:timers'
import { fgScan } from './fg-scan.mjs'
import { diagnosticEvidence } from './part2-verdict.mjs'

const args = process.argv.slice(2)
const config = JSON.parse(fs.readFileSync(process.env.FIXTURE_CONFIG, 'utf8'))
const realLsof = '/usr/sbin/lsof'
const log = (record) => fs.appendFileSync(config.log,
  JSON.stringify({ role: 'lsof-barrier', pid: process.pid, t: Date.now(), args, ...record }) + '\n')

function barrierRequest(command) {
  return new Promise((resolve, reject) => {
    let timer
    const settle = (fn, value) => { clearTimeout(timer); sock.destroy(); fn(value) }
    const sock = net.createConnection(config.socket, () => {
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
  const prefix = `p${pid}\0`
  let skip = false
  return stdout.split('\n').filter((line) => {
    if (line.startsWith('p')) skip = line.startsWith(prefix)
    return !skip
  }).join('\n')
}

async function main() {
  // The opener discovery scan is always barriered and +fg-sampled. With
  // `barrierAll` (the #100 setup) the per-PID lock-set and cwd scans are
  // barriered too; otherwise they pass through outside the transient window.
  const isPathScan = args.includes('-F0pcu')
  let entered = false
  if (config.socket && (isPathScan || config.barrierAll)) {
    try {
      const reply = await barrierRequest('attempt')
      entered = reply === 'inside'
      log({ event: 'barrier_entered', reply })
    } catch (error) {
      log({ event: 'barrier_failed', error: error.message })
    }
  }
  const result = spawnSync(realLsof, args, {
    env: { LC_ALL: 'C', LANG: 'C', PATH: '/usr/bin:/bin:/usr/sbin:/sbin' },
    maxBuffer: 4 * 1024 * 1024, timeout: 4000,
  })
  if (isPathScan) log({ event: 'fg_scan', scan: fgScan(args.at(-1)) })
  if (entered) {
    try {
      await barrierRequest('finish')
    } catch (error) {
      log({ event: 'barrier_release_failed', error: error.message })
    }
  }
  let stdout = result.stdout?.toString() ?? ''
  if (typeof config.hidePid === 'number') stdout = removePidSets(stdout, config.hidePid)
  log({ event: 'done', isPathScan, ...diagnosticEvidence(result), stdoutHead: stdout.slice(0, 200).replace(/\0/g, '|') })
  process.stdout.write(stdout)
  process.stderr.write(result.stderr?.toString() ?? '')
  process.exitCode = result.status ?? 1
}

main().catch((error) => {
  log({ event: 'fatal', error: error.message })
  process.exitCode = 1
})
