#!/usr/bin/env node
// Private diagnostic override, never a system PATH replacement.
import { spawn } from 'node:child_process'
import { Buffer } from 'node:buffer'
import fs from 'node:fs'
import net from 'node:net'
import process from 'node:process'
import { clearTimeout, setTimeout } from 'node:timers'
import { pathToFileURL } from 'node:url'

export function removePidSets(stdout, pid) {
  let skip = false
  return stdout.split('\n').filter((line) => {
    if (line.startsWith('p')) skip = line.startsWith(`p${pid}\0`)
    return !skip
  }).join('\n')
}

function runLsof(args) {
  return new Promise((resolve, reject) => {
    const child = spawn('/usr/sbin/lsof', args, {
      env: { LC_ALL: 'C', LANG: 'C', PATH: '/usr/bin:/bin:/usr/sbin:/sbin' },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let stdout = ''; let stderr = ''; let settled = false
    const finish = (error, result) => { if (settled) return; settled = true; clearTimeout(timer); if (error) { child.unref(); child.stdout.destroy(); child.stderr.destroy(); reject(error) } else resolve(result) }
    const timer = setTimeout(() => finish(new Error(`lsof incomplete deadline; pid=${child.pid}; no termination requested`)), 1000)
    for (const [stream, kind] of [[child.stdout, 'stdout'], [child.stderr, 'stderr']]) {
      stream.setEncoding('utf8')
      stream.on('data', (chunk) => { if (kind === 'stdout') stdout += chunk; else stderr += chunk; if (Buffer.byteLength(stdout) + Buffer.byteLength(stderr) > 4 * 1024 * 1024) finish(new Error(`lsof output cap; pid=${child.pid}; no termination requested`)) })
    }
    child.on('error', (error) => finish(error))
    child.on('close', (status, signal) => finish(null, { stdout, stderr, status, signal }))
  })
}

async function main() {
  const args = process.argv.slice(2)
  const config = JSON.parse(fs.readFileSync(process.env.FIXTURE_CONFIG, 'utf8'))
  const log = (record) => fs.appendFileSync(config.log, JSON.stringify({ role: 'lsof-barrier', pid: process.pid, t: Date.now(), ...record }) + '\n')
  let socket
  let pending = null
  let buffer = ''
  const request = (command) => new Promise((resolve, reject) => {
    const timer = setTimeout(() => settle(new Error('barrier timeout')), 500)
    function settle(error, reply) {
      clearTimeout(timer); pending = null
      if (error) reject(error); else resolve(reply)
    }
    pending = settle
    socket.write(`${command}\n`)
  })
  try {
    if (config.barrier !== false) {
      socket = net.createConnection(config.socket)
      socket.setEncoding('utf8')
      socket.on('data', (chunk) => { buffer += chunk; const nl = buffer.indexOf('\n'); if (nl >= 0 && pending) { const reply = buffer.slice(0, nl); buffer = buffer.slice(nl + 1); pending(null, reply) } })
      socket.on('error', (error) => pending?.(error))
      socket.on('close', () => pending?.(new Error('barrier disconnected')))
      const reply = await request('attempt')
      log({ event: 'barrier_entered', reply })
      if (reply !== 'inside') throw new Error(`invalid barrier outcome: ${reply}`)
    }
    const result = await runLsof(args)
    if (result.error || result.signal || (result.status !== 0 && result.status !== 1)) throw new Error(`lsof incomplete: ${result.error?.code ?? result.signal ?? result.status}`)
    if (socket && await request('finish') !== 'done') throw new Error('barrier release not acknowledged')
    let stdout = result.stdout.toString()
    if (Number.isSafeInteger(config.hidePid) && config.hidePid > 0) { const before = stdout; stdout = removePidSets(stdout, config.hidePid); log({ event: 'filter', hidePid: config.hidePid, removed: before !== stdout }) }
    log({ event: 'done', exitCode: result.status })
    process.stdout.write(stdout)
    process.stderr.write(result.stderr)
    process.exitCode = result.status
  } finally { socket?.destroy() }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main().catch((error) => {
  process.stderr.write(`${error.message}\n`)
  process.exitCode = 1
})
