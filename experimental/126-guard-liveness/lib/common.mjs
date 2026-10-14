// Shared lifecycle helpers for the #126/#127 research runners.
//
// Children are started with an exit promise created immediately, so cleanup
// never misses an early exit. Stopping a child only closes its stdin and waits
// with a bound. A timeout means the child's exit is unconfirmed: it is never
// escalated to a signal, and callers then preserve their scratch and fail.
import { Buffer } from 'node:buffer'
import { spawn } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import readline from 'node:readline'
import { clearTimeout, setTimeout } from 'node:timers'
import { setTimeout as delay } from 'node:timers/promises'

// The repository's temporary root for work under /Volumes/Kingston NV is
// /Volumes/Kingston NV/tmp; other hosts use /tmp. RESEARCH_TMP_ROOT overrides
// the root only: a fresh private child is always created beneath it, and the
// supplied directory itself is never chmod-ed or written into directly.
export function defaultTmpRoot() {
  return process.platform === 'darwin' ? '/Volumes/Kingston NV/tmp' : '/tmp'
}

export function freshPrivateDir(prefix, root = process.env.RESEARCH_TMP_ROOT ?? defaultTmpRoot()) {
  const real = fs.realpathSync(root)
  const stat = fs.statSync(real)
  if (!stat.isDirectory()) throw new Error(`temporary root is not a directory: ${root}`)
  fs.accessSync(real, fs.constants.W_OK)
  // mkdtemp creates the directory with mode 0700.
  const dir = fs.mkdtempSync(path.join(real, `codex-${prefix}-`))
  if ((fs.statSync(dir).mode & 0o077) !== 0) throw new Error(`fresh directory is not private: ${dir}`)
  return dir
}

// Write a new file only; an existing file is an error, never overwritten.
export function writeNew(file, data, mode = 0o600) {
  fs.writeFileSync(file, data, { flag: 'wx', mode })
}

// sun_path is 104 bytes on macOS and 108 on Linux, including the NUL.
export function assertSocketPath(socketPath) {
  const limit = process.platform === 'darwin' ? 103 : 107
  const length = Buffer.byteLength(socketPath)
  if (length > limit) throw new Error(`socket path is ${length} bytes, limit ${limit}: ${socketPath}`)
}

// Start a child and wait for its first stdout line. Rejects on spawn error,
// stdout EOF, exit before the line, or the readiness bound. The returned
// handle is registered in `live` before any await, so cleanup sees it even
// when readiness fails.
export function startChild(command, args, options, live, readyMs = 5000) {
  const child = spawn(command, args, { ...options, stdio: ['pipe', 'pipe', 'pipe'] })
  const handle = { child, pid: child.pid, stderr: '' }
  handle.exited = new Promise((resolve) => {
    child.once('exit', (code, signal) => resolve({ exitCode: code, signal }))
    child.once('error', (error) => resolve({ exitCode: null, signal: null, error: error.message }))
  })
  live.add(handle)
  handle.exited.then(() => live.delete(handle))
  child.stderr.setEncoding('utf8')
  child.stderr.on('data', (chunk) => { handle.stderr += chunk })
  const lines = readline.createInterface({ input: child.stdout })
  handle.lines = lines
  handle.ready = new Promise((resolve, reject) => {
    let timer
    const settle = (fn, value) => { clearTimeout(timer); fn(value) }
    lines.once('line', (line) => settle(resolve, line))
    child.stdout.once('end', () => settle(reject, new Error(`stdout ended before ready: ${command} ${handle.stderr}`)))
    handle.exited.then((result) => settle(reject, new Error(`exited before ready ${JSON.stringify(result)}: ${handle.stderr}`)))
    timer = setTimeout(() => settle(reject, new Error(`ready timeout: ${command}`)), readyMs)
  })
  return handle
}

// Close stdin and wait at most budgetMs. `incomplete` means the exit was not
// observed; nothing here signals the child.
export async function stopChild(handle, budgetMs = 10000) {
  try { handle.child.stdin.end() } catch { /* already closed */ }
  const result = await Promise.race([handle.exited, delay(budgetMs).then(() => null)])
  return result ?? { incomplete: true, pid: handle.pid }
}

export async function stopAll(live, budgetMs = 10000) {
  const outcomes = []
  for (const handle of [...live]) outcomes.push(await stopChild(handle, budgetMs))
  return outcomes
}
