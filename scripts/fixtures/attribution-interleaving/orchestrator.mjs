#!/usr/bin/env node
// Interleaving experiment orchestrator (#100 research).
//
// Creates a private scratch home with a synthetic Codex-like layout, then runs
// codex-unlock's inspectThread against three scenarios:
//
//   A. Control: real holder visible, no transient. Expected: live_owner, safeToUnlock.
//   B. Barrier + hidden holder: lsof sees only the transient (via PID filter).
//      Expected: unknown or live_owner on the transient, and if the latter,
//      the experiment proves an eligible interleaving exists.
//   C. Barrier only (no PID filter): both processes visible.
//      Expected: unknown (two openers).
//
// Every child exits by stdin EOF / normal exit. No SIGTERM/SIGKILL is sent by
// the orchestrator. No unlock function or signal function is called.
import { spawn } from 'node:child_process'
import { Buffer } from 'node:buffer'
import { log } from 'node:console'
import { createHash } from 'node:crypto'
import { mkdtemp, mkdir, writeFile, chmod, stat, readFile, readdir } from 'node:fs/promises'
import { performance } from 'node:perf_hooks'
import path from 'node:path'
import process from 'node:process'
import { clearTimeout, setTimeout } from 'node:timers'
import { fileURLToPath, pathToFileURL } from 'node:url'

const THREAD_ID = '01a089e8-3731-7202-ba68-0f4b0a3b2711'
const DIR = path.dirname(fileURLToPath(import.meta.url))
const DIST = path.resolve(DIR, '../../../dist')
const ROOT = path.resolve(DIR, '../../..')

export function socketFor(scratch, label) {
  const value = path.join(scratch, `${label}.sock`)
  if (Buffer.byteLength(value) >= 104) throw new Error('Unix socket path too long; supply a shorter private TMPDIR')
  return value
}

async function createHome(scratch, label = 'home') {
  const home = path.join(scratch, label)
  const lockDir = path.join(home, 'thread-writer-locks')
  const sessionDir = path.join(home, 'sessions', '2026', '10', '13')
  await mkdir(lockDir, { recursive: true })
  await writeFile(path.join(lockDir, '.coordination.lock'), '')
  const lockPath = path.join(lockDir, `${THREAD_ID}.lock`)
  await writeFile(lockPath, '')
  await mkdir(sessionDir, { recursive: true })
  const transcript = path.join(sessionDir, `rollout-2026-10-13T00-00-00-${THREAD_ID}.jsonl`)
  await writeFile(transcript, JSON.stringify({
    timestamp: '2026-10-13T00:00:00.000Z',
    type: 'event_msg',
    payload: { type: 'task_complete' },
  }) + '\n')
  return { home, lockDir, lockPath, transcript }
}

export function startChild(script, env, opts = {}) {
  return new Promise((resolve, reject) => {
    const { registry = [], budgetMs = 2000, ...spawnOptions } = opts
    const child = spawn(process.execPath, [script], {
      env: { ...process.env, ...env },
      stdio: ['pipe', 'pipe', 'pipe'],
      ...spawnOptions,
    })
    registry.push(child)
    child.once('close', () => { child._fixtureClosed = true })
    child.stdout.setEncoding('utf8')
    child.stderr.setEncoding('utf8')
    let stderr = ''; let buffer = ''
    child.stderr.on('data', (chunk) => { stderr = (stderr + chunk).slice(-4096) })
    child.stdin.on('error', () => {})
    const timer = setTimeout(() => finish(new Error('child readiness timeout')), Math.max(0, budgetMs))
    const onData = (chunk) => { buffer += chunk; if (buffer.length > 4096) finish(new Error('excess readiness output')); else if (buffer.includes('\n')) finish(buffer.split('\n')[0] === 'ready' ? null : new Error('unexpected readiness output')) }
    const onError = (error) => finish(error)
    const onClose = (code) => finish(new Error(`child closed before readiness: ${code}`))
    function finish(error) {
      clearTimeout(timer); child.stdout.removeListener('data', onData); child.removeListener('error', onError); child.removeListener('close', onClose)
      if (error) {
        error.fixturePid = child.pid
        error.fixtureScript = script
        error.fixtureStderr = stderr
        reject(error)
      } else resolve({ child, stderr: () => stderr })
    }
    child.stdout.on('data', onData)
    child.once('error', onError)
    child.once('close', onClose)
    // Keep streams drained after readiness and preserve late spawn errors.
    child.on('error', () => {})
    child.stdout.resume()
  })
}

// Normal shutdown only: close stdin so the child sees EOF, then wait with a
// bound. A child that does not exit is reported, never killed by this script.
export async function stopChild(child, budgetMs = 2000) {
  if (child._fixtureClosed) return { exitCode: child.exitCode }
  try { child.stdin.end() } catch { /* already closed */ }
  return new Promise((resolve) => {
    const timer = setTimeout(() => { child.unref(); child.stdin.destroy(); child.stdout.destroy(); child.stderr.destroy(); done({ incomplete: true, pid: child.pid }) }, Math.max(0, budgetMs))
    const onClose = (code) => { child._fixtureClosed = true; done({ exitCode: code }) }
    function done(value) { clearTimeout(timer); child.removeListener('close', onClose); resolve(value) }
    child.once('close', onClose)
    if (child.exitCode !== null && child.stdout.destroyed && child.stderr.destroyed) onClose(child.exitCode)
  })
}

async function snapshotFile(filename) {
  const value = await stat(filename, { bigint: true })
  return { dev: String(value.dev), ino: String(value.ino), size: String(value.size), mode: String(value.mode), uid: String(value.uid), mtimeNs: String(value.mtimeNs), sha256: createHash('sha256').update(await readFile(filename)).digest('hex') }
}

async function hashes(directory, prefix = '') {
  const result = {}
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const key = path.join(prefix, entry.name)
    if (entry.isDirectory()) Object.assign(result, await hashes(path.join(directory, entry.name), key))
    else if (entry.isFile()) result[key] = createHash('sha256').update(await readFile(path.join(directory, entry.name))).digest('hex')
  }
  return result
}

async function runInspect(codexHome) {
  const { inspectThread } = await import(path.join(DIST, 'inspection.js'))
  return inspectThread(THREAD_ID, { codexHome, stabilityMs: 50, terminationTimeoutMs: 3000 })
}

// codex-unlock replaces the diagnostic environment, so the override target
// must be self-contained: a shell wrapper with absolute paths that injects the
// config file path.
async function writeWrapper(scratch, barrierScript) {
  const wrapper = path.join(scratch, 'lsof-wrapper.sh')
  const configPath = path.join(scratch, 'barrier-config.json')
  const quote = (value) => `'${value.replaceAll("'", "'\\''")}'`
  await writeFile(wrapper,
    '#!/bin/sh\n' +
    `FIXTURE_CONFIG=${quote(configPath)} ` +
    `exec ${quote(process.execPath)} ${quote(barrierScript)} "$@"\n`)
  await chmod(wrapper, 0o755)
  return { wrapper, configPath }
}

async function setConfig(configPath, settings) {
  await writeFile(configPath, JSON.stringify(settings) + '\n')
}

function record(results, scenario, step, data) {
  results.push({ scenario, step, ...data, t: Date.now() })
}

async function main() {
  if (process.platform !== 'darwin') throw new Error('This Codex-like argv fixture is validated on macOS only')
  const temporaryRoot = process.env.TMPDIR
  if (!temporaryRoot) throw new Error('Supply a new private TMPDIR explicitly')
  { const value = await stat(temporaryRoot); if (!value.isDirectory() || (value.mode & 0o777) !== 0o700 || value.uid !== process.getuid()) throw new Error('Supplied TMPDIR must be a same-user private directory (0700)') }
  const scratch = await mkdtemp(path.join(temporaryRoot, 'cu-i-'))
  await chmod(scratch, 0o700)
  const logFile = path.join(scratch, 'events.jsonl')
  await writeFile(logFile, '', { mode: 0o600 })
  const results = []
  const registry = []
  const homes = []
  const deadline = performance.now() + 30000
  const remaining = () => Math.max(0, deadline - performance.now())
  const begin = async (script, env) => { if (!remaining()) throw new Error('experiment budget exhausted'); return startChild(script, env, { registry, budgetMs: Math.min(2000, remaining()) }) }
  const stop = async (child) => { const outcome = await stopChild(child, Math.min(2000, remaining())); if (outcome.incomplete || outcome.exitCode !== 0) throw new Error(`fixture shutdown incomplete/nonzero: ${child.pid}`); return outcome }
  const makeHome = async (label) => { const value = await createHome(scratch, label); value.before = {}; for (const filename of [value.lockPath, path.join(value.lockDir, '.coordination.lock'), value.transcript]) value.before[path.relative(value.home, filename)] = await snapshotFile(filename); homes.push(value); return value }
  const inspect = async (home) => {
    const wait = Math.min(10000, remaining()); if (!wait) throw new Error('experiment budget exhausted')
    let timer
    try { return await Promise.race([runInspect(home), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('inspection budget exhausted')), wait) })]) } finally { clearTimeout(timer) }
  }
  const { overrideDiagnosticExecutableForTesting } = await import(
    path.join(DIST, 'process.js')
  )
  // The existing test fixture (test/fixtures/codex) acquires flock and looks
  // like a Codex process. The transient (attribution-interleaving/codex) opens
  // the file under coordination but fails to acquire flock. Both are Node
  // scripts named "codex" so lsof reports the same command name.
  // Both are executables named "codex" so lsof reports the same command name,
  // and codex-unlock's isCodex check passes for either. The repo's own
  // test/fixtures/codex is not used here: it only exits on SIGTERM, and this
  // experiment must end every process by stdin EOF.
  const HOLDER_FIXTURE = path.resolve(DIR, 'holder', 'codex')
  const TRANSIENT_FIXTURE = path.resolve(DIR, 'codex')
  const barrierScript = path.resolve(DIR, 'lsof-barrier.mjs')
  const REQUIRE_FROM = path.join(ROOT, 'node_modules', 'fs-ext-extra-prebuilt', 'package.json')
  // Each scenario gets its own home so a previous holder cannot affect it.
  let scenarioIndex = 0
  const { wrapper, configPath } = await writeWrapper(scratch, barrierScript)

  try {
    record(results, 'input', 'hashes', { source: await hashes(DIR), dist: await hashes(DIST) })
    // ---- Scenario A: control (no barrier, no filter) ----
    {
      const { home, lockPath } = await makeHome(`s${++scenarioIndex}`)
      const { child: holder } = await begin(HOLDER_FIXTURE, {
        FIXTURE_LOCK_PATH: lockPath,
        FIXTURE_REQUIRE_FROM: REQUIRE_FROM,
      })
      const inspection = await inspect(home)
      record(results, 'A', 'inspect', {
        classification: inspection.classification,
        safeToUnlock: inspection.safeToUnlock,
        openers: inspection.openers.length,
        ownerPid: inspection.owner?.pid,
        holderPid: holder.pid,
        ownerIsHolder: inspection.owner?.pid === holder.pid,
        blockers: inspection.blockers,
      })
      record(results, 'A', 'stop:holder', await stop(holder))
    }

    // ---- Scenario B: barrier + hidden holder ----
    {
      const { home, lockPath } = await makeHome(`s${++scenarioIndex}`)
      const { child: holder } = await begin(HOLDER_FIXTURE, {
        FIXTURE_LOCK_PATH: lockPath,
        FIXTURE_REQUIRE_FROM: REQUIRE_FROM,
      })
      const socketPath = socketFor(scratch, `s${scenarioIndex}`)
      const { child: transient } = await begin(TRANSIENT_FIXTURE, {
        FIXTURE_LOCK_PATH: lockPath,
        FIXTURE_SOCKET: socketPath,
        FIXTURE_LOG: logFile,
        FIXTURE_REQUIRE_FROM: REQUIRE_FROM,
      })

      await setConfig(configPath, {
        socket: socketPath, log: logFile, barrier: true, hidePid: holder.pid,
      })
      overrideDiagnosticExecutableForTesting('lsof', wrapper)

      const inspection = await inspect(home)
      record(results, 'B', 'inspect', {
        classification: inspection.classification,
        safeToUnlock: inspection.safeToUnlock,
        openers: inspection.openers.length,
        ownerPid: inspection.owner?.pid,
        holderPid: holder.pid,
        transientPid: transient.pid,
        ownerIsTransient: inspection.owner?.pid === transient.pid,
        ownerIsHolder: inspection.owner?.pid === holder.pid,
        blockers: inspection.blockers,
      })

      // If it classified as safeToUnlock with the transient as the owner,
      // that proves the eligible interleaving exists. We do NOT actually
      // call unlock because we don't want to signal the wrong process.
      // We just record that the eligibility check would have passed.
      const events = (await readFile(logFile, 'utf8')).trim().split('\n').filter(Boolean).map((line) => JSON.parse(line))
      const substantiated = events.some((event) => event.role === 'transient' && event.pid === transient.pid && event.event === 'attempt' && event.acquired === false)
        && events.some((event) => event.role === 'lsof-barrier' && event.event === 'barrier_entered' && event.reply === 'inside')
        && events.some((event) => event.event === 'filter' && event.hidePid === holder.pid && event.removed === true)
      if (inspection.safeToUnlock && inspection.owner?.pid === transient.pid && substantiated) {
        record(results, 'B', 'eligible_wrong_target', {
          note: 'inspectThread classified a non-holder transient opener as live_owner',
          wouldSignalPid: transient.pid,
          actualHolderPid: holder.pid,
        })
      }

      overrideDiagnosticExecutableForTesting('lsof', null)

      record(results, 'B', 'stop:transient', await stop(transient))
      record(results, 'B', 'stop:holder', await stop(holder))
    }

    // ---- Scenario C: barrier but no PID filter (both visible) ----
    {
      const { home, lockPath } = await makeHome(`s${++scenarioIndex}`)
      const { child: holder } = await begin(HOLDER_FIXTURE, {
        FIXTURE_LOCK_PATH: lockPath,
        FIXTURE_REQUIRE_FROM: REQUIRE_FROM,
      })
      const socketPath = socketFor(scratch, `s${scenarioIndex}`)
      const { child: transient } = await begin(TRANSIENT_FIXTURE, {
        FIXTURE_LOCK_PATH: lockPath,
        FIXTURE_SOCKET: socketPath,
        FIXTURE_LOG: logFile,
        FIXTURE_REQUIRE_FROM: REQUIRE_FROM,
      })

      await setConfig(configPath, { socket: socketPath, log: logFile, barrier: true })
      overrideDiagnosticExecutableForTesting('lsof', wrapper)

      const inspection = await inspect(home)
      record(results, 'C', 'inspect', {
        classification: inspection.classification,
        safeToUnlock: inspection.safeToUnlock,
        openers: inspection.openers.length,
        ownerPid: inspection.owner?.pid,
        holderPid: holder.pid,
        transientPid: transient.pid,
        blockers: inspection.blockers,
      })

      overrideDiagnosticExecutableForTesting('lsof', null)

      record(results, 'C', 'stop:transient', await stop(transient))
      record(results, 'C', 'stop:holder', await stop(holder))
    }

  } catch (error) {
    record(results, 'error', 'orchestrator', { message: error.message, stack: error.stack, fixturePid: error.fixturePid, fixtureScript: error.fixtureScript, fixtureStderr: error.fixtureStderr })
    process.exitCode = 1
  } finally {
    overrideDiagnosticExecutableForTesting('lsof', null)
    for (const child of registry) { const outcome = await stopChild(child, 2000); record(results, 'cleanup', 'child', { pid: child.pid, ...outcome }); if (outcome.incomplete || outcome.exitCode !== 0) process.exitCode = 1 }
    for (const value of homes) {
      try { const after = {}; for (const filename of [value.lockPath, path.join(value.lockDir, '.coordination.lock'), value.transcript]) after[path.relative(value.home, filename)] = await snapshotFile(filename); const unchanged = JSON.stringify(after) === JSON.stringify(value.before); record(results, 'integrity', path.basename(value.home), { before: value.before, after, unchanged }); if (!unchanged) process.exitCode = 1 }
      catch (error) { record(results, 'integrity', path.basename(value.home), { unchanged: false, error: error.message }); process.exitCode = 1 }
    }
  }

  const output = path.join(scratch, 'results.json')
  await writeFile(output, JSON.stringify(results, null, 2) + '\n')
  log(JSON.stringify({ scratch, output, results }, null, 2))
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main().catch((error) => {
  log(String(error?.stack ?? error))
  process.exitCode = 1
})
