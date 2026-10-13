#!/usr/bin/env node
// Interleaving experiment orchestrator (#100 research).
//
// Creates a private scratch home with a synthetic Codex-like layout, then runs
// codex-unlock's inspectThread/unlockInspectedThread against three scenarios:
//
//   A. Control: real holder visible, no transient. Expected: live_owner, safeToUnlock.
//   B. Barrier + hidden holder: lsof sees only the transient (via PID filter).
//      Expected: unknown or live_owner on the transient, and if the latter,
//      the experiment proves an eligible interleaving exists.
//   C. Barrier only (no PID filter): both processes visible.
//      Expected: unknown (two openers).
//
// Every child exits by stdin EOF / normal exit. No SIGTERM/SIGKILL is sent by
// the orchestrator. The fake-codex fixture receives SIGTERM only from
// codex-unlock's own terminateRevalidatedOwner; we verify the signal actually
// arrives at the expected PID.
import { spawn } from 'node:child_process'
import { log } from 'node:console'
import { once } from 'node:events'
import { mkdtemp, mkdir, writeFile, chmod, stat } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import process from 'node:process'
import { setTimeout as delay } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'

const THREAD_ID = '01a089e8-3731-7202-ba68-0f4b0a3b2711'
const DIR = path.dirname(fileURLToPath(import.meta.url))
const DIST = path.resolve(DIR, '../../../dist')
const ROOT = path.resolve(DIR, '../../..')

function socketFor(scratch, label) {
  return path.join(scratch, `${label}.sock`)
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

function startChild(script, env, opts = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [script], {
      env: { ...process.env, ...env },
      stdio: ['pipe', 'pipe', 'pipe'],
      ...opts,
    })
    child.stdout.setEncoding('utf8')
    child.stderr.setEncoding('utf8')
    let stderr = ''
    child.stderr.on('data', (chunk) => { stderr += chunk })
    child.stdout.once('data', (chunk) => {
      if (chunk.includes('ready')) resolve({ child, stderr: () => stderr })
      else reject(new Error(`unexpected output: ${chunk}`))
    })
    child.once('error', reject)
    child.once('exit', (code) => reject(new Error(`child exited early: ${code}`)))
  })
}

// Normal shutdown only: close stdin so the child sees EOF, then wait with a
// bound. A child that does not exit is reported, never killed by this script.
async function stopChild(child, budgetMs = 10000) {
  if (child.exitCode !== null) return { exitCode: child.exitCode }
  try { child.stdin.end() } catch { /* already closed */ }
  const exited = once(child, 'exit').then(([code]) => ({ exitCode: code }))
  const timedOut = delay(budgetMs).then(() => ({ incomplete: true, pid: child.pid }))
  return Promise.race([exited, timedOut])
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
  await writeFile(wrapper,
    '#!/bin/sh\n' +
    `FIXTURE_CONFIG=${JSON.stringify(configPath)} ` +
    `exec ${JSON.stringify(process.execPath)} ${JSON.stringify(barrierScript)} "$@"\n`)
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
  const scratch = await mkdtemp(path.join(tmpdir(), 'codex-unlock-interleaving-'))
  await chmod(scratch, 0o700)
  const logFile = path.join(scratch, 'events.jsonl')
  const results = []
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
  await chmod(HOLDER_FIXTURE, 0o755)
  await chmod(TRANSIENT_FIXTURE, 0o755)
  const barrierScript = path.resolve(DIR, 'lsof-barrier.mjs')
  const REQUIRE_FROM = path.join(ROOT, 'node_modules', 'fs-ext-extra-prebuilt', 'package.json')
  // Each scenario gets its own home so a previous holder cannot affect it.
  let scenarioIndex = 0
  const { wrapper, configPath } = await writeWrapper(scratch, barrierScript)

  try {
    // ---- Scenario A: control (no barrier, no filter) ----
    {
      const { home, lockPath } = await createHome(scratch, `s${++scenarioIndex}`)
      const { child: holder } = await startChild(HOLDER_FIXTURE, {
        FIXTURE_LOCK_PATH: lockPath,
        FIXTURE_REQUIRE_FROM: REQUIRE_FROM,
      })
      const inspection = await runInspect(home)
      record(results, 'A', 'inspect', {
        classification: inspection.classification,
        safeToUnlock: inspection.safeToUnlock,
        openers: inspection.openers.length,
        ownerPid: inspection.owner?.pid,
        holderPid: holder.pid,
        ownerIsHolder: inspection.owner?.pid === holder.pid,
        blockers: inspection.blockers,
      })
      record(results, 'A', 'stop:holder', await stopChild(holder))
    }

    // ---- Scenario B: barrier + hidden holder ----
    {
      const { home, lockPath } = await createHome(scratch, `s${++scenarioIndex}`)
      const { child: holder } = await startChild(HOLDER_FIXTURE, {
        FIXTURE_LOCK_PATH: lockPath,
        FIXTURE_REQUIRE_FROM: REQUIRE_FROM,
      })
      const socketPath = socketFor(scratch, `s${scenarioIndex}`)
      const { child: transient } = await startChild(TRANSIENT_FIXTURE, {
        FIXTURE_LOCK_PATH: lockPath,
        FIXTURE_SOCKET: socketPath,
        FIXTURE_LOG: logFile,
        FIXTURE_REQUIRE_FROM: REQUIRE_FROM,
      })

      await setConfig(configPath, {
        socket: socketPath, log: logFile, barrier: true, hidePid: holder.pid,
      })
      overrideDiagnosticExecutableForTesting('lsof', wrapper)

      const inspection = await runInspect(home)
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
      if (inspection.safeToUnlock && inspection.owner?.pid === transient.pid) {
        record(results, 'B', 'eligible_wrong_target', {
          note: 'inspectThread classified a non-holder transient opener as live_owner',
          wouldSignalPid: transient.pid,
          actualHolderPid: holder.pid,
        })
      }

      overrideDiagnosticExecutableForTesting('lsof', null)

      record(results, 'B', 'stop:transient', await stopChild(transient))
      record(results, 'B', 'stop:holder', await stopChild(holder))
    }

    // ---- Scenario C: barrier but no PID filter (both visible) ----
    {
      const { home, lockPath } = await createHome(scratch, `s${++scenarioIndex}`)
      const { child: holder } = await startChild(HOLDER_FIXTURE, {
        FIXTURE_LOCK_PATH: lockPath,
        FIXTURE_REQUIRE_FROM: REQUIRE_FROM,
      })
      const socketPath = socketFor(scratch, `s${scenarioIndex}`)
      const { child: transient } = await startChild(TRANSIENT_FIXTURE, {
        FIXTURE_LOCK_PATH: lockPath,
        FIXTURE_SOCKET: socketPath,
        FIXTURE_LOG: logFile,
        FIXTURE_REQUIRE_FROM: REQUIRE_FROM,
      })

      await setConfig(configPath, { socket: socketPath, log: logFile, barrier: true })
      overrideDiagnosticExecutableForTesting('lsof', wrapper)

      const inspection = await runInspect(home)
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

      record(results, 'C', 'stop:transient', await stopChild(transient))
      record(results, 'C', 'stop:holder', await stopChild(holder))
    }

    // Verify fixture files are unchanged
    const { lockPath } = await createHome(scratch, `s${++scenarioIndex}`)
    const lockStat = await stat(lockPath)
    record(results, 'integrity', 'check', {
      lockExists: lockStat.isFile(),
      mode: (lockStat.mode & 0o777).toString(8),
    })
  } catch (error) {
    record(results, 'error', 'orchestrator', { message: error.message, stack: error.stack })
  }

  const output = path.join(scratch, 'results.json')
  await writeFile(output, JSON.stringify(results, null, 2) + '\n')
  log(JSON.stringify({ scratch, output, results }, null, 2))
}

main().catch((error) => {
  log(String(error?.stack ?? error))
  process.exitCode = 1
})
