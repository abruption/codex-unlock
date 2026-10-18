#!/usr/bin/env node
// G1 runner: separate argv/executable identity from lsof visibility (#126 research).
//
//   G1_BUILD=<build.mjs output> [G1_VARIANTS=script,argv0,native,node] [G1_CHILD_FAULT=stall:<stage>] \
//     node experimental/126-linux-gates/g1-identity-visibility/run.mjs
//
// Linux only, unprivileged, same real/effective UID. Every holder is a
// SYNTHETIC fixture in a fresh private scratch CODEX_HOME; no real Codex
// process or home is used. For each variant and dumpable value: start the
// holder, check its ready record and its kernel argv against the variant,
// then run inspect-child.mjs in a separate process. Stages are validated by
// protocol.mjs, rows by expectations.mjs.
//
// Provenance: the build manifest SHA-256 is taken once before any holder
// starts. The inspector must report the same value before it imports product
// code, and the runner re-verifies the build after every run (drift fails the
// run). Hashes cover dist/ and native addons only, not dependency JavaScript
// or package metadata; they do not prove upstream identity. The runner also
// records the SHA-256 of every research input file and of the interpreters.
//
// Signals: this runner sends no signal to any holder, inspector, lock owner
// or unlock path. Holders end on stdin EOF or their own lifetime; an
// inspector past its bound gets stdin EOF and is left running, recorded
// `incomplete`. Bounded diagnostic spawnSync calls here (compiler,
// `--version`, `lsof -v`) receive SIGTERM from Node if their bound expires;
// product diagnostics inside the inspector signal only their own timed-out
// process groups.
//
// Exit: 0 only if every run was collected, every prediction matched and every
// variant ran; 2 if collected and matched but a variant was not executed
// (partial); 1 otherwise. Exit 0 is a reproduced cause separation, NOT a
// passing positive control (see `controlPassed`) and not a native Codex
// result. Scratch is always kept; raw evidence stays in the 0600 result file
// and is not printed.
import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { log } from 'node:console'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { performance } from 'node:perf_hooks'
import process from 'node:process'
import { fileURLToPath } from 'node:url'
import { freshPrivateDir, writeNew } from '../../126-guard-liveness/lib/common.mjs'
import { lateExitStatus, processInstance, runIsolated } from '../../126-guard-liveness/lib/isolated-observer.mjs'
import { verifyBuild } from '../../126-guard-liveness/f2-linux-nondumpable/build.mjs'
import { evaluateReport, evaluateRun } from './expectations.mjs'
import { createSupervisor, stopFaults, superviseOnce } from './lifecycle.mjs'
import { parseChildFault, validateG1 } from './protocol.mjs'
import { expectedArgv, parseVariantSelection, VARIANT_ORDER, VARIANTS } from './variants.mjs'

if (process.platform !== 'linux') throw new Error('G1 runs on Linux only')
if (process.getuid() === 0 || process.getuid() !== process.geteuid()) throw new Error('G1 requires an unprivileged same-UID runner')
if (!process.env.G1_BUILD) throw new Error('G1_BUILD (a build.mjs output directory) is required')
const DIR = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.resolve(DIR, '..')
const SHARED = path.resolve(ROOT, '..', '126-guard-liveness')
const SCRIPT_FIXTURE = path.join(SHARED, 'f2-linux-nondumpable', 'codex')
const NODE_FIXTURE = path.join(ROOT, 'fixtures', 'node', 'codex')
const C_SOURCE = path.join(ROOT, 'fixtures', 'codex.c')
const PYTHON = '/usr/bin/python3'
const COMPILERS = ['/usr/bin/cc', '/usr/bin/gcc', '/usr/bin/clang']
const THREAD_ID = '01a089e8-3731-7202-ba68-0f4b0a3b2711'
const INSPECT_STARTUP_MS = 10000
const INSPECT_STAGES_MS = 15000
const HOLDER_LIFETIME_S = 60
const NEEDED_MS = INSPECT_STARTUP_MS + INSPECT_STAGES_MS + 5000
const BUILD = fs.realpathSync(process.env.G1_BUILD)
const CHILD_FAULT = parseChildFault(process.env.G1_CHILD_FAULT)
const SELECTED = parseVariantSelection(process.env.G1_VARIANTS)
const buildCheck = verifyBuild(BUILD)
if (!buildCheck.ok) throw new Error(`G1_BUILD does not match its manifest: ${buildCheck.faults.join(',')}`)
const EXPECTED_MANIFEST = buildCheck.manifestSha256

const sha256 = (data) => createHash('sha256').update(data).digest('hex')
const fileSha = (file) => { try { return sha256(fs.readFileSync(file)) } catch (error) { return `unreadable:${error.code}` } }
const read = (file) => { try { return fs.readFileSync(file, 'utf8').trim() } catch (error) { return `error:${error.code}` } }
const bounded = (command, args, timeout) => {
  const r = spawnSync(command, args, { encoding: 'utf8', timeout, maxBuffer: 1 << 20, stdio: ['ignore', 'pipe', 'pipe'] })
  return { status: r.status, signal: r.signal, error: r.error?.message ?? null, stdout: r.stdout ?? '', stderr: r.stderr ?? '' }
}
// Research inputs, relative to the experimental/ directory, plus interpreters.
const INPUTS = [
  ...['run.mjs', 'inspect-child.mjs', 'protocol.mjs', 'expectations.mjs', 'variants.mjs', 'lifecycle.mjs']
    .map((f) => path.join(DIR, f)),
  NODE_FIXTURE, C_SOURCE, SCRIPT_FIXTURE,
  path.join(SHARED, 'lib', 'common.mjs'), path.join(SHARED, 'lib', 'isolated-observer.mjs'),
  path.join(SHARED, 'f2-linux-nondumpable', 'build.mjs'),
  path.resolve(ROOT, '..', '..', 'package.json'),
]
function inputIdentity() {
  const base = path.resolve(ROOT, '..')
  const files = INPUTS.map((f) => ({ path: path.relative(base, f), sha256: fileSha(f) })).sort((a, b) => (a.path < b.path ? -1 : 1))
  const interpreters = [process.execPath, ...(fs.existsSync(PYTHON) ? [fs.realpathSync(PYTHON)] : [])]
    .map((f) => ({ basename: path.basename(f), sha256: fileSha(f) }))
  return { files, interpreters, combinedSha256: sha256(files.map((f) => `${f.path}\t${f.sha256}\n`).join('')),
    limits: 'covers these research files and interpreter binaries only; not shared libraries, Python stdlib or dependency JavaScript' }
}

const out = freshPrivateDir('126-g1')
const supervisor = createSupervisor()
const failures = []
const incomplete = []
const lateExits = []
const notExecuted = VARIANT_ORDER.filter((v) => !SELECTED.includes(v)).map((variant) => ({ variant, reason: 'not_selected' }))
const lsofVersion = bounded(fs.existsSync('/usr/sbin/lsof') ? '/usr/sbin/lsof' : '/usr/bin/lsof', ['-v'], 5000)
const identityAtStart = inputIdentity()
const report = {
  environment: {
    kernel: os.release(), arch: process.arch, node: process.version, nodeExecBasename: path.basename(process.execPath),
    uid: process.getuid(), ptraceScope: read('/proc/sys/kernel/yama/ptrace_scope'),
    lsofVersion: (lsofVersion.stderr.match(/revision:\s*(\S+)/) ?? [])[1] ?? null,
    lsofVersionCall: { status: lsofVersion.status, signal: lsofVersion.signal, error: lsofVersion.error },
    build: { manifestSha256: EXPECTED_MANIFEST, source: buildCheck.source, patch: buildCheck.patch,
      coverage: 'dist/ and native addons re-hashed; dependency JavaScript and package metadata are not covered' },
    inputs: identityAtStart, childFault: CHILD_FAULT, selected: SELECTED,
  },
  native: null,
  runs: [],
}

// Native fixture: compile on this host, or record not_executed.
let nativeBin = null
if (SELECTED.includes('native')) {
  const compiler = COMPILERS.find((c) => { try { fs.accessSync(c, fs.constants.X_OK); return true } catch { return false } })
  if (!compiler) {
    notExecuted.push({ variant: 'native', reason: 'no_compiler' })
    report.native = { status: 'not_executed', reason: 'no_compiler', searched: COMPILERS }
  } else {
    const dir = path.join(out, 'native')
    fs.mkdirSync(dir, { mode: 0o700 })
    nativeBin = path.join(dir, 'codex')
    const sourceSha256 = fileSha(C_SOURCE)
    const compiled = bounded(compiler, ['-std=c11', '-O1', '-Wall', '-Wextra', '-Werror', '-o', nativeBin, C_SOURCE], 60000)
    const version = bounded(compiler, ['--version'], 5000)
    report.native = { compiler, version: version.stdout.split('\n')[0], versionCall: { status: version.status, signal: version.signal },
      sourceSha256, status: compiled.status, signal: compiled.signal, error: compiled.error, stderr: compiled.stderr.slice(0, 4000) }
    if (compiled.status !== 0 || fileSha(C_SOURCE) !== sourceSha256) {
      failures.push('native_compile_failed')
      notExecuted.push({ variant: 'native', reason: 'compile_failed' })
      nativeBin = null
    } else {
      report.native.binarySha256 = fileSha(nativeBin)
    }
  }
}
if (SELECTED.includes('argv0') && !fs.existsSync(PYTHON)) failures.push('python3_missing_for_argv0')

function holderCommand(variant, env) {
  if (variant === 'script') return [SCRIPT_FIXTURE, [], { env }]
  if (variant === 'argv0') return [PYTHON, [SCRIPT_FIXTURE], { env, argv0: 'codex' }]
  if (variant === 'native') return [nativeBin, [], { env }]
  if (variant === 'node') return [process.execPath, [NODE_FIXTURE], { env: { ...env, FIXTURE_REQUIRE_FROM: path.join(BUILD, 'src', 'package.json') } }]
  throw new Error(variant)
}

// Same parsing as the product's parseProcCommandLine: drop trailing empties.
const procArgv = (pid) => {
  try {
    const argv = fs.readFileSync(`/proc/${pid}/cmdline`).toString('utf8').split('\0')
    while (argv.length > 0 && argv[argv.length - 1] === '') argv.pop()
    return argv
  } catch (error) { return `error:${error.code}` }
}

function validateReady(variant, dumpable) {
  return (ready, handle) => {
    if (ready?.ready !== true || ready.pid !== handle.pid || !Number.isSafeInteger(ready.fd) || ready.fd < 3 ||
      ready.uid !== process.getuid() || ready.euid !== process.getuid() || ready.lifetime_seconds !== HOLDER_LIFETIME_S) return 'fields'
    if (variant === 'node') {
      if (ready.dumpable !== null) return 'node_dumpable_claimed'
    } else if (ready.dumpable !== dumpable) return 'dumpable'
    return null
  }
}

try {
for (const variant of SELECTED) {
  if (notExecuted.some((n) => n.variant === variant)) continue
  for (const dumpable of VARIANTS[variant].dumpables) {
    const home = path.join(out, `home-${variant}-${dumpable}`)
    const lockDir = path.join(home, 'thread-writer-locks')
    const sessions = path.join(home, 'sessions', '2026', '10', '18')
    fs.mkdirSync(lockDir, { recursive: true, mode: 0o700 })
    fs.mkdirSync(sessions, { recursive: true, mode: 0o700 })
    writeNew(path.join(lockDir, '.coordination.lock'), '')
    const lockPath = path.join(lockDir, `${THREAD_ID}.lock`)
    writeNew(lockPath, '')
    const controlPath = path.join(home, 'lsof-control')
    writeNew(controlPath, '')
    writeNew(path.join(sessions, `rollout-2026-10-18T00-00-00-${THREAD_ID}.jsonl`),
      JSON.stringify({ timestamp: '2026-10-18T00:00:00.000Z', type: 'event_msg', payload: { type: 'task_complete' } }) + '\n')
    const run = { variant, requestedDumpable: dumpable, synthetic: true }
    const startedAt = performance.now()
    const env = { PATH: '/usr/bin:/bin', FIXTURE_LOCK_PATH: lockPath, FIXTURE_DUMPABLE: String(dumpable),
      FIXTURE_LIFETIME_SECONDS: String(HOLDER_LIFETIME_S) }
    const [command, args, options] = holderCommand(variant, env)
    const supervised = await superviseOnce(supervisor, {
      command, args, options, readyMs: 5000, stopMs: 5000, validateReady: validateReady(variant, dumpable),
      during: async (ready, handle) => {
        let holderExited = false
        handle.exited.then(() => { holderExited = true })
        run.holderInstanceAtReady = processInstance(ready.pid)
        if (variant === 'node') {
          // Node cannot prctl; infer from /proc/PID/fd ownership (root when non-dumpable).
          run.dumpableInferred = fs.statSync(`/proc/${ready.pid}/fd`).uid === process.getuid() ? 1 : 0
          if (run.dumpableInferred !== dumpable) throw new Error('node fixture dumpability differs')
        }
        run.kernelArgv = procArgv(ready.pid)
        run.expectedArgv = expectedArgv(variant, { scriptPath: SCRIPT_FIXTURE, nativePath: nativeBin, nodeExec: process.execPath, nodeFixture: NODE_FIXTURE })
        if (JSON.stringify(run.kernelArgv) !== JSON.stringify(run.expectedArgv)) throw new Error('kernel argv differs from the variant definition')
        if (performance.now() - startedAt + NEEDED_MS > HOLDER_LIFETIME_S * 1000) throw new Error('holder lifetime insufficient for inspection')
        const inspected = await runIsolated(process.execPath,
          [path.join(DIR, 'inspect-child.mjs'), BUILD, EXPECTED_MANIFEST, String(ready.pid), String(ready.fd), lockPath, home, THREAD_ID, controlPath], {
            startupBudgetMs: INSPECT_STARTUP_MS, budgetMs: INSPECT_STAGES_MS,
            env: { PATH: '/usr/sbin:/usr/bin:/bin', ...(CHILD_FAULT ? { G1_CHILD_FAULT: CHILD_FAULT } : {}) },
          })
        const { lateExit, ...record } = inspected
        run.inspect = record
        run.holderInstanceAfterInspect = processInstance(ready.pid)
        if (inspected.incomplete) {
          incomplete.push({ role: 'inspector', variant, dumpable, phase: inspected.incompletePhase, openStage: inspected.openStage })
          lateExits.push({ label: { variant, dumpable }, instance: inspected.instance, lateExit })
        }
        const protocol = validateG1(inspected, { expectedManifestSha256: EXPECTED_MANIFEST, holderPid: ready.pid })
        run.protocolFaults = protocol.faults
        run.evaluation = evaluateRun({ variant, dumpable, holder: ready, observation: inspected, protocol,
          ticks: { ready: run.holderInstanceAtReady.startTicks, afterInspect: run.holderInstanceAfterInspect.startTicks,
            holderExitedDuringInspection: holderExited } })
        if (!run.evaluation.collected) failures.push(`inspector:${variant}:${dumpable}:not_collected`)
      },
    })
    run.holder = supervised.ready
    run.holderExit = supervised.outcome
    run.holderFaults = supervised.faults
    run.holderError = supervised.error
    run.holderStderr = supervised.stderr ?? ''
    for (const fault of supervised.faults) {
      if (fault.endsWith(':incomplete')) incomplete.push({ role: 'holder', variant, dumpable })
      failures.push(`${variant}:${dumpable}:${fault}`)
    }
    // Build drift between runs fails this run's collection.
    let recheck
    try {
      recheck = verifyBuild(BUILD)
      run.buildRecheck = { ok: recheck.ok, manifestSha256: recheck.manifestSha256 }
    } catch (error) {
      recheck = { ok: false }
      run.buildRecheck = { ok: false, error: String(error?.message ?? error) }
    }
    const finalFaults = [...supervised.faults]
    if (!recheck.ok || recheck.manifestSha256 !== EXPECTED_MANIFEST) {
      failures.push(`${variant}:${dumpable}:build_drift`)
      finalFaults.push('build_drift')
    }
    if (run.evaluation && finalFaults.length) {
      run.evaluation.collected = false
      run.evaluation.collectedFaults.push(...finalFaults.map((fault) => `final:${fault}`))
    }
    report.runs.push(run)
  }
}
} catch (error) {
  failures.push('runner_exception')
  report.runnerError = String(error?.stack ?? error)
} finally {
// Any child not stopped above is stopped once here and its outcome counted.
report.sweep = await supervisor.sweep(5000)
for (const { outcome } of report.sweep) {
  for (const fault of stopFaults('swept', outcome)) {
    if (fault.endsWith(':incomplete')) incomplete.push({ role: 'swept' })
    failures.push(fault)
  }
}
}
report.lateInspectorExits = await lateExitStatus(lateExits, 2000)
for (const late of report.lateInspectorExits) {
  if (late.status !== 'exited') failures.push(`inspector_late_exit_unconfirmed:${late.variant}:${late.dumpable}`)
}
const identityAtEnd = inputIdentity()
if (identityAtEnd.combinedSha256 !== identityAtStart.combinedSha256 ||
  JSON.stringify(identityAtEnd.interpreters) !== JSON.stringify(identityAtStart.interpreters)) failures.push('input_drift')
const collected = failures.length === 0 && incomplete.length === 0
report.expectations = evaluateReport(report.runs.map((r) => r.evaluation).filter(Boolean),
  { selected: SELECTED, notExecuted, expectedManifestSha256: EXPECTED_MANIFEST, collectionValid: collected })
const exitCode = !collected || !report.expectations.predictionsMatched ? 1 : report.expectations.complete ? 0 : 2
Object.assign(report, { collected, failures, incomplete, exitCode })
const resultPath = path.join(out, 'g1-results.json')
const body = JSON.stringify(report, null, 2) + '\n'
writeNew(resultPath, body)
// Sanitized summary: classes, statuses and fault codes; no raw errors, paths or PIDs.
const publicCauses = new Set(['argv_identity', 'instance_unverified', 'owner_hidden', 'lsof_mount_warning',
  'lsof_infrastructure_error', 'held_observation_missing', 'owner_lockset_unavailable'])
log(JSON.stringify({ resultDirectory: path.basename(out), resultSha256: sha256(body), inputsSha256: identityAtStart.combinedSha256, manifestSha256: EXPECTED_MANIFEST,
  exitCode, collected, failureCount: failures.length, incompleteCount: incomplete.length,
  hostClass: report.expectations.hostClass, coverageValid: report.expectations.coverageValid,
  predictionsMatched: report.expectations.predictionsMatched, complete: report.expectations.complete, notExecuted,
  controlPassed: report.expectations.controlPassed, refusalCounted: report.expectations.refusalCounted,
  rows: report.runs.map((r) => ({ v: r.variant, d: r.requestedDumpable, holderFaults: r.holderFaults.length,
    rows: r.evaluation && Object.entries(r.evaluation.rows).map(([id, x]) => `${id}:${x.status}${x.causes.length ? `(${x.causes.map((c) => publicCauses.has(c) ? c : 'unrecognized_cause').join('+')})` : ''}`) })),
}, null, 2))
process.exitCode = exitCode
