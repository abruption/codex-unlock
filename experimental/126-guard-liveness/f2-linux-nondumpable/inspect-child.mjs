#!/usr/bin/env node
// F2 product-inspection child (#126 research). Run only by run.mjs or
// plumbing-smoke.mjs through lib/isolated-observer.mjs, never in the runner's
// own process.
//
// Usage: node inspect-child.mjs BUILD PID FD LOCK_PATH CODEX_HOME THREAD_ID EXPECTED_MANIFEST_SHA256
//
// BUILD is a directory made by build.mjs. Its content is re-hashed against
// its manifest before any product module is imported, and the static import
// graph of the imported modules is checked to exclude unlock.js. Non-literal
// dynamic imports are not covered by that check.
//
// Signals: this child sends no signal to the holder, to any lock owner, or
// through any unlock path. Product diagnostics it calls (`lsof`, `ps`) run
// with the product's own timeout, which sends SIGTERM and then SIGKILL to the
// timed-out diagnostic's own process group. No native file is created or
// removed. A stage error is recorded as observed; nothing here converts an
// error into free or allowed.
import path from 'node:path'
import process from 'node:process'
import { pathToFileURL } from 'node:url'
import { StopStages, childStages } from '../lib/isolated-observer.mjs'
import { reachableModules, verifyBuild } from './build.mjs'
import { parseChildFault } from './protocol.mjs'
import { bindVerifiedBuild, manifestBindingFaults } from './build-binding.mjs'

const [build, pidText, fdText, lockPath, codexHome, threadId, expectedManifestSha256] = process.argv.slice(2)
const pid = Number(pidText)
const fd = Number(fdText)
if (!build || !Number.isSafeInteger(pid) || pid <= 0 || !Number.isSafeInteger(fd) || fd < 0 || !lockPath || !codexHome || !threadId ||
  manifestBindingFaults(expectedManifestSha256, expectedManifestSha256).length > 0) {
  throw new Error('usage: inspect-child.mjs BUILD PID FD LOCK_PATH CODEX_HOME THREAD_ID EXPECTED_MANIFEST_SHA256')
}
const fault = parseChildFault(process.env.F2_CHILD_FAULT)
const dist = path.join(build, 'src', 'dist')
const ENTRIES = ['linux-attribution.js', 'native-coordination.js', 'lock.js', 'process.js', 'inspection.js']
const plain = (value) => JSON.parse(JSON.stringify(value, (_key, v) => (typeof v === 'bigint' ? `${v}n` : v)))
const stall = (name) => {
  // Injected finite synchronous stall, for validating the parent bound only.
  if (fault === `stall:${name}`) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 15000)
}

try {
  const c = childStages({ lifetimeMs: 30000 })
  const identity = await c.stage('dist_identity', () => {
    stall('dist_identity')
    const verified = bindVerifiedBuild(verifyBuild(build), expectedManifestSha256)
    return plain({ ok: verified.ok, faults: verified.faults, manifestSha256: verified.manifestSha256,
      source: verified.source, patch: verified.patch, distFiles: verified.distFiles, nativeFiles: verified.nativeFiles,
      verifiedBy: 'inspect-child re-hash against manifest.json before import' })
  })
  // Never import a build whose content or manifest differs from the parent's
  // startup snapshot, even if its replacement manifest is internally valid.
  if (identity.result?.ok !== true) throw new StopStages('build_unverified')
  let product
  const loaded = await c.stage('module_load', async () => {
    stall('module_load')
    const modules = reachableModules(dist, ENTRIES)
    if (modules.includes('unlock.js')) throw new Error('unlock_reachable')
    const load = (name) => import(pathToFileURL(path.join(dist, name)).href)
    const [attribution, coordination, lock, proc, inspection] = await Promise.all(ENTRIES.map(load))
    product = { ...attribution, ...coordination, ...lock, ...proc, ...inspection }
    return { modules, unlockReachable: false }
  })
  if (loaded.error) throw new StopStages('module_load_failed')

  // Product discovery and identity as the product records it. isCodex is
  // recorded, not asserted: this fixture is `python3 …/codex`, not a native
  // Codex binary.
  await c.stage('openers', async () => {
    stall('openers')
    const openers = await product.inspectLockOpeners(lockPath)
    return plain({ error: openers.error ?? null, processes: openers.processes.map((p) => ({
      pid: p.pid, isCodex: p.isCodex, identityComplete: p.identityComplete, errors: p.errors,
      startTicks: p.startTicks ?? null, commandFingerprint: p.commandFingerprint ?? null, command: p.command, arguments: p.arguments,
    })) })
  })

  let prepared
  await c.stage('prepare', () => {
    stall('prepare')
    prepared = product.prepareLinuxParticipation(pid, lockPath)
    return plain(prepared)
  })

  await c.stage('guarded_verify', () => {
    // Harness bookkeeping: nothing to verify without a preparation. This is
    // not a product refusal.
    if (!prepared) return { skipped: 'prepare_failed' }
    stall('guarded_verify')
    const probe = product.guardedProbeOnce(lockPath, product.observeLockFile(lockPath), undefined,
      () => product.verifyLinuxParticipation(lockPath, prepared))
    return plain(probe)
  })

  await c.stage('inspect_thread', async () => {
    stall('inspect_thread')
    const r = await product.inspectThread(threadId, { codexHome, stabilityMs: 200, terminationTimeoutMs: 5000 })
    return plain({
      classification: r.classification, safeToUnlock: r.safeToUnlock, blockers: r.blockers, warnings: r.warnings,
      probe: r.lock.probe, owner: r.owner && { pid: r.owner.pid, isCodex: r.owner.isCodex, identityComplete: r.owner.identityComplete,
        errors: r.owner.errors, startTicks: r.owner.startTicks ?? null },
      openers: r.openers.length, transcript: r.transcript.status,
    })
  })
  await c.finish()
} catch (error) {
  if (!(error instanceof StopStages)) throw error
  // Boundary stops set 3/4 themselves; a refused build or import is 5.
  if (!process.exitCode) process.exitCode = 5
  process.stdin.destroy()
}
