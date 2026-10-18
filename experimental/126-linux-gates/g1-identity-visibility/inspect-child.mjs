#!/usr/bin/env node
// G1 product-inspection child (#126 research). Run only by run.mjs through
// ../../126-guard-liveness/lib/isolated-observer.mjs, never in the runner.
//
// Usage: node inspect-child.mjs BUILD MANIFEST_SHA256 PID FD LOCK_PATH CODEX_HOME THREAD_ID CONTROL_PATH
//
// BUILD is a directory made by ../../126-guard-liveness/f2-linux-nondumpable/build.mjs.
// It is re-hashed against its manifest before import, the manifest's own
// SHA-256 must equal MANIFEST_SHA256 (the runner's value, taken before any
// holder starts), and the static import graph of the imported modules must
// not reach unlock.js. Hashing covers dist/ and native addons only, not
// dependency JavaScript or package metadata.
//
// Stages beyond F2:
// - `lsof_control`: product `findLockOpeners` on CONTROL_PATH, a regular file
//   nobody opens. Its `error` is the host's lsof stderr independent of the
//   holder, which classifies the host as `clean` or `warning`.
// - `held_probe`: product `guardedProbeOnce` with no attribution, right
//   before `inspect_thread`. A denial result counts only next to a typed
//   `held` observation with an acquired guard.
// - `identity_direct`: product `inspectProcess` on the holder PID even when
//   lsof did not list it, so identity is measured apart from lsof visibility.
//   The lsof `c` field is passed through only if lsof listed the PID.
//
// Signals: none from this child to the holder, any lock owner or any unlock
// path. Product diagnostics (`lsof`, `ps`) keep the product's own timeout,
// which signals only the timed-out diagnostic's own process group. No native
// file is created or removed. Errors are recorded, never converted.
import path from 'node:path'
import process from 'node:process'
import { pathToFileURL } from 'node:url'
import { StopStages, childStages } from '../../126-guard-liveness/lib/isolated-observer.mjs'
import { reachableModules, verifyBuild } from '../../126-guard-liveness/f2-linux-nondumpable/build.mjs'
import { parseChildFault } from './protocol.mjs'
import { assertPinnedBuildSource } from './variants.mjs'

const [build, expectedManifest, pidText, fdText, lockPath, codexHome, threadId, controlPath] = process.argv.slice(2)
const pid = Number(pidText)
const fd = Number(fdText)
if (!build || !/^[0-9a-f]{64}$/.test(expectedManifest ?? '') || !Number.isSafeInteger(pid) || pid <= 0 || !Number.isSafeInteger(fd) || fd < 0 ||
  !lockPath || !codexHome || !threadId || !controlPath) {
  throw new Error('usage: inspect-child.mjs BUILD MANIFEST_SHA256 PID FD LOCK_PATH CODEX_HOME THREAD_ID CONTROL_PATH')
}
const fault = parseChildFault(process.env.G1_CHILD_FAULT)
const dist = path.join(build, 'src', 'dist')
const ENTRIES = ['linux-attribution.js', 'native-coordination.js', 'lock.js', 'process.js', 'inspection.js']
const plain = (value) => JSON.parse(JSON.stringify(value, (_key, v) => (typeof v === 'bigint' ? `${v}n` : v)))
const stall = (name) => {
  // Injected finite synchronous stall, for validating the parent bound only.
  if (fault === `stall:${name}`) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 15000)
}
const identityRecord = (p) => ({
  pid: p.pid, isCodex: p.isCodex, isSharedService: p.isSharedService, identityComplete: p.identityComplete,
  errors: p.errors, startTicks: p.startTicks ?? null, commandFingerprint: p.commandFingerprint ?? null,
  command: p.command, arguments: p.arguments, lsofCommand: p.lsofCommand,
})

try {
  const c = childStages({ lifetimeMs: 30000 })
  const identity = await c.stage('dist_identity', () => {
    stall('dist_identity')
    const verified = verifyBuild(build)
    assertPinnedBuildSource(verified.source)
    return plain({ ok: verified.ok, faults: verified.faults, manifestSha256: verified.manifestSha256,
      expectedManifestSha256: expectedManifest, manifestMatchesExpected: verified.manifestSha256 === expectedManifest,
      source: verified.source, patch: verified.patch, distFiles: verified.distFiles, nativeFiles: verified.nativeFiles })
  })
  if (identity.result?.ok !== true || identity.result.manifestMatchesExpected !== true) throw new StopStages('build_unverified')
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

  await c.stage('lsof_control', async () => {
    stall('lsof_control')
    const control = await product.findLockOpeners(controlPath)
    return { error: control.error ?? null, processCount: control.processes.length }
  })

  let lsofCommand = null
  await c.stage('openers', async () => {
    stall('openers')
    const openers = await product.inspectLockOpeners(lockPath)
    lsofCommand = openers.processes.find((p) => p.pid === pid)?.lsofCommand ?? null
    return plain({ error: openers.error ?? null, processes: openers.processes.map(identityRecord) })
  })

  await c.stage('identity_direct', async () => {
    stall('identity_direct')
    return plain(identityRecord(await product.inspectProcess({ pid, command: lsofCommand, uid: null })))
  })

  let prepared
  await c.stage('prepare', () => {
    stall('prepare')
    prepared = product.prepareLinuxParticipation(pid, lockPath)
    return plain(prepared)
  })

  await c.stage('guarded_verify', () => {
    // Harness bookkeeping, not a product refusal.
    if (!prepared) return { skipped: 'prepare_failed' }
    stall('guarded_verify')
    return plain(product.guardedProbeOnce(lockPath, product.observeLockFile(lockPath), undefined,
      () => product.verifyLinuxParticipation(lockPath, prepared)))
  })

  await c.stage('held_probe', () => {
    stall('held_probe')
    return plain(product.guardedProbeOnce(lockPath, product.observeLockFile(lockPath)))
  })

  await c.stage('inspect_thread', async () => {
    stall('inspect_thread')
    const r = await product.inspectThread(threadId, { codexHome, stabilityMs: 200, terminationTimeoutMs: 5000 })
    return plain({
      classification: r.classification, safeToUnlock: r.safeToUnlock, blockers: r.blockers, warnings: r.warnings,
      probe: r.lock.probe, owner: r.owner && { pid: r.owner.pid, isCodex: r.owner.isCodex, identityComplete: r.owner.identityComplete,
        errors: r.owner.errors, startTicks: r.owner.startTicks ?? null },
      openers: r.openers.length, transcript: r.transcript.status, ownerLockFiles: r.ownerLockFiles,
    })
  })
  await c.finish()
} catch (error) {
  if (!(error instanceof StopStages)) throw error
  if (!process.exitCode) process.exitCode = 5
  process.stdin.destroy()
}
