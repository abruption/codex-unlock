#!/usr/bin/env node
// Cross-platform check of the G1 argv predictions against the product's
// pure `reconcileArguments` (#126 research).
//
//   G1_BUILD=<build.mjs output> node argv-check.mjs
//
// It imports only the build's process.js (verified against its manifest
// first) and calls one pure function with each variant's expected kernel
// argv and an equal `ps -o args=` string. No process is inspected or
// signalled. This checks the argv part of the prediction only; real ps/proc
// behaviour is measured by run.mjs on Linux.
import { log } from 'node:console'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { pathToFileURL } from 'node:url'
import { reachableModules, verifyBuild } from '../../126-guard-liveness/f2-linux-nondumpable/build.mjs'
import { expectedArgv, PRODUCT_ARGV_ERROR, VARIANT_ORDER, VARIANTS } from './variants.mjs'

if (!process.env.G1_BUILD) throw new Error('G1_BUILD is required')
const build = fs.realpathSync(process.env.G1_BUILD)
const verified = verifyBuild(build)
if (!verified.ok) throw new Error(`build does not match its manifest: ${verified.faults.join(',')}`)
const dist = path.join(build, 'src', 'dist')
if (reachableModules(dist, ['process.js']).includes('unlock.js')) throw new Error('unlock.js reachable')
const { reconcileArguments } = await import(pathToFileURL(path.join(dist, 'process.js')).href)

// Example paths with the same shape as the run host's.
const paths = { scriptPath: '/srv/research/126-guard-liveness/f2-linux-nondumpable/codex',
  nativePath: '/srv/scratch/codex-126-g1-x/native/codex', nodeExec: '/usr/bin/node',
  nodeFixture: '/srv/research/126-linux-gates/fixtures/node/codex' }
const results = VARIANT_ORDER.map((variant) => {
  const argv = expectedArgv(variant, paths)
  const evidence = reconcileArguments(argv.join(' '), { status: 'present', argv })
  const expectedError = VARIANTS[variant].argvClean ? undefined : PRODUCT_ARGV_ERROR
  return { variant, argv, evidence, ok: evidence.error === expectedError && evidence.isSharedService === false &&
    (expectedError ? evidence.arguments === null : evidence.arguments === argv.join(' ')) }
})
// The product accepts only node/nodejs as an interpreter basename.
const renamedNode = reconcileArguments('/usr/bin/node24 /x/codex', { status: 'present', argv: ['/usr/bin/node24', '/x/codex'] })
results.push({ variant: 'node_renamed_binary', evidence: renamedNode, ok: renamedNode.error === PRODUCT_ARGV_ERROR })
const ok = results.every((r) => r.ok)
log(JSON.stringify({ build: { manifestSha256: verified.manifestSha256, commit: verified.source.commit }, ok, results }, null, 2))
process.exitCode = ok ? 0 : 1
