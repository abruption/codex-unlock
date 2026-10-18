// Synthetic module trees only. No product, native addon or holder is run.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import { createRequire } from 'node:module'
import path from 'node:path'
import process from 'node:process'
import { test } from 'node:test'
import { pathToFileURL, URL } from 'node:url'
import { freshPrivateDir } from '../../126-guard-liveness/lib/common.mjs'
import { contentOf, MANIFEST_SCHEMA, verifyBuild } from '../../126-guard-liveness/f2-linux-nondumpable/build.mjs'
import { createPinnedBuildSnapshot } from './build-input.mjs'
import { PINNED_SOURCE_COMMIT } from './variants.mjs'

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')

function manifest(build, commit = PINNED_SOURCE_COMMIT, patch = { applied: false }) {
  const content = contentOf(build)
  fs.writeFileSync(path.join(build, 'manifest.json'), JSON.stringify({
    schema: MANIFEST_SCHEMA,
    source: { commit, tree: 'b'.repeat(40), archiveSha256: sha256('archive') },
    patch, lockfileSha256: sha256('{}'), dist: content.dist, native: content.native,
  }))
}

function fakeBuild() {
  const build = freshPrivateDir('126-g1-build-input-test')
  const dependency = path.join(build, 'src', 'node_modules', 'fixture-runtime')
  fs.mkdirSync(path.join(build, 'src', 'dist'), { recursive: true })
  fs.mkdirSync(dependency, { recursive: true })
  fs.writeFileSync(path.join(build, 'src', 'package.json'), '{"type":"module"}')
  fs.writeFileSync(path.join(build, 'src', 'package-lock.json'), '{}')
  fs.writeFileSync(path.join(build, 'src', 'dist', 'entry.js'), "import runtime from 'fixture-runtime'; export const value = runtime.value\n")
  fs.writeFileSync(path.join(dependency, 'package.json'), '{"main":"index.cjs"}')
  fs.writeFileSync(path.join(dependency, 'index.cjs'), "module.exports = { value: 'original' }\n")
  fs.writeFileSync(path.join(dependency, 'addon.node'), 'synthetic native bytes, never loaded')
  fs.writeFileSync(path.join(build, 'source.tar'), 'archive')
  manifest(build)
  return build
}

function dispose(directory) {
  const writable = (file) => {
    const stat = fs.lstatSync(file)
    if (stat.isDirectory()) {
      fs.chmodSync(file, 0o700)
      for (const entry of fs.readdirSync(file)) writable(path.join(file, entry))
    } else if (stat.isFile()) fs.chmodSync(file, 0o600)
  }
  writable(directory)
  fs.rmSync(directory, { recursive: true })
}

test('G1 runner, Node dependency, inspector and argv consumer keep copied bytes after coherent input mutation', async () => {
  const build = fakeBuild()
  const copies = []
  try {
    const startup = verifyBuild(build).manifestSha256
    const runner = createPinnedBuildSnapshot(build, startup); copies.push(runner)
    const argv = createPinnedBuildSnapshot(build, startup); copies.push(argv)
    fs.writeFileSync(path.join(build, 'src', 'dist', 'entry.js'), "export const value = 'replacement'\n")
    fs.writeFileSync(path.join(build, 'src', 'node_modules', 'fixture-runtime', 'index.cjs'), "module.exports = { value: 'replacement' }\n")
    fs.writeFileSync(path.join(build, 'src', 'node_modules', 'fixture-runtime', 'addon.node'), 'replacement native bytes')
    manifest(build)
    assert.equal(verifyBuild(build).ok, true)
    assert.notEqual(verifyBuild(build).manifestSha256, startup)
    const inspector = createPinnedBuildSnapshot(runner.build, startup); copies.push(inspector)
    const require = createRequire(path.join(runner.build, 'src', 'package.json'))
    assert.equal(require('fixture-runtime').value, 'original')
    for (const snapshot of [argv, inspector]) {
      assert.equal(snapshot.verified.manifestSha256, startup)
      assert.equal(snapshot.verified.source.commit, PINNED_SOURCE_COMMIT)
      assert.equal((await import(pathToFileURL(path.join(snapshot.dist, 'entry.js')).href)).value, 'original')
    }
  } finally {
    for (const snapshot of copies) dispose(snapshot.directory)
    dispose(build)
  }
})

test('G1 copied-build binding refuses a valid manifest from the wrong source pin', () => {
  const root = freshPrivateDir('126-g1-build-refusal-test')
  const build = fakeBuild()
  const previous = process.env.RESEARCH_TMP_ROOT
  try {
    process.env.RESEARCH_TMP_ROOT = root
    manifest(build, 'f'.repeat(40))
    const startup = verifyBuild(build)
    assert.equal(startup.ok, true)
    assert.throws(() => createPinnedBuildSnapshot(build, startup.manifestSha256), /G1 build source must be/)
    assert.throws(() => createPinnedBuildSnapshot(build, '0'.repeat(64)), /startup_manifest_sha256_changed/)
  } finally {
    if (previous === undefined) delete process.env.RESEARCH_TMP_ROOT
    else process.env.RESEARCH_TMP_ROOT = previous
    dispose(root)
    dispose(build)
  }
})

test('G1 consumer wrapper refuses a coherent correctly pinned patched build before returning an importable snapshot', () => {
  const root = freshPrivateDir('126-g1-patched-build-test')
  const build = fakeBuild()
  const previous = process.env.RESEARCH_TMP_ROOT
  try {
    process.env.RESEARCH_TMP_ROOT = root
    fs.writeFileSync(path.join(build, 'source.patch'), 'synthetic patch')
    manifest(build, PINNED_SOURCE_COMMIT, { applied: true, sha256: sha256('synthetic patch') })
    const startup = verifyBuild(build)
    assert.equal(startup.ok, true)
    assert.equal(startup.source.commit, PINNED_SOURCE_COMMIT)
    assert.equal(startup.patch.applied, true)
    assert.throws(() => createPinnedBuildSnapshot(build, startup.manifestSha256), /explicitly record an unpatched build/)
  } finally {
    if (previous === undefined) delete process.env.RESEARCH_TMP_ROOT
    else process.env.RESEARCH_TMP_ROOT = previous
    dispose(root)
    dispose(build)
  }
})

test('G1 build consumers use pinned snapshots before imports and preserve manifest protocol fields', () => {
  const child = fs.readFileSync(new URL('./inspect-child.mjs', import.meta.url), 'utf8')
  const identity = child.indexOf('snapshot = createPinnedBuildSnapshot(build, expectedManifest)')
  const refusal = child.indexOf("throw new StopStages('build_unverified')")
  const load = child.indexOf("c.stage('module_load'")
  assert.ok(identity >= 0 && identity < refusal && refusal < load)
  assert.ok(child.includes('reachableModules(snapshot.dist, ENTRIES)'))
  assert.ok(child.includes('path.join(snapshot.dist, name)'))
  assert.ok(child.includes('expectedManifestSha256: expectedManifest, manifestMatchesExpected: verified.manifestSha256 === expectedManifest'))
  assert.equal(child.includes("path.join(build, 'src', 'dist')"), false)

  const runner = fs.readFileSync(new URL('./run.mjs', import.meta.url), 'utf8')
  const startupSnapshot = runner.indexOf('createPinnedBuildSnapshot(BUILD, EXPECTED_MANIFEST)')
  assert.ok(startupSnapshot >= 0 && startupSnapshot < runner.indexOf("const out = freshPrivateDir('126-g1')"))
  assert.ok(runner.includes("FIXTURE_REQUIRE_FROM: path.join(runtimeSnapshot.build, 'src', 'package.json')"))
  assert.ok(runner.includes("'inspect-child.mjs'), runtimeSnapshot.build, EXPECTED_MANIFEST"))
  assert.ok(runner.includes('RESEARCH_TMP_ROOT: process.env.RESEARCH_TMP_ROOT'))
  assert.ok(runner.includes('recheck = verifyBuild(BUILD)'))
  for (const file of ['build-input.mjs', 'build-binding.mjs', 'build-snapshot.mjs']) assert.ok(runner.includes(`'${file}'`))

  const argv = fs.readFileSync(new URL('./argv-check.mjs', import.meta.url), 'utf8')
  const argvSnapshot = argv.indexOf('createPinnedBuildSnapshot(build, startup.manifestSha256)')
  assert.ok(argvSnapshot >= 0 && argvSnapshot < argv.indexOf('await import('))
  assert.ok(argv.includes('const dist = snapshot.dist'))
})
