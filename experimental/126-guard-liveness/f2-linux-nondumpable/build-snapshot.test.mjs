import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { test } from 'node:test'
import { pathToFileURL } from 'node:url'
import { freshPrivateDir } from '../lib/common.mjs'
import { MANIFEST_SCHEMA, contentOf, verifyBuild } from './build.mjs'
import { createBuildSnapshot } from './build-snapshot.mjs'

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')

function writeManifest(build) {
  const content = contentOf(build)
  fs.writeFileSync(path.join(build, 'manifest.json'), JSON.stringify({
    schema: MANIFEST_SCHEMA,
    source: { commit: 'a'.repeat(40), tree: 'b'.repeat(40), archiveSha256: sha256(fs.readFileSync(path.join(build, 'source.tar'))) },
    patch: { applied: true, sha256: sha256(fs.readFileSync(path.join(build, 'source.patch'))) },
    lockfileSha256: sha256(fs.readFileSync(path.join(build, 'src', 'package-lock.json'))),
    dist: content.dist, native: content.native,
  }, null, 2) + '\n')
}

function fakeBuild() {
  const build = freshPrivateDir('126-snapshot-input-test')
  const dependency = path.join(build, 'src', 'node_modules', 'fixture-runtime')
  fs.mkdirSync(path.join(build, 'src', 'dist'), { recursive: true })
  fs.mkdirSync(dependency, { recursive: true })
  fs.writeFileSync(path.join(build, 'src', 'package.json'), '{"type":"module"}')
  fs.writeFileSync(path.join(build, 'src', 'package-lock.json'), '{}')
  fs.writeFileSync(path.join(build, 'src', 'dist', 'entry.js'), "import { value } from 'fixture-runtime'; export const result = 'original:' + value\n")
  fs.writeFileSync(path.join(dependency, 'package.json'), '{"type":"module","exports":"./index.js"}')
  fs.writeFileSync(path.join(dependency, 'index.js'), "export const value = 'dependency-original'\n")
  fs.writeFileSync(path.join(dependency, 'addon.node'), 'synthetic native bytes, never loaded')
  fs.mkdirSync(path.join(build, 'src', 'node_modules', '.bin'))
  fs.symlinkSync('../fixture-runtime/index.js', path.join(build, 'src', 'node_modules', '.bin', 'unused'))
  fs.writeFileSync(path.join(build, 'source.tar'), 'archive')
  fs.writeFileSync(path.join(build, 'source.patch'), 'patch')
  fs.writeFileSync(path.join(build, 'unrelated.txt'), 'outside copy scope')
  fs.writeFileSync(path.join(build, 'src', 'unrelated.js'), 'outside copy scope')
  writeManifest(build)
  return build
}

// Tests own these directories, including their intentionally read-only copies.
function dispose(directory) {
  if (!directory) return
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

test('snapshot imports independent dist and runtime dependency bytes after coherent input mutation', async () => {
  const build = fakeBuild()
  let snapshot
  try {
    const startup = verifyBuild(build)
    const manifestBytes = fs.readFileSync(path.join(build, 'manifest.json'))
    snapshot = createBuildSnapshot(build, startup.manifestSha256)
    assert.equal(snapshot.verified.ok, true)
    assert.deepEqual(fs.readFileSync(path.join(snapshot.build, 'manifest.json')), manifestBytes)
    assert.equal(fs.statSync(snapshot.directory).mode & 0o777, 0o700)
    assert.equal(fs.statSync(snapshot.dist).mode & 0o777, 0o500)
    for (const relative of ['manifest.json', 'source.tar', 'source.patch', 'src/package.json', 'src/package-lock.json',
      'src/dist/entry.js', 'src/node_modules/fixture-runtime/index.js', 'src/node_modules/fixture-runtime/addon.node']) {
      const original = fs.statSync(path.join(build, relative))
      const copied = fs.statSync(path.join(snapshot.build, relative))
      assert.equal(copied.mode & 0o777, 0o400)
      assert.equal(copied.nlink, 1)
      assert.ok(copied.dev !== original.dev || copied.ino !== original.ino)
    }
    assert.equal(fs.existsSync(path.join(snapshot.build, 'unrelated.txt')), false)
    assert.equal(fs.existsSync(path.join(snapshot.build, 'src', 'unrelated.js')), false)
    assert.equal(fs.existsSync(path.join(snapshot.build, 'src', 'node_modules', '.bin')), false)
    assert.deepEqual(snapshot.omittedBinDirectories, ['src/node_modules/.bin'])

    // Change input dist, dependency JS/native bytes and its manifest together.
    // This replacement remains internally valid but must not affect imports.
    fs.writeFileSync(path.join(build, 'src', 'dist', 'entry.js'), "export const result = 'replacement'\n")
    fs.writeFileSync(path.join(build, 'src', 'node_modules', 'fixture-runtime', 'index.js'), "export const value = 'dependency-replacement'\n")
    fs.writeFileSync(path.join(build, 'src', 'node_modules', 'fixture-runtime', 'addon.node'), 'replacement native bytes')
    writeManifest(build)
    assert.equal(verifyBuild(build).ok, true)
    assert.notEqual(verifyBuild(build).manifestSha256, startup.manifestSha256)
    assert.equal(verifyBuild(snapshot.build).manifestSha256, startup.manifestSha256)
    const loaded = await import(pathToFileURL(path.join(snapshot.dist, 'entry.js')).href)
    assert.equal(loaded.result, 'original:dependency-original')
    assert.equal(fs.readFileSync(path.join(snapshot.build, 'src', 'node_modules', 'fixture-runtime', 'addon.node'), 'utf8'),
      'synthetic native bytes, never loaded')
  } finally { dispose(snapshot?.directory); dispose(build) }
})

test('a coherent input replacement before copying fails startup-manifest verification', () => {
  const build = fakeBuild()
  let snapshot
  try {
    const startup = verifyBuild(build).manifestSha256
    fs.writeFileSync(path.join(build, 'src', 'dist', 'entry.js'), 'export const replacement = true\n')
    writeManifest(build)
    snapshot = createBuildSnapshot(build, startup)
    assert.equal(snapshot.verified.ok, false)
    assert.ok(snapshot.verified.faults.includes('startup_manifest_sha256_changed'))
    assert.ok(fs.existsSync(snapshot.directory))
  } finally { dispose(snapshot?.directory); dispose(build) }
})

test('snapshot refuses links outside unused npm shims and retains private failed evidence', () => {
  const build = fakeBuild()
  let failedDirectory
  try {
    const startup = verifyBuild(build).manifestSha256
    fs.symlinkSync('entry.js', path.join(build, 'src', 'dist', 'linked.js'))
    assert.throws(() => createBuildSnapshot(build, startup), (error) => {
      failedDirectory = error.snapshotDirectory
      assert.match(error.message, /snapshot_unsafe_entry:src\/dist\/linked\.js/)
      assert.equal(fs.statSync(failedDirectory).mode & 0o777, 0o700)
      return true
    })
  } finally { dispose(failedDirectory); dispose(build) }
})

test('snapshot rehash refuses changed copied content even when manifest bytes still match startup', () => {
  const build = fakeBuild()
  let snapshot
  try {
    const startup = verifyBuild(build).manifestSha256
    fs.writeFileSync(path.join(build, 'src', 'dist', 'entry.js'), 'export const replacement = true\n')
    snapshot = createBuildSnapshot(build, startup)
    assert.equal(snapshot.verified.manifestSha256, startup)
    assert.equal(snapshot.verified.ok, false)
    assert.ok(snapshot.verified.faults.includes('dist_changed:entry.js'))
  } finally { dispose(snapshot?.directory); dispose(build) }
})
