import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { test } from 'node:test'
import { freshPrivateDir } from '../lib/common.mjs'
import { MANIFEST_SCHEMA, contentOf, reachableModules, verifyBuild } from './build.mjs'

const sha = (data) => createHash('sha256').update(data).digest('hex')

// A synthetic build tree with a manifest written the way build.mjs writes it.
function fakeBuild({ patch = false } = {}) {
  const dir = freshPrivateDir('126-build-test')
  fs.mkdirSync(path.join(dir, 'src', 'dist'), { recursive: true })
  fs.mkdirSync(path.join(dir, 'src', 'node_modules', 'addon', 'build'), { recursive: true })
  fs.writeFileSync(path.join(dir, 'src', 'dist', 'a.js'), "import './b.js'\n")
  fs.writeFileSync(path.join(dir, 'src', 'dist', 'b.js'), 'export {}\n')
  fs.writeFileSync(path.join(dir, 'src', 'node_modules', 'addon', 'build', 'x.node'), 'native')
  fs.writeFileSync(path.join(dir, 'src', 'node_modules', 'addon', 'index.js'), 'ignored')
  fs.writeFileSync(path.join(dir, 'src', 'package-lock.json'), '{}')
  fs.writeFileSync(path.join(dir, 'source.tar'), 'tar')
  if (patch) fs.writeFileSync(path.join(dir, 'source.patch'), 'patch')
  const content = contentOf(dir)
  fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify({
    schema: MANIFEST_SCHEMA, source: { commit: 'a'.repeat(40), tree: 'b'.repeat(40), archiveSha256: sha('tar') },
    patch: patch ? { applied: true, sha256: sha('patch') } : { applied: false },
    lockfileSha256: sha('{}'), dist: content.dist, native: content.native,
  }))
  return dir
}

test('verifyBuild accepts an unchanged tree and lists only *.node natives', () => {
  const dir = fakeBuild({ patch: true })
  try {
    const r = verifyBuild(dir)
    assert.deepEqual(r.faults, [])
    assert.equal(r.distFiles, 2)
    assert.equal(r.nativeFiles, 1)
  } finally { fs.rmSync(dir, { recursive: true }) }
})

test('verifyBuild refuses changed, extra, missing and unrecorded content', () => {
  const dir = fakeBuild()
  try {
    fs.writeFileSync(path.join(dir, 'src', 'dist', 'b.js'), 'export const x = 1\n')
    fs.writeFileSync(path.join(dir, 'src', 'dist', 'c.js'), '')
    fs.rmSync(path.join(dir, 'src', 'node_modules', 'addon', 'build', 'x.node'))
    fs.writeFileSync(path.join(dir, 'source.patch'), 'unrecorded')
    fs.writeFileSync(path.join(dir, 'src', 'package-lock.json'), '{"changed":1}')
    fs.symlinkSync('a.js', path.join(dir, 'src', 'dist', 'link.js'))
    const r = verifyBuild(dir)
    for (const fault of ['dist_changed:b.js', 'dist_extra:c.js', 'native_missing:addon/build/x.node', 'patch_record_invalid',
      'lockfile_changed', 'unsupported_entry:link.js']) assert.ok(r.faults.includes(fault), `${fault} in ${r.faults}`)
    assert.equal(r.ok, false)
  } finally { fs.rmSync(dir, { recursive: true }) }
})

test('verifyBuild refuses a malformed source identity', () => {
  const dir = fakeBuild()
  try {
    const file = path.join(dir, 'manifest.json')
    const m = JSON.parse(fs.readFileSync(file, 'utf8'))
    m.source.commit = 'b483cd5'
    fs.writeFileSync(file, JSON.stringify(m))
    assert.ok(verifyBuild(dir).faults.includes('source_identity_malformed'))
  } finally { fs.rmSync(dir, { recursive: true }) }
})

test('import graph follows static and literal dynamic relative imports', () => {
  const dir = freshPrivateDir('126-graph-test')
  try {
    fs.writeFileSync(path.join(dir, 'entry.js'), "import { a } from './a.js'\nconst m = await import('./sub/b.js')\nimport 'node:fs'\n")
    fs.writeFileSync(path.join(dir, 'a.js'), 'export const a = 1\n')
    fs.mkdirSync(path.join(dir, 'sub'))
    fs.writeFileSync(path.join(dir, 'sub', 'b.js'), "export * from '../unlock.js'\n")
    fs.writeFileSync(path.join(dir, 'unlock.js'), 'export {}\n')
    assert.deepEqual(reachableModules(dir, ['entry.js']), ['a.js', 'entry.js', 'sub/b.js', 'unlock.js'])
    assert.deepEqual(reachableModules(dir, ['a.js']), ['a.js'])
  } finally { fs.rmSync(dir, { recursive: true }) }
})
