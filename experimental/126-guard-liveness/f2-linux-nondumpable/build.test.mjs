import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { test } from 'node:test'
import { fileURLToPath, URL } from 'node:url'
import { freshPrivateDir } from '../lib/common.mjs'
import { MANIFEST_SCHEMA, contentOf, parseBuildArgs, reachableModules, verifyBuild } from './build.mjs'

const sha = (data) => createHash('sha256').update(data).digest('hex')

const requiredArgs = ['--repo', 'local repo', '--commit', 'HEAD', '--out', 'new build']

test('build arguments preserve patched and unpatched invocations and accept explicit equals values', () => {
  const want = { repo: 'local repo', commit: 'HEAD', out: path.resolve('new build'), patch: undefined }
  assert.deepEqual(parseBuildArgs(requiredArgs), want)
  assert.deepEqual(parseBuildArgs([...requiredArgs, '--patch', 'source patch.diff']), { ...want, patch: 'source patch.diff' })
  assert.deepEqual(parseBuildArgs(['--out=new build', '--patch=source patch.diff', '--commit=HEAD', '--repo=local repo']),
    { ...want, patch: 'source patch.diff' })
})

test('build arguments refuse unknown options, duplicates and positional arguments', () => {
  for (const extra of [['--pach', 'file.diff'], ['--unknown'], ['--patch', 'a', '--patch', 'b'],
    ['--repo', 'another'], ['--commit=another'], ['--out=another'], ['extra'], ['--', 'extra'], ['-p', 'patch']]) {
    assert.throws(() => parseBuildArgs([...requiredArgs, ...extra]), undefined, JSON.stringify(extra))
  }
})

test('every build option requires a nonempty value and the three source/output options are mandatory', () => {
  for (const name of ['repo', 'commit', 'out', 'patch']) {
    const at = requiredArgs.indexOf(`--${name}`)
    const without = at < 0 ? [...requiredArgs] : requiredArgs.filter((_arg, index) => index !== at && index !== at + 1)
    // Patch is optional; the other options are required even if all remaining
    // values are present and the source/output paths happen to be usable.
    if (name !== 'patch') assert.throws(() => parseBuildArgs(without), /missing required option/)
    for (const value of ['', '   ']) {
      assert.throws(() => parseBuildArgs([...without, `--${name}`, value]), /requires a nonempty value/)
    }
    assert.throws(() => parseBuildArgs([...without, `--${name}`]))
    assert.throws(() => parseBuildArgs([...without, `--${name}`, '--repo=other']))
  }
})

test('invalid build CLI arguments fail before creating output or accessing the repository', () => {
  const dir = freshPrivateDir('126-build-cli-test')
  try {
    const out = path.join(dir, 'must-not-exist')
    const repo = path.join(dir, 'missing-repository')
    const script = fileURLToPath(new URL('./build.mjs', import.meta.url))
    for (const extra of [['--patch'], ['--pach', 'source.patch'], ['--patch', '--out=other'], ['--out', out]]) {
      const result = spawnSync(process.execPath, [script, '--repo', repo, '--commit', 'HEAD', '--out', out, ...extra],
        { encoding: 'utf8', timeout: 10000 })
      assert.ifError(result.error)
      assert.notEqual(result.status, 0)
      assert.equal(result.stdout, '')
      assert.match(result.stderr, /(?:--patch|--pach|duplicate option: --out)/)
      assert.doesNotMatch(result.stderr, /ENOENT|output exists|npm ci/)
      assert.equal(fs.existsSync(out), false)
    }
  } finally { fs.rmSync(dir, { recursive: true }) }
})

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

test('import graph follows commented static imports, dynamic imports and re-exports', () => {
  const dir = freshPrivateDir('126-graph-comment-test')
  try {
    fs.writeFileSync(path.join(dir, 'unlock.js'), 'export const x = 1\n')
    for (const source of [
      "import /* comment */ './unlock.js'",
      "import /* comment */ { x } from /* comment */ './unlock.js'",
      "const loaded = import(/* comment */ './unlock.js')",
      "export /* comment */ { x } from /* comment */ './unlock.js'",
      "export /* comment */ * from /* comment */ './unlock.js'",
    ]) {
      fs.writeFileSync(path.join(dir, 'entry.js'), source)
      assert.deepEqual(reachableModules(dir, ['entry.js']), ['entry.js', 'unlock.js'], source)
    }
  } finally { fs.rmSync(dir, { recursive: true }) }
})

test('import graph parses multiline expressions, escaped specifiers and template literals', () => {
  const dir = freshPrivateDir('126-graph-literal-test')
  try {
    fs.writeFileSync(path.join(dir, 'entry.js'), [
      String.raw`import /* before specifier */ './quo\'ted.js'`,
      String.raw`const loaded = import(
        /* a multiline gap */
        './un\u006cock.js'
      )`,
      'const template = import(`./template.js`)',
    ].join('\n'))
    fs.writeFileSync(path.join(dir, "quo'ted.js"), 'export {}\n')
    fs.writeFileSync(path.join(dir, 'unlock.js'), 'export {}\n')
    fs.writeFileSync(path.join(dir, 'template.js'), 'export {}\n')
    assert.deepEqual(reachableModules(dir, ['entry.js']), ['entry.js', "quo'ted.js", 'template.js', 'unlock.js'])
  } finally { fs.rmSync(dir, { recursive: true }) }
})

test('import graph ignores import-shaped comments, strings, regular expressions and property calls', () => {
  const dir = freshPrivateDir('126-graph-nonedge-test')
  try {
    fs.writeFileSync(path.join(dir, 'entry.js'), [
      "// import './missing-comment.js'",
      "/* export * from './missing-block.js' */",
      'const text = "import(\'./missing-string.js\')"',
      "const template = `import './missing-template.js'`",
      'const regex = /import(\'missing-regex.js\')/',
      "const obj = { import() {} }; obj.import('./missing-property.js')",
      "import 'node:fs'",
    ].join('\n'))
    assert.deepEqual(reachableModules(dir, ['entry.js']), ['entry.js'])
  } finally { fs.rmSync(dir, { recursive: true }) }
})

test('import graph rejects malformed JavaScript instead of accepting a recovered partial graph', () => {
  const dir = freshPrivateDir('126-graph-invalid-test')
  try {
    fs.writeFileSync(path.join(dir, 'entry.js'), "const value = import(/* unfinished */ './unlock.js'")
    assert.throws(() => reachableModules(dir, ['entry.js']), /module_parse_failed:entry\.js/)
  } finally { fs.rmSync(dir, { recursive: true }) }
})
