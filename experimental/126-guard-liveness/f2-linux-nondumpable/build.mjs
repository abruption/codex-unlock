#!/usr/bin/env node
// Trusted research build for F2 inspection (#126 research).
//
//   node build.mjs --repo <local git repo> --commit <rev> [--patch <file>] --out <new dir>
//
// Provenance recorded here is limited to what this script itself did:
// - `commit` and `tree` are resolved by `git rev-parse` in the named local
//   repository, and the source is that repository's `git archive` of the
//   resolved commit. A commit string supplied elsewhere is never trusted.
//   Whether that local repository matches a remote is not checked.
// - The optional patch is applied with `git apply` and recorded by SHA-256.
// - dist files and native addons (*.node under node_modules) are hashed after
//   `npm ci` and `npm run build`.
// verifyBuild later re-hashes the same files. It verifies these dist and
// native-addon bytes, not dependency JavaScript/package metadata or that the
// manifest's source is upstream. A deployed
// native Codex binary is unrelated to this build and remains unverified.
import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath, pathToFileURL, URL } from 'node:url'
import { parseArgs } from 'node:util'
import ts from 'typescript'

export const MANIFEST_SCHEMA = 'codex-unlock-research-build/1'

// Validate the entire CLI before prepareBuild can inspect source paths, create
// output, run git/npm, or hash any bytes. A missing patch value must never
// silently select the unpatched build path.
export function parseBuildArgs(args = process.argv.slice(2)) {
  const { values, tokens } = parseArgs({
    args, strict: true, allowPositionals: false, tokens: true,
    options: {
      repo: { type: 'string' }, commit: { type: 'string' },
      patch: { type: 'string' }, out: { type: 'string' },
    },
  })
  const seen = new Set()
  for (const token of tokens) {
    if (token.kind !== 'option') continue
    if (seen.has(token.name)) throw new Error(`duplicate option: --${token.name}`)
    seen.add(token.name)
    if (!values[token.name].trim()) throw new Error(`--${token.name} requires a nonempty value`)
  }
  for (const name of ['repo', 'commit', 'out']) {
    if (!seen.has(name)) throw new Error(`missing required option: --${name}`)
  }
  return { repo: values.repo, commit: values.commit, patch: values.patch, out: path.resolve(values.out) }
}

const sha256 = (data) => createHash('sha256').update(data).digest('hex')
const fileSha256 = (file) => sha256(fs.readFileSync(file))

// Sorted regular files under `root`. Any other entry type is a fault.
export function hashTree(root, accept = () => true) {
  const files = []
  const faults = []
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
      const full = path.join(dir, entry.name)
      const rel = path.relative(root, full).split(path.sep).join('/')
      if (entry.isDirectory()) walk(full)
      else if (entry.isFile()) { if (accept(rel)) files.push({ path: rel, size: fs.statSync(full).size, sha256: fileSha256(full) }) }
      else if (accept(rel)) faults.push(`unsupported_entry:${rel}`)
    }
  }
  walk(root)
  return { files, faults }
}

export function contentOf(buildDir) {
  const dist = hashTree(path.join(buildDir, 'src', 'dist'))
  const native = hashTree(path.join(buildDir, 'src', 'node_modules'), (rel) => rel.endsWith('.node'))
  return { dist: dist.files, native: native.files, faults: [...dist.faults, ...native.faults] }
}

export function compareContent(expected, actual) {
  const mismatches = []
  for (const key of ['dist', 'native']) {
    const want = new Map(expected[key].map((f) => [f.path, f]))
    const have = new Map(actual[key].map((f) => [f.path, f]))
    for (const [p, f] of want) {
      const g = have.get(p)
      if (!g) mismatches.push(`${key}_missing:${p}`)
      else if (g.sha256 !== f.sha256 || g.size !== f.size) mismatches.push(`${key}_changed:${p}`)
    }
    for (const p of have.keys()) if (!want.has(p)) mismatches.push(`${key}_extra:${p}`)
  }
  return mismatches
}

export function verifyBuild(buildDir) {
  const manifestPath = path.join(buildDir, 'manifest.json')
  const raw = fs.readFileSync(manifestPath)
  const manifest = JSON.parse(raw)
  const faults = []
  if (manifest.schema !== MANIFEST_SCHEMA) faults.push(`schema:${manifest.schema}`)
  if (!/^[0-9a-f]{40}$/.test(manifest.source?.commit ?? '') || !/^[0-9a-f]{40}$/.test(manifest.source?.tree ?? '')) faults.push('source_identity_malformed')
  const same = (file, expected, name) => {
    try { if (fileSha256(path.join(buildDir, file)) !== expected) faults.push(`${name}_changed`) } catch { faults.push(`${name}_unreadable`) }
  }
  same('source.tar', manifest.source?.archiveSha256, 'archive')
  same(path.join('src', 'package-lock.json'), manifest.lockfileSha256, 'lockfile')
  if (manifest.patch?.applied === true) same('source.patch', manifest.patch.sha256, 'patch')
  else if (manifest.patch?.applied !== false || fs.existsSync(path.join(buildDir, 'source.patch'))) faults.push('patch_record_invalid')
  const actual = contentOf(buildDir)
  faults.push(...actual.faults, ...compareContent(manifest, actual))
  if (!actual.dist.length) faults.push('dist_empty')
  return { ok: faults.length === 0, faults, manifestSha256: sha256(raw), source: manifest.source, patch: manifest.patch,
    distFiles: actual.dist.length, nativeFiles: actual.native.length }
}

// Relative static imports/re-exports and literal dynamic imports reachable
// from `entries`, parsed as JavaScript using the existing dev dependency.
// This bounded graph does not resolve nonliteral import expressions, require,
// eval, or package imports; it is not proof of arbitrary runtime reachability.
export function reachableModules(dist, entries) {
  const root = fs.realpathSync(dist)
  if (!fs.statSync(root).isDirectory()) throw new Error('module_root_not_directory')
  const seen = new Set()
  const pending = entries.map((entry) => path.resolve(root, entry))
  while (pending.length) {
    const file = fs.realpathSync(pending.pop())
    const relative = path.relative(root, file)
    if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) throw new Error('module_outside_dist')
    if (!fs.statSync(file).isFile()) throw new Error('module_not_regular_file')
    const rel = relative.split(path.sep).join('/')
    if (seen.has(rel)) continue
    seen.add(rel)
    const text = fs.readFileSync(file, 'utf8')
    const source = ts.createSourceFile(rel, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS)
    // Do not treat a partially recovered syntax tree as a complete graph.
    if (source.parseDiagnostics.length) throw new Error(`module_parse_failed:${rel}`)
    const visit = (node) => {
      let specifier
      if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) specifier = node.moduleSpecifier
      else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) specifier = node.arguments[0]
      if (specifier && ts.isStringLiteralLike(specifier)) {
        if (/^\.{1,2}\//.test(specifier.text)) {
          // Match ESM URL decoding and canonical filesystem identity, including
          // ../dist aliases, percent escapes, fragments and in-root symlinks.
          pending.push(fileURLToPath(new URL(specifier.text, pathToFileURL(file))))
        } else if (!specifier.text.startsWith('node:') && (path.isAbsolute(specifier.text) ||
          /^[a-z][a-z0-9+.-]*:/i.test(specifier.text) || specifier.text.startsWith('\\\\'))) {
          // Absolute paths and file:/other URL aliases are not bare packages.
          throw new Error('module_unsupported_absolute_or_url_import')
        }
      }
      ts.forEachChild(node, visit)
    }
    visit(source)
  }
  return [...seen].sort()
}

function run(command, args, cwd, options = {}) {
  const result = spawnSync(command, args, { cwd, encoding: options.encoding ?? 'utf8', timeout: options.timeout ?? 600000,
    maxBuffer: 1 << 28, stdio: ['ignore', 'pipe', 'pipe'] })
  if (result.status !== 0) throw new Error(`${command} ${args.join(' ')} failed: ${result.status} ${result.signal ?? ''} ${String(result.stderr).slice(0, 2000)}`)
  return result.stdout
}

export function prepareBuild({ repo, commit, patch, out }) {
  if (fs.existsSync(out)) throw new Error(`output exists: ${out}`)
  fs.mkdirSync(out, { mode: 0o700 })
  const repoReal = fs.realpathSync(repo)
  const resolved = run('git', ['-C', repoReal, 'rev-parse', '--verify', `${commit}^{commit}`], out).trim()
  const tree = run('git', ['-C', repoReal, 'rev-parse', '--verify', `${resolved}^{tree}`], out).trim()
  const archive = run('git', ['-C', repoReal, 'archive', '--format=tar', resolved], out, { encoding: 'buffer' })
  fs.writeFileSync(path.join(out, 'source.tar'), archive, { flag: 'wx', mode: 0o600 })
  const src = path.join(out, 'src')
  fs.mkdirSync(src, { mode: 0o700 })
  run('tar', ['-xf', path.join(out, 'source.tar'), '-C', src], out)
  let patchRecord = { applied: false }
  if (patch) {
    const copy = path.join(out, 'source.patch')
    fs.copyFileSync(patch, copy, fs.constants.COPYFILE_EXCL)
    run('git', ['apply', '--check', copy], src)
    run('git', ['apply', copy], src)
    patchRecord = { applied: true, sha256: fileSha256(copy) }
  }
  run('npm', ['ci', '--no-audit', '--no-fund'], src)
  run('npm', ['run', 'build'], src)
  const content = contentOf(out)
  if (content.faults.length) throw new Error(`unsupported build entries: ${content.faults.join(',')}`)
  const manifest = {
    schema: MANIFEST_SCHEMA,
    source: { repo: repoReal, commit: resolved, tree, archiveSha256: sha256(archive),
      resolvedBy: 'git rev-parse and git archive in the named local repository, by build.mjs' },
    patch: patchRecord,
    lockfileSha256: fileSha256(path.join(src, 'package-lock.json')),
    toolchain: { node: process.version, npm: run('npm', ['--version'], src).trim(), platform: process.platform, arch: process.arch },
    dist: content.dist,
    native: content.native,
    builtAt: new Date().toISOString(),
  }
  fs.writeFileSync(path.join(out, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n', { flag: 'wx', mode: 0o600 })
  return verifyBuild(out)
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const options = parseBuildArgs()
  const result = prepareBuild(options)
  process.stdout.write(JSON.stringify(result, null, 2) + '\n')
  process.exitCode = result.ok ? 0 : 1
}
