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
import { fileURLToPath } from 'node:url'

export const MANIFEST_SCHEMA = 'codex-unlock-research-build/1'

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

// Relative static and literal dynamic imports reachable from `entries`.
export function reachableModules(dist, entries) {
  const seen = new Set()
  const pending = [...entries]
  const pattern = /(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+)["'](\.{1,2}\/[^"']+)["']/g
  while (pending.length) {
    const rel = pending.pop()
    if (seen.has(rel)) continue
    seen.add(rel)
    const text = fs.readFileSync(path.join(dist, rel), 'utf8')
    for (const match of text.matchAll(pattern)) {
      pending.push(path.posix.normalize(path.posix.join(path.posix.dirname(rel), match[1])))
    }
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
  const args = process.argv.slice(2)
  const value = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined }
  const repo = value('--repo'); const commit = value('--commit'); const out = value('--out')
  if (!repo || !commit || !out) throw new Error('usage: build.mjs --repo <repo> --commit <rev> [--patch <file>] --out <new dir>')
  const result = prepareBuild({ repo, commit, patch: value('--patch'), out: path.resolve(out) })
  process.stdout.write(JSON.stringify(result, null, 2) + '\n')
  process.exitCode = result.ok ? 0 : 1
}
