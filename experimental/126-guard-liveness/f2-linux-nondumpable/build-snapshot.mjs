// Isolate the supplied build's later mutations with independent copied bytes.
// The startup manifest authenticates only its existing dist/native/archive/
// lockfile scope. Dependency JavaScript is copied too, not authenticated by
// that manifest. Read-only modes are not OS immutability: the same UID can
// chmod or replace its own snapshot. No adversarial same-UID guarantee exists.
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { freshPrivateDir } from '../lib/common.mjs'
import { bindVerifiedBuild, manifestBindingFaults } from './build-binding.mjs'
import { verifyBuild } from './build.mjs'

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')
const within = (root, file) => {
  const relative = path.relative(root, file)
  return relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative)
}

export function createBuildSnapshot(build, expectedManifestSha256, options = {}) {
  if (manifestBindingFaults(expectedManifestSha256, expectedManifestSha256).length) throw new Error('startup_manifest_sha256_invalid')
  const source = fs.realpathSync(build)
  if (!fs.statSync(source).isDirectory()) throw new Error('snapshot_source_not_directory')
  const directory = freshPrivateDir('126-build-snapshot', options.tmpRoot)
  const copy = path.join(directory, 'build')
  fs.mkdirSync(copy, { mode: 0o700 })
  const files = []
  const directories = [copy]
  const omittedBinDirectories = []
  const copyEntry = (relative) => {
    // npm command shims are never executed by the inspection child. Omit
    // these directories entirely; all other links/special files are refused.
    if (relative === 'src/node_modules/.bin' || relative.endsWith('/node_modules/.bin')) {
      omittedBinDirectories.push(relative)
      return
    }
    const input = path.join(source, relative)
    const output = path.join(copy, relative)
    const stat = fs.lstatSync(input)
    if (stat.isSymbolicLink() || !within(source, fs.realpathSync(input))) throw new Error(`snapshot_unsafe_entry:${relative}`)
    if (stat.isDirectory()) {
      fs.mkdirSync(output, { mode: 0o700 })
      directories.push(output)
      for (const entry of fs.readdirSync(input).sort()) copyEntry(`${relative}/${entry}`)
    } else if (stat.isFile()) {
      const fd = fs.openSync(input, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW)
      try {
        if (!fs.fstatSync(fd).isFile()) throw new Error(`snapshot_unsafe_entry:${relative}`)
        const bytes = fs.readFileSync(fd)
        // New files, never hardlinks or symlinks back to the supplied build.
        fs.writeFileSync(output, bytes, { flag: 'wx', mode: 0o600 })
        files.push({ path: relative, size: bytes.length, sha256: sha256(bytes) })
      } finally { fs.closeSync(fd) }
    } else throw new Error(`snapshot_unsafe_entry:${relative}`)
  }
  try {
    copyEntry('manifest.json')
    copyEntry('source.tar')
    if (fs.lstatSync(path.join(source, 'source.patch'), { throwIfNoEntry: false })) copyEntry('source.patch')
    fs.mkdirSync(path.join(copy, 'src'), { mode: 0o700 })
    directories.push(path.join(copy, 'src'))
    for (const relative of ['src/package.json', 'src/package-lock.json', 'src/dist', 'src/node_modules']) copyEntry(relative)
    const verified = bindVerifiedBuild(verifyBuild(copy), expectedManifestSha256)
    for (const file of files) fs.chmodSync(path.join(copy, file.path), 0o400)
    for (const dir of directories.reverse()) fs.chmodSync(dir, 0o500)
    files.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0)
    return { directory, build: copy, dist: fs.realpathSync(path.join(copy, 'src', 'dist')), verified,
      copiedContentSha256: sha256(JSON.stringify(files)), fileCount: files.length, omittedBinDirectories }
  } catch (cause) {
    // Preserve private partial evidence. The caller cannot fall back to input.
    const error = new Error(`build_snapshot_failed:${path.basename(directory)}:${cause.message}`, { cause })
    error.snapshotDirectory = directory
    throw error
  }
}
