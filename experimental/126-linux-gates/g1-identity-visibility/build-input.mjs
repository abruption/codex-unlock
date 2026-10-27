// Keep the source pin and startup manifest binding on the copied bytes used
// by every G1 build-code consumer, rather than on a mutable input directory.
import path from 'node:path'
import { createBuildSnapshot } from '../../126-guard-liveness/f2-linux-nondumpable/build-snapshot.mjs'
import { assertPinnedUnpatchedBuild } from './variants.mjs'

export function createPinnedBuildSnapshot(build, expectedManifestSha256) {
  const snapshot = createBuildSnapshot(build, expectedManifestSha256)
  if (!snapshot.verified.ok) throw new Error(`G1_snapshot_unverified:${path.basename(snapshot.directory)}:${snapshot.verified.faults.join(',')}`)
  assertPinnedUnpatchedBuild(snapshot.verified)
  return snapshot
}
