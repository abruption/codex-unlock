// Bind each child's rehashed build to the parent's one startup snapshot.
// A coherently replaced build is still drift, even if verifyBuild succeeds.
const isSha256 = (value) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value)

export function manifestBindingFaults(actual, expected) {
  if (!isSha256(expected)) return ['startup_manifest_sha256_invalid']
  if (!isSha256(actual)) return ['child_manifest_sha256_invalid']
  return actual === expected ? [] : ['startup_manifest_sha256_changed']
}

export function bindVerifiedBuild(verified, expected) {
  const faults = [...verified.faults, ...manifestBindingFaults(verified.manifestSha256, expected)]
  return { ...verified, ok: verified.ok === true && faults.length === 0, faults }
}
