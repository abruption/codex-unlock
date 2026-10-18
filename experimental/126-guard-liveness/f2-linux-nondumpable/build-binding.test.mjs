import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { URL } from 'node:url'
import { bindVerifiedBuild, manifestBindingFaults } from './build-binding.mjs'

test('a coherent replacement build fails the pre-import startup binding', () => {
  const startup = 'a'.repeat(64)
  const original = { ok: true, faults: [], manifestSha256: startup, source: { commit: '1'.repeat(40) } }
  assert.equal(bindVerifiedBuild(original, startup).ok, true)
  const replaced = { ok: true, faults: [], manifestSha256: 'b'.repeat(64), source: { commit: '2'.repeat(40) } }
  const checked = bindVerifiedBuild(replaced, startup)
  assert.equal(checked.ok, false)
  assert.deepEqual(checked.faults, ['startup_manifest_sha256_changed'])
  assert.deepEqual(replaced.faults, [])
})

test('missing or malformed startup/child digest and verification faults fail closed', () => {
  const digest = 'a'.repeat(64)
  for (const invalid of [null, undefined, '', 'a', 123, 'A'.repeat(64)]) {
    assert.ok(manifestBindingFaults(digest, invalid).length > 0)
    assert.ok(manifestBindingFaults(invalid, digest).length > 0)
  }
  const result = bindVerifiedBuild({ ok: false, faults: ['dist_changed'], manifestSha256: digest }, digest)
  assert.equal(result.ok, false)
  assert.deepEqual(result.faults, ['dist_changed'])
})

test('the child refuses an unbound identity before its product module-load stage', () => {
  const source = readFileSync(new URL('./inspect-child.mjs', import.meta.url), 'utf8')
  const verification = source.indexOf('bindVerifiedBuild(verifyBuild(build), expectedManifestSha256)')
  const refusal = source.indexOf("if (identity.result?.ok !== true) throw new StopStages('build_unverified')")
  const loading = source.indexOf("c.stage('module_load'")
  assert.ok(verification >= 0 && refusal > verification && loading > refusal)
})
