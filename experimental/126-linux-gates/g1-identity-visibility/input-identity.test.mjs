import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { URL } from 'node:url'
import { combinedInputDigest, INPUT_IDENTITY_SCHEMA } from './input-identity.mjs'

const a = 'a'.repeat(64)
const b = 'b'.repeat(64)
const c = 'c'.repeat(64)
const files = [{ path: 'g1/run.mjs', sha256: a }, { path: 'g1/variants.mjs', sha256: b }]
const interpreters = [{ basename: 'node', sha256: a }, { basename: 'python3', sha256: b }]

test('combined input digest changes when either Node or Python bytes change with identical files', () => {
  const original = combinedInputDigest(files, interpreters)
  assert.equal(combinedInputDigest(files, interpreters), original)
  for (const basename of ['node', 'python3']) {
    const changed = interpreters.map((entry) => entry.basename === basename ? { ...entry, sha256: c } : entry)
    assert.notEqual(combinedInputDigest(files, changed), original, basename)
  }
})

test('combined input serialization canonically orders both record domains without mutating them', () => {
  const reversedFiles = [...files].reverse()
  const reversedInterpreters = [...interpreters].reverse()
  const before = JSON.stringify([reversedFiles, reversedInterpreters])
  assert.equal(combinedInputDigest(reversedFiles, reversedInterpreters), combinedInputDigest(files, interpreters))
  assert.equal(JSON.stringify([reversedFiles, reversedInterpreters]), before)
  assert.notEqual(combinedInputDigest([...files, files[0]], interpreters), combinedInputDigest(files, interpreters))
})

test('combined input serialization separates domains and preserves tab/newline record boundaries', () => {
  assert.notEqual(combinedInputDigest([{ path: 'node', sha256: a }], []),
    combinedInputDigest([], [{ basename: 'node', sha256: a }]))
  const split = [{ path: 'first', sha256: a }, { path: 'second', sha256: b }]
  const joined = [{ path: `first\t${a}\nsecond`, sha256: b }]
  const legacy = (entries) => entries.map((entry) => `${entry.path}\t${entry.sha256}\n`).join('')
  assert.equal(legacy(split), legacy(joined))
  assert.notEqual(combinedInputDigest(split, []), combinedInputDigest(joined, []))
})

test('combined input digest refuses unreadable/error markers and malformed records without requiring an optional interpreter', () => {
  for (const sha256 of [undefined, null, '', 'unreadable:ENOENT', 'error:EACCES', 'g'.repeat(64), 'A'.repeat(64), 123]) {
    assert.throws(() => combinedInputDigest([{ path: 'run.mjs', sha256 }], interpreters), /input_identity_record_invalid:path/)
    assert.throws(() => combinedInputDigest(files, [{ basename: 'node', sha256 }]), /input_identity_record_invalid:basename/)
  }
  for (const invalid of [null, [], {}, { path: '', sha256: a }, { path: 123, sha256: a }]) {
    assert.throws(() => combinedInputDigest([invalid], interpreters), /input_identity_record_invalid:path/)
  }
  assert.throws(() => combinedInputDigest(null, interpreters), /input_identity_records_invalid:path/)
  assert.match(combinedInputDigest(files, [{ basename: 'node', sha256: a }]), /^[a-f0-9]{64}$/)
  assert.match(combinedInputDigest(files, []), /^[a-f0-9]{64}$/)
})

test('G1 records the digest schema, fingerprints its helper and retains separate interpreter drift checking', () => {
  assert.equal(INPUT_IDENTITY_SCHEMA, 'codex-unlock-g1-input-identity/2')
  const source = readFileSync(new URL('./run.mjs', import.meta.url), 'utf8')
  assert.ok(source.includes("'input-identity.mjs'"))
  assert.ok(source.includes('schema: INPUT_IDENTITY_SCHEMA'))
  assert.ok(source.includes('combinedSha256: combinedInputDigest(files, interpreters)'))
  assert.ok(source.includes('inputsSchema: identityAtStart.schema'))
  assert.ok(source.includes('JSON.stringify(identityAtEnd.interpreters) !== JSON.stringify(identityAtStart.interpreters)'))
})
