// Offline records only: no Windows/native APIs, processes or files.
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { STEP_SCHEMAS } from '../expectations.mjs'
import { unmeasuredReason } from '../lib.mjs'

const fileId = '0000000000000001:00000000000000000000000000000001'
const token = {
  ok: true, pid: 123, integritySid: 'S-1-16-8192', userSid: 'S-1-5-21-123-1001',
  tokenOpened: true, elevationType: 3,
}
const processRecord = {
  ...token, opened: true, state: 'live', image: 'C:\\tools\\codex.exe',
  createFiletime: '132000000000000000',
}

function reason(mode, step, observed) {
  return unmeasuredReason({ step, observed }, mode, null)
}

test('every self/target token requires actual valid elevation-type evidence', () => {
  for (const [mode, step, base] of [
    ['preflight', 'token.self', token], ['observe', 'token.self', token],
    ['observe', 'process.identity', processRecord], ['observe', 'process.sample', processRecord],
    ['observe', 'process.identity_after', processRecord],
  ]) {
    for (const elevationType of [1, 2, 3]) {
      assert.equal(reason(mode, step, { ...base, elevationType }), null, `${mode}:${step}/${elevationType}`)
    }
    for (const elevationType of [undefined, null, 0, 4, -1, 1.5, '2', true]) {
      const observed = { ...base, elevationType }
      if (elevationType === undefined) delete observed.elevationType
      assert.match(reason(mode, step, observed), /^schema_(missing|format):elevationType$/)
    }
  }
})

function rangeRecord() {
  return {
    ok: true, state: 'probed', dirFileIdBefore: fileId, dirFileIdAfter: fileId,
    guardFileId: fileId, guardFileIdAfter: fileId, guardLinks: 1, guardDeletePending: false,
    threadFileIdBefore: fileId, threadFileIdAfter: fileId, threadLinks: 1, threadDeletePending: false,
    guardAcquired: true, guardReleased: true,
    ranges: Object.fromEntries(['rust', 'fsext', 'beyond_fsext', 'tail'].map((name) =>
      [name, { win32: 33, acquired: false, released: null }])),
  }
}

test('only success or lock violation yields measured range state, including the tail', () => {
  for (const name of ['rust', 'fsext', 'beyond_fsext', 'tail']) {
    for (const win32 of [0, 33]) {
      const observed = rangeRecord()
      observed.ranges[name] = { win32, acquired: win32 === 0, released: win32 === 0 ? true : null }
      assert.equal(reason('observe', 'range.probe', observed), null)
    }
    for (const win32 of [1, 2, 3, 5, 32, 50, 87, 995]) {
      const observed = rangeRecord()
      observed.ranges[name] = { win32, acquired: false, released: null }
      assert.notEqual(reason('observe', 'range.probe', observed), null, `${name}/${win32}`)
      assert.equal(STEP_SCHEMAS['observe:range.probe'].invariants.ranges_consistent(observed), false)
    }
  }
})

test('operational share-open failures are unknown rather than measured sharing mismatches', () => {
  for (const [step, access] of [['share.read_rwd', 'read'], ['share.delete_rwd', 'delete']]) {
    for (const win32 of [0, 32]) {
      assert.equal(reason('observe', step, { ok: true, opened: win32 === 0, win32, access, share: 'rwd' }), null)
    }
    for (const win32 of [1, 2, 3, 5, 33, 50, 87, 995]) {
      const observed = { ok: true, opened: false, win32, access, share: 'rwd' }
      assert.notEqual(reason('observe', step, observed), null, `${step}/${win32}`)
      assert.equal(STEP_SCHEMAS[`observe:${step}`].invariants.interpretable_result(observed), false)
    }
  }
})

test('W7 filesystem evidence must satisfy the NTFS environment precondition', () => {
  const base = { ok: true, probePath: 'C:\\temp\\private\\.volume-probe' }
  assert.equal(reason('preflight', 'host.volume', { ...base, fileSystem: 'NTFS' }), null)
  for (const fileSystem of ['ReFS', 'FAT32', 'exFAT', 'ntfs', '', null, undefined]) {
    assert.notEqual(reason('preflight', 'host.volume', { ...base, fileSystem }), null)
  }
})
