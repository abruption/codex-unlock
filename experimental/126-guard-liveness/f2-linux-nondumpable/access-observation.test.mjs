import assert from 'node:assert/strict'
import { test } from 'node:test'
import { validateAccessObservation } from './access-observation.mjs'

const expected = { pid: 123, fd: 4, uid: 1001, kernel: '6.17-test', startTicks: '123456' }
function complete() {
  return {
    pid: expected.pid, fd: expected.fd, observer_uid: expected.uid, kernel: expected.kernel,
    proc_dir_uid: { ok: 1001 }, fd_dir_uid: { ok: 1001 }, fdinfo_dir_uid: { ok: 1001 },
    self_ns_mnt_readlink: { ok: 'mnt:[4026531841]' }, ns_mnt_readlink: { ok: 'mnt:[4026531841]' },
    fd_listdir: { ok: ['0', '1', '2', '4'] }, fd_readlink: { ok: '/tmp/synthetic/thread.lock' },
    fd_stat_matches_lock: { ok: [true, true] }, fdinfo_lock_rows: { ok: ['lock:\t1: FLOCK ADVISORY WRITE 123 00:01:1 0 EOF'] },
    exe_readlink: { ok: '/usr/bin/python3' }, cmdline: { ok: ['python3', '/tmp/synthetic/codex', ''] },
    stat_start_ticks: { ok: expected.startTicks }, status_uid_line: { ok: ['Uid:\t1001\t1001\t1001\t1001'] },
  }
}

test('complete access attempts are collected without asserting permission outcomes', () => {
  assert.deepEqual(validateAccessObservation(complete(), expected), { collected: true, faults: [] })
  const observed = complete()
  observed.fd_stat_matches_lock.ok = [false, false]
  observed.fdinfo_lock_rows.ok = []
  observed.fd_listdir.ok = []
  assert.equal(validateAccessObservation(observed, expected).collected, true)
  for (const name of Object.keys(observed).filter((key) => !['pid', 'fd', 'observer_uid', 'kernel'].includes(key))) {
    observed[name] = { errno: 'EACCES' }
  }
  assert.equal(validateAccessObservation(observed, expected).collected, true)
  observed.fd_readlink = { errno: '1234' }
  assert.equal(validateAccessObservation(observed, expected).collected, true)
})

test('parseable empty, primitive, array and partial observations cannot collect successfully', () => {
  for (const observed of [{}, null, [], true, 1, 'ok', { pid: 123, fd: 4 }]) {
    assert.equal(validateAccessObservation(observed, expected).collected, false)
  }
  for (const name of Object.keys(complete())) {
    const observed = complete()
    delete observed[name]
    assert.equal(validateAccessObservation(observed, expected).collected, false, name)
  }
})

test('PID, FD, observer UID, kernel and successful start ticks bind to runner evidence', () => {
  for (const patch of [{ pid: 124 }, { pid: '123' }, { fd: 5 }, { fd: '4' },
    { observer_uid: 0 }, { kernel: 'other' }, { stat_start_ticks: { ok: '123457' } }]) {
    assert.equal(validateAccessObservation({ ...complete(), ...patch }, expected).collected, false)
  }
  for (const bad of [null, {}, { ...expected, startTicks: null }, { ...expected, pid: 0 }]) {
    assert.equal(validateAccessObservation(complete(), bad).collected, false)
  }
})

test('successful status reads require one complete UID line; errno is a collected attempt', () => {
  const line = 'Uid:\t1001\t1001\t1001\t1001'
  for (const ok of [[], [line, line], ['Uid: 1001'], ['Uid: one two three four'], [null]]) {
    const result = validateAccessObservation({ ...complete(), status_uid_line: { ok } }, expected)
    assert.equal(result.collected, false)
    assert.ok(result.faults.includes('status_uid_line:value_invalid'))
  }
  const missing = complete()
  delete missing.status_uid_line
  assert.equal(validateAccessObservation(missing, expected).collected, false)
  for (const errno of ['EACCES', 'EPERM', 'ENOENT']) {
    assert.equal(validateAccessObservation({ ...complete(), status_uid_line: { errno } }, expected).collected, true)
  }
  // Collection checks shape, not whether permission or user-match hypotheses
  // passed: a different but fully recorded UID tuple remains evidence.
  assert.equal(validateAccessObservation({ ...complete(), status_uid_line: { ok: ['Uid: 2002 2002 2002 2002'] } }, expected).collected, true)
})

test('each access row has one outcome with its actual Python output type', () => {
  for (const row of [{}, [], null, { ok: '/tmp/x', errno: 'EACCES' }, { errno: 13 },
    { errno: '' }, { errno: null }, { errno: 'permission denied' }, { ok: '/tmp/x', extra: true }]) {
    assert.equal(validateAccessObservation({ ...complete(), fd_readlink: row }, expected).collected, false)
  }
  const malformed = {
    proc_dir_uid: '1001', fd_dir_uid: -1, fdinfo_dir_uid: null, self_ns_mnt_readlink: false,
    ns_mnt_readlink: '', fd_listdir: [4], fd_readlink: [], fd_stat_matches_lock: [true],
    fdinfo_lock_rows: ['not a lock row'], exe_readlink: {}, cmdline: [], stat_start_ticks: 123456,
    status_uid_line: ['Uid: invalid'],
  }
  for (const [name, value] of Object.entries(malformed)) {
    assert.equal(validateAccessObservation({ ...complete(), [name]: { ok: value } }, expected).collected, false, name)
  }
  assert.equal(validateAccessObservation({ ...complete(), fd_listdir: { ok: ['4', '4'] } }, expected).collected, false)
  assert.equal(validateAccessObservation({ ...complete(), unexpected: { ok: true } }, expected).collected, false)
})
