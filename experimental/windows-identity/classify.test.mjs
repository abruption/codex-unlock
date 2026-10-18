// Unit tests with mock observations only. They run on any host and say
// nothing about real Windows behavior; see README for the evidence tiers.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  FAULTS,
  FLATTENED_REMOTE_OPTION_PATTERN,
  MANIFEST,
  SHARED_SERVICE_PATTERN,
  classifyCleanupProbe,
  classifyFileCompare,
  classifyFileObservation,
  classifyOwnerMode,
  classifyProcess,
  classifySecurity,
  evaluateJsonl,
  isValidFiletime,
  samePathName,
} from './classify.mjs'

const here = dirname(fileURLToPath(import.meta.url))

function fileObs(overrides = {}) {
  return {
    ok: true,
    noFollow: true,
    requestedPath: 'C:\\Lab\\home\\thread-writer-locks\\t.lock',
    finalPath: '\\\\?\\C:\\Lab\\home\\thread-writer-locks\\t.lock',
    attributes: 0x20,
    reparseTag: 0,
    volumeSerial: '00112233445566aa',
    fileId: '0102030405060708' + '0000000000000000',
    links: 1,
    deletePending: false,
    directory: false,
    filesystem: 'NTFS',
    legacyIndex: '0807060504030201',
    legacyVolumeSerial: '445566aa',
    ...overrides,
  }
}

const dirObs = (overrides = {}) => fileObs({
  requestedPath: 'C:\\Lab\\home',
  finalPath: '\\\\?\\C:\\Lab\\home',
  attributes: 0x10,
  directory: true,
  ...overrides,
})

function secObs(overrides = {}) {
  return {
    ok: true,
    noFollow: true,
    attributes: 0x20,
    reparseTag: 0,
    tokenUserClass: 'self',
    tokenOwnerClass: 'self',
    ownerClass: 'self',
    daclState: 'present',
    daclProtected: false,
    aces: [{ type: 'allow', sidClass: 'self', mask: 0x1f01ff, flags: 0x10, inherited: true, inheritOnly: false }],
    ...overrides,
  }
}

function ace(sidClass, mask, extra = {}) {
  return { type: 'allow', sidClass, mask, flags: 0, inherited: false, inheritOnly: false, ...extra }
}

const RECORDED = { pid: 4242, createFiletime: '134050000000000001' }

function procObs(overrides = {}) {
  return {
    ok: true,
    handleSource: 'held',
    pid: 4242,
    pidWin32: 0,
    wait: 'timeout',
    createFiletime: '134050000000000001',
    timesWin32: 0,
    sidClass: 'self',
    imageBase: 'cmd.exe',
    commandLine: 'cmd.exe /d /q',
    waitAfter: 'timeout',
    ...overrides,
  }
}

// ---- Mock run builder (shapes follow WinIdentityLab.cs output) -------------

const U = (reason) => ({ state: 'unknown', reason })
const R = (reason) => ({ state: 'refuse', reason })
const MATCH = { state: 'match' }
const SHIFTED = { pid: 4242, createFiletime: '134050000000000002' }
const SELF = { pid: 100, createFiletime: '134040000000000000' }

const builders = {
  'file:home': () => ({ kind: 'file', track: 'W1', expectKind: 'directory', obs: dirObs(), expect: MATCH }),
  'file:lock_dir': () => ({ kind: 'file', track: 'W1', expectKind: 'directory', obs: dirObs(), expect: MATCH }),
  'file:coordination': () => ({ kind: 'file', track: 'W1', expectKind: 'file', obs: fileObs(), expect: MATCH }),
  'file:thread_lock': () => ({ kind: 'file', track: 'W1', expectKind: 'file', obs: fileObs(), expect: MATCH }),
  'file:transcript': () => ({ kind: 'file', track: 'W1', expectKind: 'file', obs: fileObs(), expect: MATCH }),
  'same_handle:before_after': () => ({ kind: 'file_compare', track: 'W1', expectKind: 'file', before: fileObs(), after: fileObs(), expect: MATCH }),
  'case_variant:path': () => ({
    kind: 'file_compare', track: 'W1', expectKind: 'file', before: fileObs(),
    after: fileObs({ requestedPath: 'C:\\Lab\\home\\thread-writer-locks\\T.LOCK' }), expect: MATCH,
  }),
  'path_replacement:file': () => ({
    kind: 'file_compare', track: 'W1', expectKind: 'file', before: fileObs(), after: fileObs({ fileId: 'aa'.repeat(16) }),
    expect: U('identity_changed'),
  }),
  'path_replacement:same_handle': () => ({
    kind: 'file', track: 'W1', expectKind: 'file', obs: fileObs({ finalPath: '\\\\?\\C:\\Lab\\home\\thread-writer-locks\\t.lock.old' }),
    expect: U('path_handle_mismatch'),
  }),
  'parent_replacement:dir': () => ({
    kind: 'file_compare', track: 'W1', expectKind: 'directory', before: dirObs(), after: dirObs({ fileId: 'bb'.repeat(16) }),
    expect: U('identity_changed'),
  }),
  'hard_link:target': () => ({ kind: 'file', track: 'W1', expectKind: 'file', obs: fileObs({ links: 2 }), expect: U('hard_link') }),
  'hard_link:alias': () => ({ kind: 'file', track: 'W1', expectKind: 'file', obs: fileObs({ links: 2 }), expect: U('hard_link') }),
  'junction:nofollow': () => ({
    kind: 'file', track: 'W1', expectKind: 'directory', obs: dirObs({ attributes: 0x410, reparseTag: 0xa0000003 }),
    expect: U('reparse_point'),
  }),
  'sec:junction': () => ({ kind: 'security', track: 'W2', obs: secObs({ attributes: 0x410, reparseTag: 0xa0000003 }), expect: U('reparse_point') }),
  'symlink:file': () => ({
    kind: 'file', track: 'W1', expectKind: 'file', obs: fileObs({ attributes: 0x420, reparseTag: 0xa000000c }),
    expect: U('reparse_point'),
  }),
  'missing:path': () => ({ kind: 'file', track: 'W1', expectKind: 'file', obs: { ok: false, stage: 'open', win32: 2 }, expect: U('open_failed') }),
  'sec:default_owner': () => ({ kind: 'security', track: 'W2', obs: secObs(), expect: MATCH }),
  'sec:owner_administrators': () => ({
    kind: 'security', track: 'W2', obs: secObs({ ownerClass: 'administrators' }), expect: R('owner_not_current_user'),
  }),
  'sec:other_writer_explicit': () => ({
    kind: 'security', track: 'W2', obs: secObs({ aces: [ace('self', 0x1f01ff), ace('builtin_users', 0x120116)] }), expect: R('other_writer'),
  }),
  'sec:other_reader_only': () => ({ kind: 'security', track: 'W2', obs: secObs({ aces: [ace('self', 0x1f01ff), ace('builtin_users', 0x120089)] }), expect: MATCH }),
  'sec:deny_other': () => ({
    kind: 'security', track: 'W2', obs: secObs({ aces: [ace('other:1a2b3c4d', 0x1f01ff, { type: 'deny' }), ace('self', 0x1f01ff)] }), expect: MATCH,
  }),
  'sec:privileged_writers': () => ({
    kind: 'security', track: 'W2', obs: secObs({ aces: [ace('self', 0x1f01ff), ace('administrators', 0x1f01ff), ace('system', 0x1f01ff)] }),
    expect: MATCH,
  }),
  'sec:null_dacl': () => ({ kind: 'security', track: 'W2', obs: secObs({ daclState: 'null', aces: null }), expect: R('null_dacl') }),
  'sec:inherit_everyone_dir': () => ({
    kind: 'security', track: 'W2', obs: secObs({ attributes: 0x10, aces: [ace('self', 0x1f01ff), ace('everyone', 0x120116)] }), expect: R('other_writer'),
  }),
  'sec:inherit_everyone_file': () => ({
    kind: 'security', track: 'W2', obs: secObs({ aces: [ace('everyone', 0x120116, { inherited: true })] }), expect: R('other_writer'),
  }),
  'sec:missing': () => ({ kind: 'security', track: 'W2', obs: { ok: false, stage: 'open', win32: 2 }, expect: U('open_failed') }),
  'proc:self': () => ({
    kind: 'process', track: 'W3', recorded: SELF,
    obs: procObs({ handleSource: 'fresh_open', pid: 100, createFiletime: SELF.createFiletime, imageBase: 'powershell.exe' }),
    expect: { state: 'live_same_user' },
  }),
  'mode:self': () => ({ kind: 'mode', track: 'W3', obs: builders['proc:self']().obs, expect: U('not_codex_image') }),
  'launch:child': () => ({ kind: 'setup', track: 'setup', ok: true, pid: 4242, win32: 0 }),
  'proc:child_live': () => ({ kind: 'process', track: 'W3', recorded: RECORDED, obs: procObs(), expect: { state: 'live_same_user' } }),
  'proc:child_start_mismatch': () => ({ kind: 'process', track: 'W3', recorded: SHIFTED, obs: procObs(), expect: U('identity_changed') }),
  'mode:child': () => ({ kind: 'mode', track: 'W3', obs: procObs(), expect: U('not_codex_image') }),
  'eof:child': () => ({ kind: 'setup', track: 'setup', ok: true, exited: true, exitCode: 0, win32: 0 }),
  'proc:child_after_exit': () => ({
    kind: 'process', track: 'W3', recorded: RECORDED, obs: procObs({ wait: 'signaled', waitAfter: 'signaled' }), expect: { state: 'exited' },
  }),
  'proc:child_fresh_open_while_held': () => ({
    kind: 'process', track: 'W3', recorded: RECORDED, obs: procObs({ handleSource: 'fresh_open', wait: 'signaled', waitAfter: 'signaled' }),
    expect: { state: 'exited' },
  }),
  'proc:fresh_open_after_release': () => ({ kind: 'process', track: 'W3', recorded: RECORDED, obs: { ok: false, stage: 'open_process', win32: 87 } }),
  'proc:pid_reuse': () => ({
    kind: 'process', track: 'W3', recorded: RECORDED, attempts: 3,
    obs: procObs({ handleSource: 'fresh_open', createFiletime: '134050000000999999', wait: 'signaled', waitAfter: 'signaled' }),
    expect: U('identity_changed'),
  }),
  'reuse:children': () => ({ kind: 'setup', track: 'setup', ok: true, attempts: 3, abnormalExits: 0, unconfirmedExit: false, win32: 0 }),
  'cleanup:replaced_root': () => ({
    kind: 'cleanup_probe', track: 'cleanup',
    obs: { ok: true, preserved: true, removed: 0, reason: 'root_identity_changed', sentinelIntact: true, originalIntact: true },
    expect: { state: 'preserved' },
  }),
  'cleanup:replaced_parent': () => ({
    kind: 'cleanup_probe', track: 'cleanup',
    obs: { ok: true, preserved: true, removed: 0, reason: 'entry_identity_changed:dir', sentinelIntact: true, originalIntact: true },
    expect: { state: 'preserved' },
  }),
}

function build(name) {
  if (builders[name]) return { case: name, ...builders[name](), safeToUnlock: false }
  if (name.startsWith('sec:')) return { case: name, kind: 'security', track: 'W2', obs: secObs(), expect: MATCH, safeToUnlock: false }
  return { case: name, kind: 'setup', track: 'setup', ok: true, win32: 0, safeToUnlock: false }
}

const ENV = { kind: 'environment', case: 'environment', track: 'env', os: 'Microsoft Windows NT 10.0.20348.0', clr: '4.0.30319.42000',
  is64BitProcess: true, integrityRid: '12288', filesystem: 'NTFS', tokenOwnerClass: 'self', fault: null,
  budgets: { waitMs: 15000, childWaitMs: 15000, reuseAttempts: 256, reuseMs: 60000 }, safeToUnlock: false }
const CLEAN = { kind: 'cleanup', case: 'cleanup', track: 'cleanup', ok: true, preserved: false, registered: 60, removed: 60, reason: null, childrenStillRunning: 0, safeToUnlock: false }

function mockRun({ fault = null, edit = (body) => body, cleanup = {} } = {}) {
  let names = MANIFEST.slice(1, -2).map((item) => item.case)
  const spec = fault ? FAULTS[fault] : null
  if (spec?.stopAfter) names = names.slice(0, names.indexOf(spec.stopAfter) + 1)
  if (spec?.omit) names = names.filter((name) => !spec.omit.has(name))
  let body = names.map(build)
  if (spec?.failure) {
    const failed = body.find((record) => record.case === spec.failure.case)
    Object.assign(failed, { ok: false, exited: spec.failure.exited, exitCode: spec.failure.exitCode })
  }
  if (spec?.suiteError) {
    body.push({ kind: 'suite_error', case: 'suite_error', track: 'setup', fault, message: `InvalidOperationException: fault injected: ${fault}`, safeToUnlock: false })
  }
  body = edit(body)
  const records = [{ ...ENV, fault, budgets: { ...ENV.budgets, childWaitMs: fault === 'child_ignores_eof' ? 2000 : 15000 } }, ...body]
  records.push({ kind: 'suite_end', case: 'suite_end', track: 'setup', emitted: records.length, safeToUnlock: false })
  const cleanupRecord = spec && !spec.cleanupOk
    ? { ...CLEAN, ok: false, preserved: true, removed: 0, reason: 'children_running', childrenStillRunning: 1 }
    : { ...CLEAN }
  records.push({ ...cleanupRecord, ...cleanup })
  return records.map((record) => JSON.stringify(record)).join('\n') + '\n'
}

const replace = (name, patch) => (body) => body.map((record) => record.case === name ? { ...record, ...patch } : record)

// ---- W1 ---------------------------------------------------------------------

test('W1 plain file through a no-follow handle matches on the 128-bit identity', () => {
  const result = classifyFileObservation(fileObs(), { kind: 'file' })
  assert.equal(result.state, 'match')
  assert.equal(result.identity, '00112233445566aa:01020304050607080000000000000000')
  assert.equal(result.safeToUnlock, false)
})

test('W1 missing, denied or partial evidence is unknown', () => {
  assert.equal(classifyFileObservation(null).reason, 'missing_observation')
  assert.deepEqual(
    classifyFileObservation({ ok: false, stage: 'open', win32: 5 }),
    { state: 'unknown', reason: 'open_failed', win32: 5, safeToUnlock: false },
  )
  assert.equal(classifyFileObservation({ ok: false, stage: 'file_id', win32: 87 }).reason, 'file_id_failed')
  assert.equal(classifyFileObservation({ ok: false, stage: 'volume_information', win32: 1 }).reason, 'volume_information_failed')
  assert.equal(classifyFileObservation({ ok: false, stage: '../x' }).reason, 'observation_failed')
  assert.equal(classifyFileObservation(fileObs({ noFollow: false })).reason, 'follow_policy')
  assert.equal(classifyFileObservation(fileObs({ attributes: null })).reason, 'attributes_missing')
  assert.equal(classifyFileObservation(fileObs({ links: undefined })).reason, 'standard_info_missing')
  assert.equal(classifyFileObservation(fileObs({ deletePending: true })).reason, 'delete_pending')
  assert.equal(classifyFileObservation(fileObs({ finalPath: null })).reason, 'path_handle_mismatch')
  for (const filesystem of [null, undefined, '', 7]) {
    assert.equal(classifyFileObservation(fileObs({ filesystem })).reason, 'filesystem_missing')
  }
})

test('W1 the 64-bit legacy index is never a fallback identity', () => {
  for (const fileId of [undefined, null, '', '00'.repeat(16), 'ff'.repeat(16), '0102030405060708']) {
    const result = classifyFileObservation(fileObs({ fileId }))
    assert.equal(result.state, 'unknown')
    assert.equal(result.reason, 'file_id_128_missing')
  }
  // ReFS-shaped identifiers that share the low 64 bits stay distinct.
  const low = '0102030405060708'
  const a = classifyFileObservation(fileObs({ fileId: low + '0000000000000001', legacyIndex: '0807060504030201' }))
  const b = classifyFileObservation(fileObs({ fileId: low + '0000000000000002', legacyIndex: '0807060504030201' }))
  assert.equal(a.state, 'match')
  assert.notEqual(a.identity, b.identity)
  assert.equal(
    classifyFileCompare(fileObs({ fileId: low + '0000000000000001' }), fileObs({ fileId: low + '0000000000000002' })).reason,
    'identity_changed',
  )
})

test('W1 reparse points are unknown whether flagged by attribute or tag', () => {
  assert.equal(classifyFileObservation(fileObs({ attributes: 0x410, directory: true })).reason, 'reparse_point')
  assert.equal(classifyFileObservation(fileObs({ reparseTag: 0xa0000003 })).reason, 'reparse_point')
  assert.equal(classifyFileObservation(fileObs({ attributes: 0x420, reparseTag: 0xa000000c })).reason, 'reparse_point')
})

test('W1 hard links and kind conflicts are unknown', () => {
  assert.deepEqual(classifyFileObservation(fileObs({ links: 2 })), {
    state: 'unknown', reason: 'hard_link', links: 2, safeToUnlock: false,
  })
  assert.equal(classifyFileObservation(fileObs({ directory: true })).reason, 'directory_flag_conflict')
  assert.equal(classifyFileObservation(fileObs(), { kind: 'directory' }).reason, 'kind_mismatch')
  assert.equal(classifyFileObservation(dirObs(), { kind: 'directory' }).state, 'match')
  assert.equal(classifyFileObservation(dirObs(), { kind: 'file' }).reason, 'kind_mismatch')
})

test('W1 compare-before and compare-after are bound to one requested path', () => {
  assert.equal(classifyFileCompare(fileObs(), fileObs(), { kind: 'file' }).state, 'match')
  assert.equal(classifyFileCompare(fileObs(), fileObs({ fileId: 'aa'.repeat(16) })).reason, 'identity_changed')
  assert.equal(classifyFileCompare(fileObs(), fileObs({ volumeSerial: 'ffeeddccbbaa9988' })).reason, 'identity_changed')
  const renamedUnderHandle = fileObs({ finalPath: '\\\\?\\C:\\Lab\\home\\thread-writer-locks\\t.lock.old' })
  assert.deepEqual(classifyFileCompare(fileObs(), renamedUnderHandle), {
    state: 'unknown', reason: 'path_handle_mismatch', side: 'after', safeToUnlock: false,
  })
  assert.equal(classifyFileCompare(fileObs({ links: 2 }), fileObs()).side, 'before')
  assert.equal(classifyFileCompare(fileObs(), fileObs({ filesystem: 'ReFS' })).reason, 'filesystem_changed')
  // A self-consistent observation of a different path is not the same subject.
  const other = fileObs({ requestedPath: 'C:\\Lab\\other.lock', finalPath: '\\\\?\\C:\\Lab\\other.lock' })
  assert.equal(classifyFileCompare(fileObs(), other).reason, 'requested_path_mismatch')
  // Case-only variants are the same path.
  const upper = fileObs({ requestedPath: 'C:\\LAB\\HOME\\thread-writer-locks\\T.LOCK' })
  assert.equal(classifyFileCompare(fileObs(), upper).state, 'match')
})

test('W1 path agreement requires absolute DOS or UNC forms', () => {
  assert.ok(samePathName('C:\\Lab\\T.LOCK', '\\\\?\\C:\\Lab\\t.lock'))
  assert.ok(samePathName('\\\\server\\share\\Lab\\t.lock', '\\\\?\\UNC\\server\\share\\Lab\\t.lock'))
  assert.ok(samePathName('C:\\Lab\\dir\\', '\\\\?\\C:\\Lab\\dir'))
  assert.ok(samePathName('C:\\', 'C:\\'))
  assert.ok(samePathName('C:\\Lab\\\u00e4.lock', '\\\\?\\C:\\Lab\\\u00e4.lock'))
  assert.ok(!samePathName('C:\\Lab\\\u00c4.lock', '\\\\?\\C:\\Lab\\\u00e4.lock'))
  assert.ok(samePathName('C:\\사용자\\Lab\\T.LOCK', '\\\\?\\c:\\사용자\\lab\\t.lock'))
  assert.ok(!samePathName('C:/Lab/t.lock', '\\\\?\\C:\\Lab\\t.lock'))
  assert.ok(!samePathName('C:\\Lab\\RUNNER~1\\t.lock', '\\\\?\\C:\\Lab\\runneradmin\\t.lock'))
  for (const relative of ['relative', 'Lab\\t.lock', '.\\t.lock', 'C:t.lock', '\\Lab\\t.lock', '\\\\.\\pipe\\x',
    '\\\\?\\GLOBALROOT\\Device\\x', 'C:\\Lab\\..\\t.lock', 'C:\\Lab\\.\\t.lock', 'C:\\Lab\\\\t.lock', '\\\\server', '']) {
    assert.ok(!samePathName(relative, relative), relative)
  }
  const relativeObs = fileObs({ requestedPath: 'relative', finalPath: 'relative' })
  assert.equal(classifyFileObservation(relativeObs).reason, 'path_handle_mismatch')
})

// ---- W2 ---------------------------------------------------------------------

test('W2 exact current-user owner with only self writes matches', () => {
  const result = classifySecurity(secObs())
  assert.equal(result.state, 'match')
  assert.deepEqual(result.privilegedWriters, [])
  assert.equal(result.inheritedAces, 1)
  assert.equal(result.safeToUnlock, false)
})

test('W2 any owner other than the current user is refused', () => {
  for (const ownerClass of ['administrators', 'system', 'other:1a2b3c4d', 'service:00aa11bb', 'everyone']) {
    assert.deepEqual(classifySecurity(secObs({ ownerClass })), {
      state: 'refuse', reason: 'owner_not_current_user', ownerClass, safeToUnlock: false,
    })
  }
  assert.equal(classifySecurity(secObs({ ownerClass: null })).reason, 'owner_missing')
  assert.equal(classifySecurity(secObs({ tokenUserClass: null })).reason, 'token_user_missing')
})

test('W2 denied or missing security evidence is unknown', () => {
  assert.equal(classifySecurity({ ok: false, stage: 'open', win32: 5 }).reason, 'open_failed')
  assert.equal(classifySecurity({ ok: false, stage: 'security_info', win32: 5 }).reason, 'security_info_failed')
  assert.equal(classifySecurity(secObs({ attributes: 0x410 })).reason, 'reparse_point')
  assert.equal(classifySecurity(secObs({ aces: 'x' })).reason, 'dacl_unparsed')
  assert.equal(classifySecurity(secObs({ aces: null })).reason, 'dacl_unparsed')
  assert.equal(classifySecurity(secObs({ aces: [{ type: 'allow', sidClass: 'self' }] })).reason, 'dacl_unparsed')
  assert.equal(classifySecurity(secObs({ aces: [ace('self', 0x1f01ff, { type: 'other' })] })).reason, 'unsupported_ace')
  assert.equal(classifySecurity(secObs({ aces: [ace('creator_owner', 0x1f01ff)] })).reason, 'unsupported_ace')
})

test('W2 a missing DACL observation is not an observed NULL DACL', () => {
  for (const daclState of [undefined, null, '', 'PRESENT', true]) {
    assert.deepEqual(classifySecurity(secObs({ daclState })), { state: 'unknown', reason: 'dacl_missing', safeToUnlock: false })
  }
  assert.equal(classifySecurity(secObs({ daclState: 'null', aces: null })).reason, 'null_dacl')
  assert.equal(classifySecurity(secObs({ daclState: 'null', aces: null })).state, 'refuse')
  assert.equal(classifySecurity(secObs({ daclState: 'absent', aces: null })).reason, 'dacl_absent')
})

test('W2 a matching owner is insufficient when other principals can write', () => {
  const writers = ['builtin_users', 'authenticated_users', 'everyone', 'other:1a2b3c4d', 'service:00aa11bb']
  const masks = [0x2, 0x4, 0x10, 0x40, 0x100, 0x10000, 0x40000, 0x80000, 0x02000000, 0x10000000, 0x40000000, 0x120116]
  for (const sidClass of writers) {
    for (const mask of masks) {
      const result = classifySecurity(secObs({ aces: [ace('self', 0x1f01ff), ace(sidClass, mask)] }))
      assert.equal(result.state, 'refuse', `${sidClass} ${mask.toString(16)}`)
      assert.equal(result.reason, 'other_writer')
    }
  }
  const inherited = classifySecurity(secObs({ aces: [ace('everyone', 0x120116, { inherited: true })] }))
  assert.deepEqual(inherited, {
    state: 'refuse', reason: 'other_writer', sidClass: 'everyone', inherited: true, safeToUnlock: false,
  })
})

test('W2 read-only, deny-only and inherit-only ACEs for others do not refuse', () => {
  assert.equal(classifySecurity(secObs({ aces: [ace('self', 0x1f01ff), ace('builtin_users', 0x120089)] })).state, 'match')
  assert.equal(classifySecurity(secObs({ aces: [ace('other:1a2b3c4d', 0x1f01ff, { type: 'deny' }), ace('self', 0x1f01ff)] })).state, 'match')
  assert.equal(classifySecurity(secObs({ aces: [ace('everyone', 0x120116, { inheritOnly: true }), ace('self', 0x1f01ff)] })).state, 'match')
  assert.equal(classifySecurity(secObs({ aces: [ace('owner_rights', 0x1f01ff)] })).state, 'match')
})

test('W2 SYSTEM and Administrators writes are a recorded research assumption', () => {
  const result = classifySecurity(secObs({ aces: [ace('self', 0x1f01ff), ace('administrators', 0x1f01ff), ace('system', 0x1f01ff)] }))
  assert.equal(result.state, 'match')
  assert.equal(result.safeToUnlock, false)
  assert.deepEqual(result.privilegedWriters, ['administrators', 'system'])
  assert.deepEqual(result.limits, ['privileged_administrators_system', 'backup_restore_privileges'])
})

// ---- W3 ---------------------------------------------------------------------

test('W3 live same-user process through one handle bound to one PID', () => {
  assert.deepEqual(classifyProcess(RECORDED, procObs()), { state: 'live_same_user', safeToUnlock: false })
  assert.equal(classifyProcess(RECORDED, procObs({ handleSource: 'fresh_open' })).state, 'live_same_user')
})

test('W3 PID binding counterexamples are unknown', () => {
  // The review counterexample: swapped PID with an invalid handle source.
  const swapped = classifyProcess({ pid: 42, createFiletime: '134050000000000001' }, procObs({ pid: 999, handleSource: 'invalid' }))
  assert.equal(swapped.state, 'unknown')
  assert.equal(classifyProcess({ pid: 42, createFiletime: '134050000000000001' }, procObs({ pid: 999 })).reason, 'pid_mismatch')
  assert.equal(classifyProcess(RECORDED, procObs({ pid: 999 })).reason, 'pid_mismatch')
  for (const pid of [undefined, null, 0, -4, 1.5, '4242', 0x100000000]) {
    assert.equal(classifyProcess(RECORDED, procObs({ pid })).reason, 'pid_missing', String(pid))
    assert.equal(classifyProcess({ ...RECORDED, pid }, procObs()).reason, 'recorded_identity_missing', String(pid))
  }
  for (const handleSource of [undefined, null, '', 'invalid', 'HELD', 'inherited']) {
    assert.equal(classifyProcess(RECORDED, procObs({ handleSource })).reason, 'handle_source_unknown', String(handleSource))
  }
})

test('W3 creation-time counterexamples: missing, malformed and changed', () => {
  assert.equal(classifyProcess(RECORDED, procObs({ createFiletime: null })).reason, 'process_times_missing')
  assert.equal(classifyProcess(RECORDED, procObs({ createFiletime: undefined })).reason, 'process_times_missing')
  assert.equal(classifyProcess(RECORDED, procObs({ wait: 'signaled', createFiletime: null })).reason, 'process_times_missing')
  for (const createFiletime of ['', '0', '01', '-1', '+1', '1e5', 'abc', ' 1', '9223372036854775808', 134050000000000000]) {
    assert.equal(classifyProcess(RECORDED, procObs({ createFiletime })).reason, 'process_times_malformed', String(createFiletime))
    assert.equal(classifyProcess({ ...RECORDED, createFiletime }, procObs()).reason, 'recorded_identity_missing', String(createFiletime))
  }
  assert.ok(isValidFiletime('9223372036854775807'))
  assert.ok(!isValidFiletime('9223372036854775808'))
  const shifted = classifyProcess(RECORDED, procObs({ createFiletime: '134050000000000002' }))
  assert.equal(shifted.reason, 'identity_changed')
  assert.equal(Number('134050000000000001'), Number('134050000000000002'))
})

test('W3 PID reuse is detected through a fresh open even after the new process exits', () => {
  const reused = procObs({ handleSource: 'fresh_open', wait: 'signaled', waitAfter: 'signaled', createFiletime: '134050000000999999' })
  assert.deepEqual(classifyProcess(RECORDED, reused), {
    state: 'unknown', reason: 'identity_changed', pidMayBeReused: true, safeToUnlock: false,
  })
  assert.equal(classifyProcess(RECORDED, { ok: false, stage: 'open_process', win32: 87 }).reason, 'open_process_failed')
})

test('W3 liveness comes only from waiting on the handle', () => {
  assert.equal(classifyProcess(RECORDED, procObs({ wait: 'signaled' })).state, 'exited')
  assert.equal(classifyProcess(RECORDED, procObs({ wait: 'failed' })).reason, 'wait_failed')
  // An exit code of STILL_ACTIVE (259) without a wait result is not liveness.
  assert.equal(classifyProcess(RECORDED, procObs({ wait: undefined, exitCode: 259 })).reason, 'wait_failed')
  assert.equal(classifyProcess(RECORDED, procObs({ waitAfter: 'signaled' })).state, 'exited')
  assert.equal(classifyProcess(RECORDED, procObs({ waitAfter: 'failed' })).reason, 'wait_failed')
  assert.equal(classifyProcess(RECORDED, procObs({ waitAfter: undefined })).reason, 'wait_failed')
})

test('W3 token SID must be the current user', () => {
  assert.deepEqual(classifyProcess(RECORDED, procObs({ sidClass: 'other:1a2b3c4d' })), {
    state: 'refuse', reason: 'other_user', sidClass: 'other:1a2b3c4d', safeToUnlock: false,
  })
  assert.equal(classifyProcess(RECORDED, procObs({ sidClass: 'system' })).state, 'refuse')
  assert.equal(classifyProcess(RECORDED, procObs({ sidClass: null })).reason, 'token_sid_missing')
})

test('W3 shared owners are refused and nothing is promoted to standalone', () => {
  const shared = [
    'codex.exe app-server',
    '"C:\\Tools\\codex.exe" app-server --listen stdio',
    'codex.exe daemon start',
    'codex.exe remote-control',
    'codex.exe exec-server',
    'codex.exe --remote ws://127.0.0.1:1',
    'codex.exe --remote=ws://127.0.0.1:1',
    'codex.exe --remote-auth-token-env X',
  ]
  for (const commandLine of shared) {
    assert.equal(classifyOwnerMode({ ok: true, imageBase: 'codex.exe', commandLine }).state, 'refuse', commandLine)
  }
  assert.equal(classifyOwnerMode({ ok: true, imageBase: 'Codex.EXE', commandLine: 'codex app-server' }).reason, 'shared_service')
  for (const commandLine of ['codex.exe', 'codex.exe exec "hello"', 'codex.exe resume', 'codex.exe --remoteish']) {
    assert.deepEqual(classifyOwnerMode({ ok: true, imageBase: 'codex.exe', commandLine }), {
      state: 'unknown', reason: 'windows_argv_grammar_unverified', safeToUnlock: false,
    })
  }
  assert.equal(classifyOwnerMode({ ok: true, imageBase: 'cmd.exe', commandLine: 'cmd.exe /d /q' }).reason, 'not_codex_image')
  assert.equal(classifyOwnerMode({ ok: true, imageBase: 'node.exe', commandLine: 'node codex app-server' }).reason, 'not_codex_image')
  assert.equal(classifyOwnerMode({ ok: true, imageBase: 'codex.exe', commandLine: null }).reason, 'command_line_missing')
  assert.equal(classifyOwnerMode({ ok: false, stage: 'open_process', win32: 5 }).reason, 'open_process_failed')
})

test('shared-service patterns stay identical to the production source', () => {
  const source = readFileSync(join(here, '..', '..', 'src', 'process.ts'), 'utf8')
  assert.ok(source.includes(`const SHARED_SERVICE_PATTERN = ${SHARED_SERVICE_PATTERN};`))
  assert.ok(source.includes(`const FLATTENED_REMOTE_OPTION_PATTERN = ${FLATTENED_REMOTE_OPTION_PATTERN};`))
})

// ---- Cleanup probes -----------------------------------------------------------

test('cleanup probes: a replaced root or parent must delete nothing', () => {
  const base = { ok: true, preserved: true, removed: 0, sentinelIntact: true, originalIntact: true }
  assert.equal(classifyCleanupProbe(base).state, 'preserved')
  assert.equal(classifyCleanupProbe({ ...base, removed: 1 }).state, 'unsafe_delete')
  assert.equal(classifyCleanupProbe({ ...base, sentinelIntact: false }).state, 'unsafe_delete')
  assert.equal(classifyCleanupProbe({ ...base, originalIntact: false }).state, 'unsafe_delete')
  assert.equal(classifyCleanupProbe({ ...base, preserved: false }).reason, 'probe_inconsistent')
  assert.equal(classifyCleanupProbe({ ...base, removed: undefined }).reason, 'probe_fields_missing')
  assert.equal(classifyCleanupProbe(null).reason, 'missing_observation')
})

// ---- Whole-run manifest -------------------------------------------------------

test('the manifest is closed: unique cases with environment first and cleanup last', () => {
  const names = MANIFEST.map((item) => item.case)
  assert.equal(new Set(names).size, names.length)
  assert.equal(names[0], 'environment')
  assert.equal(names.at(-2), 'suite_end')
  assert.equal(names.at(-1), 'cleanup')
  for (let i = 1; i < MANIFEST.length; i += 1) assert.ok(MANIFEST[i].phase >= MANIFEST[i - 1].phase, names[i])
})

test('a complete mock run passes with full coverage', () => {
  const summary = evaluateJsonl(mockRun())
  assert.deepEqual(summary.collection.errors, [])
  assert.equal(summary.collection.complete, true)
  assert.equal(summary.hypotheses.mismatched, 0)
  assert.equal(summary.coverage.pidReuse, 'verified')
  assert.equal(summary.coverage.full, true)
  assert.equal(summary.exitCode, 0)
  assert.equal(summary.safeToUnlock, false)
})

test('the review single-line report does not pass', () => {
  const line = '{"kind":"mode","case":"mode:self","obs":{"ok":true,"imageBase":"cmd.exe","commandLine":"cmd.exe /d /q"},"expect":{"state":"unknown","reason":"not_codex_image"},"safeToUnlock":false}'
  const summary = evaluateJsonl(line)
  assert.equal(summary.collection.complete, false)
  assert.equal(summary.exitCode, 2)
  assert.ok(summary.collection.errors.includes('environment_missing'))
})

test('environment, filesystem and shifted-identity control evidence agree', () => {
  const records = mockRun().trim().split('\n').map(JSON.parse)
  for (const field of ['os', 'clr', 'is64BitProcess', 'integrityRid', 'budgets']) {
    const changed = globalThis.structuredClone(records)
    delete changed[0][field]
    assert.equal(evaluateJsonl(changed.map(JSON.stringify).join('\n')).exitCode, 2, field)
  }
  const badBudget = globalThis.structuredClone(records)
  badBudget[0].budgets.childWaitMs = -1
  assert.equal(evaluateJsonl(badBudget.map(JSON.stringify).join('\n')).exitCode, 2)
  const fsChanged = globalThis.structuredClone(records)
  fsChanged.find((r) => r.case === 'file:home').obs.filesystem = 'ReFS'
  assert.ok(evaluateJsonl(fsChanged.map(JSON.stringify).join('\n')).collection.errors.includes('filesystem_contradiction:file:home'))
  const timeChanged = globalThis.structuredClone(records)
  timeChanged.find((r) => r.case === 'proc:child_start_mismatch').obs.createFiletime = '134050000000000009'
  assert.ok(evaluateJsonl(timeChanged.map(JSON.stringify).join('\n')).collection.errors.includes('observation_contradiction:proc:child_start_mismatch'))
})

test('process cases require their own held or fresh handle evidence', () => {
  for (const name of ['proc:self', 'proc:child_live', 'proc:child_after_exit',
    'proc:child_fresh_open_while_held', 'proc:pid_reuse']) {
    const summary = evaluateJsonl(mockRun({ edit: (body) => body.map((record) => record.case !== name ? record : {
      ...record, obs: { ...record.obs, handleSource: record.obs.handleSource === 'held' ? 'fresh_open' : 'held' },
    }) }))
    assert.equal(summary.exitCode, 2, name)
    assert.equal(summary.coverage.full, false, name)
    assert.ok(summary.collection.errors.includes(`error:${name}:handle_source_case_mismatch`), name)
    if (name === 'proc:pid_reuse') assert.notEqual(summary.coverage.pidReuse, 'verified')
  }
})

test('mode observations must come from the matching process sample', () => {
  for (const name of ['mode:self', 'mode:child']) {
    for (const field of ['pid', 'createFiletime', 'imageBase', 'commandLine']) {
      const summary = evaluateJsonl(mockRun({ edit: (body) => body.map((record) => record.case !== name ? record : {
        ...record, obs: { ...record.obs, [field]: field === 'pid' ? 9999 : 'different' },
      }) }))
      assert.equal(summary.exitCode, 2, `${name}/${field}`)
      assert.ok(summary.collection.errors.includes(`binding_contradiction:${name}`), `${name}/${field}`)
    }
  }
})

test('incomplete or contradictory runs fail collection', () => {
  const full = mockRun().trimEnd().split('\n')
  const cases = {
    truncated: full.slice(0, -5).join('\n'),
    'missing cleanup': full.slice(0, -1).join('\n'),
    'missing environment': full.slice(1).join('\n'),
    'duplicate replacing a missing case': mockRun({
      edit: (body) => body.map((record) => record.case === 'file:transcript' ? build('file:thread_lock') : record),
    }),
    'unknown case': mockRun({ edit: (body) => [...body.slice(0, 3), build('file:invented'), ...body.slice(3)] }),
    'out of order': mockRun({
      edit: (body) => {
        const copy = [...body]
        const a = copy.findIndex((record) => record.case === 'file:home')
        const b = copy.findIndex((record) => record.case === 'file:lock_dir')
        const first = copy[a]
        copy[a] = copy[b]
        copy[b] = first
        return copy
      },
    }),
    'arbitrary skip': mockRun({ edit: replace('symlink:file', { kind: 'skipped', win32: 5, obs: undefined, expect: undefined }) }),
    'skip of a required case': mockRun({ edit: replace('file:home', { kind: 'skipped', win32: 1314 }) }),
    'tampered expect': mockRun({ edit: replace('hard_link:target', { obs: fileObs(), expect: MATCH }) }),
    'expect removed': mockRun({ edit: replace('hard_link:target', { expect: undefined }) }),
    'expect added to recorded case': mockRun({ edit: replace('proc:fresh_open_after_release', { expect: U('open_process_failed') }) }),
    'wrong track': mockRun({ edit: replace('file:home', { track: 'W2' }) }),
    'wrong expectKind': mockRun({ edit: replace('file:home', { expectKind: 'file' }) }),
    'missing observation': mockRun({ edit: replace('file:home', { obs: undefined }) }),
    'failed setup': mockRun({ edit: replace('create:home', { ok: false, win32: 5 }) }),
    'safeToUnlock true': mockRun({ edit: replace('file:home', { safeToUnlock: true }) }),
    'suite_error in a normal run': mockRun({
      edit: (body) => [...body, { kind: 'suite_error', case: 'suite_error', track: 'setup', fault: null, message: 'x', safeToUnlock: false }],
    }),
    'cleanup ok with a running child': mockRun({ cleanup: { childrenStillRunning: 1 } }),
    'cleanup ok but preserved': mockRun({ cleanup: { preserved: true } }),
    'cleanup ok with fewer removals': mockRun({ cleanup: { removed: 59 } }),
    'cleanup failed': mockRun({ cleanup: { ok: false, preserved: true, reason: 'entry_identity_changed:dir', removed: 0 } }),
    'eof contradiction': mockRun({ edit: replace('eof:child', { ok: true, exitCode: 7 }) }),
    'reuse children contradiction': mockRun({ edit: replace('reuse:children', { ok: true, abnormalExits: 1 }) }),
    'environment owner contradiction': mockRun({ edit: replace('sec:default_owner', { obs: secObs({ tokenOwnerClass: 'administrators' }) }) }),
    'launch pid contradiction': mockRun({ edit: replace('launch:child', { pid: 8 }) }),
    'child binding contradiction': mockRun({ edit: replace('proc:child_after_exit', { recorded: { pid: 4242, createFiletime: '134050000000000009' } }) }),
    'start mismatch not one tick': mockRun({ edit: replace('proc:child_start_mismatch', { recorded: { pid: 4242, createFiletime: '134050000000000005' } }) }),
    'invalid json line': mockRun().replace('\n', '\n{broken\n'),
  }
  for (const [label, text] of Object.entries(cases)) {
    const summary = evaluateJsonl(text)
    assert.equal(summary.collection.complete, false, label)
    assert.equal(summary.exitCode, 2, label)
  }
  const endCount = full.map((line) => line.includes('"suite_end"') ? line.replace(/"emitted":\d+/, '"emitted":3') : line).join('\n')
  assert.ok(evaluateJsonl(endCount).collection.errors.includes('suite_end_count_mismatch'))
})

test('a hypothesis mismatch is reported separately from collection', () => {
  const summary = evaluateJsonl(mockRun({ edit: replace('hard_link:target', { obs: fileObs() }) }))
  assert.equal(summary.collection.complete, true)
  assert.equal(summary.hypotheses.mismatched, 1)
  assert.equal(summary.hypotheses.pass, false)
  assert.equal(summary.exitCode, 1)
})

test('allowed skips and unobserved PID reuse are partial coverage, never a reuse PASS', () => {
  const unobserved = evaluateJsonl(mockRun({
    edit: replace('proc:pid_reuse', { kind: 'recorded', observed: false, attempts: 256, elapsedMs: 60000, obs: undefined, recorded: undefined, expect: undefined }),
  }))
  assert.equal(unobserved.collection.complete, true)
  assert.equal(unobserved.coverage.pidReuse, 'unobserved')
  assert.equal(unobserved.coverage.full, false)
  assert.equal(unobserved.exitCode, 4)
  const fakeObserved = evaluateJsonl(mockRun({ edit: replace('proc:pid_reuse', { kind: 'recorded', observed: true, attempts: 1 }) }))
  assert.equal(fakeObserved.exitCode, 2)
  const reuseMismatch = evaluateJsonl(mockRun({ edit: replace('proc:pid_reuse', { obs: procObs({ handleSource: 'fresh_open' }) }) }))
  assert.equal(reuseMismatch.coverage.pidReuse, 'failed')
  assert.equal(reuseMismatch.exitCode, 1)
  const skipped = evaluateJsonl(mockRun({ edit: replace('symlink:file', { kind: 'skipped', win32: 1314, obs: undefined, expect: undefined }) }))
  assert.deepEqual(skipped.coverage.skipped, ['symlink:file'])
  assert.equal(skipped.exitCode, 4)
  const adminSkip = evaluateJsonl(mockRun({ edit: replace('sec:owner_administrators', { kind: 'skipped', win32: 1307, obs: undefined, expect: undefined }) }))
  assert.equal(adminSkip.exitCode, 4)
})

test('sec:default_owner expectation is derived from the environment, not the producer', () => {
  const adminToken = (body) => body.map((record) => {
    if (record.case === 'sec:default_owner') {
      return { ...record, obs: secObs({ tokenOwnerClass: 'administrators', ownerClass: 'administrators' }), expect: R('owner_not_current_user') }
    }
    if (record.kind === 'security' && record.obs?.ok === true) return { ...record, obs: { ...record.obs, tokenOwnerClass: 'administrators' } }
    return record
  })
  const text = mockRun({ edit: adminToken }).replace('"tokenOwnerClass":"self"', '"tokenOwnerClass":"administrators"')
  assert.equal(evaluateJsonl(text).exitCode, 0)
  const tampered = mockRun({ edit: (body) => adminToken(body).map((record) => record.case === 'sec:default_owner' ? { ...record, expect: MATCH } : record) })
    .replace('"tokenOwnerClass":"self"', '"tokenOwnerClass":"administrators"')
  assert.equal(evaluateJsonl(tampered).exitCode, 2)
})

test('fault injection: each fault fails exactly as specified', () => {
  for (const fault of Object.keys(FAULTS)) {
    const text = mockRun({ fault })
    const summary = evaluateJsonl(text, { fault })
    assert.deepEqual(summary.collection.errors, [], fault)
    assert.equal(summary.exitCode, 0, fault)
    assert.equal(evaluateJsonl(text).exitCode, 2, `${fault} must fail a normal evaluation`)
  }
  assert.throws(() => evaluateJsonl(mockRun(), { fault: 'invented' }))
})

test('fault injection: unconfirmed children, missing errors and extra cases are caught', () => {
  const launch = 'after_child_launch'
  const running = mockRun({ fault: launch, cleanup: { ok: false, preserved: true, removed: 0, reason: 'children_running', childrenStillRunning: 1 } })
  assert.equal(evaluateJsonl(running, { fault: launch }).exitCode, 2)
  const noError = mockRun({ fault: launch, edit: (body) => body.filter((record) => record.kind !== 'suite_error') })
  assert.equal(evaluateJsonl(noError, { fault: launch }).exitCode, 2)
  const wrongFault = mockRun({ fault: launch, edit: replace('suite_error', { message: 'IOException: disk' }) })
  assert.equal(evaluateJsonl(wrongFault, { fault: launch }).exitCode, 2)
  const extra = mockRun({ fault: launch, edit: (body) => [...body.slice(0, -1), build('proc:child_live'), body.at(-1)] })
  assert.equal(evaluateJsonl(extra, { fault: launch }).exitCode, 2)
  const truncatedPrefix = mockRun({ fault: launch, edit: (body) => body.filter((record) => record.case !== 'launch:child') })
  assert.equal(evaluateJsonl(truncatedPrefix, { fault: launch }).exitCode, 2)
  // A child that ignores EOF must leave cleanup preserved with a running child.
  const ignore = 'child_ignores_eof'
  assert.equal(evaluateJsonl(mockRun({ fault: ignore, cleanup: { ...CLEAN } }), { fault: ignore }).exitCode, 2)
  const confirmedAnyway = mockRun({ fault: ignore, edit: replace('eof:child', { exited: true, exitCode: 0, ok: true }) })
  assert.equal(evaluateJsonl(confirmedAnyway, { fault: ignore }).exitCode, 2)
  // An abnormal exit must be the specified one.
  const abnormal = 'child_abnormal_exit'
  assert.equal(evaluateJsonl(mockRun({ fault: abnormal, edit: replace('eof:child', { exitCode: 3 }) }), { fault: abnormal }).exitCode, 2)
  assert.equal(evaluateJsonl(mockRun({ fault: abnormal, edit: replace('eof:child', { ok: true, exitCode: 0 }) }), { fault: abnormal }).exitCode, 2)
})

// ---- Static source checks (no Windows toolchain needed) ----------------------

function code(name) {
  return readFileSync(join(here, name), 'utf8')
    .replace(/<#[\s\S]*?#>/g, '')
    .split('\n')
    .filter((line) => !/^\s*(\/\/|#)/.test(line))
    .join('\n')
}

test('fixture sources contain no forbidden mutation, privilege, path-delete or termination calls', () => {
  const forbidden = [
    /TerminateProcess/, /\.Kill\s*\(/, /Stop-Process/i, /taskkill/i, /GenerateConsoleCtrlEvent/,
    /SetSecurityInfo/, /SetNamedSecurityInfo/, /SetFileSecurity/, /SetAccessControl/, /SetKernelObjectSecurity/,
    /AdjustTokenPrivileges/, /LookupPrivilegeValue/, /ExecutionPolicy/i, /EncodedCommand/i,
    /GetEnvironmentVariable/, /CODEX_HOME/, /USERPROFILE/i, /\.codex\b/, /Remove-Item/i, /-Recurse/i,
    /Directory\.Delete/, /File\.Delete/, /DeleteFileW/, /RemoveDirectoryW/,
    /DeleteVolume|Format-Volume|New-VHD|Mount-VHD|Set-MpPreference/i,
  ]
  for (const name of ['WinIdentityLab.cs', 'lab.ps1', 'check.ps1']) {
    const text = code(name)
    for (const pattern of forbidden) assert.ok(!pattern.test(text), `${name} matches ${pattern}`)
  }
})

test('observer structure: children registered at launch, deletion only through verified handles', () => {
  const text = code('WinIdentityLab.cs')
  assert.equal(text.match(/Process\.Start\(/g)?.length, 1)
  assert.match(text, /c\.P = Process\.Start\(psi\);\s*\n\s*Children\.Add\(c\);/)
  assert.ok(!/WorkingDirectory = Root/.test(text))
  assert.equal(text.match(/SetFileInformationByHandle\(/g)?.length, 3) // declaration + entries + root
  const guarded = text.slice(text.indexOf('static string GuardedDelete('), text.indexOf('static List<string> Out'))
  assert.ok(guarded.length > 0 && !guarded.includes('static List<string> Out'))
  assert.ok(guarded.indexOf('IdentityOf(h) != e.Identity') < guarded.indexOf('SetFileInformationByHandle'))
  assert.ok(guarded.indexOf('if (reason != null) return reason;') < guarded.indexOf('SetFileInformationByHandle'))
  assert.match(text, /finally \{ ReleaseAll\(\); \}/)
  assert.match(text, /if \(us\.Buffer == IntPtr\.Zero \|\| \(us\.Length & 1\) != 0/)
  assert.match(text, /text < start \+ header \|\| text \+ us\.Length > end/)
  const lab = code('lab.ps1')
  assert.ok(lab.indexOf('[IO.FileMode]::CreateNew') < lab.indexOf('Add-Type'), 'result file is reserved before compiling or running')
  assert.ok(lab.indexOf('[IO.FileMode]::CreateNew') < lab.indexOf('CreateScratch'))
})
