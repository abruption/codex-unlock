// Host-independent tests for the W6/W7 observer evaluator. Synthetic records
// only; nothing here touches Windows, Codex, a Codex home, or a lock.
//   node --test experimental/windows-native-observer/test/
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import { EXPECTATIONS, HARNESS_FILES, INTEGRITY, SCHEMA, STEP_SCHEMAS, normalizeLocalPath } from '../expectations.mjs'
import {
  deepEqualMap, evaluateRun, fixtureSummary, guardedCreate, guardedSample, hasAccessDenied, insideDisposableDir,
  integrityFromSid, pairSummaries, parseJsonl, pathGateSafe, recomputeIsolation, reconstructManifest,
  renderExpectationTable, sidFromWhoamiLine, tempRootSafeForCreation, validateBaseline, windowsPathRelation,
} from '../lib.mjs'

const here = dirname(fileURLToPath(import.meta.url))
const root = join(here, '..')
const HARNESS = Object.fromEntries(HARNESS_FILES.map((name, i) => [name, String(i + 1).repeat(64)]))
const COMMIT = 'c'.repeat(40)
const BINSHA = 'd'.repeat(64)
const MANIFEST_SHA = 'e'.repeat(64)
const VERSION = 'codex-cli 0.163.0'
const USER_SID = 'S-1-5-21-111-222-333-1001'
const TEMP = 'C:\\Users\\op\\AppData\\Local\\Temp'
const PARENT = `${TEMP}\\codex-win-obs-0123456789ab`
const HOME = `${PARENT}\\home`
const PARENT_B = `${TEMP}\\codex-win-obs-ba9876543210`
const HOME_B = `${PARENT_B}\\home`
const USER_HOME = 'C:\\Users\\op\\.codex'
const id = (n) => `0123456789abcdef:${String(n).padStart(32, '0')}`
const PARENT_ID = id(1)
const HOME_ID = id(2)
const THREAD_ID = id(3)
const LOCKDIR_ID = id(4)
const GUARD_ID = id(5)
const BINARY = 'C:\\Program Files\\codex\\codex.exe'
const CREATE = '132000000000000000'
const CODEX_PID = 7
const OBSERVER_PID = 5
const BASELINE = { sourceCommit: COMMIT, binarySha256: BINSHA, version: VERSION, harness: HARNESS }

// No-follow ancestry of a disposable parent, root first, as the observer
// records it: every component a plain directory, ending at the parent itself.
function ancestry(parent, parentFileId) {
  const parts = parent.split('\\')
  const drive = parts.shift()
  const out = [{ path: `${drive}\\`, fileId: id(90), directory: true, reparse: false }]
  let cur = drive
  parts.forEach((part, index) => {
    cur = `${cur}\\${part}`
    out.push({ path: cur, fileId: index === parts.length - 1 ? parentFileId : id(91 + index), directory: true, reparse: false })
  })
  return out
}

const ACL = {
  currentUserSid: USER_SID,
  owner: USER_SID, daclProtected: true, aceCount: 1, aceIdentity: USER_SID,
  aceRights: 'FullControl', aceInheritance: 'ContainerInherit, ObjectInherit', aceType: 'Allow',
  parentOwner: USER_SID, parentDaclProtected: true, parentAceCount: 1, parentAceIdentity: USER_SID,
  parentAceRights: 'FullControl', parentAceInheritance: 'ContainerInherit, ObjectInherit', parentAceType: 'Allow',
}

function homeFields(home = HOME, parent = PARENT, homeId = HOME_ID, parentId = PARENT_ID) {
  return {
    home, parent, userCodexHome: USER_HOME, envCodexHome: null, userRelation: 'disjoint', envRelation: null,
    fileId: homeId, parentFileId: parentId, ancestry: ancestry(parent, parentId), ...ACL,
  }
}

function identityFields(fileId, { directory = false, links = 1 } = {}) {
  const leaf = fileId === GUARD_ID ? '\\.coordination.lock' : fileId === THREAD_ID ? '\\t.lock' : ''
  return {
    ok: true, complete: true, attributes: directory ? 16 : 128, reparse: false, directory,
    fileId, links, deletePending: false, finalPath: `\\\\?\\${HOME}\\thread-writer-locks${leaf}`,
  }
}

function ranges(overrides = {}) {
  const held = { win32: 33, acquired: false, released: null }
  return { rust: { ...held }, fsext: { ...held }, beyond_fsext: { ...held }, tail: { ...held }, ...overrides }
}

// The union of the raw table hypotheses for a mode+step, mirroring what
// observer.ps1 records as its own advisory expectation (dotted keys literal).
function expectFor(mode, step) {
  const e = {}
  for (const x of EXPECTATIONS) if (x.mode === mode && x.step === step && x.hypothesis) Object.assign(e, x.hypothesis)
  return Object.keys(e).length > 0 ? e : null
}

function rec(mode, step, label, observed, sample = null) {
  return {
    schema: SCHEMA, mode, step, sample,
    integrity: { label, sid: INTEGRITY[label], elevationType: label === 'high' ? 2 : 3, sessionId: 1 },
    expect: expectFor(mode, step), observed, verdict: 'match', safeToUnlock: false,
  }
}

function idealRun(label, samples = 2, codexLabel = label) {
  const pf = [
    rec('preflight', 'harness', label, { ok: true, complete: true, files: { ...HARNESS }, sourceCommit: COMMIT }),
    rec('preflight', 'token.self', label, { ok: true, tokenOpened: true, pid: OBSERVER_PID, integritySid: INTEGRITY[label], userSid: USER_SID, integrityMatchesLabel: true }),
    rec('preflight', 'binary.sha256', label, { ok: true, path: BINARY, size: 12345, sha256: BINSHA, expected: BINSHA, matches: true }),
    rec('preflight', 'binary.signature', label, { ok: true, status: 'Valid', statusMessage: 'Signature verified.', signer: 'CN=OpenAI', thumbprint: 'ABCD' }),
    rec('preflight', 'binary.pe_version', label, { ok: true, declared: true, fileVersion: '0.163.0', productVersion: '0.163.0', productName: 'codex' }),
    rec('preflight', 'home.isolated', label, { ok: true, ...homeFields(), empty: true, entries: [], isolated: true }),
    rec('preflight', 'binary.version', label, {
      ok: true, exitCode: 0, pid: 4242, stdoutFirstLine: VERSION, expected: VERSION, matches: true,
      stdout: VERSION, stderr: '', stdoutComplete: true, stderrComplete: true, stdoutTruncated: false,
      stderrTruncated: false, timedOut: false, exited: true, envAllowlist: ['SystemRoot', 'CODEX_HOME'],
    }),
    rec('preflight', 'home.after_version', label, { ok: true, count: 0, entries: [] }),
    rec('preflight', 'host.execution_policy', label, { ok: true, effective: 'RemoteSigned', scopes: [] }),
    rec('preflight', 'host.defender', label, { ok: true, amServiceEnabled: true, realTimeProtectionEnabled: true, antivirusEnabled: true }),
    rec('preflight', 'host.volume', label, { ok: true, fileSystem: 'NTFS', probePath: `${PARENT}\\.volume-probe` }),
    rec('preflight', 'host.os', label, { ok: true, os: 'Microsoft Windows NT 10.0.19045.0', ps: '5.1.19041.1', elevated: label === 'high', sshSession: false }),
    rec('preflight', 'manifest', label, {
      ok: true, complete: true, home: HOME, homeFileId: HOME_ID, parent: PARENT, parentFileId: PARENT_ID,
      binaryPath: BINARY, binarySha256: BINSHA, binarySize: 12345, version: VERSION, sourceCommit: COMMIT,
      integritySid: INTEGRITY[label], label, harness: { ...HARNESS }, createdUtc: '2026-10-18T00:00:00.0000000Z',
    }),
  ]
  const ob = [
    rec('observe', 'harness', label, { ok: true, complete: true, files: { ...HARNESS }, manifestSha256: MANIFEST_SHA }),
    rec('observe', 'token.self', label, { ok: true, tokenOpened: true, pid: OBSERVER_PID, integritySid: INTEGRITY[label], userSid: USER_SID }),
    rec('observe', 'home.identity', label, { ok: true, ...homeFields() }),
    rec('observe', 'run', label, {
      ok: true, samples, codexPid: CODEX_PID, codexLabel, observerPid: OBSERVER_PID,
      observerUserSid: USER_SID, startedUtc: '2026-10-18T00:10:00.0000000Z',
    }),
    rec('observe', 'process.identity', label, {
      ok: true, pid: CODEX_PID, opened: true, state: 'live', createFiletime: CREATE, image: BINARY,
      tokenOpened: true, integritySid: INTEGRITY[codexLabel], userSid: USER_SID,
    }),
  ]
  for (let s = 1; s <= samples; s++) {
    ob.push(rec('observe', 'process.sample', label, {
      ok: true, pid: CODEX_PID, opened: true, state: 'live', createFiletime: CREATE, image: BINARY,
      tokenOpened: true, integritySid: INTEGRITY[codexLabel], userSid: USER_SID,
    }, s))
    ob.push(rec('observe', 'lockdir.identity', label, identityFields(LOCKDIR_ID, { directory: true }), s))
    ob.push(rec('observe', 'coordination.identity', label, identityFields(GUARD_ID), s))
    ob.push(rec('observe', 'thread.count', label, { ok: true, count: 1, entries: ['.coordination.lock', 't.lock'] }, s))
    ob.push(rec('observe', 'thread.identity', label, identityFields(THREAD_ID), s))
    ob.push(rec('observe', 'openers.rm', label, {
      ok: true, complete: true, count: 1, interpretation: 'opener_candidates_only',
      files: [`${HOME}\\thread-writer-locks\\t.lock`, `${HOME}\\thread-writer-locks\\.coordination.lock`],
      processes: [{ pid: CODEX_PID, startFiletime: CREATE, role: 'launched_codex', app: 'codex', service: null, type: 1, session: 1 }],
    }, s))
    ob.push(rec('observe', 'share.read_rwd', label, { ok: true, opened: true, win32: 0, access: 'read', share: 'rwd' }, s))
    ob.push(rec('observe', 'share.delete_rwd', label, { ok: true, opened: true, win32: 0, access: 'delete', share: 'rwd' }, s))
    ob.push(rec('observe', 'range.probe', label, {
      ok: true, state: 'probed',
      dirFileIdBefore: LOCKDIR_ID, dirFileIdAfter: LOCKDIR_ID,
      guardFileId: GUARD_ID, guardFileIdAfter: GUARD_ID, guardLinks: 1, guardDeletePending: false,
      threadFileIdBefore: THREAD_ID, threadFileIdAfter: THREAD_ID, threadLinks: 1, threadDeletePending: false,
      guardAcquired: true, guardReleased: true, ranges: ranges(),
    }, s))
    ob.push(rec('observe', 'thread.identity_after', label, identityFields(THREAD_ID), s))
  }
  ob.push(rec('observe', 'process.identity_after', label, {
    ok: true, pid: CODEX_PID, opened: true, state: 'live', createFiletime: CREATE, image: BINARY,
    tokenOpened: true, integritySid: INTEGRITY[codexLabel], userSid: USER_SID,
  }))
  return { preflight: { records: pf, problems: [] }, observe: { records: ob, problems: [] } }
}

const measurableOnly = EXPECTATIONS.filter((e) => e.measurable !== false)

function evaluate(run, opts = {}) {
  return evaluateRun({ ...run, preflightSha256: MANIFEST_SHA, baseline: BASELINE, ...opts })
}

function find(records, step, sample = null) {
  return records.find((r) => r.step === step && (r.sample ?? null) === sample)
}

function row(summary, id2) {
  return summary.rows.find((r) => r.id === id2)
}

test('parseJsonl accepts LF JSONL and reports format problems', () => {
  assert.deepEqual(parseJsonl('{"a":1}\n{"b":2}\n'), { records: [{ a: 1 }, { b: 2 }], problems: [] })
  assert.deepEqual(parseJsonl('').problems, ['empty_file'])
  assert.ok(parseJsonl('\ufeff{"a":1}\n').problems.includes('bom'))
  assert.ok(parseJsonl('{"a":1}\r\n').problems.includes('crlf:1'))
  assert.ok(parseJsonl('{"a":1}').problems.includes('missing_final_newline'))
  assert.ok(parseJsonl('nope\n').problems.includes('invalid_json:1'))
  assert.ok(parseJsonl('[1]\n').problems.includes('not_object:1'))
})

test('integrity is derived only from the mandatory label SID', () => {
  assert.equal(integrityFromSid('S-1-16-8192'), 'medium')
  assert.equal(integrityFromSid('S-1-16-12288'), 'high')
  assert.equal(integrityFromSid('S-1-16-8448'), 'other')
  assert.equal(integrityFromSid('S-1-5-32-544'), null)
  assert.equal(sidFromWhoamiLine('Mandatory Label\\High Mandatory Level Label S-1-16-12288'), 'S-1-16-12288')
  assert.equal(sidFromWhoamiLine('Etiqueta obligatoria\\Nivel obligatorio medio Etiqueta S-1-16-8192'), 'S-1-16-8192')
  assert.equal(sidFromWhoamiLine('S-1-16-8192 S-1-16-12288'), null)
})

test('only absolute local drive spellings are accepted; ambiguous ones are rejected', () => {
  assert.equal(normalizeLocalPath('C:\\Temp\\A\\'), 'c:\\temp\\a')
  assert.equal(normalizeLocalPath('C:\\'), 'c:\\')
  for (const bad of ['\\\\?\\C:\\Temp', '\\\\.\\C:\\Temp', '\\\\server\\share\\x', '\\rooted\\x', 'C:relative',
    'relative\\x', 'C:/Temp/x', 'C:\\Temp\\\\x', 'C:\\Temp\\..\\Users', 'C:\\Temp\\.', 'C:\\Temp\\x ',
    'C:\\Temp\\x.', 'C:\\Temp\\ x', 'C:\\Temp\\a:b', 'C:\\Temp\\a*b', 'C:\\Temp\\a?b', 'C:\\Temp\\a|b', '', null]) {
    assert.equal(normalizeLocalPath(bad), null, String(bad))
  }
})

test('windowsPathRelation is lexical, case-insensitive and boundary aware', () => {
  assert.equal(windowsPathRelation('C:\\Users\\Op\\.codex', 'c:\\users\\op\\.CODEX\\'), 'same')
  assert.equal(windowsPathRelation('C:\\Users\\op\\.codex\\x', 'C:\\Users\\op\\.codex'), 'inside')
  assert.equal(windowsPathRelation('C:\\Users\\op', 'C:\\Users\\op\\.codex'), 'contains')
  assert.equal(windowsPathRelation('C:\\Users\\op\\.codex2', 'C:\\Users\\op\\.codex'), 'disjoint')
  // A device-path spelling of the same file is refused, not normalized.
  assert.equal(windowsPathRelation('\\\\?\\C:\\Temp\\a', 'C:\\Temp\\a'), null)
  assert.equal(windowsPathRelation('C:\\Temp\\..\\Users', 'C:\\Users'), null)
})

test('the output/input path gate refuses real homes and disposable directories', () => {
  assert.equal(pathGateSafe(`C:\\Users\\op\\Documents\\w7\\out.jsonl`, USER_HOME, null), null)
  assert.equal(pathGateSafe(`${USER_HOME}\\out.jsonl`, USER_HOME, null), 'user_home_overlap')
  assert.equal(pathGateSafe('C:\\Users\\op\\out.jsonl', USER_HOME, 'C:\\Users\\op'), 'env_home_overlap')
  assert.equal(pathGateSafe(`${PARENT}\\out.jsonl`, USER_HOME, null), 'inside_disposable_dir')
  // Another volume's disposable directory is still refused, whatever %TEMP% is.
  assert.equal(pathGateSafe('D:\\scratch\\codex-win-obs-0123456789ab\\out.jsonl', USER_HOME, null), 'inside_disposable_dir')
  assert.equal(pathGateSafe('\\\\server\\share\\out.jsonl', USER_HOME, null), 'path_spelling')
  assert.equal(pathGateSafe(`${PARENT}\\home`, USER_HOME, null, { allowDisposable: true }), null)
  assert.equal(insideDisposableDir('C:\\Temp\\codex-win-obs-0123456789abc'), false)
  assert.equal(insideDisposableDir('C:\\Temp\\codex-win-obs-0123456789ab\\home'), true)
})

test('access denial is found at any depth', () => {
  assert.equal(hasAccessDenied({ ok: true, ranges: { rust: { win32: 5 } } }), true)
  assert.equal(hasAccessDenied({ ok: true, tokenWin32: 5 }), true)
  assert.equal(hasAccessDenied({ ok: true, win32: 32, list: [{ win32: 33 }] }), false)
})

test('a baseline must be format-valid with the exact harness file-name set', () => {
  assert.deepEqual(validateBaseline(BASELINE), [])
  assert.deepEqual(validateBaseline(null), ['baseline_missing'])
  assert.deepEqual(validateBaseline([]), ['baseline_not_object'])
  assert.ok(validateBaseline({ ...BASELINE, sourceCommit: 'short' }).includes('baseline_source_commit'))
  assert.ok(validateBaseline({ ...BASELINE, binarySha256: 'x' }).includes('baseline_binary_sha256'))
  assert.ok(validateBaseline({ ...BASELINE, version: '' }).includes('baseline_version'))
  const partial = { ...HARNESS }
  delete partial['lib.mjs']
  assert.ok(validateBaseline({ ...BASELINE, harness: partial }).includes('baseline_harness_name_set'))
  assert.ok(validateBaseline({ ...BASELINE, harness: { ...HARNESS, extra: 'f'.repeat(64) } }).includes('baseline_harness_name_set'))
})

test('ideal evidence still leaves W7 unknown on the unmeasurable coordination range', () => {
  const s = evaluate(idealRun('medium'), { expectedLabel: 'medium' })
  assert.equal(s.label, 'medium')
  assert.deepEqual(s.problems, [])
  assert.equal(s.w7, 'unknown')
  assert.deepEqual(s.blockers, ['OB-coordination-range'])
  assert.equal(row(s, 'OB-coordination-range').reasons[0], 'not_measurable')
  assert.equal(s.dependents.W3.nativeClassification, 'blocked_on_W7')
  assert.equal(s.safeToUnlock, false)
  assert.equal(s.provenance.state, 'validated')
  for (const r of s.rows) assert.equal(r.integrity, 'medium')
})

test('a fully measured table passes with a baseline, and authorizes nothing', () => {
  const s = evaluate(idealRun('high'), { expectedLabel: 'high', expectations: measurableOnly })
  assert.equal(s.w7, 'pass', JSON.stringify(s.rows.filter((r) => r.verdict !== 'match' && r.verdict !== 'recorded')))
  assert.equal(s.dependents.W3.nativeClassification, 'evidence_available_decision_pending')
  assert.equal(s.safeToUnlock, false)
  assert.equal(row(s, 'OB-range-beyond-fsext').measured, 'all')
  assert.equal(row(s, 'OB-run').verdict, 'match')
  assert.equal(row(s, 'OB-range-guard').verdict, 'match')
  assert.equal(row(s, 'OB-openers').verdict, 'match')
})

test('without a baseline the provenance rows stay unknown and the gate cannot pass', () => {
  const s = evaluateRun({ ...idealRun('high'), preflightSha256: MANIFEST_SHA, baseline: null, expectations: measurableOnly, expectedLabel: 'high' })
  assert.ok(s.problems.includes('baseline_missing'))
  assert.equal(s.w7, 'unknown')
  assert.equal(s.provenance.state, 'unvalidated')
  assert.equal(s.baselineProvided, false)
  for (const id2 of ['PF-harness', 'PF-binary-sha256', 'PF-binary-version', 'PF-manifest']) {
    assert.equal(row(s, id2).verdict, 'unknown')
  }
})

test('provenance verdicts are recomputed, not read from harness booleans', () => {
  // Flip every self-asserted boolean to a lie; derived rows must still pass
  // because they recompute from raw fields and the baseline.
  const run = idealRun('high')
  find(run.preflight.records, 'token.self').observed.integrityMatchesLabel = false
  find(run.preflight.records, 'binary.sha256').observed.matches = false
  find(run.preflight.records, 'home.isolated').observed.isolated = false
  find(run.preflight.records, 'binary.version').observed.matches = false
  find(run.observe.records, 'harness').observed.matchesManifest = false
  const s = evaluate(run, { expectations: measurableOnly })
  // home.isolated now disagrees with the recomputation -> unknown, not trusted.
  assert.equal(row(s, 'PF-home').verdict, 'unknown')
  assert.ok(row(s, 'PF-home').reasons.includes('evaluator_disagreement'))
  for (const id2 of ['PF-token', 'PF-binary-sha256', 'PF-binary-version', 'OB-harness']) {
    assert.equal(row(s, id2).verdict, 'match')
  }
})

test('a baseline that disagrees with the manifest is a mismatch, never success', () => {
  const s = evaluate(idealRun('high'), { baseline: { ...BASELINE, binarySha256: 'f'.repeat(64) } })
  assert.equal(row(s, 'PF-binary-sha256').verdict, 'mismatch')
  assert.equal(row(s, 'PF-manifest').verdict, 'mismatch')
  assert.equal(s.w7, 'fail')
  assert.equal(s.provenance.state, 'unvalidated')
  assert.deepEqual(s.provenance.mismatches, ['PF-binary-sha256', 'PF-manifest'])
})

test('counterexample: a paired baseline mismatch can never report compared', () => {
  const bad = { ...BASELINE, binarySha256: 'f'.repeat(64) }
  const m = evaluate(idealRun('medium'), { expectedLabel: 'medium', baseline: bad })
  const h = evaluate(idealRun('high'), { expectedLabel: 'high', baseline: bad })
  const p = pairSummaries(m, h)
  assert.equal(p.status, 'fail')
  assert.ok(p.problems.includes('medium_provenance_unvalidated'))
  assert.ok(p.problems.includes('high_provenance_unvalidated'))
  assert.ok(p.provenanceFailures.includes('medium:PF-binary-sha256'))
  assert.ok(p.provenanceFailures.includes('high:PF-manifest'))
})

test('counterexample: a W6 pair needs a validated provenance state on both sides', () => {
  const m = evaluate(idealRun('medium'), { expectedLabel: 'medium', baseline: null })
  const h = evaluate(idealRun('high'), { expectedLabel: 'high' })
  const p = pairSummaries(m, h)
  assert.equal(p.status, 'unknown')
  assert.ok(p.problems.includes('medium_provenance_unvalidated'))
  assert.ok(p.problems.includes('baseline_missing'))
})

test('observe harness that references another preflight is a mismatch', () => {
  const run = idealRun('high')
  find(run.observe.records, 'harness').observed.manifestSha256 = 'f'.repeat(64)
  const s = evaluate(run, { expectations: measurableOnly })
  assert.ok(s.problems.includes('manifest_reference_mismatch'))
  assert.equal(s.w7, 'unknown')
})

test('a record missing a schema-required field is unknown, never recorded success', () => {
  const run = idealRun('high')
  delete find(run.observe.records, 'openers.rm', 1).observed.count
  const s = evaluate(run, { expectations: measurableOnly })
  assert.equal(row(s, 'OB-openers').verdict, 'unknown')
  assert.ok(row(s, 'OB-openers').reasons.some((x) => x.startsWith('schema_missing:count')))
})

test('a recorded row with only {ok:true} fails its typed schema', () => {
  for (const [mode, step, id2] of [['observe', 'openers.rm', 'OB-openers'], ['preflight', 'binary.pe_version', 'PF-binary-pe-version'],
    ['preflight', 'binary.signature', 'PF-binary-signature'], ['preflight', 'host.volume', 'PF-volume']]) {
    const run = idealRun('high')
    const records = mode === 'preflight' ? run.preflight.records : run.observe.records
    find(records, step, step === 'openers.rm' ? 1 : null).observed = { ok: true }
    const s = evaluate(run, { expectations: measurableOnly })
    assert.equal(row(s, id2).verdict, 'unknown', id2)
  }
})

test('an undeclared PE version resource must be declared, not implied', () => {
  const run = idealRun('high')
  find(run.preflight.records, 'binary.pe_version').observed = { ok: true, declared: true, fileVersion: null, productVersion: null, productName: null }
  assert.equal(row(evaluate(run, { expectations: measurableOnly }), 'PF-binary-pe-version').verdict, 'unknown')
  const explicit = idealRun('high')
  find(explicit.preflight.records, 'binary.pe_version').observed = { ok: true, declared: false, fileVersion: null, productVersion: null, productName: null }
  assert.equal(row(evaluate(explicit, { expectations: measurableOnly }), 'PF-binary-pe-version').verdict, 'recorded')
})

test('a malformed field format is unknown', () => {
  const run = idealRun('high')
  find(run.observe.records, 'home.identity').observed.fileId = 'not-a-file-id'
  const s = evaluate(run, { expectations: measurableOnly })
  assert.equal(row(s, 'OB-home').verdict, 'unknown')
  assert.ok(row(s, 'OB-home').reasons.some((x) => x.startsWith('schema_format:fileId')))
})

test('a non-absolute or device home path fails the path contract', () => {
  for (const bad of ['home', '\\\\?\\C:\\Temp\\codex-win-obs-0123456789ab\\home', '\\\\srv\\share\\home']) {
    const run = idealRun('high')
    find(run.observe.records, 'home.identity').observed.home = bad
    assert.equal(row(evaluate(run, { expectations: measurableOnly }), 'OB-home').verdict, 'unknown', bad)
  }
})

test('samples must be an integer 1..10, checked before allocation', () => {
  for (const bad of [0, 11, 2.5, -1, '2', null, undefined]) {
    const run = idealRun('high')
    find(run.observe.records, 'run').observed.samples = bad
    const s = evaluate(run, { expectations: measurableOnly })
    assert.ok(s.problems.includes('sample_count_invalid'), `samples=${bad}`)
    assert.equal(row(s, 'OB-thread-count').reasons[0], 'sample_count_invalid')
    assert.equal(s.w7, 'unknown')
  }
})

test('a missing sample is partial collection and unknown, never success', () => {
  const run = idealRun('medium', 3)
  run.observe.records = run.observe.records.filter((r) => !(r.step === 'range.probe' && r.sample === 2))
  const s = evaluate(run, { expectations: measurableOnly })
  assert.equal(row(s, 'OB-range-rust').collected, 'partial')
  assert.equal(row(s, 'OB-range-rust').verdict, 'unknown')
  assert.ok(row(s, 'OB-range-rust').reasons.includes('not_collected#2'))
  assert.ok(s.problems.some((p) => p.startsWith('observe:sample_order:range.probe')))
})

test('counterexample: an extra, orphan or misplaced sampled record invalidates the file', () => {
  const extra = idealRun('medium', 2)
  extra.observe.records.push(rec('observe', 'range.probe', 'medium', { ok: true, state: 'probed' }, 9))
  assert.ok(evaluate(extra).problems.includes('observe:sample_invalid:range.probe#9'))
  const orphan = idealRun('medium', 2)
  orphan.observe.records.push(rec('observe', 'process.identity', 'medium', { ok: true, state: 'live' }, 99))
  assert.ok(evaluate(orphan).problems.includes('observe:sample_unexpected:process.identity#99'))
  const sampledRun = idealRun('medium', 2)
  find(sampledRun.observe.records, 'run').sample = 99
  const s = evaluate(sampledRun)
  assert.ok(s.problems.includes('observe:sample_unexpected:run#99'))
  assert.equal(s.w7, 'unknown')
  const unsampled = idealRun('medium', 2)
  find(unsampled.observe.records, 'thread.identity', 1).sample = null
  assert.ok(evaluate(unsampled).problems.includes('observe:sample_invalid:thread.identity#null'))
  const reordered = idealRun('medium', 2)
  const runRec = find(reordered.observe.records, 'run')
  reordered.observe.records = [...reordered.observe.records.filter((r) => r !== runRec), runRec]
  assert.ok(evaluate(reordered).problems.includes('observe:order:run_after_samples'))
})

test('counterexample: the run control record is mandatory and binds every process record', () => {
  const noPid = idealRun('high')
  delete find(noPid.observe.records, 'run').observed.codexPid
  const s1 = evaluate(noPid, { expectations: measurableOnly })
  assert.ok(s1.problems.some((p) => p.startsWith('run_unusable:schema_missing:codexPid')))
  assert.ok(s1.problems.includes('sample_count_invalid'))
  assert.equal(s1.w7, 'unknown')
  assert.notEqual(s1.rows.length, 0)
  assert.equal(row(s1, 'OB-run').verdict, 'unknown')
  const wrongPid = idealRun('high')
  find(wrongPid.observe.records, 'process.identity').observed.pid = CODEX_PID + 1
  const s2 = evaluate(wrongPid, { expectations: measurableOnly })
  assert.equal(row(s2, 'OB-run').verdict, 'mismatch')
  assert.ok(row(s2, 'OB-run').reasons.includes('process.identity_pid_differs_from_run'))
  assert.equal(row(s2, 'OB-process').verdict, 'mismatch')
  assert.equal(s2.w7, 'fail')
  const observerIsTarget = idealRun('high')
  find(observerIsTarget.observe.records, 'run').observed.observerPid = CODEX_PID
  assert.equal(row(evaluate(observerIsTarget, { expectations: measurableOnly }), 'OB-run').verdict, 'unknown')
  const otherUser = idealRun('high')
  find(otherUser.observe.records, 'process.identity').observed.userSid = 'S-1-5-21-111-222-333-2002'
  assert.equal(row(evaluate(otherUser, { expectations: measurableOnly }), 'OB-process').verdict, 'mismatch')
})

test('counterexample: a between-sample exit, PID reuse or token failure refuses that sample', () => {
  // The producer re-queries the declared PID before each sample's active
  // operations. A sample whose gate failed must carry its refused process
  // record and no RM/share/range records, and must never borrow the previous
  // sample's verdict.
  const exited = idealRun('high', 2)
  const gate = find(exited.observe.records, 'process.sample', 2)
  gate.observed = { ok: true, pid: CODEX_PID, opened: true, state: 'exited' }
  exited.observe.records = exited.observe.records.filter((r) => r.sample !== 2 ||
    !['openers.rm', 'share.read_rwd', 'share.delete_rwd', 'range.probe', 'thread.identity_after'].includes(r.step))
  const s = evaluate(exited, { expectations: measurableOnly })
  assert.equal(row(s, 'OB-process-sample').verdict, 'unknown')
  assert.ok(row(s, 'OB-process-sample').reasons.some((x) => x.startsWith('schema_missing:createFiletime#2')))
  for (const id2 of ['OB-openers', 'OB-share-read-rwd', 'OB-range-rust', 'OB-thread-stable']) {
    assert.equal(row(s, id2).collected, 'partial', id2)
    assert.equal(row(s, id2).verdict, 'unknown', id2)
  }
  assert.equal(s.w7, 'unknown')
  // A PID reused between samples, a changed integrity and a foreign user are
  // each a measured mismatch of that sample, not of the run as a whole.
  for (const [patch, reason] of [
    [{ createFiletime: '132000000000000999' }, 'create_filetime_changed#1'],
    [{ pid: CODEX_PID + 1 }, 'queried_pid_differs_from_run#1'],
    [{ userSid: 'S-1-5-21-111-222-333-2002' }, 'target_user_differs_from_observer#1'],
    [{ integritySid: INTEGRITY.medium }, 'integrity_sid_changed#1'],
    [{ image: 'C:\\Windows\\other.exe' }, 'image_differs_from_manifest_binary#1'],
  ]) {
    const run = idealRun('high', 2)
    Object.assign(find(run.observe.records, 'process.sample', 1).observed, patch)
    const r = row(evaluate(run, { expectations: measurableOnly }), 'OB-process-sample')
    assert.equal(r.verdict, 'mismatch', JSON.stringify(patch))
    assert.ok(r.reasons.includes(reason), `${JSON.stringify(patch)}: ${r.reasons.join(',')}`)
  }
})

test('counterexample: the manifest must be reconstructible from the raw preflight records', () => {
  // Home and its IDs moved to another disposable directory in the manifest and
  // in observe, while preflight still validates the first one.
  const moved = idealRun('high')
  const manifest = find(moved.preflight.records, 'manifest').observed
  Object.assign(manifest, { home: HOME_B, parent: PARENT_B, homeFileId: id(12), parentFileId: id(11) })
  find(moved.observe.records, 'home.identity').observed = { ok: true, ...homeFields(HOME_B, PARENT_B, id(12), id(11)) }
  const s = evaluate(moved, { expectations: measurableOnly })
  assert.equal(row(s, 'PF-manifest').verdict, 'mismatch')
  assert.ok(row(s, 'PF-manifest').reasons.includes('manifest_home_differs_from_preflight'))
  assert.equal(s.w7, 'fail')
  // The hashed binary path and the recorded source commit must bind too.
  for (const [patch, reason] of [
    [{ binaryPath: 'C:\\other\\codex.exe' }, 'manifest_binaryPath_differs_from_preflight'],
    [{ binarySize: 999 }, 'manifest_binarySize_differs_from_preflight'],
    [{ version: 'codex-cli 9.9.9' }, 'manifest_version_differs_from_preflight'],
    [{ sourceCommit: 'a'.repeat(40) }, 'manifest_sourceCommit_differs_from_preflight'],
    [{ parentFileId: id(77) }, 'manifest_parentFileId_differs_from_preflight'],
  ]) {
    const run = idealRun('high')
    Object.assign(find(run.preflight.records, 'manifest').observed, patch)
    const r = row(evaluate(run, { expectations: measurableOnly }), 'PF-manifest')
    assert.equal(r.verdict, 'mismatch', JSON.stringify(patch))
    assert.ok(r.reasons.includes(reason), `${JSON.stringify(patch)}: ${r.reasons.join(',')}`)
  }
  // A preflight record the manifest depends on being unusable keeps it unknown.
  const broken = idealRun('high')
  find(broken.preflight.records, 'binary.sha256').observed = { ok: true, complete: false }
  const r2 = row(evaluate(broken, { expectations: measurableOnly }), 'PF-manifest')
  assert.equal(r2.verdict, 'unknown')
  assert.ok(r2.reasons.some((x) => x.startsWith('preflight_unusable:binary.sha256')))
  assert.deepEqual(reconstructManifest([], 'high').fields, null)
})

test('counterexample: a complete plus incomplete manifest pair, or a manifest that is not last, refuses', () => {
  const pair = idealRun('high')
  pair.preflight.records.push(rec('preflight', 'manifest', 'high', { ok: true, complete: false, reason: 'aborted' }))
  const s1 = evaluate(pair, { expectations: measurableOnly })
  assert.ok(s1.problems.includes('preflight:manifest_not_unique:2'))
  assert.ok(s1.problems.includes('preflight:duplicate:manifest#'))
  assert.equal(s1.w7, 'unknown')
  const notLast = idealRun('high')
  notLast.preflight.records.push(rec('preflight', 'host.os', 'high', { ok: true, os: 'x', ps: '5.1', elevated: false, sshSession: false }))
  const s2 = evaluate(notLast, { expectations: measurableOnly })
  assert.ok(s2.problems.includes('preflight:manifest_not_last'))
  const missing = idealRun('high')
  missing.preflight.records = missing.preflight.records.filter((r) => r.step !== 'host.volume')
  assert.ok(evaluate(missing).problems.includes('preflight:manifest_requires_one:host.volume:0'))
  const incompleteOnly = idealRun('high')
  find(incompleteOnly.preflight.records, 'manifest').observed = { ok: true, complete: false, reason: 'aborted' }
  const s3 = evaluate(incompleteOnly, { expectations: measurableOnly })
  assert.ok(s3.problems.includes('preflight:manifest_not_complete'))
  assert.ok(s3.problems.includes('manifest_unusable'))
})

test('access denial on the process maps to unknown, not mismatch', () => {
  const run = idealRun('medium')
  find(run.observe.records, 'process.identity').observed = { ok: true, pid: CODEX_PID, opened: false, state: 'unknown', reason: 'open_process', win32: 5 }
  const s = evaluate(run, { expectations: measurableOnly })
  assert.equal(row(s, 'OB-process').verdict, 'unknown')
  assert.deepEqual(row(s, 'OB-process').reasons, ['access_denied'])
})

test('partial, native error, exception and null observations are unknown', () => {
  for (const observed of [{ ok: true, complete: false }, { ok: false, win32: 2 }, { ok: true, exception: 'x' }, null]) {
    const run = idealRun('high')
    find(run.observe.records, 'openers.rm', 1).observed = observed
    const s = evaluate(run, { expectations: measurableOnly })
    assert.equal(row(s, 'OB-openers').verdict, 'unknown')
  }
})

test('counterexample: contradictory share, range and Restart Manager records are unknown', () => {
  const cases = [
    ['share.read_rwd', { opened: true, win32: 32, access: 'read', share: 'rwd' }, 'OB-share-read-rwd'],
    ['share.read_rwd', { opened: false, win32: 0, access: 'read', share: 'rwd' }, 'OB-share-read-rwd'],
    ['share.delete_rwd', { opened: true, win32: 5, access: 'delete', share: 'rwd' }, 'OB-share-delete-rwd'],
  ]
  for (const [step, patch, id2] of cases) {
    const run = idealRun('high')
    find(run.observe.records, step, 1).observed = { ok: true, ...patch }
    assert.equal(row(evaluate(run, { expectations: measurableOnly }), id2).verdict, 'unknown', `${step} ${JSON.stringify(patch)}`)
  }
  // A held range cannot also be acquired, and an acquired range must report a release.
  for (const patch of [{ rust: { win32: 33, acquired: true, released: false } }, { rust: { win32: 0, acquired: true, released: false } },
    { fsext: { win32: 0, acquired: false, released: null } }, { tail: { win32: 33, acquired: false, released: true } }]) {
    const run = idealRun('high')
    for (const r of run.observe.records.filter((x) => x.step === 'range.probe')) r.observed.ranges = ranges(patch)
    const s = evaluate(run, { expectations: measurableOnly })
    assert.equal(row(s, 'OB-range-rust').verdict, 'unknown', JSON.stringify(patch))
    assert.ok(row(s, 'OB-range-rust').reasons.some((x) => x.includes('invariant:ranges_consistent')))
  }
  // A probed state with an unreleased guard, or a hardlinked target, is contradictory.
  for (const patch of [{ guardReleased: false }, { guardAcquired: false }, { guardLinks: 2 }, { threadLinks: 2 }, { threadDeletePending: true }]) {
    const run = idealRun('high')
    for (const r of run.observe.records.filter((x) => x.step === 'range.probe')) Object.assign(r.observed, patch)
    assert.equal(row(evaluate(run, { expectations: measurableOnly }), 'OB-range-guard').verdict, 'unknown', JSON.stringify(patch))
  }
  // Restart Manager: count, entry types, roles and interpretation must agree.
  const rmCases = [
    [{ count: 2 }, 'unknown'],
    [{ interpretation: 'holders' }, 'unknown'],
    [{ processes: [{ pid: CODEX_PID, startFiletime: 132, role: 'launched_codex', app: 'c', service: null, type: 1, session: 1 }] }, 'unknown'],
    [{ processes: [{ pid: 0, startFiletime: CREATE, role: 'launched_codex', app: 'c', service: null, type: 1, session: 1 }] }, 'unknown'],
    [{ processes: [{ pid: CODEX_PID, startFiletime: CREATE, role: 'holder', app: 'c', service: null, type: 1, session: 1 }] }, 'unknown'],
    [{
      count: 2,
      processes: [
        { pid: CODEX_PID, startFiletime: CREATE, role: 'launched_codex', app: 'c', service: null, type: 1, session: 1 },
        { pid: CODEX_PID, startFiletime: CREATE, role: 'launched_codex', app: 'c', service: null, type: 1, session: 1 },
      ],
    }, 'unknown'],
    [{ processes: [{ pid: CODEX_PID, startFiletime: CREATE, role: 'other', app: 'c', service: null, type: 1, session: 1 }] }, 'mismatch'],
    [{ processes: [{ pid: CODEX_PID, startFiletime: '132000000000000999', role: 'launched_codex', app: 'c', service: null, type: 1, session: 1 }] }, 'mismatch'],
    [{ processes: [{ pid: OBSERVER_PID, startFiletime: CREATE, role: 'other', app: 'c', service: null, type: 1, session: 1 }] }, 'mismatch'],
  ]
  for (const [patch, want] of rmCases) {
    const run = idealRun('high')
    for (const r of run.observe.records.filter((x) => x.step === 'openers.rm')) Object.assign(r.observed, patch)
    assert.equal(row(evaluate(run, { expectations: measurableOnly }), 'OB-openers').verdict, want, JSON.stringify(patch))
  }
})

test('counterexample: the guarded probe must bind to that sample\'s guard and directory', () => {
  for (const [patch, reason] of [
    [{ guardFileId: id(55) }, 'guard_identity_differs'],
    [{ guardFileIdAfter: id(55) }, 'guard_identity_differs'],
    [{ dirFileIdAfter: id(55) }, 'lock_directory_identity_differs'],
    [{ threadFileIdBefore: id(55) }, 'thread_identity_differs'],
  ]) {
    const run = idealRun('high')
    Object.assign(find(run.observe.records, 'range.probe', 1).observed, patch)
    const r = row(evaluate(run, { expectations: measurableOnly }), 'OB-range-guard')
    assert.equal(r.verdict, 'mismatch', JSON.stringify(patch))
    assert.ok(r.reasons.includes(`${reason}#1`), r.reasons.join(','))
  }
  // Without that sample's own identity records the binding is unknown.
  const run = idealRun('high')
  find(run.observe.records, 'coordination.identity', 1).observed = { ok: true, state: 'unknown', reason: 'guard_open' }
  const r = row(evaluate(run, { expectations: measurableOnly }), 'OB-range-guard')
  assert.equal(r.verdict, 'unknown')
  assert.ok(r.reasons.includes('coordination_identity_missing#1'))
})

test('a held range ending at the fs-ext boundary is a mismatch', () => {
  const run = idealRun('high')
  for (const r of run.observe.records.filter((x) => x.step === 'range.probe')) {
    r.observed.ranges = ranges({ beyond_fsext: { win32: 0, acquired: true, released: true } })
  }
  const s = evaluate(run, { expectations: measurableOnly })
  assert.equal(row(s, 'OB-range-beyond-fsext').verdict, 'mismatch')
  assert.equal(row(s, 'OB-range-rust').verdict, 'match')
  assert.equal(s.w7, 'fail')
})

test('a live process whose image differs from the manifest binary is a mismatch', () => {
  const run = idealRun('high')
  find(run.observe.records, 'process.identity').observed.image = 'C:\\Windows\\System32\\other.exe'
  const s = evaluate(run, { expectations: measurableOnly })
  assert.equal(row(s, 'OB-process').verdict, 'mismatch')
})

test('a changed creation FILETIME or PID after the samples is a mismatch', () => {
  const changed = idealRun('high')
  find(changed.observe.records, 'process.identity_after').observed.createFiletime = '132000000000000001'
  const s1 = evaluate(changed, { expectations: measurableOnly })
  assert.equal(row(s1, 'OB-process-after').verdict, 'mismatch')
  assert.equal(row(s1, 'OB-run').verdict, 'mismatch')
  const exited = idealRun('high')
  find(exited.observe.records, 'process.identity_after').observed.state = 'exited'
  assert.equal(row(evaluate(exited, { expectations: measurableOnly }), 'OB-process-after').verdict, 'mismatch')
})

test('a changed thread identity across a sample is a mismatch', () => {
  for (const patch of [{ fileId: id(33) }, { links: 2 }, { deletePending: true }]) {
    const run = idealRun('high')
    Object.assign(find(run.observe.records, 'thread.identity_after', 1).observed, patch)
    const s = evaluate(run, { expectations: measurableOnly })
    assert.equal(row(s, 'OB-thread-stable').verdict, 'mismatch', JSON.stringify(patch))
  }
})

test('an orchestrator_error record invalidates the whole file', () => {
  const run = idealRun('high')
  run.observe.records.push(rec('observe', 'orchestrator_error', 'high', { ok: false, exception: 'boom' }))
  const s = evaluate(run, { expectations: measurableOnly })
  assert.ok(s.problems.includes('observe:orchestrator_error'))
  assert.equal(s.w7, 'unknown')
  assert.ok(s.rows.filter((r) => r.mode === 'observe').every((r) => r.verdict === 'unknown'))
})

test('an unexpected step invalidates the file', () => {
  const run = idealRun('high')
  run.observe.records.push(rec('observe', 'surprise.step', 'high', { ok: true }))
  const s = evaluate(run, { expectations: measurableOnly })
  assert.ok(s.problems.includes('observe:unexpected_step:surprise.step'))
})

test('a harness expectation that drifts from the table is unknown', () => {
  const run = idealRun('high')
  find(run.observe.records, 'range.probe', 1).expect = { state: 'probed', 'ranges.rust.win32': 0 }
  const s = evaluate(run, { expectations: measurableOnly })
  assert.ok(row(s, 'OB-range-rust').reasons.includes('expectation_drift#1'))
})

test('mixed integrity in one file makes it unusable', () => {
  const run = idealRun('medium')
  run.observe.records[3].integrity = { label: 'high', sid: INTEGRITY.high }
  const s = evaluate(run, { expectations: measurableOnly })
  assert.ok(s.problems.includes('observe:mixed_integrity'))
  assert.ok(s.rows.filter((r) => r.mode === 'observe').every((r) => r.verdict === 'unknown'))
})

test('a declared label that disagrees with the measured SID is never relabelled', () => {
  const run = idealRun('medium')
  for (const r of [...run.preflight.records, ...run.observe.records]) r.integrity.sid = INTEGRITY.high
  const s = evaluate(run, { expectedLabel: 'medium', expectations: measurableOnly })
  assert.equal(s.label, null)
  assert.ok(s.problems.includes('preflight:integrity_label_sid_mismatch'))
  assert.ok(s.problems.includes('expected_label_mismatch'))
})

test('home isolation is recomputed from the recorded paths, owner, DACL and ancestry', () => {
  const base = { ...homeFields(), empty: true, entries: [] }
  assert.equal(recomputeIsolation(base), true)
  assert.equal(recomputeIsolation({ ...base, home: `${USER_HOME}\\tmp`, parent: USER_HOME }), false)
  assert.equal(recomputeIsolation({ ...base, envCodexHome: TEMP, envRelation: 'inside' }), false)
  assert.equal(recomputeIsolation({ ...base, userRelation: 'same' }), false)
  assert.equal(recomputeIsolation({ ...base, aceCount: 2 }), false)
  assert.equal(recomputeIsolation({ ...base, daclProtected: false }), false)
  assert.equal(recomputeIsolation({ ...base, owner: 'S-1-5-18' }), false)
  assert.equal(recomputeIsolation({ ...base, aceIdentity: 'S-1-1-0' }), false)
  assert.equal(recomputeIsolation({ ...base, aceRights: 'Read' }), false)
  assert.equal(recomputeIsolation({ ...base, parentAceInheritance: 'None' }), false)
  assert.equal(recomputeIsolation({ ...base, empty: false, entries: ['x'] }), false)
  // Structure: the home must be exactly the disposable parent's `home` child.
  assert.equal(recomputeIsolation({ ...base, home: `${PARENT}\\other` }), false)
  assert.equal(recomputeIsolation({ ...base, home: `${PARENT}\\home\\deeper` }), false)
  assert.equal(recomputeIsolation({ ...base, parent: TEMP, home: `${TEMP}\\home`, ancestry: ancestry(TEMP, PARENT_ID) }), false)
  // A reparse point anywhere in the recorded ancestry refuses the home.
  const junction = ancestry(PARENT, PARENT_ID)
  junction[2] = { ...junction[2], reparse: true }
  assert.equal(recomputeIsolation({ ...base, ancestry: junction }), false)
  assert.equal(recomputeIsolation({ ...base, ancestry: [] }), false)
  assert.equal(recomputeIsolation({ ...base, ancestry: [{ path: PARENT, fileId: 'bad', directory: true, reparse: false }] }), false)
  // A field that is absent makes the recomputation impossible, not false.
  assert.equal(recomputeIsolation({ ...base, ancestry: null }), null)
  assert.equal(recomputeIsolation({ ...base, currentUserSid: null }), null)
  assert.equal(recomputeIsolation({ ...base, fileId: 'bad' }), null)
  assert.equal(recomputeIsolation({ ...base, home: 'relative' }), null)
})

test('cross-level runs are reported alone and never paired', () => {
  const cross = evaluate(idealRun('medium', 2, 'high'), { expectations: measurableOnly })
  assert.equal(cross.variant, 'cross_level')
  assert.equal(cross.codexLabel, 'high')
  const p = pairSummaries(cross, evaluate(idealRun('high')))
  assert.ok(p.problems.includes('cross_level_run_not_pairable'))
  assert.notEqual(p.status, 'compared')
  const missing = idealRun('medium')
  delete find(missing.observe.records, 'run').observed.codexLabel
  assert.ok(evaluate(missing).problems.includes('codex_label_missing'))
})

test('W6 pairing compares levels side by side without carrying results', () => {
  const m = evaluate(idealRun('medium'), { expectedLabel: 'medium' })
  const h = evaluate(idealRun('high'), { expectedLabel: 'high' })
  const p = pairSummaries(m, h)
  assert.equal(p.status, 'compared')
  assert.deepEqual(p.differences, [])
  assert.deepEqual(p.provenanceFailures, [])
  assert.ok(p.rows.every((r) => r.id !== 'OB-coordination-range'))
  assert.equal(p.safeToUnlock, false)
})

test('identical mismatches at both levels are a fail, not compared', () => {
  const runM = idealRun('medium')
  const runH = idealRun('high')
  for (const run of [runM, runH]) find(run.observe.records, 'process.identity').observed.image = 'C:\\Windows\\other.exe'
  const p = pairSummaries(evaluate(runM), evaluate(runH))
  assert.ok(p.failedRows.includes('OB-process'))
  assert.equal(p.status, 'fail')
})

test('an explanation cannot erase a failed hypothesis', () => {
  const runM = idealRun('medium')
  const runH = idealRun('high')
  find(runM.observe.records, 'process.identity').observed.image = 'C:\\a.exe'
  find(runH.observe.records, 'process.identity').observed.image = 'C:\\b.exe'
  const p = pairSummaries(evaluate(runM), evaluate(runH), { 'OB-process': 'different images, explained' })
  assert.ok(p.failedRows.includes('OB-process'))
  assert.equal(p.status, 'fail')
})

test('a W6 difference needs an explanation and an unknown level stays unknown', () => {
  const runM = idealRun('medium')
  for (const r of runM.observe.records.filter((x) => x.step === 'openers.rm')) { r.observed.processes = []; r.observed.count = 0 }
  const m = evaluate(runM)
  const h = evaluate(idealRun('high'))
  const p1 = pairSummaries(m, h)
  assert.deepEqual(p1.differences, ['OB-openers'])
  assert.deepEqual(p1.unexplained, ['OB-openers'])
  assert.equal(p1.status, 'unknown')
  assert.equal(pairSummaries(m, h, { 'OB-openers': 'RM hides the High process from a Medium caller' }).status, 'compared')
})

test('W6 pairing refuses different harness, commit, binary, version, missing baseline or swapped labels', () => {
  const m = evaluate(idealRun('medium'))
  const h = evaluate(idealRun('high'))
  assert.ok(pairSummaries({ ...m, harness: { ...HARNESS, 'observer.ps1': '0'.repeat(64) } }, h).problems.includes('harness_differs'))
  assert.ok(pairSummaries({ ...m, harness: { 'observer.ps1': '0'.repeat(64) } }, h).problems.includes('harness_name_set'))
  assert.ok(pairSummaries({ ...m, sourceCommit: '1'.repeat(40) }, h).problems.includes('source_commit_differs'))
  assert.ok(pairSummaries({ ...m, binarySha256: '2'.repeat(64) }, h).problems.includes('binary_differs'))
  assert.ok(pairSummaries({ ...m, version: 'codex-cli 9.9.9' }, h).problems.includes('version_differs'))
  assert.ok(pairSummaries({ ...m, baselineProvided: false }, h).problems.includes('baseline_missing'))
  const swapped = pairSummaries(h, m)
  assert.ok(swapped.problems.includes('medium_label') && swapped.problems.includes('high_label'))
  assert.notEqual(swapped.status, 'compared')
})

// ---- fixture producer (unbound) --------------------------------------------
function labRun(label, overrides = {}, extra = []) {
  const whoami = label === 'high' ? 'Mandatory Label\\High Mandatory Level Label S-1-16-12288' : 'Mandatory Label\\Medium Mandatory Level Label S-1-16-8192'
  const records = [
    { scenario: 'environment', step: 'host', expect: null, observed: { ok: true, integrity: whoami }, verdict: 'recorded', safeToUnlock: false },
    { scenario: 'E1', step: 'free', expect: { state: 'free' }, observed: { ok: true, state: 'free' }, verdict: 'match', safeToUnlock: false },
    { scenario: 'E3', step: 'holder', expect: null, observed: { ok: true, complete: true, processes: [{ pid: 9, role: 'writer' }], count: 1 }, verdict: 'recorded', safeToUnlock: false },
    { scenario: 'identity', step: 'live', expect: { state: 'live_same_user' }, observed: { ok: true, state: 'live_same_user' }, verdict: 'match', safeToUnlock: false },
    ...extra,
  ]
  for (const [id2, patch] of Object.entries(overrides)) Object.assign(records.find((r) => `${r.scenario}/${r.step}` === id2), patch)
  const meta = [
    rec('fixture-meta', 'token.self', label, { ok: true, integritySid: INTEGRITY[label], integrityMatchesLabel: true }),
    rec('fixture-meta', 'fixture.harness', label, { ok: true, complete: true, files: { 'lab.ps1': '3'.repeat(64) }, sourceCommit: COMMIT }),
  ]
  return { lab: { records, problems: [] }, meta: { records: meta, problems: [] } }
}

test('fixture evidence is always unbound and never a successful gate', () => {
  const m = fixtureSummary({ ...labRun('medium'), expectedLabel: 'medium' })
  const h = fixtureSummary({ ...labRun('high'), expectedLabel: 'high' })
  assert.equal(m.bound, false)
  assert.equal(m.provenance.state, 'unvalidated')
  assert.ok(m.problems.includes('fixture_producer_unbound'))
  assert.ok(m.rows.every((r) => r.verdict === 'unknown'))
  const p = pairSummaries(m, h)
  assert.ok(p.problems.includes('fixture_evidence_not_pairable'))
  assert.notEqual(p.status, 'compared')
})

test('fixture counterexample 1: host-only logs do not compare', () => {
  const onlyHost = (label) => {
    const r = labRun(label)
    r.lab.records = r.lab.records.filter((x) => `${x.scenario}/${x.step}` === 'environment/host')
    return r
  }
  const m = fixtureSummary(onlyHost('medium'))
  const h = fixtureSummary(onlyHost('high'))
  assert.ok(m.problems.some((p) => p.startsWith('lab:missing_anchors')))
  assert.notEqual(pairSummaries(m, h).status, 'compared')
})

test('fixture counterexample 2: a null observation with verdict match is not success', () => {
  const m = fixtureSummary(labRun('medium', {}, [{ scenario: 'E1', step: 'null', expect: { state: 'free' }, observed: null, verdict: 'match', safeToUnlock: false }]))
  const nullRow = m.rows.find((r) => r.id === 'E1/null')
  assert.equal(nullRow.verdict, 'unknown')
  assert.ok(nullRow.reasons.includes('no_observation'))
  assert.notEqual(pairSummaries(m, fixtureSummary(labRun('high'))).status, 'compared')
})

test('fixture access failures and integrity disagreement are unknown', () => {
  const denied = fixtureSummary(labRun('medium', { 'identity/live': { observed: { ok: true, state: 'unknown', reason: 'open_process', win32: 5 }, verdict: 'mismatch' } }))
  assert.ok(denied.rows.find((r) => r.id === 'identity/live').reasons.includes('access_denied'))
  const run = labRun('medium')
  run.lab.records[0].observed.integrity = 'Mandatory Label\\High Mandatory Level Label S-1-16-12288'
  const wrong = fixtureSummary({ ...run, expectedLabel: 'medium' })
  assert.ok(wrong.problems.includes('lab_meta_integrity_differs'))
  assert.equal(wrong.label, null)
})

// ---- documentation and harness consistency ---------------------------------
const PS = readFileSync(join(root, 'observer.ps1'), 'utf8')
const CHECK = readFileSync(join(root, 'check.ps1'), 'utf8')
const CS = readFileSync(join(root, 'WinObserver.cs'), 'utf8')

// Code only: the prose in these files discusses the rules it must not break,
// so the source greps below run on the script with its comments removed.
// check.ps1 enforces the same rules on the real syntax tree.
function code(text) {
  return text.replace(/<#[\s\S]*?#>/g, '').replace(/#.*$/gm, '')
}
const PS_CODE = code(PS)
const CHECK_CODE = code(CHECK)

test('README embeds the generated expectation table verbatim', () => {
  const readme = readFileSync(join(root, 'README.md'), 'utf8')
  const start = readme.indexOf('<!-- expectations:start -->\n')
  const end = readme.indexOf('<!-- expectations:end -->')
  assert.ok(start >= 0 && end > start, 'README expectation markers')
  assert.equal(readme.slice(start + '<!-- expectations:start -->\n'.length, end), renderExpectationTable())
})

test('observer.ps1 hypotheses cover every raw-comparison row', () => {
  const block = (mode) => {
    const start = PS.indexOf(`'${mode}'`, PS.indexOf('$Expect = @{'))
    const end = PS.indexOf('\n    }', start)
    return PS.slice(start, end)
  }
  const literal = (v) => (v === true ? '$true' : v === false ? '$false' : typeof v === 'string' ? `'${v}'` : String(v))
  for (const e of EXPECTATIONS) {
    if (!e.hypothesis || e.derive || e.measurable === false) continue
    const line = block(e.mode).split('\n').find((l) => l.trimStart().startsWith(`'${e.step}'`))
    assert.ok(line, `observer.ps1 lacks ${e.mode} ${e.step}`)
    for (const [k, v] of Object.entries(e.hypothesis)) {
      const key = /^[A-Za-z][A-Za-z0-9]*$/.test(k) ? k : `'${k}'`
      assert.ok(line.includes(`${key} = ${literal(v)}`), `${e.id}: ${k}`)
    }
  }
})

test('every expectation step has a typed schema (or is not measurable)', () => {
  for (const e of EXPECTATIONS) {
    if (e.measurable === false) continue
    assert.ok(STEP_SCHEMAS[`${e.mode}:${e.step}`], `${e.id} missing schema`)
  }
})

test('harness sources contain no forbidden mutation or termination calls', () => {
  const forbidden = ['TerminateProcess', 'Stop-Process', 'taskkill', 'DeleteFile', 'Remove-Item', 'Set-ExecutionPolicy',
    /\s-ExecutionPolicy\b/, 'EncodedCommand', 'Set-MpPreference', 'Set-Acl', 'SetAccessControl', 'AdjustTokenPrivileges',
    'GenerateConsoleCtrlEvent', 'GENERIC_WRITE', 'CREATE_ALWAYS', 'OPEN_ALWAYS', 'MoveFile', 'SetFileInformationByHandle',
    'Invoke-WebRequest', 'Invoke-Expression', 'Start-Process', 'SetEnvironmentVariable', '.codex\\auth', 'auth.json']
  // check.ps1 names these commands on purpose: it refuses them in the syntax
  // tree, so it is checked separately below.
  for (const [name, text] of [['observer.ps1', PS], ['WinObserver.cs', CS]]) {
    for (const f of forbidden) assert.ok(typeof f === 'string' ? !text.includes(f) : !f.test(text), `${name} contains ${f}`)
  }
  for (const needle of ['$Forbidden = @(', 'forbidden command in', 'automatic variable write in']) {
    assert.ok(CHECK.includes(needle), `check.ps1 lost its syntax-tree gate: ${needle}`)
  }
})

test('the PowerShell harness name list is exactly the expected file-name set', () => {
  const match = PS.match(/\$HarnessNames\s*=\s*@\(([^)]*)\)/)
  assert.ok(match, 'observer.ps1 $HarnessNames not found')
  const names = match[1].split(',').map((s) => s.trim().replace(/^'|'$/g, '')).filter((s) => s.length > 0)
  assert.deepEqual([...names].sort(), [...HARNESS_FILES].sort())
})

test('no script assigns to the automatic $home variable', () => {
  // $HOME is a read-only automatic variable and PowerShell variable names are
  // case-insensitive, so `$home = ...` would fail at runtime. check.ps1 gates
  // this on the syntax tree; this test is the host-independent mirror.
  for (const [name, text] of [['observer.ps1', PS_CODE], ['check.ps1', CHECK_CODE]]) {
    // Only a line-leading assignment is a text smoke check. Mutation fixtures
    // deliberately contain forbidden assignments as string data; the actual
    // Windows AST gate checks scoped, array and unary write targets as well.
    assert.ok(!/^\s*\$home\s*=[^=]/im.test(text), `${name} assigns to $home`)
    assert.ok(!/^\s*\$(host|pid|error|matches|args|input|psitem|profile|pshome|executioncontext|true|false|null)\s*=[^=]/im.test(text),
      `${name} assigns to an automatic variable`)
  }
})

test('Add-Type runs only after the path and TEMP gate in both scripts', () => {
  for (const [name, text] of [['observer.ps1', PS_CODE], ['check.ps1', CHECK_CODE]]) {
    const gate = text.indexOf('$PathGate = Assert-PathGate')
    // The real compile site, not the name as data in check.ps1's own rules.
    const addType = text.search(/^\s*Add-Type -Path/m)
    assert.ok(gate > 0, `${name} has no Assert-PathGate call`)
    assert.ok(addType > gate, `${name} compiles before the path gate`)
  }
})

test('native preflight and observe stay hard-refused while the ancestry boundary is open', () => {
  assert.ok(/NATIVE_MODES_REFUSED\s*=\s*\$true/.test(PS), 'observer.ps1 lost its hard refusal switch')
  assert.ok(PS.includes('Refuse $NativeRefusalReason'), 'observer.ps1 does not refuse the native modes')
  // No bypass: nothing may turn the refusal off from the command line.
  assert.ok(!/param\([^)]*Force/is.test(PS), 'observer.ps1 gained a force-style parameter')
  assert.ok(!/\$env:[A-Z_]*(FORCE|BYPASS|ALLOW)/i.test(PS), 'observer.ps1 reads a bypass environment variable')
})

test('the creation gate refuses a TEMP inside a real home and skips creation', () => {
  assert.equal(tempRootSafeForCreation(TEMP, USER_HOME, null), true)
  assert.equal(tempRootSafeForCreation(`${USER_HOME}\\AppData\\Temp`, USER_HOME, null), false)
  assert.equal(tempRootSafeForCreation(TEMP, USER_HOME, `${TEMP}\\x`), false)
  assert.equal(tempRootSafeForCreation('relative', USER_HOME, null), false)
  assert.equal(tempRootSafeForCreation('\\\\?\\C:\\Temp', USER_HOME, null), false)
  let created = false
  const refused = guardedCreate(() => tempRootSafeForCreation(`${USER_HOME}\\Temp`, USER_HOME, null), () => { created = true; return { created: true } })
  assert.equal(created, false)
  assert.equal(refused.created, false)
  let created2 = false
  const ok = guardedCreate(() => tempRootSafeForCreation(TEMP, USER_HOME, null), () => { created2 = true; return { created: true } })
  assert.equal(created2, true)
  assert.equal(ok.created, true)
})

test('the per-sample seam does not run the active operations when its gate refuses', () => {
  // Mirror of Invoke-GuardedSample: a between-sample exit, PID reuse, failed
  // query or unreadable token must stop that sample before any enumeration,
  // Restart Manager, share or range operation.
  for (const reason of ['process_exited', 'create_filetime_changed', 'process_query_failed', 'token_unreadable', 'user_sid_differs']) {
    let ran = false
    const result = guardedSample(() => reason, () => { ran = true; return { probed: true } })
    assert.equal(ran, false, reason)
    assert.deepEqual(result, { ran: false, reason })
  }
  let ran2 = false
  const passed = guardedSample(() => null, () => { ran2 = true; return { probed: true } })
  assert.equal(ran2, true)
  assert.deepEqual(passed, { ran: true, result: { probed: true } })
})

test('check.ps1 exercises the real PowerShell pure helpers it gates', () => {
  for (const name of ['Get-PathRelation', 'Test-LocalPathSpelling', 'Test-InsideDisposableDir', 'Test-CandidateTempSafe',
    'Invoke-GuardedCreate', 'Invoke-GuardedSample', 'Read-BoundedStream', 'Get-OpenerRole', 'Test-Expect']) {
    assert.ok(CHECK.includes(`'${name}'`) || CHECK.includes(name), `check.ps1 does not exercise ${name}`)
    assert.ok(PS.includes(`function ${name}`), `observer.ps1 does not define ${name}`)
  }
})

test('the Restart Manager FILETIME stays a decimal string in the native layer', () => {
  assert.ok(CS.includes('\\"startFiletime\\":'), 'RmList no longer emits startFiletime')
  assert.ok(/startFiletime\\":\\"/.test(CS) || CS.includes('J(start.ToString())'), 'startFiletime must be a quoted decimal string')
})

test('source regressions found in review stay fixed', () => {
  // The home must get its own protected DACL: an inherited DACL is never
  // marked protected, so the isolation contract could never hold.
  assert.ok(PS_CODE.includes('[IO.Directory]::CreateDirectory($homeDir, $acl)'), 'home created without its own DACL')
  // The DELETE share probe needs the attribute-read right for its file-type check.
  assert.ok(CS.includes('want = DELETE | FILE_READ_ATTRIBUTES'), 'DELETE probe cannot classify its handle')
  // A failed guard release is never overwritten by a later revalidation reason.
  assert.ok(/if \(!guardReleased\)\s*\{/.test(CS), 'guard_unlock_failed can be overwritten')
  // The automatic-variable gate must see through scope prefixes.
  assert.ok(CHECK_CODE.includes('VariablePath.UserPath') && !CHECK_CODE.includes('VariablePath.UnqualifiedPath'),
    'check.ps1 must use the public Windows PowerShell variable-path property')
  assert.ok(CHECK_CODE.includes('Get-DeclaredVariableName') && CHECK_CODE.includes('global|local|script|private'),
    'the public UserPath must be checked through the scope-aware helper')
  // Each pure-helper group reports on its own.
  assert.ok((CHECK_CODE.match(/Invoke-CheckGroup '/g) ?? []).length >= 9, 'check.ps1 lost its per-group assertions')
})

test('deepEqualMap compares digest maps exactly and case-sensitively', () => {
  assert.equal(deepEqualMap({ a: 'x', b: 'y' }, { b: 'y', a: 'x' }), true)
  assert.equal(deepEqualMap({ a: 'x' }, { a: 'X' }), false)
  assert.equal(deepEqualMap({ a: 'x' }, { a: 'x', b: 'y' }), false)
  assert.equal(deepEqualMap({}, {}), false)
  assert.equal(deepEqualMap(null, { a: 'x' }), false)
})

test('ancestry must enumerate every root-to-parent component in order', () => {
  const base = homeFields()
  const chain = base.ancestry
  for (const bad of [chain.slice(-1), chain.slice(1), chain.filter((_, i) => i !== 2),
    [...chain].reverse(), [chain[0], chain[0], ...chain.slice(1)],
    [{ ...chain[0], path: 'D:\\' }, ...chain.slice(1)]]) {
    const run = idealRun('medium')
    find(run.preflight.records, 'home.isolated').observed.ancestry = bad
    const summary = evaluate(run)
    assert.notEqual(row(summary, 'PF-home').verdict, 'match')
    assert.notEqual(summary.provenance.state, 'validated')
    assert.notEqual(pairSummaries(summary, evaluate(idealRun('high'))).status, 'compared')
  }
})

test('self-token identity binds the run observer and both per-mode home owners', () => {
  const foreign = 'S-1-5-21-111-222-333-2002'
  const user = idealRun('medium')
  find(user.observe.records, 'run').observed.observerUserSid = foreign
  for (const record of user.observe.records.filter((r) => r.step.startsWith('process.'))) record.observed.userSid = foreign
  const summary = evaluate(user)
  assert.ok(row(summary, 'OB-run').reasons.includes('observer_user_differs_from_self_token'))
  assert.notEqual(summary.provenance.state, 'validated')

  const pid = idealRun('medium')
  find(pid.observe.records, 'run').observed.observerPid = 987
  assert.ok(row(evaluate(pid), 'OB-run').reasons.includes('observer_pid_differs_from_self_token'))

  for (const [mode, step, id2] of [['preflight', 'home.isolated', 'PF-home'], ['observe', 'home.identity', 'OB-home']]) {
    const run = idealRun('medium')
    const o = find(run[mode].records, step).observed
    for (const key of ['currentUserSid', 'owner', 'parentOwner', 'aceIdentity', 'parentAceIdentity']) o[key] = foreign
    const s = evaluate(run)
    assert.ok(row(s, id2).reasons.includes('home_user_differs_from_self_token'))
    assert.notEqual(s.provenance.state, 'validated')
  }
})

test('RM evidence must name exactly this sample thread and coordination files', () => {
  const files = find(idealRun('medium').observe.records, 'openers.rm', 1).observed.files
  for (const bad of [[], [null], [files[0]], [files[0], files[0]], ['C:\\other.lock', files[1]]]) {
    const run = idealRun('medium')
    find(run.observe.records, 'openers.rm', 1).observed.files = bad
    const s = evaluate(run)
    assert.notEqual(row(s, 'OB-openers').verdict, 'match')
    assert.notEqual(pairSummaries(s, evaluate(idealRun('high'))).status, 'compared')
  }
  const reordered = idealRun('medium')
  find(reordered.observe.records, 'openers.rm', 1).observed.files.reverse()
  assert.equal(row(evaluate(reordered), 'OB-openers').verdict, 'match')
})

test('sample identity paths must bind to the manifest home and selected thread', () => {
  for (const step of ['lockdir.identity', 'coordination.identity', 'thread.identity', 'thread.identity_after']) {
    for (const bad of ['C:\\elsewhere\\t.lock', '\\\\?\\UNC\\host\\share\\t.lock']) {
      const run = idealRun('medium')
      find(run.observe.records, step, 1).observed.finalPath = bad
      const s = evaluate(run)
      assert.notEqual(row(s, 'OB-openers').verdict, 'match', step)
      assert.notEqual(row(s, 'OB-range-guard').verdict, 'match', step)
    }
  }
  const run = idealRun('medium')
  find(run.observe.records, 'thread.count', 1).observed.entries = ['.coordination.lock', '..\\t.lock']
  assert.notEqual(row(evaluate(run), 'OB-openers').verdict, 'match')
})

test('share probe evidence fixes its exact requested access and sharing mode', () => {
  for (const [step, id2, access] of [['share.read_rwd', 'OB-share-read-rwd', 'delete'], ['share.delete_rwd', 'OB-share-delete-rwd', 'read']]) {
    for (const patch of [{ access }, { share: 'r' }, { share: 'rw' }]) {
      const run = idealRun('medium')
      Object.assign(find(run.observe.records, step, 1).observed, patch)
      assert.equal(row(evaluate(run), id2).verdict, 'unknown')
    }
  }
})

test('missing whole steps, late process re-query and interleaved samples are unknown', () => {
  const missing = idealRun('medium')
  missing.observe.records = missing.observe.records.filter((r) => r.step !== 'range.probe')
  assert.ok(evaluate(missing).problems.includes('observe:missing_sample_step:range.probe'))

  const late = idealRun('medium')
  const gate = find(late.observe.records, 'process.sample', 1)
  late.observe.records = late.observe.records.filter((r) => r !== gate)
  late.observe.records.splice(late.observe.records.indexOf(find(late.observe.records, 'range.probe', 1)) + 1, 0, gate)
  const s = evaluate(late)
  assert.ok(s.problems.includes('observe:sample_sequence_invalid'))
  assert.equal(s.w7, 'unknown')
  assert.notEqual(pairSummaries(s, evaluate(idealRun('high'))).status, 'compared')

  const interleaved = idealRun('medium')
  const next = find(interleaved.observe.records, 'process.sample', 2)
  interleaved.observe.records = interleaved.observe.records.filter((r) => r !== next)
  interleaved.observe.records.splice(interleaved.observe.records.indexOf(find(interleaved.observe.records, 'range.probe', 1)), 0, next)
  assert.ok(evaluate(interleaved).problems.includes('observe:sample_sequence_invalid'))
})
