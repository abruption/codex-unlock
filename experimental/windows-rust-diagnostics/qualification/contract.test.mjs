import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import path from 'node:path';
import test from 'node:test';
import { CASES, HARNESS_FILES, Frames, readyRecord, validateInputs, validateCase, validatePairIdentity, validateHigh, evaluate, summary } from './contract.mjs';

function inputs() {
  const hash = 'a'.repeat(64);
  const input = { schemaVersion: 1, sourceSha: 'b'.repeat(40), version: '0.5.0-rc.1', releaseManifestSha256: hash,
    cliSha256: hash, fixtureSha256: hash, metadataSha256: hash, securityEvidenceSha256: hash,
    harness: Object.fromEntries(HARNESS_FILES.map(x => [x, hash])),
    expectedHost: { windowsBuild: '19045', securityProduct: 'Kaspersky Endpoint Security for Windows' } };
  const release = { schemaVersion: 1, sourceSha: input.sourceSha, target: 'x86_64-pc-windows-msvc', binary: { name: 'codex-unlock-windows.exe', version: input.version, sha256: hash } };
  const metadata = { schemaVersion: 1, windowsBuild: '19045', architecture: 'x64', integrityRid: 8192, elevated: false, appContainer: false,
    defenderRealtimeEnabled: false, security: { product: input.expectedHost.securityProduct, realtimeActiveVerified: true, exclusionsReviewed: true, evidenceSource: 'operator verified vendor CLI output', evidenceSha256: hash },
    executionPolicy: 'RemoteSigned', parent: { path: 'C:\\scratch', ownerSelf: true, protectedDacl: true, writeAccessSelfOnly: true } };
  return { input, release, metadata };
}
test('release, version, source and all transitive harness inputs are bound', () => {
  const { input, release, metadata } = inputs();
  assert.equal(validateInputs(input, release, metadata), true);
  for (const mutate of [
    x => { x.release.binary.version = '0.5.0-alpha.1'; },
    x => { x.release.sourceSha = 'c'.repeat(40); },
    x => { x.release.binary.sha256 = 'c'.repeat(64); },
    x => { delete x.input.harness['scripts/validate-preview.mjs']; },
    x => { x.input.harness.extra = 'a'.repeat(64); },
    x => { x.input.fixtureSha256 = 'bad'; },
    x => { x.input.version = '0.6.0'; },
    x => { x.metadata.security.evidenceSha256 = 'c'.repeat(64); },
    x => { x.metadata.security.realtimeActiveVerified = 'true'; },
    x => { x.metadata.security.exclusionsReviewed = 'true'; },
    x => { delete x.metadata.security.exclusionsReviewed; },
    x => { x.metadata.parent.ownerSelf = false; },
  ]) { const x = inputs(); mutate(x); assert.throws(() => validateInputs(x.input, x.release, x.metadata)); }
});
test('reported Kaspersky profile is distinct from Defender and cannot silently qualify another profile', () => {
  for (const mutate of [x => { x.metadata.security.realtimeActiveVerified = false; }, x => { x.metadata.security.exclusionsReviewed = false; }, x => { x.metadata.security.product = 'unknown'; }, x => { x.metadata.windowsBuild = '22631'; }]) {
    const x = inputs(); mutate(x); assert.equal(validateInputs(x.input, x.release, x.metadata), false);
  }
});
test('framing preserves split multibyte data and multiple complete records', () => {
  const f = new Frames(), bytes = Buffer.from('{"value":"진단"}\n{"event":"finished"}\n');
  for (const b of bytes) f.push(Buffer.from([b])); f.finish();
  assert.deepEqual(f.rows, [{ value: '진단' }, { event: 'finished' }]); assert.deepEqual(f.faults, []);
});
test('partial, malformed, oversize and invalid UTF8 frames are refused', () => {
  for (const bytes of [Buffer.from('{"event":"ready"}'), Buffer.from('null\n'), Buffer.from('[]\n'), Buffer.from('not-json\n'), Buffer.alloc(16385, 120), Buffer.alloc(262145, 120), Buffer.from([123, 34, 120, 34, 58, 34, 255, 34, 125, 10])]) {
    const f = new Frames(); f.push(bytes); f.finish(); assert.ok(f.faults.length > 0);
  }
  const flooded = new Frames(); for (let i = 0; i < 20; i++) flooded.push(Buffer.alloc(262145));
  assert.deepEqual(flooded.faults, ['stream_limit']); assert.equal(flooded.pending.length, 0);
});
test('fixture ready must bind the spawned PID and its exact fresh home', () => {
  const r = { event: 'ready', home: 'C:\\scratch\\codex-windows-rust-fixture-123-456\\home', root: 'C:\\scratch\\codex-windows-rust-fixture-123-456', thread: '11111111-2222-4333-8444-555555555555', pid: 123, mode: 'thread', safeToUnlock: false, synthetic: true };
  const request = { pid: 123, mode: 'thread', parent: 'C:\\scratch' };
  readyRecord(r, request, path.win32);
  for (const change of [{ pid: 456 }, { home: 'C:\\real-home' }, { root: 'C:\\other\\codex-windows-rust-fixture-123-456' }, { synthetic: false }, { mode: 'free' }, { thread: '../other' }]) assert.throws(() => readyRecord({ ...r, ...change }, request, path.win32));
});
function report() { return { mode: 'medium', version: '0.5.0-rc.1', sourceSha: 'b'.repeat(40), hostQualified: true, inputsUnchanged: true,
  errors: [], cases: CASES.map(id => ({ id, ok: true })), identityPairs: [{ before: 'held', after: 'free', unchanged: true }, { before: 'unicode_held', after: 'unicode_free', unchanged: true }],
  cleanup: Array.from({ length: 4 }, () => ({ complete: true, code: 0, signal: null, faults: [], rootAbsent: true })) }; }
test('missing, duplicate, reordered or failed cases cannot pass', () => {
  assert.equal(evaluate(report()).ok, true);
  for (const mutate of [r => { r.cases.pop(); }, r => { r.cases.push(r.cases[0]); }, r => { r.cases.reverse(); }, r => { r.cases[0].ok = false; }, r => { r.cases[0] = null; }, r => { r.inputsUnchanged = false; }]) {
    const r = report(); mutate(r); assert.equal(evaluate(r).ok, false);
  }
  assert.equal(evaluate({}).ok, false);
});
test('incomplete cleanup, failed child or input drift invalidate collection', () => {
  for (const change of [{ code: 3 }, { signal: 'SIGTERM' }, { complete: false }, { rootAbsent: false }, { faults: ['stdin_error'] }, { faults: null }]) {
    const r = report(); Object.assign(r.cleanup[0], change); assert.equal(evaluate(r).collected, false);
  }
  const r = report(); r.cleanup.pop(); assert.equal(evaluate(r).ok, false);
  const missingPair = report(); missingPair.identityPairs.pop(); assert.equal(evaluate(missingPair).ok, false);
});
test('release pairs preserve native identities and metadata even when only one field changes', () => {
  const make = () => ({ parsed: { observation: {
    guard: { volume: 'a'.repeat(16), file_id: 'b'.repeat(32), final_path: 'C:\\fixture\\guard', size: '0', write_time: '1', change_time: '1' },
    thread: { volume: 'a'.repeat(16), file_id: 'c'.repeat(32), final_path: 'C:\\fixture\\thread', size: '0', write_time: '1', change_time: '1' },
  } } });
  validatePairIdentity(make(), make());
  for (const role of ['guard', 'thread']) for (const change of [{ volume: 'd'.repeat(16) }, { file_id: 'd'.repeat(32) }, { file_id: '123' }, { final_path: 'C:\\other' }, { size: '1' }, { write_time: '2' }, { change_time: '2' }, { change_time: undefined }]) {
    const after = make(); Object.assign(after.parsed.observation[role], change);
    assert.throws(() => validatePairIdentity(make(), after));
  }
});
test('collected cases do not claim the host qualification gate when protection is unverified', () => {
  const r = report(); r.hostQualified = false;
  assert.equal(evaluate(r).collected, true); assert.equal(evaluate(r).ok, false);
});
test('public summary omits private errors, PID, paths and unexpected case identifiers', () => {
  const r = report(); r.errors = ['private C:\\secret PID=123']; r.cases[0].id = 'private C:\\secret'; r.cleanup[0].pid = 123;
  const text = JSON.stringify(summary(r)); assert.ok(!text.includes('secret')); assert.ok(!text.includes('123')); assert.ok(text.includes('unknown_case'));
});
test('free with unverified requested PID stays an unsuccessful diagnostic, never holder authority', () => {
  const request = { pid: 4294967295, expectedVersion: '0.5.0-rc.1' };
  const r = { preview: { version: request.expectedVersion, context: { state: 'observed', integrityRid: 8192, elevated: false, appContainer: false }, safeToUnlock: false, recoveryAvailable: false, requestedPid: 4294967295, requestedPidEvidence: 'requested_pid_only_not_holder' }, exit: { code: 2 },
    parsed: { lock: { state: 'free' }, observation: { holder: 'unproven', coordination: 'acquired_and_released', process: { state: 'unknown' } } } };
  validateCase('missing_pid', r, request);
  r.preview.version = '0.5.0-alpha.1'; assert.throws(() => validateCase('missing_pid', r, request)); r.preview.version = request.expectedVersion;
  r.exit.code = 0; assert.throws(() => validateCase('missing_pid', r, request));
  r.exit.code = 2; r.parsed.observation.holder = 'proven'; assert.throws(() => validateCase('missing_pid', r, request));
});
test('High refusal binds real token, schema/version and omitted native observation', () => {
  const contract = { schema: 'codex-unlock-windows', releaseChannel: 'rc', preview: true, experimental: true };
  const host = { integrityRid: 12288, elevated: true, appContainer: false };
  const value = { ...contract, schemaVersion: 1, version: '0.5.0-rc.1', platform: 'windows', architecture: 'x86_64', safeToUnlock: false, recoveryAvailable: false,
    command: 'inspect', context: { state: 'observed', ...host }, diagnosticsAvailable: false, reason: 'elevated_context_refused', requestedPid: 4294967295,
    requestedPidEvidence: 'requested_pid_only_not_holder', lock: { state: 'unknown', reason: 'elevated_context_refused', win32: null } };
  const record = v => ({ complete: true, exit: { code: 2, signal: null }, faults: [], stderr: '', stdout: JSON.stringify(v) });
  validateHigh(record(value), 'inspect', '0.5.0-rc.1', contract, host);
  for (const change of [{ version: '0.5.0-alpha.1' }, { safeToUnlock: true }, { diagnostic: {} }, { context: { ...value.context, integrityRid: 8192 } }, { requestedPid: 1 }, { lock: { state: 'free' } }]) {
    assert.throws(() => validateHigh(record({ ...value, ...change }), 'inspect', '0.5.0-rc.1', contract, host));
  }
  for (const change of [{ complete: false }, { exit: { code: 0, signal: null } }, { faults: ['stdout_limit'] }]) assert.throws(() => validateHigh({ ...record(value), ...change }, 'inspect', '0.5.0-rc.1', contract, host));
});

test('junction coverage requires the reparse refusal, not an unrelated unknown result', () => {
  const request = { pid: null, expectedVersion: '0.5.0-rc.1' };
  const result = { preview: { version: request.expectedVersion, context: { state: 'observed', integrityRid: 8192, elevated: false, appContainer: false }, safeToUnlock: false, recoveryAvailable: false, requestedPid: null, requestedPidEvidence: 'requested_pid_only_not_holder' },
    exit: { code: 2 }, parsed: { lock: { state: 'unknown', reason: 'unsafe_file_type_or_links', win32: null } } };
  validateCase('junction', result, request);
  result.parsed.lock.reason = 'open_existing_failed';
  assert.throws(() => validateCase('junction', result, request));
});
