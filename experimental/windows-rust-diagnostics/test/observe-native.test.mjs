import assert from 'node:assert/strict';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { response, requests, threadId, RpcTranscript, parseDiagnostic, parsePreviewDiagnostic, parseObserverOptions, runVerifiedDiagnostic, isEntryPoint, nativeArguments, requireAbsent, knownFolders, KNOWN_FOLDER_QUERY, validateThreadConfiguration } from '../observe-native.mjs';
test('responses need exactly one outcome and the expected ID', () => {
  assert.deepEqual(response({ id: 1, result: {} }, 1), {});
  for (const record of [null, [], { id: 1 }, { id: 1, result: {}, error: {} }, { id: 2, result: {} }, { id: 1, error: {} }]) {
    assert.throws(() => response(record, 1));
  }
});

const home = 'C:\\private\\home';
const thread = '11111111-2222-4333-8444-555555555555';
const request = { command: 'inspect', home, thread, pid: 1234 };
const envelope = { schemaVersion: 1, experimental: true, safeToUnlock: false, platform: 'windows' };
const record = (value, code = 0) => ({ stdout: JSON.stringify(value), exit: { code, signal: null }, faults: [], complete: true });
function liveValue() {
  const snap = (leaf) => ({ volume: '1234567890abcdef', file_id: '0123456789abcdef0123456789abcdef',
    final_path: `\\\\?\\${home}\\thread-writer-locks\\${leaf}`, links: 1, directory: false,
    size: '0', write_time: '133000000000000000', change_time: '133000000000000000' });
  return { ...envelope, requestedPid: request.pid, lock: { state: 'held', reason: null, win32: null },
    observation: { state: 'held', coordination: 'acquired_and_released', range: 'offset_0_length_18446744073709551615',
      filesystem: 'NTFS', fileOwnerSelf: true, holder: 'unproven', guard: snap('.coordination.lock'), thread: snap(`${thread}.lock`),
      process: { state: 'observed', evidence: 'requested_pid_only_not_holder', pid: request.pid, live: true,
        startTime: '133000000000000000', image: 'C:\\codex.exe', sameUser: true, sessionId: 1, integrityRid: 8192 } } };
}
test('diagnostic accepts complete typed observations, including unknown lock and process', () => {
  assert.equal(parseDiagnostic(record(liveValue()), request).parsed.lock.state, 'held');
  const unavailable = { ...envelope, requestedPid: request.pid, lock: { state: 'unknown', reason: 'open_failed', win32: 2 },
    observation: { state: 'unknown', reason: 'open_failed', win32: 2, process: liveValue().observation.process } };
  assert.equal(parseDiagnostic(record(unavailable, 2), request).parsed.lock.state, 'unknown');
  const missingPid = liveValue();
  missingPid.observation.process = { state: 'unknown', reason: 'process_open_failed', win32: 87 };
  assert.equal(parseDiagnostic(record(missingPid, 2), request).parsed.observation.process.state, 'unknown');
  const after = liveValue();
  after.requestedPid = null;
  after.observation.process = null;
  assert.equal(parseDiagnostic(record(after), { ...request, pid: null }).parsed.observation.process, null);
});
test('diagnostic rejects minimal output, wrong platform, snapshot, process and exit contradictions', () => {
  assert.throws(() => parseDiagnostic(record({ schemaVersion: 1, safeToUnlock: false }), request));
  const mutations = [
    (v) => { v.platform = 'linux'; }, (v) => { v.experimental = false; }, (v) => { v.safeToUnlock = true; },
    (v) => { v.holderAttribution = 'proven'; }, (v) => { v.recoveryAvailable = true; },
    (v) => { v.requestedPid += 1; }, (v) => { v.lock.state = 'free'; }, (v) => { v.lock.reason = 'unexpected'; },
    (v) => { delete v.observation.coordination; }, (v) => { v.observation.holder = 'proven'; },
    (v) => { v.observation.fileOwnerSelf = false; }, (v) => { v.observation.range = 'partial'; },
    (v) => { v.observation.guard.links = 2; }, (v) => { v.observation.thread.directory = true; },
    (v) => { v.observation.guard.file_id = '123'; }, (v) => { v.observation.thread.volume = 'bad'; },
    (v) => { v.observation.guard.size = 0; }, (v) => { v.observation.thread.size = '-1'; },
    (v) => { v.observation.guard.write_time = '9223372036854775808'; },
    (v) => { v.observation.thread.final_path = 'C:\\elsewhere'; },
    (v) => { v.observation.process.pid += 1; }, (v) => { v.observation.process.live = false; },
    (v) => { v.observation.process.startTime = 133000000; }, (v) => { v.observation.process.sameUser = false; },
    (v) => { v.observation.process = null; }, (v) => { v.observation.process = { state: 'unknown' }; },
  ];
  for (const mutate of mutations) {
    const value = liveValue(); mutate(value);
    assert.throws(() => parseDiagnostic(record(value), request), mutate.toString());
  }
  assert.throws(() => parseDiagnostic(record(liveValue(), 2), request));
  assert.throws(() => parseDiagnostic(record(liveValue(), 64), request));
  const unknown = { ...envelope, requestedPid: null, lock: { state: 'unknown', reason: 'open_failed', win32: 2 },
    observation: { state: 'unknown', reason: 'open_failed', win32: 2, process: null } };
  assert.throws(() => parseDiagnostic(record(unknown), { ...request, pid: null }));
  unknown.observation.guard = liveValue().observation.guard;
  assert.throws(() => parseDiagnostic(record(unknown, 2), { ...request, pid: null }));
});
test('capabilities require the supported Windows contract and exit zero', () => {
  const value = { ...envelope, prototypeVersion: '0.0.0', architecture: 'x86_64', diagnosticsAvailable: true,
    recoveryAvailable: false, holderAttribution: 'unproven', commands: ['capabilities', 'inspect'],
    supportedFilesystems: ['NTFS'], probeEffects: 'brief exclusive locks' };
  assert.equal(parseDiagnostic(record(value), { command: 'capabilities' }).parsed.prototypeVersion, '0.0.0');
  for (const [key, invalid] of [['diagnosticsAvailable', false], ['recoveryAvailable', true], ['commands', ['inspect']],
    ['supportedFilesystems', ['NTFS', 'ReFS']], ['prototypeVersion', null], ['holderAttribution', 'proven'], ['architecture', null], ['probeEffects', '']]) {
    assert.throws(() => parseDiagnostic(record({ ...value, [key]: invalid }), { command: 'capabilities' }));
  }
  assert.throws(() => parseDiagnostic(record(value, 2), { command: 'capabilities' }));
  assert.throws(() => parseDiagnostic(record({ ...value, authorization: 'granted' }), { command: 'capabilities' }));
});
const previewEnvelope = () => ({ schema: 'codex-unlock-windows-preview', schemaVersion: 1, preview: true,
  experimental: true, version: '0.0.0', platform: 'windows', architecture: 'x86_64', safeToUnlock: false,
  recoveryAvailable: false, context: { state: 'observed', integrityRid: 8192, elevated: false, appContainer: false },
  diagnosticsAvailable: true });
function previewInspect() {
  const diagnostic = liveValue();
  return { ...previewEnvelope(), command: 'inspect', requestedPid: request.pid,
    requestedPidEvidence: 'requested_pid_only_not_holder', lock: { ...diagnostic.lock }, diagnostic,
    reason: 'diagnostic_observation_only' };
}
test('preview observer validates Medium context and nested observation without losing raw output', () => {
  const value = previewInspect();
  const result = parsePreviewDiagnostic(record(value), request);
  assert.deepEqual(result.preview, value);
  assert.deepEqual(result.parsed, value.diagnostic);
  assert.equal(result.stdout, JSON.stringify(value));
  const mutations = [
    (v) => { v.context.integrityRid = 12288; }, (v) => { v.context.elevated = true; },
    (v) => { v.context.appContainer = true; }, (v) => { delete v.context.elevated; },
    (v) => { v.diagnosticsAvailable = false; }, (v) => { v.safeToUnlock = true; },
    (v) => { v.requestedPid += 1; }, (v) => { v.lock.state = 'free'; },
    (v) => { v.reason = 'requested_process_unverified'; }, (v) => { delete v.diagnostic; },
    (v) => { v.diagnostic.observation.process.pid += 1; }, (v) => { v.schema = 'other'; },
    (v) => { v.extra = true; }, (v) => { v.context.state = 'unknown'; },
  ];
  for (const mutate of mutations) {
    const changed = previewInspect(); mutate(changed);
    assert.throws(() => parsePreviewDiagnostic(record(changed), request), mutate.toString());
  }
  assert.throws(() => parsePreviewDiagnostic(record(value, 2), request));
});
test('preview capabilities must prove the supported caller context before native observation', () => {
  const value = { ...previewEnvelope(), command: 'capabilities', commands: ['capabilities', 'inspect'],
    supportedFilesystems: ['NTFS'], holderAttribution: 'unproven', reason: 'diagnostic_preview_available' };
  assert.equal(parsePreviewDiagnostic(record(value), { command: 'capabilities' }).parsed.version, '0.0.0');
  for (const changed of [{ ...value, diagnosticsAvailable: false }, { ...value, reason: 'current_token_unknown' },
    { ...value, commands: ['capabilities', 'inspect', 'unlock'] }, { ...value, architecture: 'aarch64' },
    { ...value, context: { state: 'unknown', reason: 'token_open_failed', win32: 5 } }]) {
    assert.throws(() => parsePreviewDiagnostic(record(changed), { command: 'capabilities' }));
  }
});
test('preview prerelease outputs require the matching expected manifest version', () => {
  const value = { ...previewInspect(), version: '0.5.0-alpha.1' };
  const expected = { ...request, expectedVersion: '0.5.0-alpha.1' };
  assert.equal(parsePreviewDiagnostic(record(value), expected).preview.version, expected.expectedVersion);
  assert.throws(() => parsePreviewDiagnostic(record(value), request));
  assert.throws(() => parsePreviewDiagnostic(record(value), { ...expected, expectedVersion: '0.5.0-alpha.2' }));
  assert.throws(() => parsePreviewDiagnostic(record({ ...value, version: '0.5.0-alpha.01' }),
    { ...expected, expectedVersion: '0.5.0-alpha.01' }));
});
test('research capabilities accept valid prerelease Cargo versions', () => {
  const value = { ...envelope, prototypeVersion: '0.5.0-alpha.1', architecture: 'x86_64', diagnosticsAvailable: true,
    commands: ['capabilities', 'inspect'], supportedFilesystems: ['NTFS'], holderAttribution: 'unproven',
    recoveryAvailable: false, probeEffects: 'brief native locks' };
  assert.equal(parseDiagnostic(record(value), { command: 'capabilities' }).parsed.prototypeVersion, '0.5.0-alpha.1');
  assert.throws(() => parseDiagnostic(record({ ...value, prototypeVersion: '0.5.0-alpha.01' }), { command: 'capabilities' }));
});
test('diagnostic digest checks block changed input and retain executed records after drift', async () => {
  const pin = 'a'.repeat(64);
  let calls = 0;
  const run = async () => { calls += 1; return record(liveValue()); };
  await assert.rejects(runVerifiedDiagnostic('diag.exe', [], {}, 'C:\\lab', pin,
    { digest: async () => 'b'.repeat(64), run }), /diagnostic_changed_before_launch/);
  assert.equal(calls, 0);
  const stable = await runVerifiedDiagnostic('diag.exe', [], {}, 'C:\\lab', pin, { digest: async () => pin, run });
  assert.deepEqual(stable.faults, []);
  for (const after of ['b'.repeat(64), new Error('read failure')]) {
    let hashes = 0;
    const changed = await runVerifiedDiagnostic('diag.exe', [], {}, 'C:\\lab', pin, {
      run, digest: async () => { hashes += 1; if (hashes === 1) return pin; if (after instanceof Error) throw after; return after; },
    });
    assert.equal(changed.stdout, JSON.stringify(liveValue()));
    assert.equal(changed.faults.length, 1);
    assert.throws(() => parseDiagnostic(changed, request), /diagnostic_incomplete/);
  }
  assert.equal(calls, 3);
});
test('preview observer requires a manifest diagnostic digest without changing research defaults', () => {
  const args = ['--binary', 'C:\\codex.exe', '--sha256', 'a'.repeat(64), '--diagnostic', 'C:\\diag.exe',
    '--parent', 'C:\\private', '--result', 'C:\\private\\result.json'];
  assert.equal(parseObserverOptions(args).diagnosticFormat, 'research');
  assert.throws(() => parseObserverOptions([...args, '--diagnostic-format', 'preview']), /diagnostic_digest_required/);
  for (const pin of ['', 'bad', 'a'.repeat(63)]) {
    assert.throws(() => parseObserverOptions([...args, '--diagnostic-format', 'preview', '--diagnostic-sha256', pin]));
  }
  const pinned = [...args, '--diagnostic-format', 'preview', '--diagnostic-sha256', 'b'.repeat(64)];
  assert.throws(() => parseObserverOptions(pinned), /diagnostic_version_required/);
  assert.throws(() => parseObserverOptions([...pinned, '--diagnostic-version', '0.5.0-alpha.01']), /diagnostic_version_required/);
  const valid = [...pinned, '--diagnostic-version', '0.5.0-alpha.1'];
  assert.equal(parseObserverOptions(valid).options['--diagnostic-sha256'], 'b'.repeat(64));
  assert.equal(parseObserverOptions(valid).options['--diagnostic-version'], '0.5.0-alpha.1');
  assert.throws(() => parseObserverOptions([...valid, '--diagnostic-sha256', 'c'.repeat(64)]), /usage/);
});
function completeTranscript() {
  const transcript = new RpcTranscript();
  const messages = requests(home);
  transcript.sent(messages[0]); transcript.accept({ id: 1, result: {} });
  transcript.sent(messages[1]); transcript.sent(messages[2]); transcript.accept({ id: 2, result: { thread: { id: thread } } });
  return transcript;
}
test('RPC checks response IDs at arrival and rejects server requests and mixed envelopes', () => {
  for (const invalid of [{ id: 1, result: {}, method: 'notice' }, { id: 1, method: 'request', params: {} },
    { id: 1, result: {}, error: {} }, { id: 2, result: {} }, { method: 'notice', result: {} },
    { method: 'notice', error: {} }, { method: 'notice', params: null }, null, [], { jsonrpc: '1.0', id: 1, result: {} }]) {
    const transcript = new RpcTranscript(); transcript.sent(requests(home)[0]);
    assert.throws(() => transcript.accept(invalid));
  }
  const unsolicited = new RpcTranscript();
  assert.throws(() => unsolicited.accept({ id: 1, result: {} }));
  const early = new RpcTranscript(); early.sent(requests(home)[0]); early.accept({ id: 1, result: {} });
  assert.throws(() => early.accept({ id: 2, result: {} }));
});
test('RPC EOF validates trailing duplicates, malformed records, and partial lines', () => {
  completeTranscript().finish([{ method: 'thread/closed', params: {} }], 0);
  for (const duplicate of [{ id: 1, result: {} }, { id: 2, result: {} }, { id: 3, result: {} }]) {
    assert.throws(() => completeTranscript().finish([duplicate], 0));
  }
  assert.throws(() => completeTranscript().line('{broken'));
  assert.throws(() => completeTranscript().finish([], 1));
  assert.throws(() => completeTranscript().finish([{ invalidJson: true }], 0));
  assert.throws(() => new RpcTranscript().finish([], 0));
  assert.throws(() => completeTranscript().sent({ method: 'turn/start', id: 3 }));
});
test('entrypoint uses both real paths and Windows-only case folding', () => {
  const resolutions = [];
  const moduleUrl = 'file:///C:/source/observe.mjs';
  const resolve = (input) => { resolutions.push(input); return input === 'junction-entry' ? 'C:\\Real\\OBSERVER.mjs' : 'c:\\real\\observer.mjs'; };
  assert.equal(isEntryPoint('junction-entry', moduleUrl, 'win32', resolve), true);
  assert.deepEqual(resolutions, ['junction-entry', fileURLToPath(moduleUrl)]);
  assert.equal(isEntryPoint('junction-entry', moduleUrl, 'darwin', resolve), false);
  assert.equal(isEntryPoint('other', moduleUrl, 'win32', (input) => input), false);
});
test('thread identity must be a UUID, never a path', () => {
  assert.equal(threadId({ thread: { id: '11111111-2222-4333-8444-555555555555' } }), '11111111-2222-4333-8444-555555555555');
  for (const id of ['', '../other', '123', null]) assert.throws(() => threadId({ thread: { id } }));
});
test('fixed protocol cannot start a model turn or authentication', () => {
  const protocol = requests('C:\\private\\home');
  assert.deepEqual(protocol.map((item) => item.method), ['initialize', 'initialized', 'thread/start']);
  assert.equal(protocol[2].params.approvalPolicy, 'never');
  assert.equal(protocol[2].params.sandbox, 'read-only');
  assert.equal(protocol[2].params.ephemeral, false);
  assert.equal(JSON.stringify(protocol).includes('turn/start'), false);
});
test('pinned native startup uses a no-auth loopback provider and disables startup extensions', () => {
  const args = nativeArguments(12345);
  assert.equal(args.at(-1), 'app-server');
  assert.ok(args.includes('cli_auth_credentials_store="file"'));
  assert.ok(args.includes('features.shell_snapshot=false'));
  assert.ok(args.includes('features.hooks=false'));
  assert.ok(args.includes('features.plugins=false'));
  assert.ok(args.includes('features.code_mode_prewarm=false'));
  assert.ok(args.includes('project_root_markers=[]'));
  const provider = args.find((item) => item.startsWith('model_providers.research='));
  assert.ok(provider.includes('base_url="http://127.0.0.1:12345/v1"'));
  assert.ok(provider.includes('requires_openai_auth=false'));
  assert.ok(provider.includes('supports_websockets=false'));
  for (const port of [0, 65536, 1.5, '12345', NaN]) assert.throws(() => nativeArguments(port));
  assert.equal(requests('C:\\lab')[2].params.modelProvider, 'research');
});
test('startup path gate accepts only observed absence, never denial or reparse', async () => {
  const directory = { isSymbolicLink: () => false, isDirectory: () => true };
  const missing = Object.assign(new Error('missing'), { code: 'ENOENT' });
  await requireAbsent('C:\\ProgramData\\OpenAI\\Codex\\config.toml', async () => { throw missing; });
  await assert.rejects(requireAbsent('C:\\ProgramData\\OpenAI\\Codex\\config.toml', async () => directory), /external_startup_configuration_present/);
  await assert.rejects(requireAbsent('C:\\ProgramData\\OpenAI\\Codex\\config.toml', async () => ({ ...directory, isSymbolicLink: () => true })), /startup_path_reparse/);
  await assert.rejects(requireAbsent('C:\\ProgramData\\OpenAI\\Codex\\config.toml', async () => { throw Object.assign(new Error('denied'), { code: 'EACCES' }); }), /startup_path_unreadable/);
});
test('known-folder bases must be valid UTF-8 and existing plain directories before absence checks', async () => {
  const value = { profile: 'C:\\Users\\한글', common: 'C:\\ProgramData' };
  const seen = [];
  assert.deepEqual(await knownFolders(value, async (candidate) => { seen.push(candidate); return candidate; }), value);
  assert.deepEqual(seen, [value.profile, value.common]);
  assert.ok(KNOWN_FOLDER_QUERY.startsWith('[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);'));
  await assert.rejects(knownFolders({ ...value, profile: 'C:\\Users\\\uFFFD' }), /known_folders_unverified/);
  await assert.rejects(knownFolders(value, async () => { throw Object.assign(new Error('missing base'), { code: 'ENOENT' }); }), /missing base/);
});
test('effective thread model and read-only approval/network configuration are enforced', () => {
  const value = { model: 'research-no-turn', modelProvider: 'research', approvalPolicy: 'never', sandbox: { type: 'readOnly', networkAccess: false } };
  validateThreadConfiguration(value);
  for (const changed of [{ ...value, approvalPolicy: 'on-request' }, { ...value, model: 'other' },
    { ...value, modelProvider: 'openai' }, { ...value, sandbox: { type: 'readOnly', networkAccess: true } },
    { ...value, sandbox: { type: 'dangerFullAccess', networkAccess: false } }, { ...value, sandbox: null }]) {
    assert.throws(() => validateThreadConfiguration(changed), /effective_configuration_unverified/);
  }
});
