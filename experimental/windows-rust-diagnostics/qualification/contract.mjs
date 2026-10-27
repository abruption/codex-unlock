import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { TextDecoder } from 'node:util';

export const HARNESS_FILES = ['qualification/run.mjs', 'qualification/contract.mjs', 'observe-native.mjs', 'scripts/validate-preview.mjs'].sort();
export const CASES = ['held', 'free', 'busy_guard', 'missing_guard', 'missing_thread', 'hardlink_guard', 'hardlink_thread', 'junction', 'missing_pid', 'unrelated_pid', 'unicode_held', 'unicode_free'];
export const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const sha = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const closed = (value, keys) => assert.deepEqual(Object.keys(value).sort(), [...keys].sort());

export function validateInputs(input, release, metadata) {
  closed(input, ['schemaVersion', 'sourceSha', 'version', 'releaseManifestSha256', 'cliSha256', 'fixtureSha256', 'metadataSha256', 'securityEvidenceSha256', 'harness', 'expectedHost']);
  assert.equal(input.schemaVersion, 1);
  assert.match(input.sourceSha, /^[a-f0-9]{40}$/);
  assert.ok(['0.5.0-alpha.1', '0.5.0-rc.1', '0.5.0'].includes(input.version));
  for (const key of ['releaseManifestSha256', 'cliSha256', 'fixtureSha256', 'metadataSha256', 'securityEvidenceSha256']) assert.ok(sha(input[key]), key);
  closed(input.harness, HARNESS_FILES);
  for (const value of Object.values(input.harness)) assert.ok(sha(value));
  closed(input.expectedHost, ['windowsBuild', 'securityProduct']);
  assert.equal(input.expectedHost.windowsBuild, '19045', 'designated Windows 10 host profile');
  assert.equal(input.expectedHost.securityProduct, 'Kaspersky Endpoint Security for Windows');
  assert.equal(release.schemaVersion, 1);
  assert.equal(release.sourceSha, input.sourceSha);
  assert.equal(release.target, 'x86_64-pc-windows-msvc');
  assert.equal(release.binary.name, 'codex-unlock-windows.exe');
  assert.equal(release.binary.version, input.version);
  assert.equal(release.binary.sha256, input.cliSha256);
  closed(metadata, ['schemaVersion', 'windowsBuild', 'architecture', 'integrityRid', 'elevated', 'appContainer', 'defenderRealtimeEnabled', 'security', 'executionPolicy', 'parent']);
  assert.equal(metadata.schemaVersion, 1);
  assert.match(metadata.windowsBuild, /^\d{5}$/);
  assert.equal(metadata.architecture, 'x64');
  assert.ok(Number.isInteger(metadata.integrityRid) && metadata.integrityRid > 0);
  for (const key of ['elevated', 'appContainer', 'defenderRealtimeEnabled']) assert.equal(typeof metadata[key], 'boolean');
  closed(metadata.security, ['product', 'realtimeActiveVerified', 'exclusionsReviewed', 'evidenceSource', 'evidenceSha256']);
  assert.equal(typeof metadata.security.product, 'string');
  assert.equal(typeof metadata.security.realtimeActiveVerified, 'boolean');
  assert.equal(typeof metadata.security.exclusionsReviewed, 'boolean');
  assert.ok(typeof metadata.security.evidenceSource === 'string' && metadata.security.evidenceSource.length > 0);
  assert.equal(metadata.security.evidenceSha256, input.securityEvidenceSha256);
  assert.ok(typeof metadata.executionPolicy === 'string' && metadata.executionPolicy.length > 0);
  closed(metadata.parent, ['path', 'ownerSelf', 'protectedDacl', 'writeAccessSelfOnly']);
  for (const key of ['ownerSelf', 'protectedDacl', 'writeAccessSelfOnly']) assert.equal(metadata.parent[key], true);
  assert.equal(typeof metadata.parent.path, 'string');
  return metadata.windowsBuild === input.expectedHost.windowsBuild
    && metadata.security.product === input.expectedHost.securityProduct
    && metadata.security.realtimeActiveVerified === true
    && metadata.security.exclusionsReviewed === true;
}

export class Frames {
  constructor() { this.pending = Buffer.alloc(0); this.bytes = 0; this.rows = []; this.faults = []; }
  fault(kind) { if (!this.faults.includes(kind)) this.faults.push(kind); }
  push(chunk) {
    this.bytes += chunk.length;
    if (this.bytes > 262144) { this.fault('stream_limit'); this.pending = Buffer.alloc(0); return; }
    this.pending = Buffer.concat([this.pending, chunk]);
    let at;
    while ((at = this.pending.indexOf(10)) >= 0) {
      const bytes = this.pending.subarray(0, at);
      this.pending = this.pending.subarray(at + 1);
      if (bytes.length > 16384) { this.fault('line_limit'); continue; }
      try {
        const row = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
        assert.ok(row && typeof row === 'object' && !Array.isArray(row));
        this.rows.push(row);
      } catch { this.fault('malformed_frame'); }
    }
    if (this.pending.length > 16384) { this.fault('line_limit'); this.pending = Buffer.alloc(0); }
  }
  finish() { if (this.pending.length) this.fault('partial_frame'); }
}

export function readyRecord(row, { pid, mode, parent }, path) {
  closed(row, ['event', 'home', 'root', 'thread', 'pid', 'mode', 'safeToUnlock', 'synthetic']);
  assert.equal(row.event, 'ready');
  assert.equal(row.pid, pid);
  assert.equal(row.mode, mode);
  assert.equal(row.safeToUnlock, false);
  assert.equal(row.synthetic, true);
  assert.equal(path.dirname(row.root), parent);
  assert.match(path.basename(row.root), new RegExp(`^codex-windows-rust-fixture-${pid}-[0-9]+$`));
  assert.equal(row.home, path.join(row.root, 'home'));
  assert.equal(row.thread, '11111111-2222-4333-8444-555555555555');
  return row;
}

export function validateCase(id, result, request) {
  assert.ok(CASES.includes(id));
  const p = result.parsed;
  assert.equal(result.preview.version, request.expectedVersion);
  assert.deepEqual(result.preview.context, { state: 'observed', integrityRid: 8192, elevated: false, appContainer: false });
  assert.equal(result.preview.safeToUnlock, false);
  assert.equal(result.preview.recoveryAvailable, false);
  assert.equal(result.preview.requestedPid, request.pid);
  assert.equal(result.preview.requestedPidEvidence, 'requested_pid_only_not_holder');
  const state = ['held', 'unrelated_pid', 'unicode_held'].includes(id) ? 'held'
    : ['free', 'missing_pid', 'unicode_free'].includes(id) ? 'free' : 'unknown';
  assert.equal(p.lock.state, state);
  assert.equal(result.exit.code, state === 'unknown' || id === 'missing_pid' ? 2 : 0);
  if (state !== 'unknown') {
    assert.equal(p.observation.holder, 'unproven');
    assert.equal(p.observation.coordination, 'acquired_and_released');
  }
  if (id === 'busy_guard') assert.equal(p.lock.reason, 'coordination_busy');
  if (id.startsWith('missing_') && id !== 'missing_pid') {
    assert.equal(p.lock.reason, 'open_existing_failed');
    assert.equal(p.lock.win32, 2);
  }
  if (id.startsWith('hardlink_') || id === 'junction') assert.equal(p.lock.reason, 'unsafe_file_type_or_links');
  if (id === 'missing_pid') assert.equal(p.observation.process.state, 'unknown');
  if (request.pid !== null && id !== 'missing_pid') {
    assert.equal(p.observation.process.pid, request.pid);
    assert.equal(p.observation.process.live, true);
    assert.equal(p.observation.process.sameUser, true);
    assert.equal(p.observation.process.integrityRid, 8192);
  }
}

export function validatePairIdentity(before, after) {
  for (const role of ['guard', 'thread']) {
    const a = before.parsed.observation[role], b = after.parsed.observation[role];
    for (const snapshot of [a, b]) {
      assert.match(snapshot.volume, /^[a-f0-9]{16}$/);
      assert.match(snapshot.file_id, /^[a-f0-9]{32}$/);
      assert.equal(typeof snapshot.final_path, 'string');
      assert.match(snapshot.size, /^(0|[1-9]\d*)$/);
      assert.match(snapshot.write_time, /^(0|-?[1-9]\d*)$/);
      assert.match(snapshot.change_time, /^(0|-?[1-9]\d*)$/);
    }
    // Native FILE_ID_INFO is 128-bit; never substitute Node's numeric inode.
    const select = s => ({ volume: s.volume, file_id: s.file_id, final_path: s.final_path,
      size: s.size, write_time: s.write_time, change_time: s.change_time });
    assert.deepEqual(select(b), select(a), `${role} identity or metadata changed across release`);
  }
}

export function validateHigh(record, command, version, contract, host) {
  assert.ok(record.complete && record.exit?.signal === null && Array.isArray(record.faults) && record.faults.length === 0 && record.stderr === '');
  assert.equal(record.exit.code, command === 'capabilities' ? 0 : 2);
  const value = JSON.parse(record.stdout);
  const keys = ['schema', 'schemaVersion', 'preview', 'experimental', 'version', 'platform', 'architecture', 'safeToUnlock', 'recoveryAvailable', 'command', 'context', 'diagnosticsAvailable', 'reason'];
  if (contract.releaseChannel !== undefined) keys.push('releaseChannel');
  keys.push(...(command === 'capabilities' ? ['commands', 'supportedFilesystems', 'holderAttribution'] : ['requestedPid', 'requestedPidEvidence', 'lock']));
  closed(value, keys);
  assert.equal(value.command, command); assert.equal(value.schemaVersion, 1);
  assert.equal(value.platform, 'windows'); assert.equal(value.architecture, 'x86_64');
  for (const key of ['schema', 'preview', 'experimental']) assert.equal(value[key], contract[key]);
  assert.equal(value.releaseChannel, contract.releaseChannel);
  assert.equal(value.version, version); assert.equal(value.safeToUnlock, false); assert.equal(value.recoveryAvailable, false);
  assert.equal(value.diagnosticsAvailable, false); assert.equal(value.reason, 'elevated_context_refused');
  assert.ok(host.integrityRid >= 12288 && host.elevated === true && host.appContainer === false);
  assert.deepEqual(value.context, { state: 'observed', integrityRid: host.integrityRid, elevated: true, appContainer: false });
  if (command === 'capabilities') {
    assert.deepEqual(value.commands, ['capabilities', 'inspect']);
    assert.deepEqual(value.supportedFilesystems, ['NTFS']);
    assert.equal(value.holderAttribution, 'unproven');
  } else {
    assert.equal(value.requestedPid, 4294967295);
    assert.equal(value.requestedPidEvidence, 'requested_pid_only_not_holder');
    assert.deepEqual(value.lock, { state: 'unknown', reason: 'elevated_context_refused', win32: null });
  }
  return value;
}

export function evaluate(report) {
  if (!report || !Array.isArray(report.cases) || !Array.isArray(report.cleanup) || !Array.isArray(report.errors) || !Array.isArray(report.identityPairs)) return { collected: false, hostQualified: false, ok: false, errors: ['report_malformed'], safeToUnlock: false };
  const expected = report.mode === 'medium' ? CASES : ['high_capabilities', 'high_refusal'];
  // Detailed exceptions remain in the private report, never in public summaries.
  const errors = report.errors.map(() => 'collection_error');
  if (!['medium', 'high'].includes(report.mode)) errors.push('mode_unknown');
  if (JSON.stringify(report.cases.map(x => x?.id)) !== JSON.stringify(expected)) errors.push('case_coverage');
  if (report.cases.some(x => x?.ok !== true)) errors.push('case_failed');
  if (report.inputsUnchanged !== true) errors.push('input_drift_or_unverified');
  const pairs = report.mode === 'medium' ? [{ before: 'held', after: 'free', unchanged: true }, { before: 'unicode_held', after: 'unicode_free', unchanged: true }] : [];
  if (JSON.stringify(report.identityPairs) !== JSON.stringify(pairs)) errors.push('identity_pair_coverage');
  if (report.cleanup.length !== (report.mode === 'medium' ? 4 : 0)) errors.push('cleanup_coverage');
  if (report.cleanup.some(x => !x || x.complete !== true || x.code !== 0 || x.signal !== null || !Array.isArray(x.faults) || x.faults.length || x.rootAbsent !== true)) errors.push('cleanup_incomplete');
  const collected = errors.length === 0;
  return { collected, hostQualified: report.hostQualified === true, ok: collected && report.hostQualified === true,
    errors, safeToUnlock: false };
}

export function summary(report) {
  return { schemaVersion: 1, mode: ['medium', 'high'].includes(report.mode) ? report.mode : 'unknown',
    version: ['0.5.0-alpha.1', '0.5.0-rc.1', '0.5.0'].includes(report.version) ? report.version : 'unknown',
    sourceSha: /^[a-f0-9]{40}$/.test(report.sourceSha ?? '') ? report.sourceSha : null,
    ...evaluate(report), cases: report.cases.map(x => ({ id: [...CASES, 'high_capabilities', 'high_refusal'].includes(x?.id) ? x.id : 'unknown_case', ok: x?.ok === true })),
    cleanupComplete: report.cleanup.every(x => x.complete === true && x.code === 0 && x.rootAbsent === true) };
}
