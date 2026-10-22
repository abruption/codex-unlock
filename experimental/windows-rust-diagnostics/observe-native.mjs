// Operator-run, Windows-only observation of an isolated, self-started Codex.
// The existing parent must be a trusted private scratch directory. It is retained.
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { createHash } from 'node:crypto';
import { lstat, realpath, mkdtemp, open } from 'node:fs/promises';
import { realpathSync, createReadStream } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { performance } from 'node:perf_hooks';
import { Buffer } from 'node:buffer';
import { setTimeout, clearTimeout } from 'node:timers';
import { StringDecoder } from 'node:string_decoder';
import { fileURLToPath } from 'node:url';
import { versionPattern } from './scripts/validate-preview.mjs';

const CAP = 1024 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export function response(record, expectedId) {
  if (!record || typeof record !== 'object' || Array.isArray(record) || record.id !== expectedId) throw new Error('unexpected_response_id');
  if (Object.hasOwn(record, 'method') || (Object.hasOwn(record, 'jsonrpc') && record.jsonrpc !== '2.0')) throw new Error('response_envelope_invalid');
  const result = Object.hasOwn(record, 'result');
  const error = Object.hasOwn(record, 'error');
  if (result === error) throw new Error('contradictory_or_missing_outcome');
  if (error) throw new Error('rpc_rejected');
  return record.result;
}
export class RpcTranscript {
  outstanding = null;
  used = new Set();
  sentCount = 0;
  line(text) { return this.accept(JSON.parse(text)); }
  sent(message) {
    const expected = [{ method: 'initialize', id: 1 }, { method: 'initialized' }, { method: 'thread/start', id: 2 }][this.sentCount];
    if (!expected || this.outstanding !== null || message.method !== expected.method || message.id !== expected.id
      || Object.hasOwn(message, 'id') !== Object.hasOwn(expected, 'id')) throw new Error('request_sequence_invalid');
    this.sentCount += 1;
    if (Object.hasOwn(message, 'id')) this.outstanding = message.id;
  }
  accept(record) {
    if (!record || typeof record !== 'object' || Array.isArray(record)
      || (Object.hasOwn(record, 'jsonrpc') && record.jsonrpc !== '2.0')) throw new Error('malformed_rpc_record');
    if (Object.hasOwn(record, 'method')) {
      if (Object.hasOwn(record, 'result') || Object.hasOwn(record, 'error')) throw new Error('mixed_rpc_envelope');
      if (Object.hasOwn(record, 'id')) throw new Error('unexpected_server_request');
      if (typeof record.method !== 'string' || !record.method || Object.hasOwn(record, 'result') || Object.hasOwn(record, 'error')
        || (Object.hasOwn(record, 'params') && (record.params === null || typeof record.params !== 'object'))) throw new Error('malformed_notification');
      return null;
    }
    if (this.used.has(record.id)) throw new Error('duplicate_response');
    if (this.outstanding === null || record.id !== this.outstanding) throw new Error('unexpected_response_id');
    const id = this.outstanding;
    const value = response(record, id);
    this.used.add(id);
    this.outstanding = null;
    return { id, value };
  }
  finish(records, partialBytes) {
    for (const record of records) this.accept(record);
    if (partialBytes !== 0) throw new Error('unterminated_rpc_line');
    if (this.outstanding !== null || this.sentCount !== 3 || this.used.size !== 2) throw new Error('rpc_sequence_incomplete');
  }
}
export function threadId(result) {
  const id = result?.thread?.id;
  if (typeof id !== 'string' || !UUID.test(id)) throw new Error('invalid_thread_id');
  return id;
}
export function validateThreadConfiguration(result) {
  if (result?.modelProvider !== 'research' || result?.model !== 'research-no-turn'
    || result?.approvalPolicy !== 'never' || result?.sandbox?.type !== 'readOnly'
    || result?.sandbox?.networkAccess !== false) throw new Error('effective_configuration_unverified');
}
export function requests(home) {
  return [
    { id: 1, method: 'initialize', params: { clientInfo: { name: 'codex_unlock_observation', version: '0.0.0' } } },
    { method: 'initialized', params: {} },
    { id: 2, method: 'thread/start', params: { cwd: home, approvalPolicy: 'never', sandbox: 'read-only', ephemeral: false, model: 'research-no-turn', modelProvider: 'research' } },
  ];
}
function envFor(home, parent) {
  const env = {};
  for (const key of ['SystemRoot', 'SystemDrive', 'windir', 'COMSPEC', 'PATHEXT', 'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE']) {
    const found = Object.keys(process.env).find((item) => item.toLowerCase() === key.toLowerCase());
    if (found) env[key] = process.env[found];
  }
  return { ...env, CODEX_HOME: home, HOME: home, USERPROFILE: home, TEMP: parent, TMP: parent };
}
export function nativeArguments(port) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('invalid_loopback_port');
  const config = [
    'model_provider="research"', 'model="research-no-turn"',
    'cli_auth_credentials_store="file"', 'project_root_markers=[]',
    `model_providers.research={name="Isolated no-turn research",base_url="http://127.0.0.1:${port}/v1",wire_api="responses",supports_websockets=false,requires_openai_auth=false}`,
    'features.shell_snapshot=false', 'features.shell_snapshot_v2=false',
    'features.hooks=false', 'features.plugins=false', 'features.code_mode_prewarm=false',
  ];
  return [...config.flatMap((value) => ['-c', value]), 'app-server'];
}
async function loopbackTrap() {
  let connections = 0;
  const server = createServer((socket) => { connections += 1; socket.destroy(); });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  return { port: server.address().port, count: () => connections,
    close: () => new Promise((resolve) => server.close(resolve)) };
}
export async function requireAbsent(candidate, statPath = lstat) {
  const parts = path.win32.relative(path.win32.parse(candidate).root, candidate).split('\\');
  let current = path.win32.parse(candidate).root;
  for (let i = 0; i < parts.length; i += 1) {
    current = path.win32.join(current, parts[i]);
    let stat;
    try { stat = await statPath(current); }
    catch (error) { if (error.code === 'ENOENT') return; throw new Error('startup_path_unreadable', { cause: error }); }
    if (stat.isSymbolicLink()) throw new Error('startup_path_reparse');
    if (i === parts.length - 1) throw new Error('external_startup_configuration_present');
    if (!stat.isDirectory()) throw new Error('startup_parent_not_directory');
  }
}
export async function knownFolders(value, resolveDirectory = (input) => plainAbsolute(input, true)) {
  if (!value || typeof value.profile !== 'string' || typeof value.common !== 'string'
    || !/^[A-Za-z]:\\/.test(value.profile) || !/^[A-Za-z]:\\/.test(value.common)
    || value.profile.includes('\uFFFD') || value.common.includes('\uFFFD')) throw new Error('known_folders_unverified');
  // A corrupted or nonexistent base must never become proof of config absence.
  return { profile: await resolveDirectory(value.profile), common: await resolveDirectory(value.common) };
}
export const KNOWN_FOLDER_QUERY = '[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); [pscustomobject]@{profile=[Environment]::GetFolderPath("UserProfile");common=[Environment]::GetFolderPath("CommonApplicationData")} | ConvertTo-Json -Compress';
async function startupPreflight(env, home) {
  const powershell = path.win32.join(env.SystemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
  const result = await runOnce(powershell, ['-NoProfile', '-NonInteractive', '-Command', KNOWN_FOLDER_QUERY], env, home);
  if (result.exit?.code !== 0 || !result.complete || result.faults.length) throw new Error('known_folders_unverified');
  const folders = await knownFolders(JSON.parse(result.stdout));
  const systemRoot = path.win32.join(folders.common, 'OpenAI', 'Codex');
  const absent = [path.win32.join(systemRoot, 'config.toml'), path.win32.join(systemRoot, 'requirements.toml'),
    path.win32.join(systemRoot, 'skills')];
  for (const candidate of absent) await requireAbsent(candidate);
  const profileSkillsPath = path.win32.join(folders.profile, '.agents', 'skills');
  let profileSkills = 'absent';
  try {
    const metadata = await lstat(profileSkillsPath);
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) throw new Error('profile_skills_not_plain_directory');
    profileSkills = 'present_readonly_discovery';
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  return { state: 'system_configuration_absent', paths: absent, knownFolders: folders,
    profileSkills: { path: profileSkillsPath, state: profileSkills } };
}
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function launch(binary, args, env, cwd, rpcMode = false) {
  const child = spawn(binary, args, { env, cwd, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  const state = { pid: child.pid ?? null, exit: null, stdout: '', stderr: '', faults: [], complete: false };
  let stdoutBytes = 0, stderrBytes = 0, pending = Buffer.alloc(0);
  const records = [];
  const transcript = new RpcTranscript();
  let rpcUsed = rpcMode;
  let exitResolve;
  const exited = new Promise((resolve) => { exitResolve = resolve; });
  child.once('error', () => { state.faults.push('spawn_error'); });
  child.once('exit', (code, signal) => { state.exit = { code, signal }; });
  child.once('close', () => { state.complete = true; exitResolve(); });
  child.stdin.on('error', () => { state.faults.push('stdin_error'); });
  for (const [stream, key] of [[child.stdout, 'stdout'], [child.stderr, 'stderr']]) {
    const decoder = new StringDecoder('utf8');
    stream.on('end', () => { state[key] += decoder.end(); });
    stream.on('error', () => { state.faults.push(`${key}_error`); });
    stream.on('data', (chunk) => {
      const previous = key === 'stdout' ? stdoutBytes : stderrBytes;
      if (key === 'stdout') stdoutBytes += chunk.length; else stderrBytes += chunk.length;
      const usable = chunk.subarray(0, Math.max(0, CAP - previous));
      state[key] += decoder.write(usable);
      if (previous + chunk.length > CAP && !state.faults.includes(`${key}_limit`)) state.faults.push(`${key}_limit`);
      if (key === 'stdout') {
        pending = Buffer.concat([pending, usable]);
        let newline;
        while ((newline = pending.indexOf(10)) >= 0) {
          const line = pending.subarray(0, newline).toString('utf8');
          pending = pending.subarray(newline + 1);
          if (rpcUsed) {
            try {
              const received = transcript.line(line);
              if (received) records.push(received);
            } catch (error) { state.faults.push(error instanceof SyntaxError ? 'malformed_rpc_json' : error.message); }
          }
        }
      }
    });
  }
  const wait = async (ms) => {
    let timer;
    try { await Promise.race([exited, new Promise((resolve) => { timer = setTimeout(resolve, ms); })]); }
    finally { clearTimeout(timer); }
    return state.exit !== null && state.complete;
  };
  return {
    state, records, wait,
    async rpc(message, timeoutMs) {
      if (state.exit || state.faults.length) throw new Error('server_not_usable');
      rpcUsed = true;
      transcript.sent(message);
      child.stdin.write(`${JSON.stringify(message)}\n`);
      if (!Object.hasOwn(message, 'id')) return;
      const deadline = performance.now() + timeoutMs;
      while (performance.now() < deadline) {
        if (state.faults.length) throw new Error('server_capture_failed');
        while (records.length) {
          const received = records.shift();
          if (received) return received.value;
        }
        if (state.exit) throw new Error('server_exited_before_response');
        await delay(20);
      }
      throw new Error('rpc_timeout');
    },
    async stop() {
      if (!state.exit && !child.stdin.destroyed && !child.stdin.writableEnded) child.stdin.end();
      await wait(5000);
      if (!state.exit || !state.complete) {
        state.faults.push('incomplete_child');
        child.unref();
      }
      if (rpcUsed) {
        try {
          if (records.length) throw new Error('unconsumed_rpc_response');
          transcript.finish([], pending.length);
        }
        catch (error) { state.faults.push(error.message); }
      }
      // Pipe closure is not a process termination request; later writes can fail.
      child.stdin.destroy(); child.stdout.destroy(); child.stderr.destroy();
      return state;
    },
  };
}
async function runOnce(binary, args, env, cwd, ms = 10000) {
  const command = launch(binary, args, env, cwd);
  command.state.args = args;
  if (!(await command.wait(ms))) command.state.faults.push('command_timeout');
  await command.stop();
  return command.state;
}
async function digest(file) { const hash = createHash('sha256'); for await (const chunk of createReadStream(file)) hash.update(chunk); return hash.digest('hex'); }
export async function runVerifiedDiagnostic(binary, args, env, cwd, expected, dependencies = {}) {
  const hash = dependencies.digest ?? digest;
  const run = dependencies.run ?? runOnce;
  if (await hash(binary) !== expected) throw new Error('diagnostic_changed_before_launch');
  const record = await run(binary, args, env, cwd);
  try {
    if (await hash(binary) !== expected) record.faults.push('diagnostic_changed_after_run');
  } catch {
    record.faults.push('diagnostic_digest_recheck_failed');
  }
  return record;
}
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const integer = (value, min = 0, max = 0xffffffff) => Number.isInteger(value) && value >= min && value <= max;
const text = (value) => typeof value === 'string' && value.length > 0;
function requireSchema(condition) { if (!condition) throw new Error('diagnostic_contract_mismatch'); }
function exactKeys(value, keys) { return object(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key)); }
function decimal(value, min, max) { return typeof value === 'string' && /^-?(0|[1-9][0-9]*)$/.test(value) && BigInt(value) >= min && BigInt(value) <= max; }
function failure(value, extra = []) {
  requireSchema(exactKeys(value, ['state', 'reason', 'win32', ...extra]) && value.state === 'unknown'
    && typeof value.reason === 'string' && /^[a-z][a-z0-9_]*$/.test(value.reason)
    && (value.win32 === null || integer(value.win32)));
}
function snapshot(value, expectedPath) {
  requireSchema(exactKeys(value, ['volume', 'file_id', 'final_path', 'links', 'size', 'write_time', 'change_time', 'directory']));
  requireSchema(typeof value.volume === 'string' && /^[0-9a-f]{16}$/.test(value.volume)
    && typeof value.file_id === 'string' && /^[0-9a-f]{32}$/.test(value.file_id)
    && value.links === 1 && value.directory === false && text(value.final_path)
    && decimal(value.size, 0n, 0x7fffffffffffffffn)
    && decimal(value.write_time, -0x8000000000000000n, 0x7fffffffffffffffn)
    && decimal(value.change_time, -0x8000000000000000n, 0x7fffffffffffffffn));
  requireSchema(value.final_path.replace(/^\\\\\?\\/, '').toLowerCase() === expectedPath.toLowerCase());
}
export function parseDiagnostic(record, request) {
  if (![0, 2].includes(record.exit?.code) || record.exit?.signal !== null || !record.complete || !Array.isArray(record.faults) || record.faults.length) throw new Error('diagnostic_incomplete');
  const value = JSON.parse(record.stdout);
  requireSchema(object(value) && value.schemaVersion === 1 && value.safeToUnlock === false && value.experimental === true && value.platform === 'windows');
  if (request?.command === 'capabilities') {
    requireSchema(exactKeys(value, ['schemaVersion', 'safeToUnlock', 'experimental', 'platform', 'architecture', 'diagnosticsAvailable', 'commands', 'supportedFilesystems', 'holderAttribution', 'recoveryAvailable', 'probeEffects', 'prototypeVersion']));
    requireSchema(record.exit.code === 0 && value.diagnosticsAvailable === true && value.recoveryAvailable === false
      && value.holderAttribution === 'unproven' && typeof value.prototypeVersion === 'string' && versionPattern.test(value.prototypeVersion)
      && ['x86_64', 'aarch64', 'x86'].includes(value.architecture)
      && JSON.stringify(value.commands) === JSON.stringify(['capabilities', 'inspect'])
      && JSON.stringify(value.supportedFilesystems) === JSON.stringify(['NTFS']) && text(value.probeEffects));
  } else {
    requireSchema(exactKeys(value, ['schemaVersion', 'safeToUnlock', 'experimental', 'platform', 'requestedPid', 'lock', 'observation']));
    requireSchema(request?.command === 'inspect' && (request.pid === null || integer(request.pid, 1))
      && text(request.home) && UUID.test(request.thread) && value.requestedPid === request.pid);
    const observation = value.observation;
    requireSchema(exactKeys(value.lock, ['state', 'reason', 'win32']) && object(observation) && value.lock.state === observation.state);
    if (observation.state === 'unknown') {
      failure(observation, ['process']);
      requireSchema(value.lock.reason === observation.reason && value.lock.win32 === observation.win32);
    } else {
      requireSchema(['held', 'free'].includes(observation.state) && value.lock.reason === null && value.lock.win32 === null
        && exactKeys(observation, ['state', 'coordination', 'range', 'filesystem', 'fileOwnerSelf', 'guard', 'thread', 'holder', 'process'])
        && observation.coordination === 'acquired_and_released' && observation.range === 'offset_0_length_18446744073709551615'
        && observation.filesystem === 'NTFS' && observation.fileOwnerSelf === true && observation.holder === 'unproven');
      snapshot(observation.guard, `${request.home}\\thread-writer-locks\\.coordination.lock`);
      snapshot(observation.thread, `${request.home}\\thread-writer-locks\\${request.thread}.lock`);
      requireSchema(observation.guard.volume === observation.thread.volume);
    }
    const processObservation = observation.process;
    if (request.pid === null) requireSchema(processObservation === null);
    else if (processObservation?.state === 'unknown') failure(processObservation);
    else requireSchema(exactKeys(processObservation, ['state', 'evidence', 'pid', 'live', 'startTime', 'image', 'sameUser', 'sessionId', 'integrityRid'])
      && processObservation.state === 'observed' && processObservation.evidence === 'requested_pid_only_not_holder'
      && processObservation.pid === request.pid && processObservation.live === true && typeof processObservation.sameUser === 'boolean'
      && decimal(processObservation.startTime, 1n, 0xffffffffffffffffn) && text(processObservation.image)
      && integer(processObservation.sessionId) && integer(processObservation.integrityRid));
    const unknown = observation.state === 'unknown' || (request.pid !== null && (processObservation.state !== 'observed' || !processObservation.sameUser));
    requireSchema(record.exit.code === (unknown ? 2 : 0));
  }
  record.parsed = value;
  return record;
}
// Preview is a distinct envelope. Validate it before accepting the unchanged
// research observation nested inside; raw stdout remains the preview output.
export function parsePreviewDiagnostic(record, request) {
  if (![0, 2].includes(record.exit?.code) || record.exit?.signal !== null || !record.complete
    || !Array.isArray(record.faults) || record.faults.length) throw new Error('diagnostic_incomplete');
  const value = JSON.parse(record.stdout);
  const common = ['schema', 'schemaVersion', 'preview', 'experimental', 'version', 'platform', 'architecture',
    'safeToUnlock', 'recoveryAvailable', 'context', 'diagnosticsAvailable', 'command', 'reason'];
  requireSchema(object(value) && value.schema === 'codex-unlock-windows-preview' && value.schemaVersion === 1
    && value.preview === true && value.experimental === true && value.safeToUnlock === false
    && value.recoveryAvailable === false && value.platform === 'windows' && value.architecture === 'x86_64'
    && versionPattern.test(request?.expectedVersion ?? '0.0.0')
    && value.version === (request?.expectedVersion ?? '0.0.0') && value.diagnosticsAvailable === true
    && exactKeys(value.context, ['state', 'integrityRid', 'elevated', 'appContainer'])
    && value.context.state === 'observed' && value.context.integrityRid === 8192
    && value.context.elevated === false && value.context.appContainer === false);
  if (request?.command === 'capabilities') {
    requireSchema(exactKeys(value, [...common, 'commands', 'supportedFilesystems', 'holderAttribution'])
      && value.command === 'capabilities' && record.exit.code === 0
      && value.reason === 'diagnostic_preview_available' && value.holderAttribution === 'unproven'
      && JSON.stringify(value.commands) === JSON.stringify(['capabilities', 'inspect'])
      && JSON.stringify(value.supportedFilesystems) === JSON.stringify(['NTFS']));
    record.parsed = value;
  } else {
    requireSchema(exactKeys(value, [...common, 'requestedPid', 'requestedPidEvidence', 'lock', 'diagnostic'])
      && value.command === 'inspect' && value.requestedPid === request.pid
      && value.requestedPidEvidence === 'requested_pid_only_not_holder');
    const nested = parseDiagnostic({ ...record, stdout: JSON.stringify(value.diagnostic) }, request).parsed;
    requireSchema(exactKeys(value.lock, ['state', 'reason', 'win32'])
      && ['state', 'reason', 'win32'].every((key) => value.lock[key] === nested.lock[key]));
    const p = nested.observation.process;
    const expectedReason = nested.lock.state === 'unknown' ? nested.lock.reason
      : p !== null && (p.state !== 'observed' || !p.sameUser) ? 'requested_process_unverified' : 'diagnostic_observation_only';
    requireSchema(value.reason === expectedReason);
    record.parsed = nested;
  }
  record.preview = value;
  return record;
}
function inside(candidate, parent) {
  const relative = path.win32.relative(parent.toLowerCase(), candidate.toLowerCase());
  return relative === '' || (!relative.startsWith('..\\') && relative !== '..' && !path.win32.isAbsolute(relative));
}
async function plainAbsolute(input, directory) {
  if (!/^[A-Za-z]:\\/.test(input) || input.includes('\0')) throw new Error('absolute_local_path_required');
  const stat = await lstat(input);
  if (stat.isSymbolicLink() || (directory ? !stat.isDirectory() : !stat.isFile())) throw new Error('plain_path_required');
  const resolved = await realpath(input);
  if (resolved.toLowerCase() !== path.win32.normalize(input).toLowerCase()) throw new Error('redirecting_path');
  return resolved;
}
async function nativeFilePresence(home, thread) {
  const presence = {};
  for (const [name, leaf] of [['coordination', '.coordination.lock'], ['thread', `${thread}.lock`]]) {
    try {
      const stat = await lstat(path.join(home, 'thread-writer-locks', leaf));
      presence[name] = { exists: true, kind: stat.isSymbolicLink() ? 'symlink' : stat.isFile() ? 'file' : stat.isDirectory() ? 'directory' : 'other' };
    } catch (error) {
      presence[name] = error.code === 'ENOENT' ? { exists: false } : { exists: null, error: error.code ?? 'lstat_failed' };
    }
  }
  return presence;
}
export function isEntryPoint(entry, moduleUrl, platform = process.platform, resolve = realpathSync) {
  const entryPath = resolve(entry);
  const modulePath = resolve(fileURLToPath(moduleUrl));
  return platform === 'win32' ? entryPath.toLowerCase() === modulePath.toLowerCase() : entryPath === modulePath;
}
export function parseObserverOptions(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i];
    if (!['--binary', '--sha256', '--diagnostic', '--parent', '--result', '--diagnostic-format', '--diagnostic-sha256', '--diagnostic-version'].includes(key) || options[key] || !argv[i + 1]) throw new Error('usage');
    options[key] = argv[i + 1];
  }
  if (!['--binary', '--sha256', '--diagnostic', '--parent', '--result'].every((key) => options[key])
    || !/^[0-9a-f]{64}$/i.test(options['--sha256'])) throw new Error('usage');
  const diagnosticFormat = options['--diagnostic-format'] ?? 'research';
  if (!['research', 'preview'].includes(diagnosticFormat)) throw new Error('usage');
  if ((diagnosticFormat === 'preview' || options['--diagnostic-sha256'] !== undefined)
    && !/^[0-9a-f]{64}$/i.test(options['--diagnostic-sha256'] ?? '')) throw new Error('diagnostic_digest_required');
  if ((diagnosticFormat === 'preview' || options['--diagnostic-version'] !== undefined)
    && !versionPattern.test(options['--diagnostic-version'] ?? '')) throw new Error('diagnostic_version_required');
  return { options, diagnosticFormat };
}
export async function main(argv) {
  if (process.platform !== 'win32') throw new Error('windows_required');
  const { options, diagnosticFormat } = parseObserverOptions(argv);
  const expectedDiagnostic = options['--diagnostic-sha256']?.toLowerCase();
  const jsonArgs = diagnosticFormat === 'preview' ? ['--json'] : [];
  const parseOutput = diagnosticFormat === 'preview'
    ? (record, request) => parsePreviewDiagnostic(record, { ...request, expectedVersion: options['--diagnostic-version'] })
    : parseDiagnostic;
  const binary = await plainAbsolute(options['--binary'], false);
  const diagnostic = await plainAbsolute(options['--diagnostic'], false);
  const parent = await plainAbsolute(options['--parent'], true);
  if (!binary.toLowerCase().endsWith('.exe') || !diagnostic.toLowerCase().endsWith('.exe')) throw new Error('native_exe_required');
  const knownHomes = [process.env.CODEX_HOME, process.env.USERPROFILE && path.join(process.env.USERPROFILE, '.codex')].filter(Boolean);
  if (knownHomes.some((home) => inside(parent, home) || inside(home, parent))) throw new Error('scratch_overlaps_real_home');
  const resultPath = options['--result'];
  if (!path.win32.isAbsolute(resultPath)) throw new Error('absolute_result_required');
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*\.json$/.test(path.win32.basename(resultPath))) throw new Error('plain_json_result_name_required');
  const resultParent = await plainAbsolute(path.dirname(resultPath), true);
  if (resultParent.toLowerCase() !== parent.toLowerCase()) throw new Error('result_must_be_directly_inside_private_parent');
  const expected = options['--sha256'].toLowerCase();
  if (await digest(binary) !== expected) throw new Error('binary_digest_mismatch');
  const resultFile = await open(resultPath, 'wx', 0o600);
  const report = { schemaVersion: 1, safeToUnlock: false, mode: 'own_stdio_appserver_no_model_turn',
    holderAttribution: 'unproven', status: 'partial', binarySha256: expected, diagnosticSha256: null,
    diagnosticVersion: null, home: null, observations: [], server: null, reason: null };
  if (diagnosticFormat === 'preview') report.diagnosticFormat = diagnosticFormat;
  let server, trap;
  try {
    report.diagnosticSha256 = await digest(diagnostic);
    if (expectedDiagnostic !== undefined && report.diagnosticSha256 !== expectedDiagnostic) throw new Error('diagnostic_digest_mismatch');
    report.home = await mkdtemp(path.join(parent, 'codex-native-observation-'));
    const env = envFor(report.home, parent);
    report.startupPreflight = await startupPreflight(env, report.home);
    if (await digest(binary) !== expected) throw new Error('binary_changed_before_version');
    const version = await runOnce(binary, ['--version'], env, report.home);
    report.version = version;
    if (version.exit?.code !== 0 || version.faults.length) throw new Error('version_failed');
    if (version.stdout.trim() !== 'codex-cli 0.163.0') throw new Error('upstream_version_not_reviewed');
    report.upstreamCommit = '83086188ae0614bd882818ff1aa23f3194962012';
    const runDiagnostic = (args) => runVerifiedDiagnostic(diagnostic, args, env, report.home, report.diagnosticSha256);
    report.capabilities = await runDiagnostic(['capabilities', ...jsonArgs]);
    parseOutput(report.capabilities, { command: 'capabilities' });
    report.diagnosticVersion = diagnosticFormat === 'preview'
      ? report.capabilities.parsed.version : report.capabilities.parsed.prototypeVersion;
    if (await digest(binary) !== expected) throw new Error('binary_changed_before_launch');
    trap = await loopbackTrap();
    report.nativeArguments = nativeArguments(trap.port);
    server = launch(binary, report.nativeArguments, env, report.home, true);
    const [initialize, initialized, start] = requests(report.home);
    report.initialize = await server.rpc(initialize, 10000);
    await server.rpc(initialized, 0);
    report.threadStart = await server.rpc(start, 15000);
    validateThreadConfiguration(report.threadStart);
    const id = threadId(report.threadStart);
    if (!Number.isInteger(server.state.pid) || server.state.pid <= 0) throw new Error('missing_server_pid');
    report.nativeFilesBeforeInspection = await nativeFilePresence(report.home, id);
    const live = await runDiagnostic(
      ['inspect', '--home', report.home, '--thread', id, '--pid', String(server.state.pid), ...jsonArgs]);
    report.observations.push({ phase: 'server_live', result: live });
    parseOutput(live, { command: 'inspect', home: report.home, thread: id, pid: server.state.pid });
    report.server = await server.stop();
    server = null;
    if (!report.server.exit || !report.server.complete || report.server.faults.length || report.server.exit.code !== 0) throw new Error('server_exit_unconfirmed');
    report.nativeFilesAfterExit = await nativeFilePresence(report.home, id);
    const after = await runDiagnostic(['inspect', '--home', report.home, '--thread', id, ...jsonArgs]);
    report.observations.push({ phase: 'after_server_exit', result: after });
    parseOutput(after, { command: 'inspect', home: report.home, thread: id, pid: null });
    if (trap.count() !== 0) throw new Error('unexpected_provider_connection');
    report.status = 'collected'; // Observation completion is not a passing product gate.
  } catch (error) {
    report.reason = error instanceof Error ? error.message : 'unexpected_error';
  } finally {
    if (server) report.server = await server.stop();
    if (trap) { report.providerConnections = trap.count(); await trap.close(); }
    await resultFile.writeFile(`${JSON.stringify(report)}\n`);
    await resultFile.close();
  }
  process.stdout.write(`${JSON.stringify({ status: report.status, safeToUnlock: false, holderAttribution: 'unproven' })}\n`);
  return report.status === 'collected' ? 0 : 2;
}
if (process.argv[1] && isEntryPoint(process.argv[1], import.meta.url)) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, () => {
    process.stdout.write('{"status":"refused","safeToUnlock":false}\n');
    process.exitCode = 2;
  });
}
