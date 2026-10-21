// Operator-run, Windows-only observation of an isolated, self-started Codex.
// The existing parent must be a trusted private scratch directory. It is retained.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstat, readFile, realpath, mkdtemp, open } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { performance } from 'node:perf_hooks';
import { Buffer } from 'node:buffer';
import { setTimeout, clearTimeout } from 'node:timers';
import { StringDecoder } from 'node:string_decoder';
import { fileURLToPath } from 'node:url';

const CAP = 1024 * 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export function response(record, expectedId) {
  if (!record || typeof record !== 'object' || Array.isArray(record) || record.id !== expectedId) throw new Error('unexpected_response_id');
  const result = Object.hasOwn(record, 'result');
  const error = Object.hasOwn(record, 'error');
  if (result === error) throw new Error('contradictory_or_missing_outcome');
  if (error) throw new Error('rpc_rejected');
  return record.result;
}
export function threadId(result) {
  const id = result?.thread?.id;
  if (typeof id !== 'string' || !UUID.test(id)) throw new Error('invalid_thread_id');
  return id;
}
export function requests(home) {
  return [
    { id: 1, method: 'initialize', params: { clientInfo: { name: 'codex_unlock_observation', version: '0.0.0' } } },
    { method: 'initialized', params: {} },
    { id: 2, method: 'thread/start', params: { cwd: home, approvalPolicy: 'never', sandbox: 'read-only', ephemeral: false } },
  ];
}
function envFor(home, parent) {
  const env = {};
  for (const key of ['SystemRoot', 'SystemDrive', 'windir', 'COMSPEC', 'PATHEXT', 'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE']) {
    const found = Object.keys(process.env).find((item) => item.toLowerCase() === key.toLowerCase());
    if (found) env[key] = process.env[found];
  }
  return { ...env, CODEX_HOME: home, TEMP: parent, TMP: parent };
}
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
function launch(binary, args, env, cwd) {
  const child = spawn(binary, args, { env, cwd, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  const state = { pid: child.pid ?? null, exit: null, stdout: '', stderr: '', faults: [], complete: false };
  let stdoutBytes = 0, stderrBytes = 0, pending = Buffer.alloc(0);
  const records = [];
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
          try { records.push(JSON.parse(line)); } catch { records.push({ invalidJson: true }); }
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
      child.stdin.write(`${JSON.stringify(message)}\n`);
      if (!Object.hasOwn(message, 'id')) return;
      const deadline = performance.now() + timeoutMs;
      while (performance.now() < deadline) {
        if (state.faults.length) throw new Error('server_capture_failed');
        while (records.length) {
          const record = records.shift();
          if (record.invalidJson) throw new Error('malformed_rpc_json');
          if (Object.hasOwn(record, 'id')) return response(record, message.id);
          if (typeof record.method !== 'string') throw new Error('malformed_notification');
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
async function digest(file) { return createHash('sha256').update(await readFile(file)).digest('hex'); }
function parseDiagnostic(record) {
  if (![0, 2].includes(record.exit?.code) || !record.complete || record.faults.length) throw new Error('diagnostic_incomplete');
  const value = JSON.parse(record.stdout);
  if (value.schemaVersion !== 1 || value.safeToUnlock !== false) throw new Error('diagnostic_contract_mismatch');
  record.parsed = value;
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
export async function main(argv) {
  if (process.platform !== 'win32') throw new Error('windows_required');
  const options = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i];
    if (!['--binary', '--sha256', '--diagnostic', '--parent', '--result'].includes(key) || options[key] || !argv[i + 1]) throw new Error('usage');
    options[key] = argv[i + 1];
  }
  if (Object.keys(options).length !== 5 || !/^[0-9a-f]{64}$/i.test(options['--sha256'])) throw new Error('usage');
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
  let server;
  try {
    report.diagnosticSha256 = await digest(diagnostic);
    report.home = await mkdtemp(path.join(parent, 'codex-native-observation-'));
    const env = envFor(report.home, parent);
    if (await digest(binary) !== expected) throw new Error('binary_changed_before_version');
    const version = await runOnce(binary, ['--version'], env, report.home);
    report.version = version;
    if (version.exit?.code !== 0 || version.faults.length) throw new Error('version_failed');
    report.capabilities = await runOnce(diagnostic, ['capabilities'], env, report.home);
    parseDiagnostic(report.capabilities);
    report.diagnosticVersion = report.capabilities.parsed.prototypeVersion ?? null;
    if (await digest(binary) !== expected) throw new Error('binary_changed_before_launch');
    server = launch(binary, ['app-server'], env, report.home);
    const [initialize, initialized, start] = requests(report.home);
    report.initialize = await server.rpc(initialize, 10000);
    await server.rpc(initialized, 0);
    report.threadStart = await server.rpc(start, 15000);
    const id = threadId(report.threadStart);
    if (!Number.isInteger(server.state.pid) || server.state.pid <= 0) throw new Error('missing_server_pid');
    const live = await runOnce(diagnostic,
      ['inspect', '--home', report.home, '--thread', id, '--pid', String(server.state.pid)], env, report.home);
    report.observations.push({ phase: 'server_live', result: live });
    parseDiagnostic(live);
    report.server = await server.stop();
    server = null;
    if (!report.server.exit || !report.server.complete || report.server.faults.length || report.server.exit.code !== 0) throw new Error('server_exit_unconfirmed');
    const after = await runOnce(diagnostic, ['inspect', '--home', report.home, '--thread', id], env, report.home);
    report.observations.push({ phase: 'after_server_exit', result: after });
    parseDiagnostic(after);
    report.status = 'collected'; // Observation completion is not a passing product gate.
  } catch (error) {
    report.reason = error instanceof Error ? error.message : 'unexpected_error';
  } finally {
    if (server) report.server = await server.stop();
    await resultFile.writeFile(`${JSON.stringify(report)}\n`);
    await resultFile.close();
  }
  process.stdout.write(`${JSON.stringify({ status: report.status, safeToUnlock: false, holderAttribution: 'unproven' })}\n`);
  return report.status === 'collected' ? 0 : 2;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, () => {
    process.stdout.write('{"status":"refused","safeToUnlock":false}\n');
    process.exitCode = 2;
  });
}
