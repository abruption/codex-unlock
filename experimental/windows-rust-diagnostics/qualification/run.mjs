// Operator-run qualification of exact release bytes, using only fresh synthetic homes.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile, readdir, lstat, realpath, open, mkdir, rename, link, unlink, symlink, rmdir, stat } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { performance } from 'node:perf_hooks';
import { fileURLToPath, URL } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { setTimeout, clearTimeout } from 'node:timers';
import { digest, HARNESS_FILES, Frames, readyRecord, validateInputs, validateCase, validatePairIdentity, validateHigh, summary } from './contract.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const w = path.win32;
const hash = async file => digest(await readFile(file));
const contains = (parent, child) => { const p = w.relative(parent.toLowerCase(), child.toLowerCase()); return p === '' || (!p.startsWith('..\\') && p !== '..' && !w.isAbsolute(p)); };
function spelling(value) {
  assert.ok(typeof value === 'string' && /^[A-Za-z]:\\/.test(value) && !value.includes('/') && !value.endsWith('\\'));
  for (const part of value.slice(3).split('\\')) assert.ok(part && !['.', '..'].includes(part) && !/[. ]$/.test(part)
    && [...part].every(c => c.charCodeAt(0) >= 32 && !'<>:"|?*'.includes(c)));
  return value;
}
async function plain(value, directory) {
  spelling(value);
  let cursor = value;
  while (true) {
    const s = await lstat(cursor);
    assert.ok(!s.isSymbolicLink(), 'reparse/symlink input');
    assert.ok(cursor === value && !directory ? s.isFile() : s.isDirectory());
    const next = w.dirname(cursor);
    if (next === cursor) break;
    cursor = next;
  }
  assert.equal((await realpath(value)).toLowerCase(), value.toLowerCase(), 'aliased input');
  return value;
}
async function absent(file) { try { await lstat(file); return false; } catch (e) { if (e.code === 'ENOENT') return true; throw e; } }
async function metadata(file) { const s = await stat(file, { bigint: true }); return { size: String(s.size), mtimeNs: String(s.mtimeNs) }; }

function startFixture(binary, parent, mode) {
  const child = spawn(binary, ['--parent', parent, '--mode', mode, '--lifetime-ms', '60000'], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  const frames = new Frames();
  const state = { pid: child.pid ?? null, code: null, signal: null, complete: false, faults: [], stderr: '' };
  let errBytes = 0;
  child.stdout.on('data', b => frames.push(b));
  child.stdout.on('end', () => frames.finish());
  child.stdout.on('error', () => state.faults.push('stdout_error'));
  child.stderr.on('data', b => { errBytes += b.length; if (errBytes <= 65536) state.stderr += b.toString('utf8'); else if (!state.faults.includes('stderr_limit')) state.faults.push('stderr_limit'); });
  child.stderr.on('error', () => state.faults.push('stderr_error'));
  child.stdin.on('error', () => state.faults.push('stdin_error'));
  child.once('error', () => state.faults.push('spawn_error'));
  child.once('exit', (code, signal) => { state.code = code; state.signal = signal; });
  child.once('close', () => { state.complete = true; });
  let stopped = false;
  return { child, state, frames, ready: null,
    async row(event) {
      const deadline = performance.now() + 10000;
      while (performance.now() < deadline) {
        assert.equal(state.faults.length + frames.faults.length, 0, 'fixture capture fault');
        if (frames.rows.length) { const row = frames.rows.shift(); assert.equal(row.event, event, 'unexpected fixture frame'); return row; }
        assert.equal(state.complete, false, 'fixture exited before frame');
        await delay(20);
      }
      throw new Error('fixture frame timeout');
    },
    async release() {
      assert.ok(!stopped && !state.complete);
      const sent = new Promise((resolve, reject) => child.stdin.write('release\n', e => e ? reject(e) : resolve()));
      let timer;
      try { await Promise.race([sent, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('fixture write timeout')), 2000); })]); }
      finally { clearTimeout(timer); }
      const row = await this.row('released');
      assert.deepEqual(row, { event: 'released' });
    },
    async stop() {
      if (stopped) return state;
      stopped = true;
      if (!child.stdin.destroyed && !child.stdin.writableEnded) child.stdin.end();
      const deadline = performance.now() + 5000;
      while (!state.complete && performance.now() < deadline) await delay(20);
      state.faults.push(...frames.faults);
      if (state.complete) {
        if (state.stderr) state.faults.push('fixture_stderr');
        if (frames.rows.length !== 1 || frames.rows[0]?.event !== 'finished' || frames.rows[0]?.expired !== false) state.faults.push('fixture_finish_protocol');
      } else { state.faults.push('incomplete_child'); child.unref(); }
      child.stdin.destroy(); child.stdout.destroy(); child.stderr.destroy();
      return state;
    },
  };
}

async function main() {
  assert.equal(process.platform, 'win32', 'Windows host required');
  const args = process.argv.slice(2), options = {};
  for (let i = 0; i < args.length; i += 2) {
    assert.ok(['--input', '--input-sha256', '--release-manifest', '--metadata', '--security-evidence', '--cli', '--fixture', '--parent', '--result', '--mode'].includes(args[i]) && !options[args[i]] && args[i + 1]);
    options[args[i]] = args[i + 1];
  }
  assert.equal(Object.keys(options).length, 10);
  assert.ok(['medium', 'high'].includes(options['--mode']));
  assert.match(options['--input-sha256'], /^[a-f0-9]{64}$/);
  const inputBytes = await readFile(options['--input']);
  assert.equal(digest(inputBytes), options['--input-sha256'], 'input manifest digest');
  const input = JSON.parse(inputBytes);
  const releaseBytes = await readFile(options['--release-manifest']);
  const metadataBytes = await readFile(options['--metadata']);
  assert.equal(digest(releaseBytes), input.releaseManifestSha256);
  assert.equal(digest(metadataBytes), input.metadataSha256);
  const release = JSON.parse(releaseBytes), host = JSON.parse(metadataBytes);
  const hostQualified = validateInputs(input, release, host);
  const fixed = new Map([[options['--input'], options['--input-sha256']], [options['--release-manifest'], input.releaseManifestSha256], [options['--metadata'], input.metadataSha256], [options['--security-evidence'], input.securityEvidenceSha256], [options['--cli'], input.cliSha256], [options['--fixture'], input.fixtureSha256], ...HARNESS_FILES.map(n => [path.join(root, n), input.harness[n]])]);
  const verify = async () => { for (const [file, expected] of fixed) assert.equal(await hash(file), expected, 'input bytes changed'); };
  await verify();
  const observer = await import('../observe-native.mjs');
  const contract = observer.previewReleaseContract(input.version);
  assert.ok(contract, 'unsupported release contract');
  const parent = await plain(options['--parent'], true);
  assert.equal(host.parent.path, parent);
  for (const home of [process.env.CODEX_HOME, process.env.USERPROFILE && w.join(process.env.USERPROFILE, '.codex')].filter(Boolean)) assert.ok(!contains(parent, home) && !contains(home, parent), 'scratch overlaps a real home');
  assert.deepEqual(await readdir(parent), [], 'operator parent must be fresh and empty');
  assert.equal(w.dirname(spelling(options['--result'])), parent);
  const cli = await plain(options['--cli'], false), fixture = await plain(options['--fixture'], false);
  const output = await open(options['--result'], 'wx', 0o600);
  const report = { schemaVersion: 1, mode: options['--mode'], version: input.version, sourceSha: input.sourceSha, inputSha256: options['--input-sha256'], inputs: input, hostMetadataSource: 'operator_launcher_supplied_hash_bound', host, hostQualified, capabilities: null, cases: [], identityPairs: [], cleanup: [], errors: [], inputsUnchanged: false, safeToUnlock: false };
  const active = [];
  const run = async args => {
    await verify();
    const result = await observer.runVerifiedDiagnostic(cli, args, process.env, parent, input.cliSha256);
    assert.equal(result.stderr, '', 'diagnostic stderr');
    return result;
  };
  const observe = async (id, f, pid = null, home = f.ready.home) => {
    const row = { id, ok: false, request: { home, thread: f.ready.thread, pid, expectedVersion: input.version, command: 'inspect' } };
    report.cases.push(row);
    assert.equal(f.state.complete, false, 'fixture already exited');
    row.result = await run(['inspect', '--home', home, '--thread', f.ready.thread, ...(pid === null ? [] : ['--pid', String(pid)]), '--json']);
    observer.parsePreviewDiagnostic(row.result, row.request);
    validateCase(id, row.result, row.request);
    assert.equal(f.state.complete, false, 'fixture exited during observation');
    row.ok = true;
    return row.result;
  };
  const start = async (mode, at = parent) => {
    await verify();
    const f = startFixture(fixture, at, mode);
    active.push(f);
    f.ready = readyRecord(await f.row('ready'), { pid: f.state.pid, mode, parent: at }, w);
    await plain(f.ready.home, true);
    return f;
  };
  try {
    const cap = await run(['capabilities', '--json']); report.capabilities = cap;
    const value = JSON.parse(cap.stdout);
    assert.ok(cap.complete && cap.exit.code === 0 && cap.exit.signal === null && cap.faults.length === 0);
    assert.deepEqual(value.context, { state: 'observed', integrityRid: host.integrityRid, elevated: host.elevated, appContainer: host.appContainer });
    if (report.mode === 'high') {
      validateHigh(cap, 'capabilities', input.version, contract, host);
      report.cases.push({ id: 'high_capabilities', ok: true });
      const missing = w.join(parent, 'not-created');
      const refused = await run(['inspect', '--home', missing, '--thread', '11111111-2222-4333-8444-555555555555', '--pid', '4294967295', '--json']);
      validateHigh(refused, 'inspect', input.version, contract, host);
      assert.equal(await absent(missing), true);
      report.cases.push({ id: 'high_refusal', ok: true, result: refused });
    } else {
      observer.parsePreviewDiagnostic(cap, { command: 'capabilities', expectedVersion: input.version });
      const first = await start('thread');
      const file = w.join(first.ready.home, 'thread-writer-locks', first.ready.thread + '.lock');
      const guard = w.join(first.ready.home, 'thread-writer-locks', '.coordination.lock');
      const before = await Promise.all([metadata(file), metadata(guard)]);
      const firstHeld = await observe('held', first, first.state.pid);
      await first.release();
      const firstFree = await observe('free', first);
      validatePairIdentity(firstHeld, firstFree);
      report.identityPairs.push({ before: 'held', after: 'free', unchanged: true });
      assert.deepEqual(await Promise.all([metadata(file), metadata(guard)]), before, 'file metadata changed');
      await first.stop();
      const busy = await start('guard'); await observe('busy_guard', busy); await busy.stop();
      const free = await start('free');
      const base = w.join(free.ready.home, 'thread-writer-locks');
      for (const [id, name] of [['missing_guard', '.coordination.lock'], ['missing_thread', free.ready.thread + '.lock']]) {
        const original = w.join(base, name), saved = w.join(base, name + '.saved');
        await rename(original, saved);
        try { await observe(id, free); assert.equal(await absent(original), true, 'diagnostic created native file'); }
        finally { await rename(saved, original); }
      }
      for (const [id, name] of [['hardlink_guard', '.coordination.lock'], ['hardlink_thread', free.ready.thread + '.lock']]) {
        const extra = w.join(base, name + '.extra'); await link(w.join(base, name), extra);
        try { await observe(id, free); } finally { await unlink(extra); }
      }
      const junction = w.join(free.ready.root, 'junction'); await symlink(free.ready.home, junction, 'junction');
      try { await observe('junction', free, null, junction); }
      finally { assert.equal((await lstat(junction)).isSymbolicLink(), true); await unlink(junction); }
      await observe('missing_pid', free, 4294967295); await free.stop();
      // Restart a held fixture for an intentionally unrelated same-user PID.
      const unicodeParent = w.join(parent, '진단 test'); await mkdir(unicodeParent);
      const unicode = await start('thread', unicodeParent);
      await observe('unrelated_pid', unicode, process.pid);
      const unicodeHeld = await observe('unicode_held', unicode);
      await unicode.release();
      const unicodeFree = await observe('unicode_free', unicode);
      validatePairIdentity(unicodeHeld, unicodeFree);
      report.identityPairs.push({ before: 'unicode_held', after: 'unicode_free', unchanged: true });
      await unicode.stop();
      if (unicode.state.complete && unicode.state.code === 0) { assert.deepEqual(await readdir(unicodeParent), []); await rmdir(unicodeParent); }
    }
  } catch (error) { report.errors.push(error instanceof Error ? error.message : 'qualification_error'); }
  finally {
    for (const f of active) {
      const state = await f.stop();
      let rootAbsent = false;
      try { rootAbsent = !!f.ready && await absent(f.ready.root); } catch { state.faults.push('cleanup_lookup_failed'); }
      report.cleanup.push({ ...state, rootAbsent });
    }
    try { await verify(); report.inputsUnchanged = true; } catch { report.errors.push('input_changed'); }
    report.verdict = summary(report);
    await output.writeFile(JSON.stringify(report) + '\n'); await output.close();
  }
  process.stdout.write(JSON.stringify(report.verdict) + '\n');
  return report.verdict.ok ? 0 : 2;
}
main().then(code => { process.exitCode = code; }, () => {
  process.stdout.write('{"schemaVersion":1,"status":"refused","safeToUnlock":false}\n'); process.exitCode = 3;
});
