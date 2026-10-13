import assert from 'node:assert/strict';
import process from 'node:process';
import { URL } from 'node:url';
import { spawn, spawnSync } from 'node:child_process';
import { once } from 'node:events';
import { test } from 'node:test';
import { mkdtempSync, writeFileSync, openSync, closeSync, rmSync, readFileSync, renameSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { flockSync } from 'fs-ext-extra-prebuilt';
import { assertProcNamespace, parseFlockRows, parseStartTicks, prepareLinuxParticipation, verifyLinuxParticipation } from '../dist/linux-attribution.js';
import { guardedProbeOnce } from '../dist/native-coordination.js';
import { observeLockFile } from '../dist/lock.js';

test('granted flock rows preserve inode precision and ignore acquisition PID', () => {
  assert.deepEqual(parseFlockRows('lock:\t1: FLOCK  ADVISORY  WRITE -1 00:02:9007199254740993 0 EOF\n'),
    [{ major: 0n, minor: 2n, inode: 9007199254740993n }]);
  assert.deepEqual(parseFlockRows('pos:\t0\n'), []);
  for (const type of ['POSIX', 'OFDLCK', 'LEASE', '-> FLOCK']) {
    assert.throws(() => parseFlockRows(`lock:\t1: ${type} ADVISORY WRITE 5 00:02:1 0 EOF\n`));
  }
  assert.throws(() => parseFlockRows('lock: truncated'));
  assert.throws(() => parseFlockRows('lock: 1: FLOCK ADVISORY READ 5 00:02:1 0 EOF'));
  const large = (1n << 512n).toString();
  assert.throws(() => parseFlockRows(`lock: 1: FLOCK ADVISORY WRITE 1 00:02:${large} 0 EOF`));
});

test('positive attribution callback cannot bind a replacement inode to an old snapshot', () => {
  const root = mkdtempSync(join(tmpdir(), 'codex-attribution-identity-'));
  const path = join(root, 'thread.lock');
  writeFileSync(path, '');
  writeFileSync(join(root, '.coordination.lock'), '');
  const original = observeLockFile(path);
  writeFileSync(join(root, 'replacement'), '');
  renameSync(join(root, 'replacement'), path);
  const fd = openSync(path, 'r');
  try {
    flockSync(fd, 'exnb');
    let attributed = 0;
    const result = guardedProbeOnce(path, original, undefined, () => {
      attributed += 1;
      return { pid: process.pid, startTicks: '1', descriptor: String(fd) };
    });
    assert.equal(result.status, 'unknown');
    assert.equal(attributed, 0);
    assert.equal(result.participation, undefined);
  } finally { closeSync(fd); rmSync(root, { recursive: true }); }
});

test('real native guard refuses a nonlocking candidate while another description holds; no signal', { skip: process.platform !== 'linux' }, async () => {
  const root = mkdtempSync(join(tmpdir(), 'codex-attribution-guard-'));
  const path = join(root, 'thread.lock');
  writeFileSync(path, '');
  writeFileSync(join(root, '.coordination.lock'), '');
  const holder = openSync(path, 'r');
  flockSync(holder, 'exnb');
  const child = spawn(process.execPath, ['--input-type=module', '-e', `
    import {openSync,closeSync} from 'node:fs';
    import process from 'node:process';
    const fd=openSync(process.argv[1],'r');
    const timer=setTimeout(()=>{closeSync(fd);process.exitCode=2;process.stdin.destroy();},5000);
    process.stdin.resume(); process.stdin.on('end',()=>{clearTimeout(timer);closeSync(fd);});
    console.log('ready');
  `, path], { stdio: ['pipe', 'pipe', 'pipe'] });
  const closed = once(child, 'close');
  try {
    await once(child.stdout, 'data');
    const prepared = prepareLinuxParticipation(child.pid);
    let signals = 0;
    const original = process.kill;
    let result;
    try {
      process.kill = () => { signals += 1; throw new Error('unexpected signal'); };
      result = guardedProbeOnce(path, undefined, undefined, () => verifyLinuxParticipation(path, prepared));
    } finally { process.kill = original; }
    assert.equal(result.status, 'unknown');
    assert.equal(signals, 0);
    assert.equal(guardedProbeOnce(path).status, 'held');
  } finally {
    child.stdin.end();
    const [status] = await closed;
    closeSync(holder);
    rmSync(root, { recursive: true });
    assert.equal(status, 0);
  }
});

test('foreign proc namespace is refused, never guessed from observed PID', () => {
  assertProcNamespace('42', 42);
  assert.throws(() => assertProcNamespace('1', 42), /namespace_mismatch/);
  assert.throws(() => assertProcNamespace('self', 42), /namespace_mismatch/);
});

test('proc stat uses final comm delimiter and start tick field, rejects zombies', () => {
  const fields = ['S', ...Array(18).fill('0'), '9007199254740993'];
  assert.equal(parseStartTicks(`42 (name ) with spaces) ${fields.join(' ')}`, 42), '9007199254740993');
  assert.throws(() => parseStartTicks(`42 (name) Z ${Array(19).fill('0').join(' ')}`, 42));
  assert.throws(() => parseStartTicks('43 (wrong pid) S', 42));
});

test('Linux real FLOCK participates; open-but-unlocked descriptor does not', { skip: process.platform !== 'linux' }, (t) => {
  const root = mkdtempSync(join(tmpdir(), 'codex-attribution-test-'));
  const path = join(root, 'thread.lock');
  writeFileSync(path, '');
  const fd = openSync(path, 'r');
  try {
    flockSync(fd, 'exnb');
    const prepared = prepareLinuxParticipation(process.pid);
    // Proc files on unsupported CI filesystems refuse rather than guessing.
    let evidence;
    try { evidence = verifyLinuxParticipation(path, prepared); }
    catch (error) {
      if (error.message === 'linux_filesystem_unsupported') { t.skip('actual filesystem mapping unsupported; positive evidence unverified'); return; }
      throw error;
    }
    assert.equal(evidence.pid, process.pid);
    assert.equal(evidence.descriptor, String(fd));
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', `
      import {prepareLinuxParticipation,verifyLinuxParticipation} from ${JSON.stringify(new URL('../dist/linux-attribution.js', import.meta.url).href)};
      import process from 'node:process';
      console.log(JSON.stringify(verifyLinuxParticipation(process.argv[1],prepareLinuxParticipation(process.pid))));
    `, path], { stdio: ['ignore', 'pipe', 'pipe', fd], encoding: 'utf8', timeout: 5000 });
    assert.equal(child.status, 0, child.stderr);
    const inherited = JSON.parse(child.stdout);
    assert.equal(inherited.descriptor, '3');
    assert.notEqual(inherited.pid, process.pid);
    const nonholder = spawnSync(process.execPath, ['--input-type=module', '-e', `
      import {prepareLinuxParticipation,verifyLinuxParticipation} from ${JSON.stringify(new URL('../dist/linux-attribution.js', import.meta.url).href)};
      import {openSync,closeSync} from 'node:fs';
      import process from 'node:process';
      const fd=openSync(process.argv[1],'r');
      try {
        try { verifyLinuxParticipation(process.argv[1],prepareLinuxParticipation(process.pid)); process.exitCode=1; }
        catch(error) { console.log(error.message); }
      } finally {closeSync(fd);}
    `, path], { encoding: 'utf8', timeout: 5000 });
    assert.equal(nonholder.status, 0, nonholder.stderr);
    assert.match(nonholder.stdout, /linux_participation_unproven/);
    const competing = openSync(path, 'r');
    try { assert.throws(() => flockSync(competing, 'exnb')); } finally { closeSync(competing); }
    assert.equal(readFileSync(path, 'utf8'), '');
    assert.throws(() => verifyLinuxParticipation(path, { ...prepared, startTicks: '0' }));
    assert.throws(() => verifyLinuxParticipation(path, { ...prepared, descriptors: [] }), /identity_changed/);
    flockSync(fd, 'un');
    assert.throws(() => verifyLinuxParticipation(path, prepareLinuxParticipation(process.pid)), /linux_participation_unproven/);
  } finally { closeSync(fd); rmSync(root, { recursive: true }); }
});
