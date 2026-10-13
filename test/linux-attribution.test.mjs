import assert from 'node:assert/strict';
import process from 'node:process';
import { URL } from 'node:url';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { mkdtempSync, writeFileSync, openSync, closeSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { flockSync } from 'fs-ext-extra-prebuilt';
import { assertProcNamespace, parseFlockRows, parseStartTicks, prepareLinuxParticipation, verifyLinuxParticipation } from '../dist/linux-attribution.js';

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
  assert.equal(parseFlockRows(`lock: 1: FLOCK ADVISORY WRITE 1 00:02:${large} 0 EOF`)[0].inode.toString(), large);
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

test('Linux real FLOCK participates; open-but-unlocked descriptor does not', { skip: process.platform !== 'linux' }, () => {
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
      if (error.message === 'linux_filesystem_unsupported') return;
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
    assert.equal(readFileSync(path, 'utf8'), '');
    assert.throws(() => verifyLinuxParticipation(path, { ...prepared, startTicks: '0' }));
    assert.throws(() => verifyLinuxParticipation(path, { ...prepared, descriptors: [] }), /identity_changed/);
    flockSync(fd, 'un');
    assert.throws(() => verifyLinuxParticipation(path, prepareLinuxParticipation(process.pid)), /linux_participation_unproven/);
  } finally { closeSync(fd); rmSync(root, { recursive: true }); }
});
