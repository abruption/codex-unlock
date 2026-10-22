import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, symlinkSync, unlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import process from 'node:process';
import { digest, validatePayload as validateRawPayload } from './validate-preview.mjs';

const sha = 'a'.repeat(40);
const binary = Buffer.from('synthetic executable bytes');
const quickstart = Buffer.from('Diagnostic preview quickstart');
const validatePayload = (entries, bytes, source) => validateRawPayload(entries, bytes, source, quickstart);
function fixture() {
  const files = {
    'codex-unlock-windows.exe': binary,
    'PREVIEW.md': Buffer.from('Diagnostic preview quickstart'),
    'manifest.json': Buffer.from(JSON.stringify({ schemaVersion: 1, sourceSha: sha,
      target: 'x86_64-pc-windows-msvc', binary: { name: 'codex-unlock-windows.exe', version: '0.0.0', sha256: digest(binary) } })),
  };
  files.SHA256SUMS = Buffer.from(Object.entries(files).map(([name, bytes]) => `${digest(bytes)}  ${name}\n`).join(''));
  return Object.entries(files);
}
test('valid minimal preview and exact build bytes', () => validatePayload(fixture(), binary, sha));
test('validator CLI executes through a directory alias and rejects changed payload', () => {
  const scratch = mkdtempSync(join(tmpdir(), 'codex-preview-validator-'));
  const alias = join(scratch, 'aliased-scripts');
  let linked = false;
  try {
    const payload = join(scratch, 'payload');
    mkdirSync(payload);
    for (const [name, bytes] of fixture()) writeFileSync(join(payload, name), bytes);
    const build = join(scratch, 'build.exe');
    writeFileSync(build, binary);
    const quickstartPath = join(scratch, 'source-PREVIEW.md');
    writeFileSync(quickstartPath, quickstart);
    symlinkSync(dirname(fileURLToPath(import.meta.url)), alias, process.platform === 'win32' ? 'junction' : 'dir');
    linked = true;
    const args = [join(alias, 'validate-preview-cli.mjs'), payload, build, sha, quickstartPath];
    assert.match(execFileSync(process.execPath, args, { encoding: 'utf8', timeout: 10_000 }), /checks passed/);
    writeFileSync(join(payload, 'codex-unlock-windows.exe'), 'changed');
    assert.throws(() => execFileSync(process.execPath, args, { stdio: 'pipe', timeout: 10_000 }),
      (error) => error.status !== 0);
  } finally {
    if (linked) unlinkSync(alias);
    rmSync(scratch, { recursive: true, force: true });
  }
});
test('rejects extra research binaries, traversal, missing and duplicate entries', () => {
  for (const extra of ['fixture.exe', '../evidence.json', 'codex-unlock-windows.exe']) {
    assert.throws(() => validatePayload([...fixture(), [extra, binary]], binary, sha));
  }
  assert.throws(() => validatePayload(fixture().slice(1), binary, sha));
});
test('rejects modified executable, quickstart, manifest, checksums and source SHA', () => {
  for (let index = 0; index < 4; index++) {
    const entries = fixture();
    entries[index] = [entries[index][0], Buffer.from('tampered')];
    assert.throws(() => validatePayload(entries, binary, sha));
  }
  assert.throws(() => validatePayload(fixture(), Buffer.from('different build'), sha));
  assert.throws(() => validatePayload(fixture(), binary, 'b'.repeat(40)));
  assert.throws(() => validatePayload(fixture(), binary, 'not-a-sha'));
  assert.throws(() => validateRawPayload(fixture(), binary, sha, Buffer.from('different source')));
});
test('rejects structurally valid but incorrect manifest fields', () => {
  for (const change of [
    (manifest) => { manifest.target = 'aarch64-pc-windows-msvc'; },
    (manifest) => { manifest.schemaVersion = 2; },
    (manifest) => { manifest.binary.version = '1.0.0'; },
    (manifest) => { manifest.binary.sha256 = '0'.repeat(64); },
    (manifest) => { manifest.binary.name = 'fixture.exe'; },
    (manifest) => { manifest.extra = 'unexpected'; },
  ]) {
    const entries = fixture();
    const manifest = JSON.parse(entries[2][1]);
    change(manifest);
    entries[2][1] = Buffer.from(JSON.stringify(manifest));
    // Rehashing a malformed manifest does not make its metadata acceptable.
    entries[3][1] = Buffer.from(entries.slice(0, 3).map(([name, bytes]) => `${digest(bytes)}  ${name}\n`).join(''));
    assert.throws(() => validatePayload(entries, binary, sha));
  }
});
