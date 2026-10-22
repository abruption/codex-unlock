import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

export const names = ['PREVIEW.md', 'SHA256SUMS', 'codex-unlock-windows.exe', 'manifest.json'].sort();
export const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
export const versionPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

export function validatePayload(entries, binary, sourceSha, quickstart, expectedVersion) {
  assert.match(expectedVersion, versionPattern, 'explicit expected version required');
  assert.match(sourceSha, /^[a-f0-9]{40}$/);
  assert.deepEqual(entries.map(([name]) => name).sort(), names, 'unexpected or duplicate archive entries');
  const files = Object.fromEntries(entries);
  assert.ok(binary.length > 0, 'empty executable');
  assert.deepEqual(files['codex-unlock-windows.exe'], binary, 'packaged executable differs from build');
  assert.ok(quickstart?.length > 0, 'empty source quickstart');
  assert.deepEqual(files['PREVIEW.md'], quickstart, 'packaged quickstart differs from source');
  const manifest = JSON.parse(files['manifest.json'].toString('utf8'));
  assert.deepEqual(Object.keys(manifest).sort(), ['binary', 'schemaVersion', 'sourceSha', 'target']);
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.sourceSha, sourceSha);
  assert.equal(manifest.target, 'x86_64-pc-windows-msvc');
  assert.deepEqual(manifest.binary, {
    name: 'codex-unlock-windows.exe', version: expectedVersion, sha256: digest(binary),
  });
  const expected = ['codex-unlock-windows.exe', 'PREVIEW.md', 'manifest.json']
    .map((name) => `${digest(files[name])}  ${name}\n`).join('');
  assert.equal(files.SHA256SUMS.toString('utf8').replaceAll('\r\n', '\n'), expected, 'payload checksum mismatch');
}

