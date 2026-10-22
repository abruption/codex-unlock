import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import process from 'node:process';
import test from 'node:test';
import { parsePreviewDiagnostic } from '../observe-native.mjs';

const directory = process.env.PREVIEW_TEST_GOLDEN_DIR;
test('observer accepts actual Rust mapping output with the documented exit contract', {
  skip: !directory && process.env.PREVIEW_GOLDEN_REQUIRED !== '1',
}, () => {
  assert.ok(directory, 'CI must supply the Rust-generated mapping fixtures');
  const cases = JSON.parse(readFileSync(join(directory, 'preview-mapping-golden.json'), 'utf8'));
  const expected = { held_no_pid: [0, 'held'], free_no_pid: [0, 'free'], unknown_lock: [2, 'unknown'],
    unknown_process: [2, 'held'], different_user: [2, 'free'], same_user: [0, 'held'] };
  assert.ok(Array.isArray(cases));
  assert.deepEqual(cases.map(({ name }) => name).sort(), Object.keys(expected).sort());
  for (const entry of cases) {
    assert.deepEqual([entry.exitCode, entry.result.lock.state], expected[entry.name]);
    assert.equal(typeof entry.request.expectedVersion, 'string', 'Rust producer must supply the expected build version');
    const record = { stdout: JSON.stringify(entry.result), exit: { code: entry.exitCode, signal: null },
      complete: true, faults: [] };
    assert.equal(parsePreviewDiagnostic(record, entry.request).parsed.safeToUnlock, false);
    assert.throws(() => parsePreviewDiagnostic({ ...record }, { ...entry.request, expectedVersion: '999.0.0' }));
  }
});
