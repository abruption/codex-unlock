import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import process from 'node:process';
import test from 'node:test';
import { fileURLToPath, URL } from 'node:url';
import { validateStaticCrt } from './validate-static-crt.mjs';

const report = (extra = '') => `
Dump of file C:\\build directory\\codex-unlock-windows.exe

File Type: EXECUTABLE IMAGE

  Image has the following dependencies:

    KERNEL32.dll
    ADVAPI32.dll
    ntdll.dll
${extra}
  Summary

        1000 .data
        1000 .pdata
`;

test('static CRT gate accepts system dependencies with Windows line endings', () => {
  assert.deepEqual(validateStaticCrt(report().replaceAll('\n', '\r\n')), ['KERNEL32.dll', 'ADVAPI32.dll', 'ntdll.dll']);
});

test('static CRT gate rejects direct and delay-loaded runtime dependencies', () => {
  for (const name of ['VCRUNTIME140.dll', 'vcruntime140_1.dll', 'MSVCP140.dll', 'msvcr120.dll',
    'CONCRT140.dll', 'ucrtbase.dll', 'api-ms-win-crt-runtime-l1-1-0.dll']) {
    for (const heading of ['', '\n  Image has the following delay load dependencies:\n']) {
      assert.throws(() => validateStaticCrt(report(`${heading}    ${name}\n`)), /external MSVC CRT/);
    }
  }
});

test('static CRT gate fails closed on empty, incomplete and unexpected reports', () => {
  for (const invalid of ['', 'dumpbin failed', report().replace('KERNEL32.dll', 'UNKNOWN.dll'),
    report().replace('Dump of file', 'Something else'), report('    C:\\external\\VCRUNTIME140.dll\n')]) {
    assert.throws(() => validateStaticCrt(invalid));
  }
});

test('static CRT CLI consumes stdin and exits unsuccessfully for dynamic CRT', () => {
  const args = [fileURLToPath(new URL('./validate-static-crt-cli.mjs', import.meta.url))];
  assert.match(execFileSync(process.execPath, args, { input: report(), encoding: 'utf8', timeout: 10_000 }), /check passed/);
  assert.throws(() => execFileSync(process.execPath, args, {
    input: report('    VCRUNTIME140.dll\n'), stdio: ['pipe', 'pipe', 'pipe'], timeout: 10_000,
  }), (error) => error.status !== 0);
});
