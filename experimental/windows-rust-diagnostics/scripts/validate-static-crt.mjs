import assert from 'node:assert/strict';

// dumpbin /DEPENDENTS includes both normal and delay-loaded dependencies.
// Inspect every DLL line, rather than stopping at the first dependency group.
export function validateStaticCrt(output) {
  assert.equal(typeof output, 'string');
  assert.match(output, /^Dump of file .+\.exe\s*$/im, 'missing dumpbin PE report');
  const imports = [];
  for (const line of output.split(/\r?\n/)) {
    if (!/\.dll/i.test(line)) continue;
    const match = /^\s+([a-z0-9_.-]+\.dll)\s*$/i.exec(line);
    assert.ok(match, 'unrecognized DLL dependency line');
    imports.push(match[1]);
  }
  assert.ok(imports.some((name) => /^kernel32\.dll$/i.test(name)), 'missing expected Windows system import');
  const runtime = /^(?:vcruntime|msvcp|msvcr|concrt|ucrtbase|api-ms-win-crt-).*\.dll$/i;
  assert.deepEqual(imports.filter((name) => runtime.test(name)), [], 'preview requires an external MSVC CRT');
  return imports;
}
