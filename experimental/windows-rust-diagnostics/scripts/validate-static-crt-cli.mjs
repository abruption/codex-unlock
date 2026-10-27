import assert from 'node:assert/strict';
import { log } from 'node:console';
import { readFileSync } from 'node:fs';
import process from 'node:process';
import { validateStaticCrt } from './validate-static-crt.mjs';

assert.equal(process.argv.length, 2, 'usage: dumpbin /DEPENDENTS BINARY | node validate-static-crt-cli.mjs');
const imports = validateStaticCrt(readFileSync(0, 'utf8'));
log(`Static CRT dependency check passed: ${imports.join(', ')}`);
