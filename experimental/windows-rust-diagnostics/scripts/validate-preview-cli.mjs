// Unconditional CLI entry: path aliases must never skip artifact validation.
import assert from 'node:assert/strict';
import process from 'node:process';
import { log } from 'node:console';
import { readFile, readdir, lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { validatePayload } from './validate-preview.mjs';

const args = process.argv.slice(2);
assert.equal(args.length, 5, 'usage: validate-preview-cli.mjs DIRECTORY BINARY SOURCE_SHA QUICKSTART EXPECTED_VERSION');
const [directory, binaryPath, sourceSha, quickstartPath, expectedVersion] = args;
assert.ok(directory && binaryPath && sourceSha && quickstartPath);
const entries = await Promise.all((await readdir(directory)).map(async (name) => {
  const path = join(directory, name);
  assert.ok((await lstat(path)).isFile(), 'payload must contain regular files only');
  return [name, await readFile(path)];
}));
validatePayload(entries, await readFile(binaryPath), sourceSha, await readFile(quickstartPath), expectedVersion);
log('Preview payload shape, manifest and build-byte checks passed.');
