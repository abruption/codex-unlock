import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm, lstat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import process from "node:process";
import { spawnSync } from "node:child_process";
import { URL } from "node:url";

import { publicSnapshot, sameSnapshot } from "../dist/util.js";
import { observeLockFile } from "../dist/lock.js";
import { inspectTranscriptPath, stableFileHash } from "../dist/transcript.js";

const fixture = (extra = {}) => ({
  dev: 1n, ino: 9007199254740992n, mode: 33152n, uid: 501n,
  nlink: 1n, size: 5n, mtime: new Date(1700000000000),
  mtimeMs: 1700000000000n, mtimeNs: 1700000000000123456n, ...extra,
});

test("adjacent 64-bit identities stay distinct and JSON serializable", () => {
  const first = publicSnapshot(fixture());
  const second = publicSnapshot(fixture({ ino: 9007199254740993n }));
  assert.equal(first.inode, "9007199254740992");
  assert.equal(second.inode, "9007199254740993");
  assert.equal(sameSnapshot(first, second), false);
  assert.equal(sameSnapshot(first, publicSnapshot(fixture())), true);
  const device = publicSnapshot(fixture({ dev: 18446744073709551615n }));
  assert.equal(device.device, "18446744073709551615");
  assert.equal(sameSnapshot(first, device), false);
  assert.doesNotThrow(() => JSON.stringify(device));
});

test("v1 fractional modification time is retained, not truncated", () => {
  const first = publicSnapshot(fixture());
  assert.equal(first.modifiedMs, 1700000000000 + 123456 / 1000000);
  assert.equal(first.modifiedAt, "2023-11-14T22:13:20.000Z");
  assert.equal(sameSnapshot(first, publicSnapshot(fixture({
    mtimeNs: 1700000000000987654n,
  }))), false);
});

test("rounded numeric identities and unrepresentable v1 fields are rejected", () => {
  for (const field of ["dev", "ino", "mode", "uid", "nlink", "size"]) {
    assert.throws(() => publicSnapshot(fixture({ [field]: Number(9007199254740993n) })), /safe/);
  }
  for (const field of ["mode", "uid", "nlink", "size"]) {
    assert.throws(() => publicSnapshot(fixture({ [field]: 9007199254740993n })), /safe/);
    assert.throws(() => publicSnapshot(fixture({ [field]: -1n })), /safe/);
  }
  assert.throws(() => publicSnapshot(fixture({ dev: -1n })), /negative/);
  const numeric = { ...fixture(), dev: 1, ino: 2, mtimeMs: 1700000000000.125 };
  delete numeric.mtimeNs;
  assert.equal(publicSnapshot(numeric).modifiedMs, numeric.mtimeMs);
  assert.throws(() => publicSnapshot({ ...numeric, mtimeMs: NaN }), /representable/);
});

test("real lock and rollout producers preserve bigint identity and stable hashes", async () => {
  const root = await mkdtemp(join(tmpdir(), "codex-lossless-"));
  try {
    const path = join(root, "fixture.jsonl");
    await writeFile(path, '{"type":"event_msg","payload":{"type":"task_complete"}}\n');
    const stat = await lstat(path, { bigint: true });
    const expected = publicSnapshot(stat);
    const observed = observeLockFile(path);
    assert.equal(observed.status, "present");
    assert.deepEqual(observed.snapshot, expected);
    assert.equal(observed.ownedByCurrentUser, stat.uid === BigInt(process.getuid()));
    const transcript = await inspectTranscriptPath(path);
    assert.equal(transcript.status, "found");
    assert.equal(transcript.stable, true);
    assert.deepEqual(transcript.snapshot, expected);
    assert.deepEqual((await stableFileHash(path)).snapshot, expected);
    assert.equal(observeLockFile(join(root, "missing")).status, "absent");
    assert.equal((await inspectTranscriptPath(join(root, "missing"))).status, "unreadable");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("unrepresentable snapshot fields fail closed at diagnostic boundaries", async () => {
  const root = await mkdtemp(join(tmpdir(), "codex-lossless-failure-"));
  try {
    const path = join(root, "fixture.jsonl");
    await writeFile(path, '{"type":"event_msg","payload":{"type":"task_complete"}}\n');
    const child = spawnSync(process.execPath, ["--input-type=module", "--eval", `
      import fs from "node:fs";
      import fsp from "node:fs/promises";
      import { syncBuiltinESMExports } from "node:module";
      const sync = fs.lstatSync;
      const asyncStat = fsp.lstat;
      fs.lstatSync = (...args) => ({ ...sync(...args), size: 9007199254740993n,
        isFile: () => true, isSymbolicLink: () => false });
      fsp.lstat = async (...args) => ({ ...await asyncStat(...args), size: 9007199254740993n,
        isFile: () => true, isSymbolicLink: () => false });
      syncBuiltinESMExports();
      const { observeLockFile } = await import(${JSON.stringify(new URL("../dist/lock.js", import.meta.url).href)});
      const { inspectTranscriptPath, stableFileHash } = await import(${JSON.stringify(new URL("../dist/transcript.js", import.meta.url).href)});
      const path = ${JSON.stringify(path)};
      const lock = observeLockFile(path);
      const transcript = await inspectTranscriptPath(path);
      let hashRejected = false;
      try { await stableFileHash(path); } catch { hashRejected = true; }
      console.log(JSON.stringify({ lock, transcript, hashRejected }));
    `], { encoding: "utf8", timeout: 5000 });
    assert.equal(child.status, 0, child.stderr);
    const result = JSON.parse(child.stdout);
    assert.equal(result.lock.status, "unknown");
    assert.equal(result.lock.snapshot, null);
    assert.equal(result.transcript.status, "unreadable");
    assert.equal(result.transcript.snapshot, null);
    assert.equal(result.hashRejected, true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
