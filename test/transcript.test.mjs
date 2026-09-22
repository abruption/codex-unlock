import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  inspectTranscriptCandidates,
  inspectTranscriptPath,
  sameLastRecord,
  stableFileHash,
} from "../dist/transcript.js";

test("reads the last non-empty transcript record", async () => {
  const directory = await mkdtemp(join(tmpdir(), "codex-unlock-transcript-"));
  const path = join(directory, "rollout.jsonl");
  await writeFile(
    path,
    `${JSON.stringify({ type: "event_msg", payload: { type: "task_started" } })}\n` +
      `${JSON.stringify({
        timestamp: "2026-09-22T00:00:00.000Z",
        type: "event_msg",
        payload: { type: "task_complete" },
      })}\n\n`,
  );

  const result = await inspectTranscriptPath(path);
  assert.equal(result.status, "found");
  assert.equal(result.stable, true);
  assert.deepEqual(result.lastRecord, {
    recordType: "event_msg",
    eventType: "task_complete",
    timestamp: "2026-09-22T00:00:00.000Z",
    ordinal: null,
  });
  const hashed = await stableFileHash(path);
  assert.equal(hashed.hash.length, 64);
});

test("distinguishes missing and ambiguous transcript candidates", async () => {
  assert.equal((await inspectTranscriptCandidates([])).status, "missing");
  const ambiguous = await inspectTranscriptCandidates(["/tmp/a.jsonl", "/tmp/b.jsonl"]);
  assert.equal(ambiguous.status, "ambiguous");
  assert.equal(ambiguous.path, null);
});

test("compares normalized last-record evidence", () => {
  const record = {
    recordType: "event_msg",
    eventType: "task_complete",
    timestamp: null,
    ordinal: 3,
  };
  assert.equal(sameLastRecord(record, { ...record }), true);
  assert.equal(sameLastRecord(record, { ...record, ordinal: 4 }), false);
});
