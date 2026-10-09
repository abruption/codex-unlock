import assert from "node:assert/strict";
import test from "node:test";

import { verifyReleaseMetadata } from "../scripts/verify-release-source.mjs";

const fixture = () => ({
  tag: "v0.4.4", sha: "a".repeat(40), manifest: { name: "codex-unlock", version: "0.4.4" },
  versions: { ".": "0.4.4" },
  release: { tag_name: "v0.4.4", draft: false, prerelease: false, immutable: true,
    author: { login: "github-actions[bot]" } },
  pulls: [{ merged_at: "2026-10-07T00:00:00Z", merge_commit_sha: "a".repeat(40),
    base: { ref: "main" }, user: { login: "github-actions[bot]" },
    head: { ref: "release-please--branches--main--components--codex-unlock" },
    labels: [{ name: "autorelease: tagged" }] }],
});

test("recovery requires an existing immutable Release Please release for the exact version and merge", () => {
  verifyReleaseMetadata(fixture());
  for (const mutate of [
    (f) => { f.tag = "v9.9.9"; },
    (f) => { f.manifest.version = "0.4.5"; },
    (f) => { f.versions["."] = "0.4.5"; },
    (f) => { f.release.draft = true; },
    (f) => { f.release.prerelease = true; },
    (f) => { f.release.immutable = false; },
    (f) => { f.release.author.login = "writer"; },
    (f) => { f.pulls = []; },
    (f) => { f.pulls[0].merged_at = null; },
    (f) => { f.pulls[0].merge_commit_sha = "b".repeat(40); },
    (f) => { f.pulls[0].base.ref = "unreviewed"; },
    (f) => { f.pulls[0].user.login = "writer"; },
    (f) => { f.pulls[0].head.ref = "ordinary-feature"; },
    (f) => { f.pulls[0].labels = []; },
  ]) {
    const value = fixture();
    mutate(value);
    assert.throws(() => verifyReleaseMetadata(value));
  }
});
