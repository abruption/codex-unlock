import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import process from "node:process";
import test from "node:test";
import { fileURLToPath, URL } from "node:url";
import { ARCHIVE, COMPONENT, TAG, VERSION, completePage, digest, verifyAssets, verifyConfig, verifyDraft, verifyExistingAssets, verifyImmutablePolicyAcknowledgement, verifySource } from "../scripts/windows-prerelease.mjs";

const sha = "a".repeat(40);
const release = { id: 1, tag_name: TAG, target_commitish: sha, draft: true, prerelease: true, author: { login: "github-actions[bot]" } };
const pull = { merged_at: "2026-10-22", merge_commit_sha: sha,
  base: { ref: "main", repo: { full_name: "abruption/codex-unlock" } },
  head: { ref: "release-please--branches--main--components--windows", repo: { full_name: "abruption/codex-unlock" } },
  user: { login: "github-actions[bot]" }, labels: [{ name: "windows-release: tagged" }] };
const source = { release, sha, pulls: [pull], cargo: `[package]\nname = "windows"\nversion = "${VERSION}"\n`, versions: { [COMPONENT]: VERSION } };
function files() {
  const zip = Buffer.from("synthetic archive for outer checksum unit test");
  return { [ARCHIVE]: zip, SHA256SUMS: Buffer.from(`${digest(zip)}  ${ARCHIVE}\r\n`),
    "manifest.json": Buffer.from(JSON.stringify({ schemaVersion: 1, sourceSha: sha,
      target: "x86_64-pc-windows-msvc", binary: { name: "codex-unlock-windows.exe", version: VERSION, sha256: "b".repeat(64) } })) };
}

test("draft verification refuses public releases, mutable refs, wrong version and author", () => {
  verifyDraft(release, sha);
  for (const change of [{ draft: false }, { prerelease: false }, { target_commitish: "main" },
    { tag_name: "v0.4.7" }, { author: { login: "abruption" } }, { id: 0 }]) {
    assert.throws(() => verifyDraft({ ...release, ...change }, sha));
  }
});
test("source requires merged component bot PR and matching Cargo/manifest versions", () => {
  verifySource(source);
  for (const change of [{ merged_at: null }, { merge_commit_sha: "b".repeat(40) },
    { head: { ...pull.head, repo: { full_name: "someone/fork" } } },
    { head: { ref: "release-please--branches--main--components--codex-unlock" } },
    { labels: [{ name: "autorelease: tagged" }] }, { user: { login: "abruption" } }]) {
    assert.throws(() => verifySource({ ...source, pulls: [{ ...pull, ...change }] }));
  }
  assert.throws(() => verifySource({ ...source, cargo: source.cargo.replace(VERSION, "0.0.0") }));
  assert.throws(() => verifySource({ ...source, versions: { [COMPONENT]: "0.0.0" } }));
});

test("immutable policy requires explicit operator acknowledgement and listing pages must be complete", () => {
  verifyImmutablePolicyAcknowledgement("true");
  for (const value of ["false", "", null, undefined, true, { enabled: true }]) {
    assert.throws(() => verifyImmutablePolicyAcknowledgement(value));
  }
  assert.deepEqual(completePage([]), []);
  assert.equal(completePage(Array(99).fill({})).length, 99);
  for (const page of [Array(100).fill({}), Array(101).fill({}), {}]) {
    assert.throws(() => completePage(page));
  }
});
test("assets require exactly three files, source/version manifest and archive digest", () => {
  verifyAssets(files(), sha);
  assert.throws(() => verifyAssets({}, sha));
  const changed = files();
  changed[ARCHIVE] = Buffer.from("tampered");
  assert.throws(() => verifyAssets(changed, sha));
  assert.throws(() => verifyAssets({ ...files(), "extra.exe": Buffer.from("") }, sha));
  assert.throws(() => verifyAssets(files(), "b".repeat(40)));
  const wrongVersion = files();
  wrongVersion["manifest.json"] = Buffer.from(wrongVersion["manifest.json"].toString().replace(VERSION, "0.0.0"));
  assert.throws(() => verifyAssets(wrongVersion, sha));
});
test("retry only accepts identical existing assets; refuses duplicates, unknown, partial and changed bytes", () => {
  const payload = files();
  const asset = { name: ARCHIVE, state: "uploaded", size: payload[ARCHIVE].length, digest: `sha256:${digest(payload[ARCHIVE])}` };
  verifyExistingAssets([asset], payload);
  for (const change of [{ name: "extra.exe" }, { state: "starter" }, { size: 0 }, { digest: "sha256:bad" }]) {
    assert.throws(() => verifyExistingAssets([{ ...asset, ...change }], payload));
  }
  assert.throws(() => verifyExistingAssets([asset, asset], payload));
});
test("separate configuration remains a fixed draft-only Rust prerelease", () => {
  const config = JSON.parse(readFileSync(new URL("../release-please-windows-config.json", import.meta.url), "utf8"));
  verifyConfig(config);
  assert.equal(config.draft, true);
  assert.equal(config.prerelease, true);
  assert.equal(config["force-tag-creation"], false);
  assert.equal(config["draft-pull-request"], true);
  assert.equal(config.label, "windows-release: pending");
  assert.equal(config["release-label"], "windows-release: tagged");
  assert.deepEqual(Object.keys(config.packages), [COMPONENT]);
  assert.equal(config.packages[COMPONENT]["release-type"], "rust");
  assert.equal(config.packages[COMPONENT]["release-as"], VERSION);
});

test("preflight rejects configuration changes that could publish or target another version", () => {
  const config = JSON.parse(readFileSync(new URL("../release-please-windows-config.json", import.meta.url), "utf8"));
  for (const change of [{ draft: false }, { prerelease: false }, { "force-tag-creation": true },
    { "draft-pull-request": false }, { label: "autorelease: pending" },
    { "release-label": "autorelease: tagged" }, { "separate-pull-requests": false }]) {
    assert.throws(() => verifyConfig({ ...config, ...change }));
  }
  for (const change of [{ draft: false }, { "release-as": "0.5.0" }, { component: "stable" },
    { "include-component-in-tag": false }, { "include-v-in-tag": false },
    { "tag-separator": "/" }, { "release-type": "node" }]) {
    assert.throws(() => verifyConfig({ ...config,
      packages: { [COMPONENT]: { ...config.packages[COMPONENT], ...change } } }));
  }
  assert.throws(() => verifyConfig({ ...config, packages: { ...config.packages, ".": {} } }));
});

test("CLI invoked through a filesystem alias fails closed without GitHub context", () => {
  const directory = mkdtempSync(join(tmpdir(), "codex-windows-prerelease-"));
  try {
    const entry = fileURLToPath(new URL("../scripts/windows-prerelease-cli.mjs", import.meta.url));
    const alias = join(directory, "aliased-cli.mjs");
    symlinkSync(entry, alias);
    for (const path of [entry, alias]) {
      const result = spawnSync(process.execPath, [path, "preflight"], { env: {}, encoding: "utf8" });
      assert.equal(result.status, 1, result.stderr);
      assert.match(result.stderr, /AssertionError/);
      assert.match(result.stderr, /abruption\/codex-unlock/);
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
