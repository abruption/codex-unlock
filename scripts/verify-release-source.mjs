import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { log } from "node:console";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import process from "node:process";

export function verifyReleaseMetadata({ tag, sha, manifest, versions, release, pulls }) {
  assert.match(tag ?? "", /^v\d+\.\d+\.\d+$/);
  assert.match(sha ?? "", /^[a-f0-9]{40}$/);
  assert.equal(manifest.name, "codex-unlock");
  assert.equal(tag, `v${manifest.version}`, "Release tag must match package version");
  assert.equal(versions["."], manifest.version, "Release Please version must match package version");
  assert.equal(release.tag_name, tag);
  assert.equal(release.draft, false);
  assert.equal(release.prerelease, false);
  assert.equal(release.immutable, true, "Recovery requires an existing immutable release");
  assert.equal(release.author?.login, "github-actions[bot]");
  assert.ok(pulls.some((pr) => pr.merged_at && pr.merge_commit_sha === sha &&
    pr.base?.ref === "main" && pr.user?.login === "github-actions[bot]" &&
    pr.head?.ref === "release-please--branches--main--components--codex-unlock" &&
    pr.labels?.some(({ name }) => name === "autorelease: tagged")),
  "Source must be the merge commit of a tagged Release Please PR on main");
}

async function github(path) {
  const response = await globalThis.fetch(`https://api.github.com/repos/abruption/codex-unlock/${path}`, {
    headers: { Accept: "application/vnd.github+json", Authorization: `Bearer ${process.env.GH_TOKEN}`,
      "X-GitHub-Api-Version": "2022-11-28" },
    redirect: "error", signal: globalThis.AbortSignal.timeout(10_000),
  });
  assert.ok(response.ok, `Release source lookup failed: HTTP ${response.status}`);
  return await response.json();
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(import.meta.filename)) {
  const tag = process.env.RELEASE_TAG;
  const sha = process.env.GITHUB_SHA;
  assert.match(tag ?? "", /^v\d+\.\d+\.\d+$/);
  assert.match(sha ?? "", /^[a-f0-9]{40}$/);
  if (process.env.GITHUB_EVENT_NAME === "workflow_dispatch") {
    assert.equal(process.env.GITHUB_REF, `refs/tags/${tag}`, "Recovery must run on the release tag");
  }
  assert.equal(execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim(), sha);
  execFileSync("git", ["merge-base", "--is-ancestor", "HEAD", "origin/main"]);
  const [release, pulls] = await Promise.all([
    github(`releases/tags/${tag}`), github(`commits/${sha}/pulls`),
  ]);
  verifyReleaseMetadata({ tag, sha, release, pulls,
    manifest: JSON.parse(readFileSync("package.json", "utf8")),
    versions: JSON.parse(readFileSync(".release-please-manifest.json", "utf8")),
  });
  log(`Verified existing Release Please release ${tag} at ${sha}`);
}
