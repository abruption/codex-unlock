import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, lstatSync, readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import process from "node:process";
import { URL } from "node:url";

export function verifyPlan(plan) {
  const allowed = [
    { version: "0.5.0-rc.1", previousVersion: "0.5.0-alpha.1", prerelease: true },
    { version: "0.5.0", previousVersion: "0.5.0-rc.1", prerelease: false },
  ];
  const expected = allowed.find((candidate) => candidate.version === plan?.version);
  assert.ok(expected, "Unsupported Windows release target");
  assert.deepEqual(plan, expected, "Windows release plan must follow alpha.1 -> rc.1 -> 0.5.0");
}

export const PLAN = Object.freeze(JSON.parse(readFileSync(new URL("../windows-release-plan.json", import.meta.url), "utf8")));
verifyPlan(PLAN);
export const VERSION = PLAN.version;
export const TAG = `windows-v${VERSION}`;
export const COMPONENT = "experimental/windows-rust-diagnostics";
export const ARCHIVE = "windows-diagnostics-preview-windows-x86_64.zip";
export const ASSETS = [ARCHIVE, "SHA256SUMS", "manifest.json"].sort();
const repo = "abruption/codex-unlock";
// The reusable workflow definition and attachment helper come from the dispatch
// checkout, while the executable comes from the version-PR merge. Bind all
// release control files to the same bytes to prevent interpreting that source
// under another plan or workflow. Ordinary source/documentation may differ.
export const SOURCE_BINDINGS = [
  "windows-release-plan.json", "release-please-windows-config.json",
  "scripts/windows-prerelease.mjs", "scripts/windows-prerelease-cli.mjs",
  ".github/workflows/windows-prerelease.yml", ".github/workflows/windows-rust-diagnostics.yml",
];
export const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

export function verifyImmutablePolicyAcknowledgement(value) {
  assert.equal(value, "true",
    "Maintainer must independently verify immutable releases are enabled before dispatch; this is an acknowledgement, not a policy measurement");
}

export function completePage(items) {
  assert.ok(Array.isArray(items) && items.length < 100,
    "Refuse incomplete paginated results; release preparation requires fewer than 100 entries");
  return items;
}

export function verifyConfig(config, plan = PLAN) {
  verifyPlan(plan);
  // This preparation lane is intentionally fixed. Reject unexpected fields as
  // well as overrides: a per-package draft:false would defeat a top-level check.
  assert.deepEqual(config, {
    $schema: "https://raw.githubusercontent.com/googleapis/release-please/main/schemas/config.json",
    "bootstrap-sha": "cdd4bf1769c6a24d90b1624c4c9ea8d022666b7e",
    "separate-pull-requests": true,
    "draft-pull-request": true,
    draft: true,
    prerelease: plan.prerelease,
    "force-tag-creation": false,
    label: "windows-release: pending",
    "release-label": "windows-release: tagged",
    packages: { [COMPONENT]: {
      "release-type": "rust",
      component: "windows",
      "include-component-in-tag": true,
      "include-v-in-tag": true,
      "tag-separator": "-",
      "release-as": plan.version,
      "changelog-path": "CHANGELOG.md",
    } },
  }, "Windows preparation configuration must remain fixed and draft-only");
}

export function verifyDraft(release, sha, plan = PLAN) {
  verifyPlan(plan);
  assert.match(sha ?? "", /^[a-f0-9]{40}$/);
  assert.equal(release.tag_name, `windows-v${plan.version}`);
  assert.equal(release.target_commitish, sha, "Draft must target the immutable release merge SHA");
  assert.equal(release.draft, true, "Only draft releases may receive assets");
  assert.equal(release.prerelease, plan.prerelease);
  assert.equal(release.author?.login, "github-actions[bot]");
  assert.ok(Number.isSafeInteger(release.id) && release.id > 0);
}

export function verifyCargoVersion(cargo, version) {
  const sections = cargo.split(/^\[package\]\s*$/m);
  assert.equal(sections.length, 2, "Require exactly one Cargo package section");
  const packageSection = sections[1]?.split(/^\[/m)[0];
  assert.ok(packageSection, "Missing Cargo package section");
  const matches = [...packageSection.matchAll(/^version\s*=\s*"([^"\r\n]+)"\s*$/gm)];
  assert.equal(matches.length, 1, "Require exactly one literal Cargo package version");
  assert.equal(matches[0][1], version, "Cargo version differs from the release plan");
}

export function verifyVersionState(versions, operation, plan = PLAN) {
  verifyPlan(plan);
  assert.ok(["prepare", "draft"].includes(operation));
  assert.deepEqual(versions, { [COMPONENT]: operation === "prepare" ? plan.previousVersion : plan.version },
    "Windows manifest does not match the release phase");
}

export function verifyPreviousRelease(release, tagCommit, plan = PLAN) {
  verifyPlan(plan);
  assert.equal(release.tag_name, `windows-v${plan.previousVersion}`);
  assert.equal(release.draft, false, "Previous Windows release must be public");
  assert.equal(release.prerelease, true, "Both allowed predecessors are prereleases");
  assert.equal(release.immutable, true, "Previous Windows release must be immutable");
  assert.equal(release.author?.login, "github-actions[bot]");
  assert.ok(Number.isSafeInteger(release.id) && release.id > 0);
  assert.match(release.target_commitish ?? "", /^[a-f0-9]{40}$/);
  assert.equal(tagCommit, release.target_commitish, "Previous public tag must match its release source");
}

export function verifySourceBindings(sourceFiles, checkoutFiles) {
  assert.deepEqual(Object.keys(sourceFiles).sort(), [...SOURCE_BINDINGS].sort());
  assert.deepEqual(Object.keys(checkoutFiles).sort(), [...SOURCE_BINDINGS].sort());
  for (const path of SOURCE_BINDINGS) {
    assert.ok(Buffer.isBuffer(sourceFiles[path]) && Buffer.isBuffer(checkoutFiles[path]));
    assert.deepEqual(sourceFiles[path], checkoutFiles[path], `Release control file differs at source: ${path}`);
  }
}

export function verifySource({ release, sha, pulls, cargo, versions, plan, config }, expectedPlan = PLAN) {
  verifyPlan(plan);
  assert.deepEqual(plan, expectedPlan, "Version PR source belongs to another release plan");
  verifyConfig(config, expectedPlan);
  verifyDraft(release, sha, expectedPlan);
  verifyCargoVersion(cargo, expectedPlan.version);
  verifyVersionState(versions, "draft", expectedPlan);
  assert.ok(pulls.some((pr) => pr.merged_at && pr.merge_commit_sha === sha &&
    pr.base?.ref === "main" && pr.base?.repo?.full_name === repo &&
    pr.user?.login === "github-actions[bot]" &&
    pr.head?.ref === "release-please--branches--main--components--windows" &&
    pr.head?.repo?.full_name === repo &&
    pr.labels?.some(({ name }) => name === "windows-release: tagged")),
  "Source must be a merged Windows Release Please PR");
}

export function verifyAssets(files, sha, plan = PLAN) {
  verifyPlan(plan);
  assert.deepEqual(Object.keys(files).sort(), ASSETS);
  const manifest = JSON.parse(files["manifest.json"].toString("utf8"));
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.sourceSha, sha);
  assert.equal(manifest.target, "x86_64-pc-windows-msvc");
  assert.equal(manifest.binary?.name, "codex-unlock-windows.exe");
  assert.equal(manifest.binary?.version, plan.version);
  assert.match(manifest.binary?.sha256 ?? "", /^[a-f0-9]{64}$/);
  assert.equal(files.SHA256SUMS.toString("utf8").trim(), `${digest(files[ARCHIVE])}  ${ARCHIVE}`);
  return manifest;
}

export function verifyExistingAssets(assets, files) {
  completePage(assets);
  assert.equal(new Set(assets.map((asset) => asset.name)).size, assets.length);
  for (const asset of assets) {
    assert.ok(ASSETS.includes(asset.name), "Unexpected existing release asset");
    assert.equal(asset.state, "uploaded");
    assert.equal(asset.size, files[asset.name].length);
    assert.equal(asset.digest, `sha256:${digest(files[asset.name])}`, "Existing bytes differ; never overwrite assets");
  }
}

async function api(path, options = {}) {
  const response = await globalThis.fetch(`https://api.github.com/repos/${repo}/${path}`, {
    ...options, headers: { Accept: "application/vnd.github+json",
      Authorization: `Bearer ${process.env.GH_TOKEN}`, "X-GitHub-Api-Version": "2022-11-28",
      ...options.headers }, redirect: "error", signal: globalThis.AbortSignal.timeout(30_000),
  });
  assert.ok(response.ok, `GitHub lookup failed: HTTP ${response.status}`);
  return response.json();
}

async function repositoryFile(path, ref) {
  const file = await api(`contents/${path}?ref=${ref}`);
  assert.equal(file.type, "file");
  assert.equal(file.encoding, "base64");
  assert.equal(typeof file.content, "string");
  return Buffer.from(file.content, "base64");
}

async function previousTagCommit(tag) {
  const ref = await api(`git/ref/tags/${tag}`);
  assert.equal(ref.ref, `refs/tags/${tag}`);
  let object = ref.object;
  const visited = new Set();
  for (let depth = 0; depth < 4; depth++) {
    assert.match(object?.sha ?? "", /^[a-f0-9]{40}$/);
    if (object.type === "commit") return object.sha;
    assert.equal(object.type, "tag", "Previous tag must resolve to a commit");
    assert.ok(!visited.has(object.sha), "Cyclic tag reference");
    visited.add(object.sha);
    const annotated = await api(`git/tags/${object.sha}`);
    assert.equal(annotated.sha, object.sha);
    object = annotated.object;
  }
  assert.fail("Previous annotated tag chain exceeds the inspection bound");
}

async function previousRelease(releases) {
  const previousTag = `windows-v${PLAN.previousVersion}`;
  const matches = releases.filter((release) => release.tag_name === previousTag);
  assert.equal(matches.length, 1, "Require exactly one published predecessor");
  verifyPreviousRelease(matches[0], await previousTagCommit(previousTag));
  const comparison = await api(`compare/${matches[0].target_commitish}...main`);
  assert.ok(["ahead", "identical"].includes(comparison.status), "Previous release must belong to main");
}

async function findDraft() {
  // Drafts have no tag ref; list releases rather than resolving a public tag.
  const releases = completePage(await api("releases?per_page=100"));
  const matches = releases.filter((release) => release.tag_name === TAG);
  assert.equal(matches.length, 1, "Require exactly one matching release");
  return matches[0];
}

async function source(release) {
  const sha = release.target_commitish;
  verifyDraft(release, sha);
  const [pulls, cargo, versions, comparison, bindings] = await Promise.all([
    api(`commits/${sha}/pulls`),
    repositoryFile(`${COMPONENT}/Cargo.toml`, sha),
    repositoryFile(".release-please-windows-manifest.json", sha),
    api(`compare/${sha}...main`),
    Promise.all(SOURCE_BINDINGS.map(async (path) => [path, await repositoryFile(path, sha)])),
  ]);
  assert.ok(["ahead", "identical"].includes(comparison.status), "Source must belong to main");
  const sourceFiles = Object.fromEntries(bindings);
  verifySourceBindings(sourceFiles, Object.fromEntries(SOURCE_BINDINGS.map((path) => [path, readFileSync(path)])));
  verifySource({ release, sha, pulls,
    cargo: cargo.toString("utf8"),
    versions: JSON.parse(versions.toString("utf8")),
    plan: JSON.parse(sourceFiles["windows-release-plan.json"].toString("utf8")),
    config: JSON.parse(sourceFiles["release-please-windows-config.json"].toString("utf8")),
  });
  return sha;
}

export async function main() {
  assert.equal(process.env.GITHUB_REPOSITORY, repo);
  assert.equal(process.env.GITHUB_REF, "refs/heads/main");
  assert.equal(process.env.GITHUB_EVENT_NAME, "workflow_dispatch");
  const mode = process.argv[2];
  assert.ok(["preflight", "resolve", "attach"].includes(mode));
  if (mode === "preflight") {
    verifyImmutablePolicyAcknowledgement(process.env.IMMUTABLE_POLICY_CONFIRMED);
    const operation = process.env.OPERATION;
    assert.ok(["prepare", "draft"].includes(operation));
    verifyConfig(JSON.parse(readFileSync("release-please-windows-config.json", "utf8")));
    // Release Please reads target-branch files, which can advance after dispatch.
    const [livePlan, liveConfig] = await Promise.all([
      repositoryFile("windows-release-plan.json", "main"),
      repositoryFile("release-please-windows-config.json", "main"),
    ]);
    assert.deepEqual(JSON.parse(livePlan.toString("utf8")), PLAN, "Live main has a different release plan");
    verifyConfig(JSON.parse(liveConfig.toString("utf8")));
    const versions = JSON.parse(readFileSync(".release-please-windows-manifest.json", "utf8"));
    verifyVersionState(versions, operation);
    verifyCargoVersion(readFileSync(`${COMPONENT}/Cargo.toml`, "utf8"), versions[COMPONENT]);
    const refs = await api(`git/matching-refs/tags/${TAG}`);
    assert.ok(!refs.some((ref) => ref.ref === `refs/tags/${TAG}`), "Preparation requires no public release tag");
    const releases = completePage(await api("releases?per_page=100"));
    await previousRelease(releases);
    const matches = releases.filter((item) => item.tag_name === TAG);
    assert.ok(matches.length <= 1, "Ambiguous release identity");
    if (matches.length) {
      assert.equal(operation, "draft", "An existing draft already completes preparation");
      await source(matches[0]);
    }
    appendFileSync(process.env.GITHUB_OUTPUT, `run_release_please=${matches.length === 0}\n`);
    return;
  }
  const release = await findDraft();
  const sha = await source(release);
  if (mode === "resolve") {
    if (process.env.CREATED_SHA) assert.equal(sha, process.env.CREATED_SHA);
    if (process.env.CREATED_TAG) assert.equal(release.tag_name, process.env.CREATED_TAG);
    appendFileSync(process.env.GITHUB_OUTPUT, `source_sha=${sha}\nrelease_id=${release.id}\n`);
    return;
  }
  assert.equal(sha, process.env.SOURCE_SHA);
  assert.equal(String(release.id), process.env.RELEASE_ID);
  verifyImmutablePolicyAcknowledgement(process.env.IMMUTABLE_POLICY_CONFIRMED);
  const directory = resolve(process.argv[3]);
  const files = Object.fromEntries(readdirSync(directory).map((name) => {
    assert.ok(ASSETS.includes(name));
    assert.ok(lstatSync(join(directory, name)).isFile(), "Assets must be regular files");
    return [name, readFileSync(join(directory, name))];
  }));
  const manifest = verifyAssets(files, sha);
  // Inspect ZIP members as bytes; never extract or run downloaded code.
  const zip = join(directory, ARCHIVE);
  const entries = execFileSync("unzip", ["-Z1", zip], { encoding: "utf8" }).trim().split(/\r?\n/).sort();
  assert.deepEqual(entries, ["PREVIEW.md", "SHA256SUMS", "codex-unlock-windows.exe", "manifest.json"].sort());
  const inner = Object.fromEntries(entries.map((name) => [name,
    execFileSync("unzip", ["-p", zip, name], { maxBuffer: 64 * 1024 * 1024 })]));
  assert.deepEqual(inner["manifest.json"], files["manifest.json"]);
  assert.equal(digest(inner["codex-unlock-windows.exe"]), manifest.binary.sha256);
  assert.equal(inner.SHA256SUMS.toString("utf8").trim().replaceAll("\r\n", "\n"),
    ["codex-unlock-windows.exe", "PREVIEW.md", "manifest.json"].map((name) => `${digest(inner[name])}  ${name}`).join("\n"));
  const assets = await api(`releases/${release.id}/assets?per_page=100`);
  verifyExistingAssets(assets, files);
  for (const name of ASSETS) {
    if (assets.some((asset) => asset.name === name)) continue;
    // Recheck the acknowledgement and draft immediately before each upload.
    // The independently verified immutable release policy provides the server
    // boundary; this job cannot measure policy with its non-admin token.
    // Never patch release metadata, overwrite/delete assets, or publish.
    verifyImmutablePolicyAcknowledgement(process.env.IMMUTABLE_POLICY_CONFIRMED);
    verifyDraft(await api(`releases/${release.id}`), sha);
    const response = await globalThis.fetch(`https://uploads.github.com/repos/${repo}/releases/${release.id}/assets?name=${encodeURIComponent(name)}`, {
      method: "POST", headers: { Authorization: `Bearer ${process.env.GH_TOKEN}`,
        Accept: "application/vnd.github+json", "Content-Type": "application/octet-stream" },
      body: files[name], redirect: "error", signal: globalThis.AbortSignal.timeout(60_000),
    });
    assert.ok(response.ok, `Upload failed: HTTP ${response.status}`);
    verifyExistingAssets([await response.json()], files);
  }
  verifyDraft(await api(`releases/${release.id}`), sha);
  const finalAssets = await api(`releases/${release.id}/assets?per_page=100`);
  assert.deepEqual(finalAssets.map((asset) => asset.name).sort(), ASSETS);
  verifyExistingAssets(finalAssets, files);
}
