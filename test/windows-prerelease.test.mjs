import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import process from "node:process";
import test from "node:test";
import { fileURLToPath, URL } from "node:url";
import { ARCHIVE, COMPONENT, PLAN, SOURCE_BINDINGS, TAG, VERSION, completePage, digest, verifyAssets, verifyCargoVersion, verifyConfig, verifyDraft, verifyExistingAssets, verifyImmutablePolicyAcknowledgement, verifyPlan, verifyPreviousRelease, verifySource, verifySourceBindings, verifyVersionState } from "../scripts/windows-prerelease.mjs";

const sha = "a".repeat(40);
const rcPlan = { version: "0.5.0-rc.1", previousVersion: "0.5.0-alpha.1", prerelease: true };
const stablePlan = { version: "0.5.0", previousVersion: "0.5.0-rc.1", prerelease: false };
const otherPlan = PLAN.version === stablePlan.version ? rcPlan : stablePlan;
const config = JSON.parse(readFileSync(new URL("../release-please-windows-config.json", import.meta.url), "utf8"));
function configFor(plan) {
  return { ...config, prerelease: plan.prerelease,
    packages: { [COMPONENT]: { ...config.packages[COMPONENT], "release-as": plan.version } } };
}
const release = { id: 1, tag_name: TAG, target_commitish: sha, draft: true, prerelease: PLAN.prerelease, author: { login: "github-actions[bot]" } };
const pull = { merged_at: "2026-10-22", merge_commit_sha: sha,
  base: { ref: "main", repo: { full_name: "abruption/codex-unlock" } },
  head: { ref: "release-please--branches--main--components--windows", repo: { full_name: "abruption/codex-unlock" } },
  user: { login: "github-actions[bot]" }, labels: [{ name: "windows-release: tagged" }] };
const source = { release, sha, pulls: [pull], cargo: `[package]\nname = "windows"\nversion = "${VERSION}"\n`,
  versions: { [COMPONENT]: VERSION }, plan: PLAN, config };
function files(version = VERSION) {
  const zip = Buffer.from("synthetic archive for outer checksum unit test");
  return { [ARCHIVE]: zip, SHA256SUMS: Buffer.from(`${digest(zip)}  ${ARCHIVE}\r\n`),
    "manifest.json": Buffer.from(JSON.stringify({ schemaVersion: 1, sourceSha: sha,
      target: "x86_64-pc-windows-msvc", binary: { name: "codex-unlock-windows.exe", version, sha256: "b".repeat(64) } })) };
}

test("release plans allow only the reviewed RC and stable transitions", () => {
  verifyPlan(PLAN);
  verifyPlan(rcPlan);
  verifyPlan(stablePlan);
  for (const plan of [null, {}, { ...rcPlan, version: "0.5.0-rc.2" },
    { ...rcPlan, previousVersion: "0.0.0" }, { ...rcPlan, prerelease: false },
    { ...stablePlan, previousVersion: "0.5.0-alpha.1" }, { ...stablePlan, prerelease: true },
    { ...PLAN, publish: true }]) assert.throws(() => verifyPlan(plan));
});

test("release phase requires exactly the prior or target version and a literal matching Cargo version", () => {
  for (const plan of [rcPlan, stablePlan]) {
    verifyVersionState({ [COMPONENT]: plan.previousVersion }, "prepare", plan);
    verifyVersionState({ [COMPONENT]: plan.version }, "draft", plan);
    assert.throws(() => verifyVersionState({ [COMPONENT]: plan.version }, "prepare", plan));
    assert.throws(() => verifyVersionState({ [COMPONENT]: plan.previousVersion }, "draft", plan));
    assert.throws(() => verifyVersionState({ [COMPONENT]: plan.version, ".": "0.5.0" }, "draft", plan));
    verifyCargoVersion(`[package]\nversion = "${plan.version}"\n[dependencies]\n`, plan.version);
    for (const cargo of [`[package]\nversion = "${plan.version.replaceAll(".", "x")}"\n`,
      `[workspace.package]\nversion = "${plan.version}"\n`,
      `[package]\nversion = "${plan.version}"\nversion = "${plan.version}"\n`,
      `[package]\nversion = "${plan.version}"\n[package]\nversion = "${plan.version}"\n`]) {
      assert.throws(() => verifyCargoVersion(cargo, plan.version));
    }
  }
  assert.throws(() => verifyVersionState({ [COMPONENT]: VERSION }, "publish"));
});

test("the predecessor must be public, immutable and bound to its actual tag commit", () => {
  for (const plan of [rcPlan, stablePlan]) {
    const previous = { ...release, tag_name: `windows-v${plan.previousVersion}`, draft: false, prerelease: true, immutable: true };
    verifyPreviousRelease(previous, sha, plan);
    for (const change of [{ draft: true }, { immutable: false }, { immutable: undefined },
      { prerelease: false }, { target_commitish: "main" }, { tag_name: "v0.4.7" },
      { author: { login: "someone" } }, { id: 0 }]) {
      assert.throws(() => verifyPreviousRelease({ ...previous, ...change }, sha, plan));
    }
    assert.throws(() => verifyPreviousRelease(previous, "b".repeat(40), plan));
  }
});

test("draft verification refuses public releases, mutable refs, wrong version and author", () => {
  verifyDraft(release, sha);
  for (const change of [{ draft: false }, { prerelease: !PLAN.prerelease }, { target_commitish: "main" },
    { tag_name: "v0.4.7" }, { author: { login: "abruption" } }, { id: 0 }]) {
    assert.throws(() => verifyDraft({ ...release, ...change }, sha));
  }
});
test("stable drafts and assets require the stable channel without changing draft-only rules", () => {
  const stableRelease = { ...release, tag_name: "windows-v0.5.0", prerelease: false };
  verifyConfig(configFor(stablePlan), stablePlan);
  verifyDraft(stableRelease, sha, stablePlan);
  verifyAssets(files("0.5.0"), sha, stablePlan);
  assert.throws(() => verifyDraft({ ...stableRelease, draft: false }, sha, stablePlan));
  assert.throws(() => verifyDraft({ ...stableRelease, prerelease: true }, sha, stablePlan));
  assert.throws(() => verifyDraft(stableRelease, sha, rcPlan));
  assert.throws(() => verifyAssets(files(rcPlan.version), sha, stablePlan));
  assert.throws(() => verifyConfig(configFor(stablePlan), rcPlan));
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
  assert.throws(() => verifySource({ ...source, plan: otherPlan }));
  assert.throws(() => verifySource({ ...source, config: configFor(otherPlan) }));
  const stableSource = { ...source, plan: stablePlan, config: configFor(stablePlan),
    release: { ...release, tag_name: "windows-v0.5.0", prerelease: false },
    cargo: '[package]\nversion = "0.5.0"\n', versions: { [COMPONENT]: "0.5.0" } };
  verifySource(stableSource, stablePlan);
  assert.throws(() => verifySource(stableSource, rcPlan));
});

test("source control files must match dispatch bytes, including both workflows and helpers", () => {
  const files = Object.fromEntries(SOURCE_BINDINGS.map((path) => [path, Buffer.from(`fixture:${path}`)]));
  verifySourceBindings(files, files);
  for (const path of SOURCE_BINDINGS) {
    assert.throws(() => verifySourceBindings({ ...files, [path]: Buffer.from("changed") }, files));
    assert.throws(() => verifySourceBindings(files, { ...files, [path]: Buffer.from("changed") }));
    const omitted = { ...files };
    delete omitted[path];
    assert.throws(() => verifySourceBindings(omitted, files));
    assert.throws(() => verifySourceBindings({ ...files, [path]: files[path].toString() }, files));
  }
  assert.throws(() => verifySourceBindings({ ...files, unexpected: Buffer.from("x") }, files));
});

test("large source-binding drift rejects with bounded diagnostics and exact byte comparison", () => {
  const path = ".github/workflows/windows-rust-diagnostics.yml";
  const files = Object.fromEntries(SOURCE_BINDINGS.map((name) => [name, Buffer.from(`fixture:${name}`)]));
  const large = Buffer.alloc(256 * 1024, "a");
  const independentCopy = Buffer.from(large);
  verifySourceBindings({ ...files, [path]: large }, { ...files, [path]: independentCopy });
  const samePrefix = Buffer.from(large);
  samePrefix[samePrefix.length - 1] = "b".charCodeAt(0);
  for (const actual of [Buffer.from("different workflow"), samePrefix]) {
    assert.throws(() => verifySourceBindings({ ...files, [path]: actual }, { ...files, [path]: large }), (error) => {
      assert.equal(error.code, "ERR_ASSERTION");
      assert.equal(error.actual, false, "the assertion must not retain the actual Buffer");
      assert.equal(error.expected, true, "the assertion must not retain the expected Buffer");
      assert.ok(error.message.length < 512, "large file rejection must not render its byte contents");
      assert.match(error.message, /Release control file differs at source/);
      assert.ok(error.message.includes(path));
      assert.ok(error.message.includes(`source-bytes=${actual.length},source-sha256=${digest(actual)}`));
      assert.ok(error.message.includes(`checkout-bytes=${large.length},checkout-sha256=${digest(large)}`));
      return true;
    });
  }
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
test("separate configuration remains bound to the reviewed draft-only Rust release plan", () => {
  verifyConfig(config);
  assert.equal(config.draft, true);
  assert.equal(config.prerelease, PLAN.prerelease);
  assert.equal(config["force-tag-creation"], false);
  assert.equal(config["draft-pull-request"], true);
  assert.equal(config.label, "windows-release: pending");
  assert.equal(config["release-label"], "windows-release: tagged");
  assert.deepEqual(Object.keys(config.packages), [COMPONENT]);
  assert.equal(config.packages[COMPONENT]["release-type"], "rust");
  assert.equal(config.packages[COMPONENT]["release-as"], VERSION);
});

test("preflight rejects configuration changes that could publish or target another version", () => {
  for (const change of [{ draft: false }, { prerelease: !PLAN.prerelease }, { "force-tag-creation": true },
    { "draft-pull-request": false }, { label: "autorelease: pending" },
    { "release-label": "autorelease: tagged" }, { "separate-pull-requests": false }]) {
    assert.throws(() => verifyConfig({ ...config, ...change }));
  }
  for (const change of [{ draft: false }, { "release-as": otherPlan.version }, { component: "stable" },
    { "include-component-in-tag": false }, { "include-v-in-tag": false },
    { "tag-separator": "/" }, { "release-type": "node" }]) {
    assert.throws(() => verifyConfig({ ...config,
      packages: { [COMPONENT]: { ...config.packages[COMPONENT], ...change } } }));
  }
  assert.throws(() => verifyConfig({ ...config, packages: { ...config.packages, ".": {} } }));
});

test("mocked preflight wires predecessor, phase and source-control checks without network", () => {
  const directory = mkdtempSync(join(tmpdir(), "codex-windows-release-flow-"));
  try {
    const sourceFiles = {};
    for (const path of SOURCE_BINDINGS) {
      const bytes = readFileSync(new URL(`../${path}`, import.meta.url));
      sourceFiles[path] = bytes.toString("base64");
      mkdirSync(dirname(join(directory, path)), { recursive: true });
      writeFileSync(join(directory, path), bytes);
    }
    mkdirSync(join(directory, COMPONENT), { recursive: true });
    const previous = { ...release, id: 2, tag_name: `windows-v${PLAN.previousVersion}`,
      target_commitish: "b".repeat(40), draft: false, prerelease: true, immutable: true };
    const moduleUrl = new URL("../scripts/windows-prerelease.mjs", import.meta.url).href;
    for (const scenario of ["prepare", "annotated", "draft", "missing", "mutable", "workflow_drift", "live_plan_drift"]) {
      const operation = ["draft", "workflow_drift"].includes(scenario) ? "draft" : "prepare";
      const current = operation === "prepare" ? PLAN.previousVersion : VERSION;
      writeFileSync(join(directory, ".release-please-windows-manifest.json"), JSON.stringify({ [COMPONENT]: current }));
      writeFileSync(join(directory, COMPONENT, "Cargo.toml"), `[package]\nversion = "${current}"\n`);
      const output = join(directory, `output-${scenario}`);
      const code = `
        import assert from 'node:assert/strict';
        import { Buffer } from 'node:buffer';
        import process from 'node:process';
        process.stderr.write('fixture_child_started\\n');
        const { main } = await import(${JSON.stringify(moduleUrl)});
        const sourceFiles = ${JSON.stringify(sourceFiles)};
        const previous = ${JSON.stringify(previous)};
        const release = ${JSON.stringify(release)};
        const scenario = ${JSON.stringify(scenario)};
        const file = (bytes) => ({type:'file',encoding:'base64',content:bytes});
        const calls = [];
        globalThis.fetch = async (input) => {
          assert.ok(input.startsWith('https://api.github.com/repos/abruption/codex-unlock/'));
          const path = input.slice('https://api.github.com/repos/abruption/codex-unlock/'.length);
          calls.push(path);
          let result;
          if (path === 'releases?per_page=100') result = scenario === 'missing' ? [] :
            [{...previous,immutable:scenario !== 'mutable'}, ...(${JSON.stringify(operation)} === 'draft' ? [release] : [])];
          else if (path === 'git/matching-refs/tags/${TAG}') result = [];
          else if (path === 'git/ref/tags/windows-v${PLAN.previousVersion}') result = {
            ref:'refs/tags/windows-v${PLAN.previousVersion}', object: scenario === 'annotated' ?
              {type:'tag',sha:'c'.repeat(40)} : {type:'commit',sha:previous.target_commitish}};
          else if (path === 'git/tags/'+'c'.repeat(40)) result = {sha:'c'.repeat(40), object:{type:'commit',sha:previous.target_commitish}};
          else if (path === 'compare/'+previous.target_commitish+'...main' || path === 'compare/${sha}...main') result = {status:'ahead'};
          else if (path === 'commits/${sha}/pulls') result = [${JSON.stringify(pull)}];
          else if (path === 'contents/${COMPONENT}/Cargo.toml?ref=${sha}') result = file(Buffer.from(${JSON.stringify(source.cargo)}).toString('base64'));
          else if (path === 'contents/.release-please-windows-manifest.json?ref=${sha}') result = file(Buffer.from(${JSON.stringify(JSON.stringify(source.versions))}).toString('base64'));
          else if (path.startsWith('contents/')) {
            const [name, ref] = path.slice('contents/'.length).split('?ref=');
            assert.ok(ref === 'main' || ref === '${sha}');
            assert.ok(Object.hasOwn(sourceFiles,name));
            let bytes = sourceFiles[name];
            if (scenario === 'workflow_drift' && ref === '${sha}' && name === '.github/workflows/windows-rust-diagnostics.yml') bytes = Buffer.from('different workflow').toString('base64');
            if (scenario === 'live_plan_drift' && ref === 'main' && name === 'windows-release-plan.json') bytes = Buffer.from(${JSON.stringify(JSON.stringify(otherPlan))}).toString('base64');
            result = file(bytes);
          } else throw new Error('unexpected_mock_request:'+path);
          return {ok:true,status:200,json:async()=>result};
        };
        await assert.rejects(globalThis.fetch('https://api.github.com/repos/abruption/codex-unlock/unmatched-fixture-route'), /unexpected_mock_request/);
        process.stderr.write('fixture_mock_ready\\n');
        process.argv = ['node','test','preflight'];
        await main();
        assert.ok(calls.includes('git/ref/tags/windows-v${PLAN.previousVersion}'));
        if (${JSON.stringify(operation)} === 'draft') assert.ok(calls.includes('contents/.github/workflows/windows-rust-diagnostics.yml?ref=${sha}'));
        process.stdout.write('fixture_preflight_completed\\n');
      `;
      // Keep the embedded source-file bytes out of argv. This is a subprocess
      // startup/deadlock watchdog for loaded CI runners, not a product timing
      // assertion: all HTTP is replaced above and every outcome stays checked.
      const result = spawnSync(process.execPath, ["--input-type=module", "-"], {
        cwd: directory, encoding: "utf8", input: code, timeout: 60_000,
        env: { GITHUB_REPOSITORY: "abruption/codex-unlock", GITHUB_REF: "refs/heads/main",
          GITHUB_EVENT_NAME: "workflow_dispatch", GH_TOKEN: "mock-only", GITHUB_OUTPUT: output,
          IMMUTABLE_POLICY_CONFIRMED: "true", OPERATION: operation },
      });
      const details = `${scenario}: stdout=${result.stdout}; stderr=${result.stderr}`;
      assert.equal(result.error, undefined, details);
      assert.match(result.stderr, /fixture_child_started\nfixture_mock_ready\n/, details);
      if (["prepare", "annotated", "draft"].includes(scenario)) {
        assert.equal(result.status, 0, `${scenario}: ${result.stderr}`);
        assert.equal(result.stdout, "fixture_preflight_completed\n", scenario);
        assert.equal(readFileSync(output, "utf8"), `run_release_please=${operation === "prepare"}\n`);
      } else {
        assert.equal(result.status, 1, `${scenario}: ${result.stderr}`);
        const reason = { missing: /Require exactly one published predecessor/, mutable: /Previous Windows release must be immutable/,
          workflow_drift: /Release control file differs at source/, live_plan_drift: /Live main has a different release plan/ }[scenario];
        assert.match(result.stderr, reason, scenario);
      }
    }
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
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
