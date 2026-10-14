import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { URL } from "node:url";

import { CODEX_GRAMMAR_BASELINE, reconcileArguments } from "../dist/process.js";

const fixture = JSON.parse(await readFile(new URL("./fixtures/codex-grammar.json", import.meta.url), "utf8"));

test("the documented grammar baseline and source fixture identify the same upstream commit", async () => {
  assert.deepEqual(CODEX_GRAMMAR_BASELINE, fixture.baseline);
  assert.equal(Object.isFrozen(CODEX_GRAMMAR_BASELINE), true);
  const documentation = await readFile(new URL("../docs/platform-support.md", import.meta.url), "utf8");
  assert.ok(documentation.includes(`codex-cli ${fixture.baseline.version}`));
  assert.ok(documentation.includes(fixture.baseline.commit));
  assert.equal(fixture.upstreamLicense.spdx, "Apache-2.0");
  assert.equal(fixture.upstreamLicense.url,
    `https://github.com/openai/codex/blob/${fixture.baseline.commit}/LICENSE`);
  const license = await readFile(new URL(`./fixtures/${fixture.upstreamLicense.licenseFile}`, import.meta.url), "utf8");
  const notice = await readFile(new URL(`./fixtures/${fixture.upstreamLicense.noticeFile}`, import.meta.url), "utf8");
  assert.match(license, /Apache License/);
  assert.match(notice, /OpenAI Codex/);
  const sources = new Map(fixture.sources.map((source) => [source.id, source]));
  assert.equal(sources.size, fixture.sources.length);
  for (const source of sources.values()) {
    assert.match(source.blob, /^[a-f0-9]{40}$/);
    assert.equal(source.url,
      `https://github.com/openai/codex/blob/${fixture.baseline.commit}/${source.path}#L${source.startLine}-L${source.endLine}`);
    assert.equal(source.excerpt.split("\n").length, source.endLine - source.startLine + 1);
  }
  for (const example of fixture.cases) assert.ok(sources.has(example.source), example.id);
  // Source declarations record arity, hidden aliases and scope without localized help text.
  assert.match(sources.get("shared").excerpt, /pub model: Option<String>/);
  assert.match(sources.get("shared").excerpt, /num_args = 1\.\./);
  assert.match(sources.get("shared").excerpt, /alias = "yolo"/);
  assert.match(sources.get("shared").excerpt, /alias = "not-so-yolo"/);
  assert.match(sources.get("exec").excerpt, /alias = "experimental-json"/);
  assert.match(sources.get("root").excerpt, /visible_alias = "e"/);
});

for (const { id, argv, expected } of fixture.cases) {
  test(`source-reviewed bounded grammar: ${id}`, () => {
    const evidence = reconcileArguments(argv.join(" "), { status: "present", argv });
    if (expected === "accepted") {
      assert.equal(evidence.arguments, argv.join(" "));
      assert.equal(evidence.isSharedService, false);
      assert.equal(evidence.error, undefined);
    } else if (expected === "shared") {
      assert.equal(evidence.isSharedService, true);
    } else {
      assert.equal(expected, "unverified");
      assert.equal(evidence.arguments, null);
      assert.match(evidence.error, /^arguments_unverified:/);
    }
  });
}
