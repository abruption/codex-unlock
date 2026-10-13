import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { URL } from "node:url";
import { CODEX_EXEC_CYBER_GRAMMAR, reconcileArguments } from "../dist/process.js";

const fixture = JSON.parse(await readFile(new URL("./fixtures/codex-exec-cyber.json", import.meta.url), "utf8"));
const evidence = (argv) => reconcileArguments(argv.join(" "), { status: "present", argv });

test("the narrowly reviewed exec extension matches pinned upstream enum and scope", async () => {
  assert.deepEqual(CODEX_EXEC_CYBER_GRAMMAR, fixture.extension);
  assert.ok(Object.isFrozen(CODEX_EXEC_CYBER_GRAMMAR.values));
  assert.equal(fixture.source.url,
    `https://github.com/openai/codex/blob/${fixture.extension.commit}/${fixture.source.path}`);
  assert.match(fixture.source.blob, /^[a-f0-9]{40}$/);
  const text = fixture.source.excerpts.map((part) => part.text).join("\n");
  assert.match(text, /value_enum.*global = true/);
  assert.match(text, /Option<CyberAccessProgramCliArg>/);
  assert.match(text, /rename_all = "snake_case"/);
  for (const variant of ["Standard", "DaybreakBlue", "DaybreakRed"]) assert.ok(text.includes(variant));
  const docs = await readFile(new URL("../docs/platform-support.md", import.meta.url), "utf8");
  assert.ok(docs.includes(fixture.extension.commit));
  assert.ok(docs.includes(fixture.extension.option));
});

test("reviewed exec enum accepts both value forms and exec alias", () => {
  for (const mode of ["exec", "e"]) {
    for (const value of fixture.extension.values) {
      for (const option of [["--cyber-access-program", value], [`--cyber-access-program=${value}`]]) {
        const argv = ["codex", mode, ...option, "fix the daemon"];
        assert.deepEqual(evidence(argv), { arguments: argv.join(" "), isSharedService: false });
      }
    }
  }
});

test("invalid enum, arity, scope, duplicates and nested modes remain unverified", () => {
  for (const args of [
    ["exec", "--cyber-access-program"],
    ["exec", "--cyber-access-program="],
    ["exec", "--cyber-access-program", "--json"],
    ["exec", "--cyber-access-program", "daybreak-blue"],
    ["exec", "--cyber-access-program", "STANDARD"],
    ["exec", "--cyber-access-program", "private-invalid-value"],
    ["exec", "--cyber-access-program=standard", "--cyber-access-program=standard"],
    ["--cyber-access-program", "standard", "exec", "fix bugs"],
    ["resume", "--cyber-access-program", "standard", "thread-id"],
    ["fork", "--cyber-access-program", "standard", "thread-id"],
    ["exec", "--cyber-access-program", "standard", "resume", "thread-id"],
    ["exec", "--cyber-access-program", "standard", "review"],
    ["exec", "--cyber-access-programs", "standard", "fix bugs"],
    ["exec", "--future-unreviewed-option", "standard", "fix bugs"],
    ["exec", "--cyber-access-program", "standard", "first", "second"],
  ]) {
    const result = evidence(["codex", ...args]);
    assert.equal(result.arguments, null, JSON.stringify(args));
    assert.match(result.error, /^arguments_unverified:/);
    assert.ok(!result.error.includes("private-invalid-value"));
  }
});

test("reviewed enum does not bypass remote service evidence or literal delimiters", () => {
  for (const option of ["--remote=unix:///example", "--remote-auth-token-env=EXAMPLE_TOKEN"]) {
    assert.equal(evidence(["codex", "exec", "--cyber-access-program", "standard", option]).isSharedService, true);
  }
  const argv = ["codex", "exec", "--", "--cyber-access-program"];
  assert.deepEqual(evidence(argv), { arguments: argv.join(" "), isSharedService: false });
});
