// Preloaded with `node --import` by CLI tests that inject a failing diagnostic
// tool. The CLI resolves ps and lsof only from fixed system paths, so tests
// replace them through the in-process seam instead of PATH.
import process from "node:process";

import { overrideDiagnosticExecutableForTesting } from "../../dist/process.js";

for (const [tool, variable] of [
  ["ps", "CODEX_UNLOCK_TEST_PS"],
  ["lsof", "CODEX_UNLOCK_TEST_LSOF"],
]) {
  const executable = process.env[variable];
  if (executable) overrideDiagnosticExecutableForTesting(tool, executable);
}
