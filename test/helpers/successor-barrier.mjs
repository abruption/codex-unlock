// Test-only: guarantee reacquisition before the first post-signal observation.
import { existsSync } from "node:fs";
import { performance } from "node:perf_hooks";
import process from "node:process";

const kill = process.kill.bind(process);
process.kill = (pid, signal) => {
  const result = kill(pid, signal);
  if (signal === "SIGTERM") {
    const deadline = performance.now() + 3_000;
    while (!existsSync(process.env.CODEX_UNLOCK_TEST_SUCCESSOR_ACQUIRED)) {
      if (performance.now() >= deadline) throw new Error("successor acquisition barrier timed out");
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 1);
    }
  }
  return result;
};
