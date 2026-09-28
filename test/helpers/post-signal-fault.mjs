// Preloaded with `node --import` to inject a failure immediately after the CLI
// sends SIGTERM. Only the unlock signal arms the fault; earlier probes run
// normally.
import { openSync } from "node:fs";
import process from "node:process";

const mode = process.env.CODEX_UNLOCK_TEST_POST_SIGNAL_FAULT;
// Materialize stdout before descriptors can run out.
const output = process.stdout;
void output;
const kill = process.kill.bind(process);
const now = Date.now.bind(Date);
let armed = false;
let signaled = false;

process.kill = (pid, signal) => {
  const result = kill(pid, signal);
  if (signal === "SIGTERM" && pid > 0 && !signaled) {
    signaled = true;
    if (mode === "emfile") {
      const held = [];
      try {
        for (;;) held.push(openSync("/dev/null", "r"));
      } catch {
        // Descriptors are exhausted for the rest of this process.
      }
    } else if (mode === "throw") {
      armed = true;
    }
  }
  return result;
};

Date.now = () => {
  if (armed) {
    armed = false;
    throw new Error("injected post-signal fault");
  }
  return now();
};
