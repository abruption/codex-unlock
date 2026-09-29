// Preloaded with `node --import` to inject a failure immediately after the CLI
// sends SIGTERM. Only the unlock signal arms the fault; earlier probes run
// normally.
import childProcess from "node:child_process";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import process from "node:process";

const mode = process.env.CODEX_UNLOCK_TEST_POST_SIGNAL_FAULT;
const kill = process.kill.bind(process);
const now = Date.now.bind(Date);
let armed = false;
let signaled = false;

function descriptorExhaustion(syscall) {
  return Object.assign(new Error(`${syscall} EMFILE`), {
    code: "EMFILE",
    errno: -24,
    syscall,
  });
}

process.kill = (pid, signal) => {
  const result = kill(pid, signal);
  if (signal === "SIGTERM" && pid > 0 && !signaled) {
    signaled = true;
    if (mode === "emfile") {
      // Every later diagnostic spawn and lock probe fails as if the process
      // had run out of descriptors.
      childProcess.spawn = () => {
        throw descriptorExhaustion("spawn");
      };
      fs.openSync = () => {
        throw descriptorExhaustion("open");
      };
      syncBuiltinESMExports();
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
