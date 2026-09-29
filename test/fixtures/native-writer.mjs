import fs from "node:fs";
import { once } from "node:events";
import { dirname, join } from "node:path";
import process from "node:process";
import readline from "node:readline";
import { performance } from "node:perf_hooks";
import { setTimeout } from "node:timers";

import { flockSync } from "fs-ext-extra-prebuilt";

const [mode, lockPath, countOrMs = "0"] = process.argv.slice(2);
const guard = fs.openSync(join(dirname(lockPath), ".coordination.lock"), "r");
if (mode === "hold") {
  flockSync(guard, "ex");
  process.stdout.write("ready\n");
  const finish = () => { fs.closeSync(guard); process.exit(0); };
  if (Number(countOrMs) > 0) setTimeout(finish, Number(countOrMs));
  else readline.createInterface({ input: process.stdin }).once("line", (command) => {
    if (command === "unlink") fs.unlinkSync(lockPath);
    if (command === "replace") {
      fs.renameSync(lockPath, `${lockPath}.old`);
      fs.writeFileSync(lockPath, "replacement inode");
    }
    finish();
  });
} else if (mode === "probe") {
  try {
    flockSync(guard, "exnb");
  } catch (error) {
    if (!["EAGAIN", "EWOULDBLOCK", "EACCES"].includes(error.code)) throw error;
    process.stdout.write("GUARDED\n");
    process.exit(0);
  }
  const thread = fs.openSync(lockPath, "r+");
  try {
    flockSync(thread, "exnb");
    process.stdout.write("ACQUIRED\n");
  } catch (error) {
    if (!["EAGAIN", "EWOULDBLOCK", "EACCES"].includes(error.code)) throw error;
    process.stdout.write("WOULD_BLOCK\n");
  } finally {
    fs.closeSync(thread);
    fs.closeSync(guard);
  }
} else if (mode === "stress") {
  const commands = readline.createInterface({ input: process.stdin });
  process.stdout.write("ready\n");
  await once(commands, "line");
  commands.close();
  process.stdin.pause();
  let wouldBlock = 0;
  let acquired = 0;
  const deadline = performance.now() + 5_000;
  for (let index = 0; index < Number(countOrMs) && performance.now() < deadline; index += 1) {
    // Synthetic Codex acquire/publication/drop: serialize thread try_lock
    // and closing the thread descriptor with the same native coordinator.
    flockSync(guard, "ex");
    const thread = fs.openSync(lockPath, "r+");
    try {
      flockSync(thread, "exnb");
      acquired += 1;
    } catch (error) {
      if (!["EAGAIN", "EWOULDBLOCK", "EACCES"].includes(error.code)) throw error;
      wouldBlock += 1;
    } finally {
      flockSync(guard, "un");
    }
    flockSync(guard, "ex");
    fs.closeSync(thread);
    flockSync(guard, "un");
  }
  fs.closeSync(guard);
  process.stdout.write(`${JSON.stringify({ acquired, wouldBlock })}\n`);
} else {
  throw new Error(`unknown synthetic writer mode: ${mode}`);
}
