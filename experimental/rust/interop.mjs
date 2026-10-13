// Synthetic Unix interoperation only; never accepts a Codex home or lock path.
import assert from "node:assert/strict";
import process from "node:process";
import console from "node:console";
import { setTimeout, clearTimeout } from "node:timers";
import { spawn } from "node:child_process";
import { closeSync, openSync, readFileSync, statSync } from "node:fs";
import { mkdtemp, chmod, realpath, rename, unlink, rmdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { flockSync } from "fs-ext-extra-prebuilt";
import { guardedProbeOnce } from "../../dist/native-coordination.js";

assert.ok(["darwin", "linux"].includes(process.platform), "Unix-only experiment");
assert.ok(process.env.CODEX_UNLOCK_LAB_SCRATCH_ROOT, "explicit scratch parent required");
const root = await realpath(await mkdtemp(join(process.env.CODEX_UNLOCK_LAB_SCRATCH_ROOT, "codex-rust-interop-")));
await chmod(root, 0o700);
const binary = join(dirname(fileURLToPath(import.meta.url)), "target/debug/codex-unlock-lab");
const child = spawn(binary, ["__interop-fixture", "--scratch-root", root], { stdio: ["pipe", "pipe", "pipe"] });
let stderr = "";
child.stderr.setEncoding("utf8").on("data", (data) => { stderr += data; });
child.stdin.on("error", () => {}); // Cleanup may close an already exited child.
const exited = new Promise((resolve, reject) => {
  child.once("error", reject);
  child.once("exit", (code) => resolve(code));
});
const output = createInterface({ input: child.stdout })[Symbol.asyncIterator]();
async function bounded(promise) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("interop deadline; scratch preserved")), 12_000);
    })]);
  } finally { clearTimeout(timer); }
}
async function line() {
  const value = await bounded(output.next());
  assert.equal(value.done, false, stderr);
  return value.value;
}
async function command(value, expected) {
  child.stdin.write(`${value}\n`);
  assert.equal(await line(), expected);
}
let fixture;
let guardFd;
let threadFd;
function snapshot(path) {
  const stat = statSync(path, { bigint: true });
  return { bytes: readFileSync(path), ino: stat.ino, dev: stat.dev, mode: stat.mode,
    uid: stat.uid, mtime: stat.mtimeNs, size: stat.size };
}
try {
  const name = await line();
  assert.match(name, new RegExp(`^codex-unlock-lab-${child.pid}-[0-9]+$`));
  fixture = join(root, name);
  const guard = join(fixture, ".coordination.lock");
  const thread = join(fixture, "00000000-0000-4000-8000-000000000122.lock");
  const before = [snapshot(guard), snapshot(thread)];
  const probe = (status, guardStatus = "acquired") => {
    const result = guardedProbeOnce(thread);
    assert.equal(result.status, status);
    assert.equal(result.guard?.status, guardStatus);
  };
  probe("free");
  await command("acquire", "held");
  probe("held"); // Rust standard lock is visible to the production TS adapter.
  await command("guard", "guarded");
  probe("unknown", "busy");
  await command("unguard", "unguarded");
  await command("release", "free");
  probe("free");
  guardFd = openSync(guard, "r+");
  threadFd = openSync(thread, "r+");
  flockSync(guardFd, "exnb");
  flockSync(threadFd, "exnb");
  flockSync(guardFd, "un");
  await command("probe", "held"); // Node's addon lock is visible to Rust.
  flockSync(guardFd, "exnb");
  await command("probe", "unknown-busy");
  flockSync(threadFd, "un");
  flockSync(guardFd, "un");
  await command("probe", "free");
  closeSync(threadFd); threadFd = undefined;
  closeSync(guardFd); guardFd = undefined;
  await rename(guard, `${guard}.saved`);
  try {
    probe("unknown", "absent");
    await command("probe", "unknown-missing");
  } finally { await rename(`${guard}.saved`, guard); }
  assert.deepEqual([snapshot(guard), snapshot(thread)], before);
  child.stdin.end("quit\n");
  assert.equal(await bounded(exited), 0, stderr);
  assert.equal(stderr, "");
  console.log(JSON.stringify({ experiment: "rust-typescript-unix-interop", status: "passed",
    rustOwnerTsProbe: true, nodeOwnerRustProbe: true, busyAndMissingGuard: "unknown",
    bytesAndMetadataUnchanged: true, productionSupport: false }));
} finally {
  // No signals. EOF makes the fixture exit itself; its own total deadline is 10s.
  if (threadFd !== undefined) closeSync(threadFd);
  if (guardFd !== undefined) closeSync(guardFd);
  child.stdin.end();
  await bounded(exited);
  if (fixture) {
    await unlink(join(fixture, ".coordination.lock"));
    await unlink(join(fixture, "00000000-0000-4000-8000-000000000122.lock"));
    await rmdir(fixture);
  }
  await rmdir(root);
}
