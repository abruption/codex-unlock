import { once } from "node:events";
import { chmod, mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import process from "node:process";
import { setTimeout as delay } from "node:timers/promises";
import { spawn } from "node:child_process";

import { acquireUnlockLease } from "../../dist/coordination.js";

export const THREAD_ID = "01a089e8-3731-7202-ba68-0f4b0a3b2711";
export const OTHER_THREAD_ID = "02b190f9-4842-8313-ca79-1f5c1b4c3822";
export const OWNER_FIXTURE = resolve("test/fixtures/codex");

export async function fixture(lastEvent = "task_complete", settings = {}) {
  const codexHome =
    settings.codexHome ?? await mkdtemp(join(tmpdir(), "codex-unlock-test-"));
  const lockDirectory = join(codexHome, "thread-writer-locks");
  const sessionDirectory = join(codexHome, "sessions", "2026", "09", "15");
  await mkdir(lockDirectory, { recursive: true });
  await mkdir(sessionDirectory, { recursive: true });
  const lockPath = join(lockDirectory, `${THREAD_ID}.lock`);
  const transcriptPath = join(
    sessionDirectory,
    `rollout-2026-09-15T00-00-00-${THREAD_ID}.jsonl`,
  );
  await writeFile(lockPath, "");
  await writeFile(
    transcriptPath,
    `${JSON.stringify({
      timestamp: "2026-09-15T00:00:00.000Z",
      type: "event_msg",
      payload: { type: lastEvent },
    })}\n`,
  );
  await chmod(OWNER_FIXTURE, 0o755);
  const child = spawn(OWNER_FIXTURE, [lockPath, ...(settings.additionalLockPaths ?? [])], {
    env: { ...process.env, ...(settings.ownerEnv ?? {}) },
    stdio: ["pipe", "pipe", "pipe"],
  });
  child.stdout.setEncoding("utf8");
  await new Promise((resolveReady, reject) => {
    child.stdout.once("data", (chunk) => {
      if (chunk.includes("ready")) resolveReady();
      else reject(new Error(`unexpected owner output: ${chunk}`));
    });
    child.once("error", reject);
    child.once("exit", (code) => reject(new Error(`owner exited early: ${code}`)));
  });
  return {
    codexHome,
    lockPath,
    transcriptPath,
    child,
    options: { codexHome, stabilityMs: 50, terminationTimeoutMs: 3_000 },
  };
}

let ownerCommandId = 0;
export async function commandOwner(child, command) {
  ownerCommandId += 1;
  const id = ownerCommandId;
  const acknowledged = new Promise((resolveAcknowledged, reject) => {
    const onData = (chunk) => {
      if (chunk.includes(`ack:${id}`)) {
        child.stdout.off("data", onData);
        resolveAcknowledged();
      }
    };
    child.stdout.on("data", onData);
    child.once("exit", (code) => reject(new Error(`owner exited before command ${id}: ${code}`)));
  });
  child.stdin.write(`${JSON.stringify({ id, ...command })}\n`);
  await acknowledged;
}

export async function otherLockPath(root, label = "other") {
  const directory = join(root, label, "thread-writer-locks");
  await mkdir(directory, { recursive: true });
  const path = join(directory, `${OTHER_THREAD_ID}.lock`);
  await writeFile(path, "");
  return path;
}

export async function stopChild(child) {
  if (child.exitCode === null && child.signalCode === null) {
    child.kill("SIGTERM");
    await once(child, "exit");
  }
}

export async function runCli(args, env = process.env) {
  const child = spawn(process.execPath, [resolve("dist/cli.js"), ...args], {
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  const [code, signal] = await once(child, "exit");
  return { code, signal, stdout, stderr };
}

export async function waitForUnlockLeaseContention(codexHome, timeoutMs = 5_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const attempt = acquireUnlockLease(codexHome, THREAD_ID);
    if (attempt.status === "contended") return;
    if (attempt.status === "acquired") attempt.lease.release();
    else throw new Error(`could not observe unlock lease: ${attempt.reason}`);
    await delay(25);
  }
  throw new Error("timed out waiting for the first unlock lease");
}
