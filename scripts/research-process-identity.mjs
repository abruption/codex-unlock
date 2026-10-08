// Bounded observations of our own disposable children. No signals, host clock
// changes, PID reuse, or real Codex processes are involved.
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { log } from "node:console";
import { once } from "node:events";
import { readFile } from "node:fs/promises";
import { release } from "node:os";
import process from "node:process";
import { setTimeout as delay } from "node:timers/promises";

const children = [];
const observations = [];
try {
  for (let index = 0; index < 4; index += 1) {
    const child = spawn(process.execPath, ["-e", [
      'process.stdin.resume(); process.stdin.on("end", () => process.exit(0));',
      'setTimeout(() => process.exit(0), 10000); process.stdout.write("ready\\n");',
    ].join(" ")], { stdio: ["pipe", "pipe", "inherit"] });
    const closed = once(child, "close");
    children.push({ child, closed });
    await once(child.stdout, "data", { signal: globalThis.AbortSignal.timeout(2000) });
    const lstart = execFileSync("/bin/ps", ["-ww", "-p", String(child.pid), "-o", "lstart="],
      { encoding: "utf8", timeout: 1000, env: { PATH: "/usr/bin:/bin", LC_ALL: "C", TZ: "UTC" } }).trim();
    assert.ok(lstart && !Number.isNaN(Date.parse(lstart)));
    let startTicks = null;
    if (process.platform === "linux") {
      const stat = await readFile(`/proc/${child.pid}/stat`, "utf8");
      // comm may contain spaces or ')'; fields after its final ')' start at 3.
      startTicks = stat.slice(stat.lastIndexOf(")") + 2).trim().split(/\s+/)[19];
      assert.match(startTicks, /^\d+$/);
    }
    observations.push({ child: index, lstart, startTicks });
    await delay(40);
  }
  const groups = Object.values(Object.groupBy(observations, ({ lstart }) => lstart));
  log(JSON.stringify({ platform: process.platform, arch: process.arch, kernel: release(),
    node: process.version, observations,
    sameSecondGroups: groups.filter((group) => group.length > 1).map((group) => ({
      children: group.map(({ child }) => child),
      distinctStartTicks: process.platform === "linux"
        ? new Set(group.map(({ startTicks }) => startTicks)).size : null,
    })),
    signalsSent: 0,
    limits: "Distinct PIDs with equal lstart demonstrate resolution loss, not PID reuse or a wrong signal.",
  }, null, 2));
} finally {
  for (const { child } of children) child.stdin.end();
  await Promise.all(children.map(({ closed }) => closed));
}
