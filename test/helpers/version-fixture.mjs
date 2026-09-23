import { readFileSync } from "node:fs";

export const currentVersion = JSON.parse(
  readFileSync(new URL("../../package.json", import.meta.url), "utf8"),
).version;

const match = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.exec(currentVersion);
if (!match) throw new Error("test package version must be stable x.y.z");

export const newerVersion = `${match[1]}.${match[2]}.${BigInt(match[3]) + 1n}`;
