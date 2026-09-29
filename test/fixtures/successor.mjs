// Waits until the owner fixture records SIGTERM, then immediately takes the
// same native thread lock, modelling a user resuming the thread elsewhere.
import fs from "node:fs";
import process from "node:process";
import { dirname, join } from "node:path";
import { setInterval, setTimeout } from "node:timers";

import { flockSync } from "fs-ext-extra-prebuilt";

const [marker, lockPath, acquiredMarker] = process.argv.slice(2);
const wait = () => {
  if (!fs.existsSync(marker)) {
    setTimeout(wait, 5);
    return;
  }
  const fd = fs.openSync(lockPath, "r+");
  const guard = fs.openSync(join(dirname(lockPath), ".coordination.lock"), "r");
  flockSync(guard, "ex");
  try {
    flockSync(fd, "exnb");
  } finally {
    flockSync(guard, "un");
    fs.closeSync(guard);
  }
  if (acquiredMarker) fs.writeFileSync(acquiredMarker, "acquired\n");
  process.stdout.write("acquired\n");
};
process.stdout.write("waiting\n");
wait();
setInterval(() => {}, 1_000);
