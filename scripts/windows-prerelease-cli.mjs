import { main } from "./windows-prerelease.mjs";

// Unconditional entry point: symlinked/aliased paths must not skip guards.
await main();
