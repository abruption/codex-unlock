/**
 * Compatibility facade for the CLI's existing internal import path.
 *
 * The npm package remains CLI-only. Focused modules keep inspection, policy,
 * and unlock execution independently reviewable without changing JSON output.
 */
export { inspectThread, listThreads } from "./inspection.js";
export { defaultOptions, validateThreadId } from "./options.js";
export { unlockInspectedThread, unlockThread } from "./unlock.js";
