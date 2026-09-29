# JSON v1 contract

`codex-unlock` supports automation through its command-line interface. It does
not expose a supported JavaScript library API. Run `list`, `inspect`, `unlock`,
or `check-update` with `--json` and consume the single JSON value written to
stdout.

The normative machine-readable schema is
[`schemas/codex-unlock-v1.schema.json`](../schemas/codex-unlock-v1.schema.json).
The schema deliberately permits unknown additive properties. Consumers must
ignore fields they do not recognize. Removing or changing the meaning or type
of an existing field requires a new `schemaVersion` and the documented
breaking-change process.

## TypeScript types

The package provides type-only JSON v1 declarations at `codex-unlock/types`.
Version 0.3.0 and earlier do not include this entry point; the npm release
containing this addition is required. For example, after validating a CLI result
against the schema:

```ts
import type { InspectionResult, JsonResult } from "codex-unlock/types";

function describe(result: JsonResult): string {
  if ("errorCode" in result) return result.error;
  if (result.command === "inspect") return result.classification;
  return result.command;
}

function explainOwner(result: InspectionResult): number | null {
  return result.owner?.pid ?? null;
}
```

`JsonResult` covers `ListResult`, `InspectionResult`, `UnlockResult`,
`CheckUpdateResult`, and `CliErrorResult`. Nested JSON evidence models, enums,
nullability, and the optional `ClientUpdate` advisory are also exported. The
declarations have no Node.js/native dependency imports and work with TypeScript
NodeNext and bundler resolution. The supported entry point is the `/types`
subpath, not the package root or generated `dist/` paths.

Always use `import type`; there is no runtime implementation at `/types`.
Runtime imports of the root, `/types`, and internal modules remain rejected.
Internal options, constants, inspection functions, and signal/executor helpers
are not supported exports. The package's `types` metadata lets npm identify
the bundled declarations; it does not advertise an executable library API.

Types disappear at runtime: `JSON.parse` or a type assertion does not validate
an unknown value. Validate with the normative JSON Schema when consuming
untrusted output. Types do not enforce integer ranges, timestamps, or safety
policy; `live_owner` is still not authorization to unlock. Ignore unknown
additive JSON fields as before. Public declarations follow the JSON v1
compatibility policy above; extending an enum may require updating exhaustive
consumer switches.

## Common rules

- `schemaVersion` is the integer `1` on command results and CLI errors.
- `command` identifies `list`, `inspect`, `unlock`, or `check-update`. It is
  set whenever the first positional argument is a known command, even when
  options precede it. A usage error that did not identify a command uses
  `null`.
- Timestamps are UTC ISO 8601 strings. File sizes, inode values, process IDs,
  and times retain the types defined in the schema.
- Nullable evidence means that the observation was unavailable or not
  applicable. It must not be interpreted as a positive safety fact.
- `transcript.lastRecord.ordinal` is a non-negative safe integer copied from
  the last rollout record, or `null` when that value is missing, fractional,
  negative, larger than `Number.MAX_SAFE_INTEGER`, or not a number. Output
  therefore always satisfies the schema's `integer | null`, `minimum: 0`
  constraint.
- JSON string values are not altered for terminal display. Control characters
  from paths, process arguments, or transcripts are preserved and appear only
  as standard JSON escapes.
- `classification: "live_owner"` is liveness evidence only. It is not
  permission to terminate a process. Only `safeToUnlock: true` after complete
  revalidation can authorize the `unlock` implementation.
- Raw transcript contents, environment variables, credentials, and tokens are
  not part of the JSON contract.

## Command results

`inspect` returns the lock observation and OS probe separately, correlated
owner/openers, owner identity stability, the owner's native thread-lock set,
descendants, transcript evidence, blockers, and warnings.

`classification` is one of:

- `absent`: the lock path was confirmed absent inside an existing Codex home
  whose `thread-writer-locks` directory exists or has not been created yet;
- `stale_residue`: a regular lock file exists but the OS lock is free;
- `live_owner`: the OS lock is held and one owner was correlated;
- `unknown`: ownership, lock, or transcript evidence could not be established,
  including a dangling symlink or non-directory at `thread-writer-locks`.

A missing or non-directory Codex home is not an `absent` lock. `list`,
`inspect`, and `unlock` return a CLI error with `errorCode: "command_failed"`
and exit `3` instead of a command result. `list` also fails that way when
`thread-writer-locks` is a dangling symlink or not a directory, because it
cannot enumerate locks.

`list` contains zero or more complete `inspect` results in `sessions`.

`lock.probe.method` remains `flock_exclusive_nonblocking`. An optional
`lock.probe.guard` object records the native coordinator observation:

| `guard.status` | Meaning |
|---|---|
| `acquired` | Guard acquired and released around this probe |
| `busy` | Guard contention exhausted this probe's acquisition budget |
| `absent` | Existing thread lock has no native coordinator |
| `unsafe` | Guard type, owner, access, or cleanup could not be validated |
| `changed` | Guard or parent identity changed during observation |

`guard.attempts`, when present, is a positive integer. This is evidence about
the completed probe, not a currently held guard or proof of a live writer.
`acquired` can accompany an `unknown` thread state. Consumers must use the
existing `classification`, `status`, and `safeToUnlock` contracts.
Verified absent thread locks omit guard evidence. An existing thread lock with
an absent or unusable coordinator is `unknown`; no unguarded fallback is used.
These fields are additive under schema version 1.

`unlock` contains the final outcome, signal attempt, process-exit observation,
lock-release observation, transcript-invariance result, reasons, and the
inspection that authorized or refused the operation. `lockFileRemovedByTool`
is always `false`.

`outcome` is one of:

- `unlocked`: the owner exited, the OS lock is free, and the transcript is
  unchanged;
- `not_locked`: the lock was absent or stale residue, and nothing was signaled;
- `refused`: the evidence was not safe, and nothing was signaled;
- `termination_failed`: `SIGTERM` was attempted, but owner exit or lock release
  could not be confirmed;
- `verification_failed`: the owner exited and released its lock, but a later
  check failed (for example, the transcript changed or another process
  reacquired the lock).

Every result past the signal boundary keeps `pid`, `signalSent: "SIGTERM"`, and
`changed: true`, including when an observation after the signal throws
(`post_signal_verification_failed:<error>`). Such failures use exit `3`.

`processObservation.zombie` is `true` only when the signaled owner has exited
but its parent has not reaped it. The owner then counts as exited
(`processExited: true`): its descriptors, and therefore its lock, are closed.

`lockReacquiredBy` is present only when the original owner is confirmed exited
and a different process (a different PID, or the same PID with a different
start time) holds the lock again. It lists that process's `pid` and
`startTime`. The result is `verification_failed` with the reason
`lock_reacquired_by_other_owner:<pids>` instead of `lock_was_not_released`, and
`lockReleased` stays `false` because the lock is held now. Retrying `unlock`
would inspect and target that new holder, not the original owner. If the
current holder is one of the owner's known descendants (it inherited the lock
descriptor), the reason is `lock_held_by_owner_descendant:<pids>` together with
`lock_was_not_released`. A holder that cannot be identified adds
`lock_holder_unidentified:<error>`.

Just before signaling, `unlock` samples the owner's start time and the lock
file's identity and probe again, after the transcript hash. A change refuses
with `owner_changed_before_signal` or `lock_changed_before_signal`.
Native guard contention at that last synchronous probe adds
`native_coordination_busy_before_signal`; nothing is signaled. No asynchronous
retry is inserted between that last identity sample and SIGTERM.

`check-update` is the only command that performs a foreground npm registry
request. It returns `status: "ok"`, the current and latest stable versions,
the check timestamp, an `updateAvailable` boolean, and conservative update
guidance. Registry, timeout, and response failures use the normal structured
command error and exit `3`.

Since 0.4.1, `check-update` also adds two optional fields. `cacheUpdated` is
`true` when the result was written to the local advisory cache. When it is
`false`, `cacheWarning` is a stable reason string such as
`cache_directory_unavailable`, `cache_user_is_elevated`,
`cache_root_owner_mismatch`, or `refresh_in_progress`; otherwise it is `null`.
A cache that cannot be written no longer turns a successful registry check into
an error. Consumers must treat unknown `cacheWarning` values as opaque and must
tolerate both fields being absent in output from earlier versions.

## Cached update advisory

`list`, `inspect`, and `unlock` may add `clientUpdate` at the root when a fresh
local cache proves that a newer stable release exists. The block has its own
`schemaVersion: 1`, `source: "npm"`, current/latest versions, `checkedAt`,
`updateAvailable: true`, and `updateCommand`. It is absent when the cache is
missing, stale, unsafe, equal, older, or suppressed.

Consumers must ignore this optional block. It cannot change classification,
`safeToUnlock`, signaling, refusal reasons, the primary result, or exit code.
JSON commands write no update text to stderr and never perform synchronous
network access.

## CLI errors

Errors retain the top-level string `error` field and add:

- `status: "error"`;
- `errorCode: "invalid_usage" | "command_failed"`;
- `exitCode: 64 | 3`;
- `retryable`, currently `false` because retry safety depends on new evidence;
- `suggestedAction`, a string for usage errors and otherwise `null`.

Usage validation happens before inspection. Malformed thread ids, option values
that begin with `-`, and `--help` or `--version` combined with `--json` are
`invalid_usage` with exit `64`, so JSON consumers never receive non-JSON stdout.

JSON mode writes no human-formatted diagnostic to stderr. A caller may treat
stderr output as an unexpected diagnostic, but must use the process exit code
and JSON fields for decisions.

## Exit codes

| Exit | Meaning | JSON result |
|---:|---|---|
| `0` | Successful diagnostic/update check, successful unlock, or already absent lock | `list`, `inspect`, `unlock`, or `check-update` |
| `2` | Unlock refused because the evidence is not safe | `unlock` with `outcome: "refused"` |
| `3` | Termination/post-check failure, missing Codex home, or an unexpected command failure | `unlock` failure outcome or `errorCode: "command_failed"` |
| `64` | Invalid command-line usage | `errorCode: "invalid_usage"` |

An additive optional root field, such as a future advisory metadata block, is
backward compatible when it cannot affect lock classification, policy,
signaling, or the exit code.
