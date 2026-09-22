# JSON v1 contract

`codex-unlock` supports automation through its command-line interface. It does
not expose a supported JavaScript library API. Run `list`, `inspect`, or
`unlock` with `--json` and consume the single JSON value written to stdout.

The normative machine-readable schema is
[`schemas/codex-unlock-v1.schema.json`](../schemas/codex-unlock-v1.schema.json).
The schema deliberately permits unknown additive properties. Consumers must
ignore fields they do not recognize. Removing or changing the meaning or type
of an existing field requires a new `schemaVersion` and the documented
breaking-change process.

## Common rules

- `schemaVersion` is the integer `1` on command results and CLI errors.
- `command` identifies `list`, `inspect`, or `unlock`. A usage error that did
  not identify a command uses `null`.
- Timestamps are UTC ISO 8601 strings. File sizes, inode values, process IDs,
  and times retain the types defined in the schema.
- Nullable evidence means that the observation was unavailable or not
  applicable. It must not be interpreted as a positive safety fact.
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

- `absent`: the lock path was confirmed absent;
- `stale_residue`: a regular lock file exists but the OS lock is free;
- `live_owner`: the OS lock is held and one owner was correlated;
- `unknown`: ownership, lock, or transcript evidence could not be established.

`list` contains zero or more complete `inspect` results in `sessions`.

`unlock` contains the final outcome, signal attempt, process-exit observation,
lock-release observation, transcript-invariance result, reasons, and the
inspection that authorized or refused the operation. `lockFileRemovedByTool`
is always `false`.

## CLI errors

Errors retain the top-level string `error` field and add:

- `status: "error"`;
- `errorCode: "invalid_usage" | "command_failed"`;
- `exitCode: 64 | 3`;
- `retryable`, currently `false` because retry safety depends on new evidence;
- `suggestedAction`, a string for usage errors and otherwise `null`.

JSON mode writes no human-formatted diagnostic to stderr. A caller may treat
stderr output as an unexpected diagnostic, but must use the process exit code
and JSON fields for decisions.

## Exit codes

| Exit | Meaning | JSON result |
|---:|---|---|
| `0` | Successful read-only command, successful unlock, or already absent lock | `list`, `inspect`, or `unlock` |
| `2` | Unlock refused because the evidence is not safe | `unlock` with `outcome: "refused"` |
| `3` | Termination/post-check failure or an unexpected command failure | `unlock` failure outcome or `errorCode: "command_failed"` |
| `64` | Invalid command-line usage | `errorCode: "invalid_usage"` |

An additive optional root field, such as a future advisory metadata block, is
backward compatible when it cannot affect lock classification, policy,
signaling, or the exit code.
