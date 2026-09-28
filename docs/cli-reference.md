# CLI reference

`codex-unlock` diagnoses Codex native thread writer locks. Its supported
automation interface is the CLI and JSON v1, with type-only TypeScript models
at `codex-unlock/types`. There is no executable JavaScript library API.
See the [JSON contract](json-v1.md) for schema, types, and compatibility.

## Commands

```text
codex-unlock list [options]
codex-unlock inspect <thread-id> [options]
codex-unlock unlock <thread-id> [options]
codex-unlock check-update [options]
```

- `list`: inspect threads with native lock files in the selected Codex home;
  it is not a list of every saved or resumable conversation.
- `inspect`: collect lock, process, and transcript evidence for one thread.
- `unlock`: revalidate a completed idle owner, send `SIGTERM` only if safe,
  then verify process exit, actual lock release, and transcript invariance.
- `check-update`: explicitly check npm for a newer stable version; never install it.

`list` and `inspect` are read-only. Use `--json` on any command for one
versioned JSON value. A `live_owner` classification is liveness evidence,
not permission to unlock.

## Safety model

Lock-file existence is not treated as ownership. The tool independently:

1. probes the actual OS lock with a nonblocking exclusive `flock` attempt;
2. uses `lsof` only to correlate open file descriptors with a PID;
3. samples PID start time, command, PPID, TTY, cwd, lock inode, and rollout
   size/mtime across a stability window;
4. requires exactly one same-user Codex owner holding exactly one thread lock;
5. requires the rollout's last record to be `event_msg/task_complete`;
6. refuses shared `app-server`, Remote Control, and daemon owners;
7. repeats the complete safety inspection immediately before signaling,
   including process identity, every open native thread lock across Codex
   homes, lock inode/ownership, and the terminal transcript record;
8. waits for process exit and actual lock release, then verifies that the
   transcript hash did not change.

Before a safe candidate can reach final revalidation and signaling, `unlock`
acquires a private same-user advisory operation lease keyed by the canonical
Codex home and thread UUID. A concurrent `unlock` is refused; this coordination
file is outside native lock paths, and its existence is never lock evidence.
Unsafe and already-unlocked cases do not create it.

`unlock` never deletes native lock files, never sends `SIGKILL`, and has no
force flag. Missing, ambiguous, or changing evidence fails closed. Persistent
helper children are reported as warnings because only the lock-owning PID
receives `SIGTERM`. Every `ps` and `lsof` subprocess has a deadline and bounded
output; timeout, overflow, spawn, and parsing failures remain unknown evidence.
`--timeout-ms` controls only the post-`SIGTERM` wait.

There is an unavoidable interval between final validation and the signal
system call. Eliminating that last race requires an owner-cooperative upstream
protocol. The [handoff proposal](upstream-handoff-proposal.md) is not an
implemented command or fallback: shared or unsupported owners remain refused,
and a failed handoff must never automatically chain to process termination.

Stale residue—an existing file with no actual OS lock—is reported but left in
place. Codex handles stale lock-file cleanup during its coordinated startup.
See the [safety race matrix](safety-race-matrix.md) for regression coverage.

## Requirements

- macOS or Linux
- Node.js 22.13+ (22.x) or Node.js 24.x
- `lsof` available on the host

The actual lock probe uses `fs-ext-extra-prebuilt`, which provides prebuilt
native binaries for common macOS and Linux architectures. Node.js 26 is not
supported because that dependency does not provide a compatible prebuilt binary.
The [platform evidence](platform-support.md) lists verified OS, architecture,
and runtime combinations; unlisted combinations are unverified rather than
implicitly supported.

## Options and exit codes

```text
--json                   Emit machine-readable JSON
--codex-home <path>       Defaults to CODEX_HOME or ~/.codex
--stability-ms <ms>       250..30000 (default: 1000)
--timeout-ms <ms>         100..60000 (default: 5000)
--no-update-notice       Disable cached notices and automatic refresh
-h, --help               Show help
-v, --version            Show version
```

- `0`: success, including an already-unlocked or absent lock
- `2`: unlock refused because the evidence was not safe
- `3`: termination/post-unlock verification or an unexpected command failure
- `64`: invalid command-line usage

With `--json`, stdout is one JSON value and human diagnostics are not mixed into
stderr. Usage and command failures retain the top-level `error` string and add
stable `errorCode`, `exitCode`, and `schemaVersion` fields.

## Updates

```bash
codex-unlock check-update
npm install --global codex-unlock@latest
```

Normal commands never wait for the network. An interactive command
may show a fresh cached advisory on stderr after its primary result, then start
a detached best-effort cache refresh when the cache is missing or expired.
JSON output instead uses an optional versioned `clientUpdate` field and never
mixes advisory text into stderr. CI and non-TTY human commands do not show or
refresh notices. The safety-critical `unlock` path never starts a registry
request or update refresher during inspection, revalidation, signaling, or
post-signal verification. Any automatic refresh starts only after the command
has completed and printed its primary result.

`check-update` (also available with `--json`) is an explicit foreground registry
check. It does not install or automatically update the package. Set
`CODEX_UNLOCK_NO_UPDATE_NOTICE=1` or pass `--no-update-notice` to disable cache
reads, notices, and automatic refreshes; these do not disable an explicit
`check-update`. See the [update security contract](update-security.md) for
permissions, offline behavior, bounds, and failure isolation.

## Source installation

The supported published installation is `npm install --global codex-unlock`.
For source development:

```bash
git clone https://github.com/abruption/codex-unlock.git
cd codex-unlock
npm ci
npm link
codex-unlock --help
```

`npm ci` runs the `prepare` build. Direct global Git dependency installation
(`npm install --global git+https://...`) is not supported; some npm versions
omit build-time dependencies when preparing Git packages. Use the cloned source
or npm registry installation instead.

See [Contributing](../CONTRIBUTING.md) for development checks and
[v0.2 migration](v0.2-migration.md) for the historical 0.1.1 integration boundary.
