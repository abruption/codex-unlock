<div align="center">

# codex-unlock

[![npm version](https://img.shields.io/npm/v/codex-unlock?color=cb3837&logo=npm)](https://www.npmjs.com/package/codex-unlock)
[![npm downloads](https://img.shields.io/npm/dm/codex-unlock?color=cb3837&logo=npm)](https://www.npmjs.com/package/codex-unlock)
[![CI](https://github.com/abruption/codex-unlock/actions/workflows/ci.yml/badge.svg)](https://github.com/abruption/codex-unlock/actions/workflows/ci.yml)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![node](https://img.shields.io/node/v/codex-unlock?color=339933&logo=node.js)](https://www.npmjs.com/package/codex-unlock)
[![platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)](#requirements)
[![license](https://img.shields.io/npm/l/codex-unlock?color=blue)](LICENSE)

**Fail-closed diagnostics and safe recovery for Codex native thread writer locks.**

</div>

```bash
npx codex-unlock list
npx codex-unlock inspect 01a089e8-3731-7202-ba68-0f4b0a3b2711
npx codex-unlock unlock 01a089e8-3731-7202-ba68-0f4b0a3b2711
npx codex-unlock check-update
```

Add `--json` to any command for a stable, versioned JSON result.

The supported automation surface is the CLI and its `schemaVersion: 1` JSON
output. The package does not expose a JavaScript library API; imports of
generated `dist/` modules are intentionally unsupported and blocked by package
exports. See the [JSON v1 contract](docs/json-v1.md) for field, error, and exit
code compatibility rules.

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

Before a safe candidate can reach the final revalidation and signal, `unlock`
also acquires a private same-user advisory operation lease keyed by the
canonical Codex home and thread UUID. A concurrent `unlock` is refused; the
coordination file is outside Codex native lock paths and its existence is never
treated as lock evidence. Unsafe and already-unlocked cases do not create it.

`unlock` never deletes lock files, never sends `SIGKILL`, and has no force flag.
Any missing or ambiguous evidence fails closed. Persistent helper children are
reported as warnings because only the lock-owning PID receives `SIGTERM`.
Every `ps` and `lsof` subprocess has a deadline and bounded output; timeout,
overflow, spawn, and parsing failures remain `unknown` evidence. The
`--timeout-ms` option is separate and controls only the post-`SIGTERM` wait.

There is an unavoidable interval between final validation and the signal
system call. Eliminating that last race requires an owner-cooperative upstream
handoff protocol; see the linked proposal below.

Stale residue—an existing file with no actual OS lock—is reported but left in
place. Codex itself removes stale lock files during its coordinated startup
cleanup.

## Requirements

- macOS or Linux
- Node.js 22.13+ (22.x) or Node.js 24.x
- `lsof` available on the host

The actual lock probe uses `fs-ext-extra-prebuilt`, which provides prebuilt
native binaries for common macOS and Linux architectures.
Node.js 26 is not currently supported because that dependency does not provide
a compatible prebuilt binary.
The exact OS, architecture, and runtime combinations backed by real lock and
process evidence are listed in
[`docs/platform-support.md`](docs/platform-support.md). Unlisted combinations
are unverified rather than implicitly supported.

## Install

Install the published package globally from npm:

```bash
npm install --global codex-unlock
codex-unlock --version
codex-unlock --help
```

For an ephemeral invocation without a retained global installation:

```bash
npx --yes codex-unlock@latest list
```

To install from source instead:

```bash
git clone https://github.com/abruption/codex-unlock.git
cd codex-unlock
npm ci
npm link
codex-unlock --help
```

The `prepare` lifecycle builds `dist/` when `npm ci` runs. Direct
`npm install --global git+https://...` installation is not supported; some npm
versions omit the build-time dependencies while preparing a Git package.
Users moving from the hardened 0.1.1 baseline should review the
[`v0.2 integration and migration boundary`](docs/v0.2-migration.md). The CLI's
JSON v1 output remains the supported integration surface; internal module
imports remain blocked.

## Options and exit codes

```text
--codex-home <path>  defaults to CODEX_HOME or ~/.codex
--stability-ms <ms>  defaults to 1000
--timeout-ms <ms>    defaults to 5000
--no-update-notice   disables cached notices and automatic refresh
```

Normal commands never wait for the network. An interactive invocation may
show a fresh cached update advisory on stderr after its primary result, then
start one detached best-effort cache refresh when the cache is missing or
expired. JSON output instead uses an optional versioned `clientUpdate` field
and never mixes advisory text into stderr. CI and non-TTY human commands do not
show or refresh notices.

Use `codex-unlock check-update` (or `codex-unlock check-update --json`) when
you explicitly want a foreground registry check. Set
`CODEX_UNLOCK_NO_UPDATE_NOTICE=1` or pass
`--no-update-notice` to disable cache reads, notices, and automatic refreshes;
the flag does not disable an explicitly requested `check-update`. The metadata
request, cache permissions, offline behavior, and safety isolation are detailed
in the [update security contract](docs/update-security.md).

- `0`: success, including an already-unlocked or absent lock
- `2`: unlock refused because the evidence was not safe
- `3`: termination or post-unlock verification failed
- `64`: invalid command-line usage

With `--json`, stdout is always one JSON value and human diagnostics are not
mixed into stderr. Usage and command failures retain the top-level string
`error` field for compatibility and add a stable `errorCode`, `exitCode`, and
`schemaVersion`.

## Development

```bash
npm ci
npm run check
npm run lint
npm test
npm run smoke:package
```

Runtime responsibilities are kept in focused internal modules: `inspection`
collects stable OS and transcript evidence, `policy` makes a pure fail-closed
authorization decision, and `unlock` owns the advisory operation lease,
complete revalidation, signaling, and post-signal verification. Only a private
revalidated-evidence type can reach the narrow SIGTERM function. These modules
are review and test boundaries, not a supported JavaScript API; automation
should continue to use the CLI's versioned JSON output.

Any advisory update feature must remain outside those safety boundaries. Its
cache, registry request, single-flight lease, privacy limits, CI/TTY policy,
and failure isolation are specified in the
[`update metadata security contract`](docs/update-security.md). The contract
does not permit synchronous network access from `list`, `inspect`, or
`unlock`, and it does not permit automatic self-update.

The upstream handoff design proposed alongside this tool is preserved in
[`docs/upstream-handoff-proposal.md`](docs/upstream-handoff-proposal.md).

Changes use Conventional Commits and are released through Release Please. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for contribution rules and
[`SECURITY.md`](SECURITY.md) for private vulnerability reporting. Maintainers
can use [`docs/maintainer-release.md`](docs/maintainer-release.md) for releases.
