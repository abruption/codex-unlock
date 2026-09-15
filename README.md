# codex-unlock

`codex-unlock` diagnoses Codex native thread writer locks and can release a
completed idle CLI session without deleting its lock file.

```bash
npx codex-unlock list
npx codex-unlock inspect 01a089e8-3731-7202-ba68-0f4b0a3b2711
npx codex-unlock unlock 01a089e8-3731-7202-ba68-0f4b0a3b2711
```

Add `--json` to any command for a stable, versioned JSON result.

## Safety model

Lock-file existence is not treated as ownership. The tool independently:

1. probes the actual OS lock with a nonblocking exclusive `flock` attempt;
2. uses `lsof` only to correlate open file descriptors with a PID;
3. samples PID start time, command, PPID, TTY, cwd, lock inode, and rollout
   size/mtime across a stability window;
4. requires exactly one same-user Codex owner holding exactly one thread lock;
5. requires the rollout's last record to be `event_msg/task_complete`;
6. refuses shared `app-server`, Remote Control, and daemon owners;
7. revalidates PID identity, the lock, and a SHA-256 transcript snapshot before
   sending `SIGTERM`;
8. waits for process exit and actual lock release, then verifies that the
   transcript hash did not change.

`unlock` never deletes lock files, never sends `SIGKILL`, and has no force flag.
Any missing or ambiguous evidence fails closed. Persistent helper children are
reported as warnings because only the lock-owning PID receives `SIGTERM`.

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

## Install from GitHub

Until the npm package is available, install directly from the repository:

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

## Options and exit codes

```text
--codex-home <path>  defaults to CODEX_HOME or ~/.codex
--stability-ms <ms>  defaults to 1000
--timeout-ms <ms>    defaults to 5000
```

- `0`: success, including an already-unlocked or absent lock
- `2`: unlock refused because the evidence was not safe
- `3`: termination or post-unlock verification failed
- `64`: invalid command-line usage

## Development

```bash
npm ci
npm run check
npm run lint
npm test
npm run smoke:package
```

The upstream handoff design proposed alongside this tool is preserved in
[`docs/upstream-handoff-proposal.md`](docs/upstream-handoff-proposal.md).

Changes use Conventional Commits and are released through Release Please. See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for contribution rules and
[`docs/maintainer-release.md`](docs/maintainer-release.md) for repository setup.
