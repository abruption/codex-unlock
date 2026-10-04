# Supported platform evidence

`codex-unlock` supports macOS and Linux only. Support means that the published
CLI can load its native advisory-lock dependency and that CI proves the full
non-mutating evidence path, including native coordination, against a real lock
owner. It does not mean that every
Unix-like platform or architecture is assumed safe.

## Verified matrix

The `supported-tests` CI gate requires every combination below to pass:

| Operating system | Architecture | GitHub runner | Node.js |
|---|---|---|---|
| Ubuntu 24.04 | x64 | `ubuntu-24.04` | 22.13.0, latest 22.x, latest 24.x |
| Ubuntu 24.04 | arm64 | `ubuntu-24.04-arm` | 22.13.0, latest 22.x, latest 24.x |
| macOS 15 | x64 | `macos-15-intel` | 22.13.0, latest 22.x, latest 24.x |
| macOS 15 | arm64 | `macos-15` | 22.13.0, latest 22.x, latest 24.x |

These explicit labels and architectures follow GitHub's
[hosted-runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
They are intentionally not expressed as `*-latest` aliases.

The published package ships a runtime-only `npm-shrinkwrap.json`, so an npm
installation receives the same exact `fs-ext-extra-prebuilt` and `nan`
versions that this matrix validated, and nothing else.

Each matrix job performs the normal type and integration suite and then runs a
platform smoke test that verifies all of the following on the runner itself:

- `fs-ext-extra-prebuilt` loads for the active OS, architecture, and Node ABI;
- a separate process holds a real exclusive advisory `flock`;
- the nonblocking lock probe observes `held` independently of `lsof`;
- the probe acquires and releases the existing native coordinator safely;
- `lsof` correlates exactly one owner PID and its only native thread lock;
- `ps` supplies a stable process start time, PPID, uid, command, and arguments;
- the lock's device, inode, ownership, type, and link count are available;
- a stable rollout ending in `event_msg/task_complete` authorizes policy.

The test does not signal the owner through the unlock path. It terminates its
own fixture during cleanup after evidence collection.

## Diagnostic command execution

Process evidence is collected with the same rules on every supported platform:

- `ps` runs only from `/bin/ps` or `/usr/bin/ps`, and `lsof` only from
  `/usr/sbin/lsof` or `/usr/bin/lsof`. `PATH` is never consulted; when neither
  fixed location exists the evidence is `unknown`.
- Commands run with a fixed environment (`LC_ALL=C`, `LANG=C`, and a system
  `PATH`) instead of the caller's, so `COLUMNS`, `LINES`, `PS_FORMAT`,
  `PS_PERSONALITY`, and locale variables cannot change their output.
- `ps` is invoked with `-ww`, which disables width truncation for both macOS
  BSD `ps` and Linux procps-ng.
- On Linux, `ps` arguments are cross-checked against `/proc/<pid>/cmdline`. If
  the kernel argv is unreadable, or `ps` output disagrees with it, the
  owner's arguments are `null` with an `arguments_unverified:` or
  `arguments_truncated:` error, and identity is incomplete. Verified kernel
  argument boundaries distinguish execution modes from prompts and known
  single-value options: `codex exec 'fix the daemon'` or
  `codex -C /work/app-server` is not a shared-service invocation. Actual
  `app-server`, `remote-control`, `daemon`, `exec-server`, and remote connection
  options remain refused. The bounded grammar follows `codex-cli 0.159.2`
  help for interactive, exec, resume, and fork modes; unknown options,
  variadic image options, unsupported modes (including service-looking root
  tokens such as `daemon-worker`), and ambiguous operands make
  identity incomplete. Exact service/subcommand-looking operands after `--`
  also remain conservatively refused; delimiter precedence has not been
  verified for every Codex version. Direct Node shebang execution is recognized only as
  `node /path/to/codex ...`, without arbitrary wrapper or interpreter flags.
- macOS supplies a flattened `ps` argument string without verified argument
  boundaries. Shared-service words anywhere in that string remain a
  conservative refusal, including words inside prompts or paths. The tool
  does not infer a shell quoting grammar or split this string into argv.
- The owner's native lock set is matched to the intended lock by the `lsof`
  device (`D`) and inode (`i`) fields, not by the rendered name, because the
  C locale makes `lsof` escape non-ASCII path bytes as `\xNN`. Any other lock
  name that cannot be resolved still blocks with `owner_lock_file_lookup_failed`.
- Every spawn failure, including a synchronous throw or an `EMFILE`/`ENFILE`
  child without pipes, is reported as a `spawn_error` command failure.

## Failure and unsupported-platform policy

A parser, command, native-module, permission, or identity failure is not
treated as partial success. Inspection returns `unknown` or adds a blocker, and
`unlock` must not send `SIGTERM`. The integration suite separately replaces
`ps` with a failing command through a test-only in-process seam and proves
that this path remains refused; it also proves that a shadowing `ps` or `lsof`
on `PATH` is never executed.

Windows, other Unix variants, and OS/architecture combinations absent from the
matrix are unverified. Windows lock and process semantics require a separate
design and real-host evidence before the package may advertise support. The
tool does not infer support from a fixture-only or cross-compiled result.
