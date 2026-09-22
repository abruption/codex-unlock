# Supported platform evidence

`codex-unlock` supports macOS and Linux only. Support means that the published
CLI can load its native advisory-lock dependency and that CI proves the full
read-only evidence path against a real lock owner. It does not mean that every
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

Each matrix job performs the normal type and integration suite and then runs a
platform smoke test that verifies all of the following on the runner itself:

- `fs-ext-extra-prebuilt` loads for the active OS, architecture, and Node ABI;
- a separate process holds a real exclusive advisory `flock`;
- the nonblocking lock probe observes `held` independently of `lsof`;
- `lsof` correlates exactly one owner PID and its only native thread lock;
- `ps` supplies a stable process start time, PPID, uid, command, and arguments;
- the lock's device, inode, ownership, type, and link count are available;
- a stable rollout ending in `event_msg/task_complete` authorizes policy.

The test does not signal the owner through the unlock path. It terminates its
own fixture during cleanup after evidence collection.

## Failure and unsupported-platform policy

A parser, command, native-module, permission, or identity failure is not
treated as partial success. Inspection returns `unknown` or adds a blocker, and
`unlock` must not send `SIGTERM`. The integration suite separately replaces
`ps` with a failing command and proves that this path remains refused.

Windows, other Unix variants, and OS/architecture combinations absent from the
matrix are unverified. Windows lock and process semantics require a separate
design and real-host evidence before the package may advertise support. The
tool does not infer support from a fixture-only or cross-compiled result.
