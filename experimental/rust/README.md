# Rust Windows-support experiment

Research for [#122](https://github.com/abruption/codex-unlock/issues/122).
This unpublished `codex-unlock-lab` executable measures file-lock behavior using
new synthetic fixtures. It is not a replacement for the production CLI and does
not inspect, repair, or terminate existing Codex sessions. The npm package and
its macOS/Linux support contract are unchanged.

## Run the experiment

Use Rust 1.90.0 (pinned in `rust-toolchain.toml`). From this directory:

```sh
cargo test --locked --offline
cargo run --locked --offline -- capabilities
cargo run --locked --offline -- self-test --scratch-root /path/to/scratch
```

Pass an existing scratch directory suitable for disposable fixtures. The
experiment creates its own unique child directory; do not pass a Codex home.
On Windows, use a scratch path such as `C:\Temp` that already exists. Tests can
use `CODEX_UNLOCK_LAB_SCRATCH_ROOT` to select the scratch parent; CI uses the
runner's temporary directory. This variable is exclusively a test/lab setting,
not a production CLI setting.

The laboratory has no `list`, `inspect`, or `unlock` command for real sessions.
Its experimental JSON is a separate contract, not production JSON schema v1.
`safeToUnlock` remains false even when a fixture lock is free: lock state alone
does not establish the owner's identity or authorize recovery.

## What this establishes

Rust's stable file-lock API uses `flock` on Unix and `LockFileEx` on Windows.
The experiment checks contention between independent processes, cooperative
release, and nonblocking coordination-before-thread probing. A missing or busy
fixture coordinator must yield unknown. No fallback probes the thread without
the coordinator. Fixture bytes are checked before and after the experiment.

The fixture owner cooperates through a bounded test protocol and exits itself;
this does not implement or prove graceful shutdown of Codex on Windows. The
fixture harness is intended for a private scratch directory, not hostile native
paths. There is no production-grade ACL/reparse-point/identity adapter yet.

`Rust experiment` CI runs on Ubuntu 24.04 x64, macOS 15 arm64, and Windows
Server 2022 x64 with the pinned toolchain. Passing these jobs is evidence for
these synthetic fixtures only, not support for native Windows Codex, every
Windows filesystem, network shares, WSL interoperation, or Windows arm64.

## Next decision gates

1. Match an explicitly pinned upstream Codex coordination protocol and Windows
   lock range/open/share flags, and test actual interoperability. A Rust-to-Rust
   fixture is not that test. Compare Unix evidence with the TypeScript adapter.
2. Validate file identity across path/handle observations, parent replacement,
   symlinks/reparse points, hard links, and same-user ownership (Windows SID/ACL).
3. Establish actual lock-holder attribution and complete owner lock sets; an
   open handle is not ownership proof. Track #100 rather than assuming Rust
   solves visibility limitations.
4. Establish PID/start-time identity, command-mode classification, process
   handle lifetimes, stable `task_complete` transcript evidence, and revalidation.
5. Design a cooperative Windows release/exit route. `TerminateProcess` or a
   forceful emulation of `SIGTERM` does not satisfy the current safety contract.
6. Test exit, reacquisition, concurrent recovery, and unchanged transcript
   after recovery before considering a production Windows unlock implementation.

Only then decide between a Rust helper, a full migration, or retaining the
existing implementation. This issue stays open during that evaluation. No
crates.io/npm publication, release assets, or new installation channel is
introduced by this prototype.

## References

- [Rust File::try_lock and platform behavior](https://doc.rust-lang.org/1.90.0/std/fs/struct.File.html#method.try_lock)
- [Windows LockFileEx](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex)
- [Current platform contract](../../docs/platform-support.md)
- [Native coordination regression](https://github.com/abruption/codex-unlock/issues/55)

The manifest is `publish = false`, and the production npm `files` allowlist does
not include this directory. Rust has a separate lockfile and build directory.
