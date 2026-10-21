# Diagnostic-only Rust Windows prototype

This unpublished prototype observes explicitly selected Windows lock files and
an optional PID. It implements no recovery command. Every JSON result includes
`safeToUnlock: false`; `held` means an OS lock conflicted, not that the supplied
PID owns it. It is a separate experimental schema, not production JSON v1.

## Build and run

Rust 1.90.0 is pinned. On Windows, run from this directory:

```powershell
cargo build --locked
.\target\debug\codex-unlock-windows-diagnostic.exe capabilities
.\target\debug\codex-unlock-windows-diagnostic.exe inspect --home C:\private-lab\home --thread 11111111-2222-4333-8444-555555555555 --pid 1234
```

The home and UUID must be explicit. Initially only local fixed NTFS volumes and
plain absolute drive paths are accepted. ReFS, UNC/device paths, aliases,
reparse points, hardlinked lock files, missing files and failed observations are
unknown. Unsupported operating systems return `windows_required`.

Exit 0 means the requested observations were collected, 2 means unknown or an
unusable requested PID, and 64 means invalid command arguments. Exit 0 never
authorizes recovery. Lock state and PID evidence are independent: a failed PID
query can coexist with a measured free/held lock and still produce exit 2.
Any other exit code, missing output or invalid JSON must be treated as unknown.

## What is observed

- Existing-file handles provide 128-bit file IDs, volume serials, final paths,
  link counts and metadata. Home, lock directory and lock files must be owned
  by the current user. No raw SID is emitted.
- Directory ancestors are opened without delete sharing and held throughout
  the observation. Files use read/write/delete sharing, so the observer does
  not prevent normal Codex file deletion merely through its share flags.
- The existing `.coordination.lock` is acquired nonblocking before a
  nonblocking whole-range thread probe. Only Win32 error 33 is lock contention;
  other failures are unknown. Unlock failures are unknown. No native files
  are created, removed or read for content by the diagnostic executable.
- The optional requested PID is queried through one process handle: live
  checks, creation time, image path, token user, session and integrity level.
  This is not holder attribution, Codex execution-mode verification, a pinned
  image digest, or evidence of a stable completed conversation.

These probes have effects: a client not serialized by this exact coordinator
can see transient exclusive-lock contention; holding coordination can delay another coordinator; directory
handles temporarily deny directory renames/deletion. Synchronous OS calls have
no hard wall-clock bound. This is intended first for disposable test homes.
Delete sharing permits a deletion request, but delete-pending lifetime and name
reuse can still be affected until the observer closes its file handles.

File handles allow deletion, so before/after identity and path observations are
samples rather than atomic name binding. Same-user malicious replacement or
permission changes are not excluded. File ownership is checked; a full DACL
authorization policy is not implemented. Other users, Medium integrity, ReFS,
Defender interference and actual Codex modes require separate evidence.
An elevated Codex can create objects owned by Administrators; the exact
current-user ownership rule then returns `file_owner_not_self`. Raw results
include local paths and PIDs: keep them private and redact public summaries.
Directory identity is rechecked independently of unrelated directory timestamp
changes; thread/guard file metadata must remain unchanged.

The pinned [Codex 0.163.0 writer](https://github.com/openai/codex/blob/83086188ae0614bd882818ff1aa23f3194962012/codex-rs/rollout/src/writer_lock.rs#L43)
opens `<thread-id>.lock` under coordination, using `try_lock` for the thread.
Its [coordinator](https://github.com/openai/codex/blob/83086188ae0614bd882818ff1aa23f3194962012/codex-rs/rollout/src/writer_lock.rs#L108)
uses blocking `lock()`. The synthetic fixture instead uses nonblocking guard
acquisition so its setup failure can be reported without an unbounded wait.

## Synthetic tests

Create an existing private scratch directory owned by the current user, with a
protected DACL allowing that user only, and set
`WINDOWS_DIAGNOSTIC_FIXTURE_PARENT` to it. Then run:

```powershell
cargo test --locked -- --test-threads=1
```

The separate `codex-unlock-windows-fixture` executable creates a new child home,
uses Rust std whole-range locks, and exits itself on stdin EOF or its lifetime
limit. It deletes only its own named synthetic files and empty directories.
Tests do not use process termination as cleanup. Unconfirmed exit is failure
and can leave synthetic files behind. A trusted private scratch parent is a
precondition, not an adversarial-filesystem guarantee.

Transferred integration test binaries can use `WINDOWS_DIAGNOSTIC_BIN` and
`WINDOWS_FIXTURE_BIN` to select the accompanying executables instead of their
build-machine paths. Run them with `--test-threads=1`.

The Windows CI job compiles and exercises synthetic cases. Its artifact is
temporary research input, not a release asset or installation channel. Native
Codex interoperability and a possible recovery design will be assessed from
separate recorded measurements. W1-W7 (#146-#152) are not completed merely by
passing these tests.

## Operator-run native observation

`observe-native.mjs` verifies an explicitly supplied Codex binary SHA-256,
creates a fresh child home below an operator-created private parent, and starts
its own stdio app-server. It sends only `initialize`, `initialized` and
`thread/start`, without a model turn or authentication request. It samples the
diagnostic, closes its own server stdin, and records a second observation after
confirmed normal exit. This tests one self-started app-server mode only.

```powershell
node observe-native.mjs --binary C:\private-lab\codex.exe --sha256 <sha256> --diagnostic C:\private-lab\codex-unlock-windows-diagnostic.exe --parent C:\private-lab\measurements --result C:\private-lab\measurements\native.json
```

The parent must already be a trusted, private, plain directory outside real
Codex homes. It is not an adversarial-path/ACL verifier. Results and the newly
created native home are retained for inspection. Capture and parent waits are
bounded, but a child blocked in an OS call can remain alive: the observer sends
EOF and records incomplete status, never force-terminates it. `collected` means
the sequence completed, not that diagnostics were positive or recovery passed.
The hash check does not pin the launched image against same-user replacement.

## Recovery decision

The current result is diagnostic-only. Rust makes the Windows primitives
available, but `LockFileEx` does not identify the holder, and querying a PID does
not establish that relationship. Safe automatic recovery additionally needs
verified holder attribution, execution-mode checks and a cooperative release
route. None is provided by this prototype. No signals, force termination,
lock-file deletion, release, or package publication is included.

References: [Windows/Rust evaluation](../../docs/windows-rust-evaluation.md),
[cooperative release research](../../docs/windows-recovery-contract.md),
[LockFileEx](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-lockfileex).
