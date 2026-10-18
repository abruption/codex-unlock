# Windows and Rust evaluation (research, #122)

**Research record only.** This document does not add Windows support, change
the production CLI, JSON v1, the npm artifact, or the supported-platform
contract in [platform-support.md](platform-support.md). Windows remains
unverified. Nothing here authorizes unlocking, signaling, terminating, or
deleting anything on Windows.

It records (1) what the merged experiments actually established, (2) the
successful thread-scoped writer-lock teardown path in a pinned upstream Codex
release, (3) a proposed go/no-go recommendation between a Rust helper, a full Rust rewrite and
the current TypeScript CLI, and (4) the remaining Windows work split into
follow-up units that can be tracked separately.

## 1. Evidence inventory: synthetic results versus product support

| Source | What ran | What it establishes | What it does **not** establish |
| --- | --- | --- | --- |
| #123 `experimental/rust/` (`codex-unlock-lab`, Rust 1.90.0, `publish = false`) | Rust-to-Rust fixture processes on CI `ubuntu-24.04`, `macos-15`, `windows-2022` | Real cross-process exclusive contention and cooperative release of **synthetic** files with Rust std locks (`flock` / `LockFileEx`); missing or busy fixture coordinator reported as unknown; fixture bytes unchanged | Any interaction with a real Codex process or Codex home; owner identity; holder attribution; Windows recovery |
| #128 `experimental/rust/interop.mjs` | Rust fixture versus the production TypeScript `guardedProbeOnce` adapter on Linux and macOS CI only | Primitive interoperability in both directions on those Unix hosts; inode/owner/mode/mtime invariance of fixture files | Windows interoperability (Windows CI runs Rust-only fixtures); actual Codex ownership |
| #133 `experimental/windows-fixture/` | (a) CI `Windows fixture compile`: PowerShell 5.1 parse, pure helper checks, C# compile, **no native execution**. (b) Two operator runs on a designated host: Windows 10 build 19045, PowerShell 5.1, NTFS, **High-integrity SSH token**, input commits `6a8b00e` and `b363316` | Each run: 102 records, 81 `match`, 20 `recorded`, 1 `error` (`read_locked:empty.bin`, Win32 33, before the hypothesis was added); all `safeToUnlock=false`; five agent-stop records with exit 0. Covers coordination ordering, Rust/fs-ext range conflicts (Win32 33), share-delete behavior, junction no-follow, Restart Manager opener candidates, and handle/start-time/SID identity of fixture processes | Real Codex binary behavior; Medium integrity; Defender or other third-party openers; ReFS; forced-exit release; rerun of the latest script; production adapter quality (path scoping is lexical) |
| Issue comment (2026-10-14) | Hash comparison of upstream `writer_lock.rs` | Byte identity of that one file between `rust-v0.162.1` and `0.163.0-alpha.11` | Absence of any other release path; protocol completeness |

All four are **synthetic or source-level** evidence. None of them is a Windows
product-support result, and none establishes owner attribution or safe unlock.

## 2. Upstream pin

| Item | Value |
| --- | --- |
| Release | `rust-v0.163.0` (GitHub "Latest" as checked on 2026-10-16, not a pre-release, published 2026-10-15T21:30:38Z) |
| Annotated tag object | `129b8ec7ee6f4511557a4856279f529025c25af4` |
| Commit | `83086188ae0614bd882818ff1aa23f3194962012` |
| Upstream toolchain | Rust 1.95.0 (`codex-rs/rust-toolchain.toml`) |
| `codex-rs/rollout/src/writer_lock.rs` SHA-256 | `e9a49bef7540dc688de8243d6df1ee9a24cf328c082934b1352d8bebef857468` (same digest recorded for `rust-v0.162.1` and alpha.11) |

Line numbers below refer to that commit. The verifier covers 17 file digests
and 61 line anchors, checked by
[`experimental/122-windows-evaluation/verify-upstream.mjs`](../experimental/122-windows-evaluation/verify-upstream.mjs)
(see section 8). Upstream lines are paraphrased; consult the source for exact
text. Tag-object, release metadata and toolchain values were checked separately
through GitHub at review time. Supplemental TUI/exec target-selection sources
below are outside this 17-file manifest. The integrating review independently
matched all 17 hashes and 61 anchors through the GitHub API on 2026-10-16.

## 3. Successful thread-scoped teardown path at the pinned commit

### 3.1 Acquisition and who keeps the guard alive

| Step | Location | Behavior |
| --- | --- | --- |
| Guard type | `codex-rs/rollout/src/writer_lock.rs:26-31` | `WriterLockGuard` keeps the coordinator, the lock path and the open `File` |
| Acquire | `writer_lock.rs:43-86` | Takes the coordination lock, removes stale unlocked thread files once per coordinator (`45-49`, `124-171`), opens `<thread-id>.lock` read/write/create, then nonblocking `try_lock` (`65-79`); `WouldBlock` means another active writer |
| Coordination lock | `writer_lock.rs:108-122` | `create_dir_all`, then a **blocking** exclusive `lock()` on `thread-writer-locks/.coordination.lock` (`116`) |
| Thread store wrapper | `codex-rs/thread-store/src/local/mod.rs:342-357` | `acquire_writer_lock` wraps the guard in `Arc`; `WouldBlock` becomes `ThreadStoreError::Conflict` |
| Create / resume | `codex-rs/thread-store/src/local/live_writer.rs:25-38`, `40-46` | Acquire the writer lock, build a recorder with a clone of the `Arc`, then `insert_live_recorder` |
| Live entry owns a clone | `thread-store/src/local/mod.rs:162-172`, `373-393` | `LiveRecorderEntry.writer_lock` |
| Writer task owns a clone | `codex-rs/rollout/src/recorder.rs:145-161`, `1018` | `RolloutWriterTask._writer_lock`, so the lock outlives queued file writes |

The guard is released only when the **last** `Arc` clone is dropped.

### 3.2 Release chain (app-server, idle thread without subscribers)

1. **`thread/unsubscribe`** (`codex-rs/app-server-protocol/src/protocol/common.rs:580-584`)
   is handled in `codex-rs/app-server/src/request_processors/thread_processor.rs:1034-1060`.
   It removes **only the calling connection's** subscription
   (`unsubscribe_connection_from_thread`, `1051`) and returns
   `unsubscribed`, `notSubscribed` or `notLoaded`. It does not itself shut the
   thread down. The README describes it as stopping delivery
   (`codex-rs/app-server/README.md:64-65`).
2. **Unload trigger.** The thread listener computes an unload target only when
   the thread has **no subscribers and is not active**, plus
   `thread_unload_delay` (`app-server/src/request_processors/thread_lifecycle.rs:59-66`).
   The default delay is **1800 seconds** (`codex-rs/core/src/config/mod.rs:4031-4032`,
   `thread_unload_delay_secs`). Older notes in
   [upstream-handoff-proposal.md](upstream-handoff-proposal.md) recorded 60
   seconds; that value is historical. A running agent defers unloading
   (`thread_lifecycle.rs:405-408`).
3. **Unload.** For a non-child thread, `unload_thread_without_subscribers`
   (`thread_lifecycle.rs:527-536`, `559-624`) cancels pending requests, removes
   thread state and calls `CodexThread::shutdown_and_wait`
   (`codex-rs/core/src/codex_thread.rs:319-321`). A slow shutdown is waited for,
   not forced (`582-592`). v2 child threads take `try_evict_v2_thread` instead
   (`419-472`, `473-526`); that branch was not traced further.
4. **`Op::Shutdown`.** `shutdown_and_wait` submits `Op::Shutdown` and awaits
   session-loop termination (`codex-rs/core/src/session/mod.rs:1156-1165`). The
   submission loop dispatches it to `handlers::shutdown`
   (`codex-rs/core/src/session/handlers.rs:716`), which stops the session
   runtime and calls `LiveThread::shutdown` (`350-367`). If the submission
   channel closes without an explicit shutdown, the loop still calls
   `LiveThread::shutdown` (`736-753`).
5. **Thread store.** `LiveThread::shutdown`
   (`codex-rs/thread-store/src/live_thread.rs:296-310`) calls
   `ThreadStore::shutdown_thread` (`thread-store/src/local/mod.rs:565-567`) →
   `live_writer::shutdown_thread` (`live_writer.rs:169-213`): drain and stop the
   recorder (`178`/`180`, recorder `shutdown` and `wait_for_exit` at
   `recorder.rs:1190-1236`), then remove the `LiveRecorderEntry` (`207`).
6. **Guard drop, conditional on the last reference.** If the last `Arc` clone
   is gone, `Drop for WriterLockGuard`
   (`writer_lock.rs:174-196`) takes the coordination lock, closes the thread
   file (`185`; the comment notes this ordering is needed for Windows).
   Windows lock lifetime in the presence of duplicated/inherited handles is
   not established by this source trace and remains a W4/W5 experiment.
   It then removes `<thread-id>.lock` (`186-193`) and releases
   coordination (`194`).
7. **Observable signal.** After `shutdown_and_wait` returns and the runtime is
   removed, the app-server emits `thread/closed`
   (`thread_lifecycle.rs:607-616`; method at `common.rs:1958`). It is an
   observable notification, not a documented lock-release acknowledgement.

Caveats visible in the source:

- Recorder shutdown or persistence errors can return from `live_writer.rs`
  before entry removal at line 207. `handlers.rs:364-400` records such an error
  but still emits `ShutdownComplete` and ends the loop. Session-loop completion
  does not prove that every writer reference was dropped. The inventory of
  `Arc` clones and inherited/duplicated descriptions is not exhaustive.
- `thread/closed` is conditional on successful `shutdown_and_wait` and a matching runtime
  teardown. Submission failure or a replaced runtime can skip it. Neither
  its presence nor its absence is an OS-lock-state measurement. The blocking
  coordination acquisition in `Drop` also has no hard duration bound.
- If `Drop` cannot take the coordination lock, it logs and returns
  (`writer_lock.rs:176-182`). The `File` field is still dropped with the struct,
  so this reference should close. The effect of other handle references on
  Windows lock lifetime is unverified; the name is not removed by this path
  and may remain until a later
  coordinator's stale cleanup (`124-171`). This is inferred from Rust drop
  semantics and was not executed.
- `discard_thread` (`live_writer.rs:215-235`) is a second internal teardown
  path (failed initialization, migration). It is not an external API.
- `thread/archive` and `thread/delete` also shut a thread down
  (`prepare_thread_for_removal`, `thread_processor.rs:1062-1075`), but they
  change persisted state. They are not a non-destructive release.

### 3.3 Process-wide paths (not thread-scoped)

| Path | Location | Why it is not a thread release for codex-unlock |
| --- | --- | --- |
| App-server exit | `codex-rs/app-server/src/lib.rs:1338-1350`; `thread_processor.rs:1297-1308` | On a non-forced exit, `shutdown_threads` shuts **all** threads with a 10 s bound. On a forced exit, cleanup tasks are aborted and `shutdown_threads` is skipped; the OS releases locks at process exit and lock files may remain |
| Daemon control socket `/daemon/shutdown` | `codex-rs/app-server-transport/src/transport/unix_socket.rs:180-187`, `217-233` | Accepted only when the server is `DaemonShutdownAccess::Managed`, and requires the server PID; it shuts the whole managed app-server down |
| Daemon `stop_with_grace` | `codex-rs/app-server-daemon/src/backend/pid.rs:162-245` | Used by the daemon's own lifecycle. On Windows it sends `request_shutdown` (`199`), returns if the process exits, and can call `process.terminate()` if it remains active after the grace period (`221-236`) |
| Windows process helper | `codex-rs/app-server-daemon/src/backend/windows.rs:196-253` | Process handle, `GetProcessTimes` creation time, `WaitForSingleObject(h, 0)`, then `TerminateProcess` |

These paths target the whole process. The daemon's Windows path can escalate
to `TerminateProcess` if cooperative exit has not completed. Those broad or
forceful actions conflict with the codex-unlock safety contract,
which refuses shared app-server/daemon owners and never escalates. The
daemon's handle-plus-creation-time pattern is a useful reference for W3 below.
It is not authority for third-party termination.

### 3.4 External release API: not found in targeted search

The method table in `common.rs` was searched for names containing `release`,
`handoff`, `takeover`, `evict`, `unlock`, `owner`, `writer`, `shutdown`, `exit`,
`stop`, `terminate`, `kill`, `close` and `unload`, and the Rust sources for the
literal strings `thread/release`, `thread/handoff`, `thread/unload` and
`thread/close`. Matches were
`thread/attachmentOwner/list`, `turn/interrupt`, `command/exec/terminate`,
`process/kill`, `thread/backgroundTerminals/terminate`, `thread/realtime/stop`,
`mcpServer/event/stream/stop` and the `thread/closed` notification. These act on
turns, child processes, streams or attachments, not the writer lock.

**An external app-server method that releases a given thread's writer lock
immediately, or that releases or terminates all owners from another process,
was not found in this targeted search.** A search is not a proof of absence.
`thread/unsubscribe` is not such a method. It is connection-scoped, it cannot
remove other connections' subscriptions or other processes' writers, and any
release it allows depends on a server-side idle delay.

Release therefore requires cooperation from the actual owner. A TUI frontend
can select an embedded server, a local daemon or a remote target; its name alone
does not identify the writer process or endpoint. The pinned
[target selection](https://github.com/openai/codex/blob/83086188ae0614bd882818ff1aa23f3194962012/codex-rs/tui/src/lib.rs#L1028)
and [connection/fallback paths](https://github.com/openai/codex/blob/83086188ae0614bd882818ff1aa23f3194962012/codex-rs/tui/src/lib.rs#L575)
distinguish these modes. The pinned
[`exec` startup](https://github.com/openai/codex/blob/83086188ae0614bd882818ff1aa23f3194962012/codex-rs/exec/src/lib.rs#L1022)
also uses an in-process app-server client. Internal app-server use does not
establish an externally accessible release endpoint for an embedded owner.
A daemon connection likewise does not let a third party unsubscribe other
clients or safely release a writer in another process. These source paths
do not establish an external thread-scoped recovery API.

## 4. Options and proposed recommendation

Rust **does not automatically solve holder attribution or safe termination**.
`LockFileEx` has no query for the holding process. Restart Manager and handle
enumeration report openers, not lock holders (E3 records are
`opener_candidates_only`). Windows has no Unix-style per-process graceful
`SIGTERM` equivalent for this design. `TerminateProcess` is
forceful, and console control events need console sharing and are not
thread-scoped. Every one of these limits applies equally to Rust, C#, a Node
addon and PowerShell.

| Option | Recommendation, not migration approval | Reasoning |
| --- | --- | --- |
| A. Keep the current TypeScript CLI; Windows stays unsupported | **Go** (preserve current behavior) | Preserves the existing Unix checks and disclosed attribution limits, JSON v1, npm/Trusted Publisher release flow and test suite. Windows research continues in `experimental/` without changing claims |
| B. Rust helper binary invoked by the TS CLI for Windows-native observations | **No-go for now; conditional re-evaluation** | It would add value only for a Windows primitive that cannot be reached safely otherwise (for example `GetFileInformationByHandleEx(FileIdInfo)`, token/owner SIDs, process handles and times). Cost: per-architecture signed binaries inside an npm package, a supply-chain and update-security review, Defender/SmartScreen behavior, and a second JSON contract. It does not settle W4 or W5. Re-evaluate only after W1-W3 show a needed primitive that the existing addon or a read-only PowerShell/C# observer cannot provide |
| C. Full CLI rewrite in Rust | **No-go** | It replaces the current checks and release pipeline while using the same OS APIs and attribution/termination limits. Existing coordination, revalidation and transcript checks do not eliminate the known macOS holder-correlation gap. Prototype evidence shows lock primitive interoperability (Unix, #128), not a need for a full rewrite |

The prototypes in `experimental/rust/` and `experimental/windows-fixture/`
remain unpublished research tools. Promoting any of them requires its own
issue with the gates below.

## 5. Follow-up units

Each unit is tracked in a separate issue. None authorizes Windows unlock. Every
experimental record keeps `safeToUnlock=false` until every applicable W1-W7
gate for the chosen design and supported environment is resolved and a separate
production design is accepted. These are future work units; this document
does not authorize new host, account, policy or real-Codex operations.

W1-W3 can begin with synthetic fixtures. W7's pinned real-binary observations
are a later prerequisite for completing W3 classification and W5. W6 requires
evidence for each integrity level claimed by the final design, including the
relevant W7 observations; High-integrity results do not automatically transfer.
Re-evaluating a helper for a specific read-only primitive is not approval to
skip W4/W5 or promote it to a recovery tool.

### W1. File identity on NTFS and ReFS

Tracking: [#146](https://github.com/abruption/codex-unlock/issues/146).

- **Scope:** stable identity for the Codex home, `thread-writer-locks`,
  `.coordination.lock`, thread lock files and transcripts: volume serial plus
  128-bit `FILE_ID_INFO`, link count, and attributes. Covers no-follow opening
  of reparse points (junctions, symlinks, mount points), hard links,
  parent-directory replacement between observations, path/handle agreement and
  case-insensitive names.
- **Evidence:** real-host JSONL on NTFS **and** ReFS (Dev Drive or a ReFS
  volume), with a recorded hypothesis for each case. Include a compare-before
  and compare-after on the same handle.
- **Acceptance:** every case is `match`. Any reparse point or identity change
  yields `unknown`. The 64-bit `nFileIndex` is not used as the only identity on
  ReFS. Unix lossless identity ([lossless-file-identity.md](lossless-file-identity.md))
  stays unchanged.
- **Existing coverage:** fixture `junction:nofollow` and
  `junction:follow_control`, and a recorded scratch-directory file ID (NTFS,
  High integrity only). Path scoping is lexical. ReFS has not been tested.

### W2. SID and owner checks

Tracking: [#147](https://github.com/abruption/codex-unlock/issues/147).

- **Scope:** owner SID and DACL of the Codex home, the lock directory and lock
  and transcript files, compared with the current token user SID. Covers
  inherited versus explicit ACEs, and the fact that Administrators and
  backup/restore privileges bypass the DACL.
- **Evidence:** real-host records for files owned by the current user, another
  user and Administrators (fixture files only), plus the recorded refusal
  results.
- **Acceptance:** anything other than an exact current-user match yields
  `unknown` or a refusal. A matching owner SID is insufficient on its own:
  define and test refusal for write access granted to other ordinary users.
  State the threat-model limits for privileged Administrators/SYSTEM and
  backup/restore access. No ACL is changed and no privilege is enabled.
- **Existing coverage:** a protected single-ACE scratch DACL is verified before
  fixtures run, and the identity case matches the token SID of fixture
  processes. No check exists for lock-file owners in a Codex-shaped home.

### W3. Process identity and start time

Tracking: [#148](https://github.com/abruption/codex-unlock/issues/148).

- **Scope:** one process handle per candidate. Identity is the handle plus
  `GetProcessTimes` creation time plus token SID, and liveness is
  `WaitForSingleObject(h, 0)`, never `STILL_ACTIVE`. Covers revalidation of the
  same handle before any action, PID reuse, and classification of the image and
  command line as standalone TUI/`exec`, app-server, managed daemon or Remote
  Control, with every ambiguous case refused.
- **Evidence:** real-host records for live, `start_mismatch` and `after_exit`
  states, plus a deliberate PID-reuse attempt under a bounded budget, with a
  real Codex binary in a **disposable** `CODEX_HOME` for classification.
- **Acceptance:** identity changes and ambiguous modes yield `unknown`. Shared
  app-server, daemon and Remote Control owners are refused, matching the Unix
  contract.
- **Existing coverage:** fixture identity cases `live`, `start_mismatch` and
  `after_exit` matched at High integrity. There is no PID-reuse run and no real
  Codex classification. The upstream daemon uses the same handle and start-time
  pattern (`windows.rs:196-253`).

### W4. Holder attribution (Windows counterpart of #100)

Tracking: [#149](https://github.com/abruption/codex-unlock/issues/149).

- **Scope:** decide whether a positive holder for a `LockFileEx` lock can be
  established at all. Candidate sources are Restart Manager, handle
  enumeration (which may require privileges that are out of scope) and
  owner-side cooperation from upstream.
- **Evidence:** records showing that a candidate set contains the holder and
  excludes non-holder openers, the prober and the orchestrator, in the same
  forms as E3.
- **Acceptance:** without positive single-holder evidence the result stays
  `unknown` for an opener-targeted action. An opener list is never promoted
  to holder evidence. An authenticated owner-cooperative design must instead
  prove its endpoint, thread and owner binding under a separately reviewed
  contract; it is not implicitly authorized by an opener list.
- **Existing coverage:** E3 `opener_candidates_only` records.

### W5. Cooperative termination and release path

Tracking: [#150](https://github.com/abruption/codex-unlock/issues/150).

- **Scope:** find a Windows route that lets the owner release one thread
  without force. Options are an upstream owner-side release (see
  [upstream-handoff-proposal.md](upstream-handoff-proposal.md) and section 3.4)
  or a documented cooperative exit of a standalone owner. `TerminateProcess`,
  `taskkill /F`, injected console control events and daemon `stop_with_grace`
  are excluded.
- **Evidence:** on a disposable `CODEX_HOME`, with a real Codex binary pinned
  by version and SHA: owner exit or release, actual lock release (reacquire
  under coordination), lock-file state, and transcript hash invariance,
  including concurrent-recovery races.
- **Acceptance:** a standalone-exit route verifies the same process instance's
  normal exit, actual lock release and transcript invariance. A thread-release
  route verifies the bound thread's actual lock release and transcript
  invariance; the server process may remain alive. Both routes re-probe under
  coordination and reject changing targets or concurrent recovery. A failed
  or unavailable cooperative route never falls back to force.
  Any route exposed through `codex-unlock unlock` must also preserve its
  same-user, stable completed-idle transcript requirements; endpoint
  authentication alone does not authorize releasing a busy thread.
- **Existing coverage:** none against a real Codex. Fixture agents exit
  cooperatively on EOF, which only proves that the harness never signals.

### W6. Medium versus High integrity tokens

Tracking: [#151](https://github.com/abruption/codex-unlock/issues/151).

- **Scope:** rerun the E1, E3 and identity cases from a Medium-integrity
  interactive desktop session and compare with the High-integrity SSH results.
  Covers cross-integrity `OpenProcess` access (`PROCESS_QUERY_LIMITED_INFORMATION`
  and `SYNCHRONIZE`), Restart Manager visibility and UAC split tokens.
- **Evidence:** paired JSONL from the same commit at both levels, with the token
  integrity level recorded for every record. The run uses the host's existing
  execution policy and makes no host changes.
- **Acceptance:** any difference is explained, and an access failure maps to
  `unknown`. No conclusion is carried from one integrity level to the other.
- **Existing coverage:** High-integrity SSH runs only.

### W7. Real Codex interoperability on Windows (prerequisite for W3 and W5)

Tracking: [#152](https://github.com/abruption/codex-unlock/issues/152).

- **Scope:** the pinned upstream release (section 2) runs in a disposable
  `CODEX_HOME`. A read-only observer checks the coordination and thread lock
  ranges and share modes against the fixture model: Rust std `LockFileEx(0,
  u32::MAX, u32::MAX)` versus the fs-ext `0..0xffff0000` emulation.
- **Evidence:** a hypothesis-compared JSONL record with binary version/SHA,
  token integrity and host policy recorded, plus checks on a host where
  Defender is already enabled and third-party openers can be observed.
  Changing protection or execution policy requires separate authorization.
- **Acceptance:** every hypothesis `match`. No real user Codex home is read.
- **Existing coverage:** fixture range conflicts (Win32 33) only.

## 6. Status of #122

The proposed recommendation is **A go, B conditional no-go, C no-go**;
no migration or product-support decision is adopted by this record.
The remaining gates are W1-W7 above, tracked in #146–#152 as of 2026-10-18.
#122 is closed as the initial evaluation; its outstanding safety evidence
continues in those follow-up issues. No release,
publication or support claim follows from this document.

## 7. Not done here

For this evaluation record, no Windows host was used, and no real Codex binary, Codex home or process was
run, opened or signaled. No Medium-integrity, ReFS or Defender run took place.
No upstream code was executed. The later tracking update created #146–#152;
it did not execute their experiments.

## 8. Reproducing the citations

```sh
git init codex && cd codex
git remote add origin https://github.com/openai/codex.git
git fetch --depth 1 --filter=blob:none origin refs/tags/rust-v0.163.0:refs/tags/rust-v0.163.0
cd -
node experimental/122-windows-evaluation/verify-upstream.mjs ./codex
```

The script reads only git blobs at the pinned commit and checks the tag commit,
17 file SHA-256 digests and 61 line anchors. It is not part of `npm test` or the
npm package. A pass confirms that the citations match the source. It does not
confirm runtime behavior, the document's paraphrases, complete causal coverage
or the final holder. The example's blobless clone may lazily fetch missing
objects during `git cat-file`; source-only does not mean offline. The caller's
clone/configuration is trusted. Tag-object/release metadata, toolchain and
supplemental TUI/exec citations are outside this helper's manifest.
