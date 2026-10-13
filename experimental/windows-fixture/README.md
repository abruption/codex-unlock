# Windows lock observation fixture (research, #122)

Fixture-only experiment for Windows native lock semantics. It is not part of
the npm package, the production CLI, or JSON v1. Every recorded result carries
`safeToUnlock: false`. Passing it does not authorize any Windows recovery.
Observation APIs used here (Restart Manager, process identity) are evidence
sources, not recovery permissions.

## Scope

| Track | Question | Output |
| --- | --- | --- |
| E1 | Do the native coordination and whole-file thread locks behave as the pinned Codex source implies, and how should errors be classified? | Each step compared with its stated hypothesis (`match` or `mismatch`). Every setup step is recorded as evidence |
| E3 | What does Restart Manager report for holder, non-holder opener, self, and post-exit states? | Opener candidates only |
| Identity | Do one process handle, a wait on that handle, the creation time, and the token SID distinguish live, changed, and exited processes? | Bounded contract check with no PID-reuse spawning |

## Source pins

- Codex `writer_lock.rs` is byte-identical at v0.162.1
  (`092d3acd6bec3e3a14bdc7e7a2810ab628ab759d`) and at the v0.155.1 tag
  commit (`be2951ea34f0d295ed0becf97079f92fa5f6950e`). Both pin Rust 1.95.0.
- The fixture reproduces those source semantics without running Codex. The
  behavior of any installed Codex binary, including 0.155.1, is unverified
  and is reported separately.
- Rust std 1.95.0 `library/std/src/sys/fs/windows.rs`: `OpenOptions` share
  mode is read, write, and delete, with handles not inherited. `try_lock` calls
  `LockFileEx(EXCLUSIVE | FAIL_IMMEDIATELY, 0, u32::MAX, u32::MAX)`. Only
  `ERROR_LOCK_VIOLATION` maps to `WouldBlock`.
- fs-ext-extra-prebuilt 2.2.14 Windows emulation locks `0..0xffff0000` and
  maps every other error to `EINVAL`. It ships no Windows binaries.

## Safety boundary

- **Scratch directory:** `%TEMP%\codex-unlock-lab-<random>` is created by
  `Directory.CreateDirectory(path, DirectorySecurity)`.
  - The DACL is protected and holds one ACE: full control for the current user
    SID. The script reads it back and records the directory's file ID.
  - If verification fails, the run stops with exit 3 before any fixture file or
    agent exists.
  - This narrows access by other non-admin principals. It does not exclude
    administrators or holders of backup, restore, or take-ownership privileges.
- **Path limits:** agents accept paths only under that root. The check
  normalizes to a full path, then compares with `OrdinalIgnoreCase` at a
  directory boundary.
  - The check is lexical. A reparse point inside the root could still redirect
    elsewhere, so the only junction the orchestrator creates targets a
    directory inside the root.
  - Thread names must be leaf names.
- **Codex untouched:** `CODEX_HOME`, `%USERPROFILE%\.codex`, and real Codex
  processes are never read or touched.
- **Processes:** only agent processes started by the orchestrator take part.
  - An agent exits on `exit` or stdin EOF. EOF also covers the parent
    disappearing. On exit it disposes every fixture handle it holds.
  - The orchestrator never calls `Stop-Process`, `TerminateProcess`, or
    `taskkill`, and never sends console control events.
  - An agent that does not exit within budget is reported with its PID, and
    the scratch directory is preserved.
- **Cleanup:** `DeleteFileW` is called only on scoped fixture paths. Recursive
  cleanup runs only when all of these hold:
  - every agent exited
  - every junction was removed as a link
  - the scratch file ID is unchanged
  - `-OutFile` is outside scratch

  Otherwise the scratch directory is preserved and the reason is printed.
- **No host changes:** no installation, authentication, account, firewall,
  Defender, scheduled-task, or execution-policy changes.

## Execution policy

The documented entry point is
`powershell -NoProfile -NonInteractive -File lab.ps1`, under the host's
existing policy. It does not use `-ExecutionPolicy Bypass`, `-EncodedCommand`,
or wrapper scripts. Agents start with the same flags.

If the host policy blocks the script (for example, `Restricted`, the Windows
client default), the run fails, and that is reported. Choosing a policy change
is a separate decision outside this fixture.

## Output and exit codes

- `-OutFile` is required and must not already exist. The file is created with
  `FileMode.CreateNew` and written as UTF-8 without a BOM, one JSON object per
  line, LF-terminated.
- `-OutFile` must not be inside any `codex-unlock-lab-*` directory.

| Verdict | Meaning |
| --- | --- |
| `match` / `mismatch` | Compared with the step's hypothesis |
| `recorded` | No hypothesis, and the observation reported success |
| `error` | No hypothesis, and the observation reported `ok:false`, `complete:false`, or an exception |
| `incomplete` | No observation (timeout, stalled agent, missing response). This is checked before anything else |

| Exit code | Meaning |
| --- | --- |
| 0 | Every hypothesis matched and every agent exited |
| 1 | At least one mismatch |
| 2 | Any `incomplete` or `error`, an orchestrator error, or an agent still running |
| 3 | Refused before any fixture existed |

## Timing model

| Budget | Default | Applies to |
| --- | --- | --- |
| `ReadyBudgetMs` | 60 s | Each agent's `ready` line after start |
| `WaitBudgetMs` | 15 s | Each stdin write, each flush, each reply, each exit wait |
| `TotalBudgetSec` | 600 s | Monotonic `Stopwatch`. Every wait is `min(per-wait, remaining)`, including stderr collection |

- **Not bounded:** the total budget limits the waits this script performs. It
  is not a hard wall-clock cap, because these steps are not bounded:
  - `Add-Type` compilation
  - `Process.Start`
  - the synchronous file I/O used to build fixtures and write results
  - `Remove-Item` cleanup
- **Writes:** stdin writes go through `BaseStream.WriteAsync` and
  `FlushAsync`, with bounded waits. A broken pipe or a timeout marks the agent
  stalled, and nothing more is written to it. Its stdin is then closed so EOF
  ends it.
- **Reads:** each agent has at most one outstanding `ReadLineAsync`. A
  timed-out read is kept, because `StreamReader` rejects a second concurrent
  read.
- **Stderr:** stderr is drained by `ReadToEndAsync` from process start, so a
  full pipe cannot block an agent.
- **Output:** agents emit ASCII-only JSON, so localized Win32 messages survive
  any console code page.

## E1 cases

Each case below is preceded by recorded `setup:*` steps (open, lock, close)
that are expected to report success. Those steps show the test condition held.

| Step | Setup | Hypothesis |
| --- | --- | --- |
| `free` / `absent` | guard + thread / guard only | `free` / `absent` |
| `missing_guard` | thread only | `unknown/missing_guard` |
| `busy_guard` | writer holds guard (Rust range) | `unknown/busy_guard` |
| `held`, `held:after_writer_close` | writer holds thread, then closes | `held`, then `free` |
| `range:X-held/Y-try` | X, Y ∈ {rust, fsext} | all four conflict with `ERROR_LOCK_VIOLATION` (33) |
| `share:rw:delete_while_prober_open` | prober open without `FILE_SHARE_DELETE`; writer closes, then `DeleteFileW` | `ERROR_SHARING_VIOLATION` (32) |
| `share:rwd:delete_while_prober_open` | prober open with `FILE_SHARE_DELETE` | recorded only (POSIX vs pending delete may differ by build) |
| `share:*:exists_after_last_close`, `delete_after_last_close` | after the last handle closes | recorded only. A failure here is not attributed to share mode |
| `read_locked:data.bin` | 16 bytes written before locking | `ERROR_LOCK_VIOLATION` (33) |
| `read_locked:empty.bin` | empty file | recorded only. Zero bytes at EOF must not be classified as a violation |
| `thread_is_directory` | directory named like the thread lock | `unknown` |
| `junction:nofollow` / `junction:follow_control` | lock directory is a junction | `unknown` comes only from the probe's explicit no-follow policy. The control shows plain `CreateFileW` follows the junction and reports `free` |
| `guard_sharing_violation` | guard opened with share `0` | `unknown/guard_open/32` |

The guarded probe releases the guard in `finally`, including when identity
collection or serialization throws. A failed thread or guard unlock turns the
result into `unknown` (`thread_unlock_failed` or `guard_unlock_failed`).

## E3 cases

The steps are `none`, `holder`, `holder+opener`, `holder+opener+self`,
`opener_only`, and `after_holder_exit:0..4`. Guarded probes follow the
`after_holder_exit` observations; the earlier steps record Restart Manager
results with explicitly recorded setup conditions.

- Each entry is labelled by PID and start time as `writer`, `opener`,
  `prober` (self), `orchestrator`, or `other`.
- A complete empty list is a normal observation (`count: 0`). A missing
  response is `incomplete`.
- Results are tagged `opener_candidates_only`. Neither a single entry nor
  `held` plus a single entry is promoted to holder evidence.

## Identity cases

| Step | Hypothesis |
| --- | --- |
| `live` | `live_same_user`: the wait on the probe's own handle times out, the creation time matches, and the SID matches |
| `start_mismatch` | `identity_changed` |
| `after_exit` | `exited`. The orchestrator still holds a `Process` handle, so the object stays openable; liveness comes only from `WaitForSingleObject(h, 0)` on the probe's handle, never from `STILL_ACTIVE` (259) |

Liveness is checked again after identity collection. `WAIT_FAILED` is
`unknown`.

## Go/no-go for the next research step

- **Go:** every hypothesis `match`, no `incomplete` or `error`, every agent
  exited, exit code 0. E3 data are complete enough to characterise the self,
  opener, and post-exit behavior.
- **No-go:**
  - any mismatch
  - a setup step that failed
  - an empty-file read classified as a violation
  - the junction case resolving without the explicit policy
  - any agent left running
- Results describe only the observed token and integrity level (for example,
  High integrity over SSH). They say nothing about Medium-integrity desktop
  sessions, a real Codex binary, Defender or other third-party openers, or
  ReFS.

## Static gate (separate from a fixture run)

`check.ps1` parses `lab.ps1` and `check.ps1` and compiles `WinLockLab.cs` with
`Add-Type`. It creates no fixture files, starts no agents, and takes no locks.
The compiler may create its own temporary build files.

The separate `Windows fixture compile` workflow uses `windows-2022` and its
Windows PowerShell 5.1 shell to parse the orchestrator, exercise only its pure
path-boundary predicate, and compile the native declarations without calling
them. It does not run the fixture, change execution policy, or establish lock
semantics. A passed compile gate does not replace the planned fixture run on
the designated real host.

macOS has no PowerShell or C# toolchain here, so neither script has been
parsed or compiled yet.
