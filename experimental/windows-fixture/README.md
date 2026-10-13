# Windows lock observation fixture (research, #122)

Fixture-only experiment for Windows native lock semantics. It is not part of
the npm package, the production CLI, or JSON v1. Every recorded result carries
`safeToUnlock: false`. Passing it does not authorize any Windows recovery.

## Scope

| Track | Question | Output |
| --- | --- | --- |
| E1 | Do the native coordination and whole-file thread locks behave as the pinned Codex source implies, and how should errors be classified? | `match`/`mismatch` against stated hypotheses |
| E3 | What does Restart Manager report for holder, non-holder opener, self, and post-exit states? | Recorded opener candidates only |
| Identity | Does one process handle plus creation time plus token SID detect an identity change? | Bounded contract check, no PID-reuse spawning |

## Source pins

- Codex `writer_lock.rs` is byte-identical at v0.162.1
  (`092d3acd6bec3e3a14bdc7e7a2810ab628ab759d`) and at the tag for v0.155.1
  (`be2951ea34f0d295ed0becf97079f92fa5f6950e`). Both pin Rust 1.95.0.
  The fixture mirrors the source semantics; it does not run Codex. Behavior of
  a specific installed Codex binary remains unverified.
- Rust std 1.95.0 `library/std/src/sys/fs/windows.rs`: `OpenOptions` share
  mode is read, write, and delete, with handles not inherited. `try_lock` calls
  `LockFileEx(EXCLUSIVE | FAIL_IMMEDIATELY, 0, u32::MAX, u32::MAX)`. Only
  `ERROR_LOCK_VIOLATION` maps to `WouldBlock`.
- fs-ext-extra-prebuilt 2.2.14 Windows emulation locks `0..0xffff0000`. It
  maps every other error to `EINVAL`. It ships no Windows binaries.

## Safety boundary

- One new directory: `%TEMP%\codex-unlock-lab-<random>`. `CODEX_HOME`,
  `%USERPROFILE%\.codex`, and real Codex processes are never read or touched.
- Only agent processes started by the orchestrator take part. They exit on
  `exit` or stdin EOF. The orchestrator never calls `Stop-Process`,
  `TerminateProcess`, `taskkill`, or sends console control events. An agent
  that does not exit within budget is reported as `incomplete` with its PID,
  and the scratch directory is kept.
- `DeleteFileW` is called only on fixture files inside the scratch directory.
  Junctions are removed as links before any recursive cleanup. Cleanup runs
  only when `-OutFile` points outside scratch and every agent has exited.
- No installation, authentication, account, firewall, Defender, or
  scheduled-task changes. `-ExecutionPolicy Bypass` is passed per process and
  is not persisted.

## Timing model

| Budget | Default | Applies to |
| --- | --- | --- |
| `ReadyBudgetMs` | 60 s | Agent start including `Add-Type` compile, until its `ready` line |
| `WaitBudgetMs` | 15 s | Each command reply and each agent exit wait |
| `TotalBudgetSec` | 600 s | Hard cap; every wait is `min(per-wait, remaining)` |

Each agent has at most one outstanding `ReadLineAsync`. A timed-out read is
kept rather than abandoned, because `StreamReader` rejects a second concurrent
read. The agent is then marked stalled and receives no further commands.
Stderr is drained by `ReadToEndAsync` from process start, so a full pipe
cannot block an agent. The agent blocks on `Console.In.ReadLine`. The
orchestrator never blocks without a budget. The only unbounded step is the
`Process.Start` call, and that is outside this protocol.

## E1 cases

| Step | Setup | Hypothesis |
| --- | --- | --- |
| `free` / `absent` | guard + thread / guard only | `free` / `absent` |
| `missing_guard` | thread only | `unknown/missing_guard` |
| `busy_guard` | writer holds guard (Rust range) | `unknown/busy_guard` |
| `held`, `after_writer_close` | writer holds thread, then closes | `held`, then `free` |
| `range:X-held/Y-try` | X, Y ∈ {rust, fsext} | all four conflict with `ERROR_LOCK_VIOLATION` (33) |
| `share:rw:delete_while_prober_open` | prober open without `FILE_SHARE_DELETE`; writer closes, then `DeleteFileW` | `ERROR_SHARING_VIOLATION` (32) |
| `share:rwd:delete_while_prober_open` | prober open with `FILE_SHARE_DELETE` | recorded only (POSIX vs pending delete may differ by build) |
| `share:*:exists_after_last_close`, `delete_after_last_close` | after the last handle closes | recorded only. A failure here cannot be attributed to share mode |
| `read_locked:data.bin` | 16 bytes written before locking | `ERROR_LOCK_VIOLATION` (33) |
| `read_locked:empty.bin` | empty file | recorded only. Zero bytes at EOF must not be classified as a violation |
| `thread_is_directory` | directory named like the thread lock | `unknown` |
| `junction:nofollow` / `junction:follow_control` | lock directory is a junction | `unknown` only because the probe applies an explicit no-follow policy. The control shows plain `CreateFileW` follows the junction and reports `free` |
| `guard_sharing_violation` | guard opened with share `0` | `unknown/guard_open/32` |

## E3 cases

The steps are `none`, `holder`, `holder+opener`, `holder+opener+self`,
`opener_only`, and `after_holder_exit:0..4` (with a guarded probe at each).
Each Restart Manager entry is labelled by PID and start time as `writer`,
`opener`, `prober` (self), `orchestrator`, or `other`. The result is tagged
`opener_candidates_only`. Neither a single entry nor `held` plus a single
entry is promoted to holder evidence. Incomplete or changing lists are
reported as such.

## Go/no-go for the next research step

- **Go:** every E1 hypothesis is `match`, with no `incomplete` and every agent
  exited. E3 data are complete enough to characterise the self, opener, and
  post-exit behavior.
- **No-go:**
  - any range or guard `mismatch`
  - an empty-file read classified as a violation
  - the junction case resolving without the explicit policy
  - any agent left running
- Results describe only the observed token and integrity level (for example,
  High integrity over SSH). They say nothing about Medium-integrity desktop
  sessions, a real Codex binary, Defender or other third-party openers, or
  ReFS.

## Run (only after the remote execution boundary is approved)

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File lab.ps1 -OutFile C:\path\outside\scratch\results.jsonl
```

Static review on macOS cannot compile `WinLockLab.cs` or parse `lab.ps1`. No
PowerShell or C# toolchain is available there. First-run compile errors are
expected possibilities, not evidence.
