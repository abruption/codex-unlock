# Guard liveness and macOS refusal filter (research, #126/#127)

Research only. Nothing here changes `src/`, eligibility, policy, platform
support, dependencies, or the JSON contract, and nothing is published by
`npm pack` (`experimental/` is outside `files`). No experiment calls
`unlockInspectedThread` or sends a signal. Every child ends on stdin EOF
within a bounded wait.

Measured on Darwin 27.0.0 arm64 (macOS 27.0.1, 26A434), Node v24.16.0,
lsof 4.91, APFS, same user, main `3bc4091`.

## F1: injected delay inside the native guard (`f1-guard-delay/`)

Question: while codex-unlock holds `.coordination.lock`, does a Codex-like
process waiting on the same file wait for exactly that long?

The delay is a bounded `Atomics.wait` injected through the existing
`afterGuardAcquired` test hook of `guardedProbeOnce` in the dist build. **It is
an injected finite delay. It is not a reproduction of a `/proc` cmdline wait
or any other kernel wait.** The waiter polls a nonblocking flock every 0.1 ms
under its own 5 s deadline. Real Codex waits with a blocking flock, which this
fixture avoids because a blocking wait has no bound of its own.

5 repeats per delay; `blocked` is the waiter's own time from seeing the marker
(written inside the guard) to acquiring coordination.

| Injected | Baseline blocked (median) | Guarded blocked (min / median / max) | Acquire after guard release |
| --- | --- | --- | --- |
| 0 ms | 0.03 ms | 0.01 / 0.03 / 0.19 ms | ≤ 0.16 ms |
| 10 ms | 0.02 ms | 12.4 / 15.1 / 15.2 ms | ≤ 0.13 ms |
| 50 ms | 0.02 ms | 52.1 / 59.7 / 60.2 ms | ≤ 0.16 ms |
| 200 ms | 0.02 ms | 203.4 / 206.9 / 210.4 ms | ≤ 0.14 ms |
| 1000 ms | 0.03 ms | 1002.6 / 1006.5 / 1010.1 ms | ≤ 0.11 ms |

Result: the waiter's blocked time tracks the guard hold time one for one, and
it acquires within 0.2 ms of release. Any synchronous stall inside the guard
callback therefore becomes a stall of every Codex process in the same
`CODEX_HOME` that needs coordination. Overshoot above the injected value
(e.g. 10 → 15 ms) is `Atomics.wait` scheduling, present in the hook duration
itself. All rounds returned probe `free` with guard `acquired`; native file
identities (dev, ino, size, mtime) were unchanged; waiter exit 0.

Run: `F1_OUT=<private dir> node experimental/126-guard-liveness/f1-guard-delay/run.mjs`

## M2: `lsof +fg` FWASLOCKED as a refusal-side filter (`m2-macos-fwaslocked/`)

XNU sets `FWASLOCKED` (0x4000) on the open file description only when
`flock` succeeds and never clears it. The filter evaluated here is
refusal-only: bit absent → `reject`, unreadable or missing → `unknown`, bit
present → `not_excluded`. There is no "holder" outcome.

Part 1, flag matrix, 3 repeats, all identical:

| Case | Probe | Flags per role |
| --- | --- | --- |
| holder | held | holder `0x4003` not_excluded |
| holder + never-locked opener | held | holder `0x4003`; opener `0x3` reject |
| holder + failed acquirer (FD kept) | held | holder `0x4003`; failed `0x3` reject |
| former holder (LOCK_UN, FD kept) + actual holder | held | former `0x4003`; holder `0x4003` — indistinguishable |
| former holder only | **free** | former `0x4003` not_excluded |
| failed acquirer after holder exit | free | failed `0x3` reject |

Part 2 reruns the #100 wrong-target shape. The actual holder is hidden from
the product's opener scan (modelled clean omission), and the same omission is
applied to the `+fg` view. The `+fg` scan runs in the same barrier window as
the product's opener scan; it is a separate lsof invocation, not the
product's own sample. 3 repeats, all identical:

| Scenario | Product result | Owner is holder | Filter on owner |
| --- | --- | --- | --- |
| B_failed: transient failed acquirer, barrier on opener scan only | `live_owner`, **safe false** (`owner_holds_other_thread_locks`) | no | reject |
| B_failed_all_scans: barrier on every lsof call (the #100 setup) | `live_owner`, **safe true, wrong target** | no | **reject** |
| B_former: Codex-looking former holder with kept FD | `live_owner`, **safe true, wrong target** | no | **not_excluded** |
| control: holder visible | `live_owner`, safe true | yes | not_excluded |

Findings:

1. The filter removes the failed-acquirer and never-locked opener cases,
   including the #100 wrong-target reproduction.
2. It does not remove a former holder that keeps its descriptor. That process
   is a wrong target that every current check and the filter accept. Its
   bit is identical to the actual holder's in Part 1. The bit is sticky, so it
   cannot be positive holder evidence.
3. Refinement of #100: with a barrier only around the opener scan, the
   transient had already closed its thread descriptor by the time of the
   per-owner lock-set scan, so `owner_holds_other_thread_locks` blocked. The
   #100 reproduction needs the transient to be inside its window for both the
   opener scan and the per-owner lock-set scan. The #100 barrier did hold it
   open across both. This lowers how likely the shape is with real Codex's
   short failed-acquire window. It is not a probability estimate.
4. Whether real Codex can be a "former holder with kept FD" is source-only.
   v0.162.1 `WriterLockGuard::drop` closes the file. Rust std opens with
   `O_CLOEXEC`, so exec'd children do not inherit it. A forked child without
   exec would share the description, flag, and lock. No such path was found,
   but not every path was audited.

Run: `M2_SOCKET_ROOT=<short private dir> M2_OUT=<private dir> node
experimental/126-guard-liveness/m2-macos-fwaslocked/run.mjs`. Unix socket paths
are limited to 104 bytes on macOS. The first attempt failed `listen EINVAL` for
that reason; its stuck holder was released by stopping the orchestrator, after
which the holder exited on stdin EOF. Error paths now stop every live child.

`holder/codex` and `transient/codex` are unchanged copies of the #100
fixtures (`research/100-attribution-interleaving`). The holder's comment that
its process name is not Codex-like is inaccurate: it is named `codex`.

## F2: Linux non-dumpable holder (`f2-linux-nondumpable/`) — prepared, not run

`codex` (Python) takes the thread flock under coordination and, with
`FIXTURE_DUMPABLE=0`, calls `prctl(PR_SET_DUMPABLE, 0)` and verifies it.
`observe.py` records the same-user access matrix for the reads #137 performs.
`run.mjs` drives dumpable 1 and 0 and, with `F2_DIST`, records `inspectThread`
for a chosen build. It refuses to run off Linux. It has passed syntax checks
only. No Linux host was used.

Expected from Linux v6.17 source, all unverified until run:

| Read | dumpable=1 | dumpable=0 |
| --- | --- | --- |
| `stat /proc/PID` uid | owner | owner (0555 directory is exempt in `task_dump_owner`) |
| `/proc/PID/fd`, `fdinfo` dir uid | owner | root |
| `fd` listdir / readlink, `fdinfo` open, `exe` readlink | allowed | EACCES/EPERM (`ptrace_may_access` READ_FSCREDS) |
| `cmdline` | allowed | allowed (no ptrace check) |
| `stat` start ticks | allowed | allowed |

So #137 on a non-dumpable target should end `unknown` at `/proc/PID/fd`
before any participation claim. Real Codex's dumpable state needs a real
binary and is not claimed. Pinned v0.162.1 source calls
`pre_main_hardening` only from `codex-responses-api-proxy` and
`codex-voice-host`, and `disable_process_dumping` only from the
linux-sandbox bridge child, not from the `codex` binary.

## F3: indefinite waits — source limits only

No kernel wait was induced. From source reasoning only:

- `/proc/PID/cmdline` reaches `access_remote_vm`, which takes the target's
  `mmap_lock` for read (killable) and may page in argument memory. A target
  holding or queued behind a writer of its `mmap_lock` can stall the reader.
- Every other read #137 makes is also a synchronous syscall with **no hard
  bound**: directory reads, readlinks, `stat` through `/proc/PID/fd/N`
  (which reaches the target file's filesystem), and `stat`/`statfs` of the
  lock path. Some are expected to be short, but none is guaranteed finite.
  The 25 ms budget is checked between calls and cannot interrupt one.
- Moving cmdline out of the guard (guard-before and guard-after reads, with
  no await before the signal) removes the coordination stall. It does not make
  the signal safe: a slow post-guard read makes the inode, participation, and
  PID evidence collected inside the guard stale by the time of the signal.
- #137's command fingerprint hashes the `/proc/PID/exe` readlink string and
  the cmdline bytes. It does not hash the executable image.
