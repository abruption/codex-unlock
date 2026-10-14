# Guard liveness and macOS refusal filter (research, #126/#127)

Research only. Nothing here changes `src/`, eligibility, policy, platform
support, dependencies, or the JSON contract, and nothing is published by
`npm pack` (`experimental/` is outside `files`). No experiment calls
`unlockInspectedThread`, so no Codex or lock owner is signalled by the
product's unlock path.

Measured on Darwin 27.0.0 arm64 (macOS 27.0.1, 26A434), Node v24.16.0,
lsof 4.91, APFS, same user, main `3bc4091`.

## Signals and process lifetime

What is recorded, not guaranteed:

- **First M2 attempt (original measurement round).** The transient fixture
  failed `listen EINVAL` because its Unix socket path exceeded the macOS
  limit. The runner's error path did not stop the holder it had already
  started, so the runner stayed waiting. The research runner process itself
  (the holder's parent) was sent **one SIGTERM**. The holder then saw stdin
  EOF and exited normally. No Codex process or fixture child was signalled.
- **Completed runs.** The research runners send no signal to fixture children.
  They close stdin and wait with a bound. Each fixture also has its own
  lifetime and exits with code 3 when it runs out.
- **Not covered by the above.** Node sends SIGTERM to a child whose
  `spawnSync` timeout expires. That applies to the `lsof` calls in M2's `+fg`
  scan and barrier wrapper. The +fg scan records `signal`/`error`, and the
  validation runs recorded none. The product's own diagnostics (`lsof`, `ps`)
  run with a command timeout, may signal their timed-out children, and are
  not instrumented here.
- **What a bound means.** Waits on children are bounded, and an exceeded bound
  is reported as `incomplete`. It is never escalated to a signal. A bound does
  not guarantee that the child ended: an `incomplete` run sets a nonzero exit status,
  keeps its scratch, and M2 keeps its socket directory. Every completed
  measurement and validation run below recorded `incomplete: 0`.

Runners create a fresh private `codex-*` directory under the temporary root
required by `AGENTS.md` (set `RESEARCH_TMP_ROOT` on macOS), or `/tmp` elsewhere. `RESEARCH_TMP_ROOT`
replaces only that root: the supplied directory is never chmod-ed, and
existing files outside that fresh scratch are never overwritten. M2 rewrites
its own scratch configuration between scenarios. A runner exits nonzero on any error,
incomplete child, or missing or mismatched round or result.

## F1: injected delay inside the native guard (`f1-guard-delay/`)

Question: while codex-unlock holds `.coordination.lock`, does a Codex-like
process waiting on the same file wait for exactly that long?

The delay is a bounded `Atomics.wait` injected through the existing
`afterGuardAcquired` test hook of `guardedProbeOnce` in the dist build. **It is
an injected finite delay. It is not a reproduction of a `/proc` cmdline wait
or any other kernel wait.** The waiter polls a nonblocking flock every 0.1 ms
under a per-round deadline and a process lifetime that both checks in its
loops. Real Codex waits with a blocking flock instead.

Original measurement: 5 repeats, 25 guarded and 25 baseline rounds.
`blocked` is the waiter's own time from seeing the marker (written inside
the guard) to acquiring coordination. `acquire − return` is the waiter's
acquisition time minus the moment `guardedProbeOnce` returned in the runner,
read from the same system monotonic clock. The guard's `LOCK_UN` happens
before that return, so this is **not** the delay after guard release, and it
can be negative. None of the 50 measured values was negative.

| Injected | Baseline blocked (median) | Guarded blocked (min / median / max) | Guarded acquire − return (range) |
| --- | --- | --- | --- |
| 0 ms | 0.03 ms | 0.01 / 0.03 / 0.19 ms | 0.014 – 0.159 ms |
| 10 ms | 0.02 ms | 12.4 / 15.1 / 15.2 ms | 0.022 – 0.130 ms |
| 50 ms | 0.02 ms | 52.1 / 59.7 / 60.2 ms | 0.025 – 0.155 ms |
| 200 ms | 0.02 ms | 203.4 / 206.9 / 210.4 ms | 0.035 – 0.137 ms |
| 1000 ms | 0.03 ms | 1002.6 / 1006.5 / 1010.1 ms | 0.037 – 0.111 ms |

Result: increasing injected delay increased the synthetic waiter's measured
blocked time. A process waiting on the same coordination lock cannot acquire
it until release. This measured one polling fixture, not every Codex process.
Overshoot above the injected value (for example 10 → 15 ms) was also recorded
in the hook's own duration; this does not isolate every scheduling cause.
All guarded rounds returned probe
`free` with guard `acquired`. Native file identities (dev, ino, size, mtime)
were unchanged.

Fault checks: `F1_FAULT=skip_round` (waiter never answers round 3) and
`F1_FAULT=waiter_lifetime` (300 ms waiter lifetime) must both exit nonzero.

## M2: `lsof +fg` FWASLOCKED as a refusal-side filter (`m2-macos-fwaslocked/`)

XNU sets `FWASLOCKED` (0x4000) on the open file description only when
`flock` succeeds, and never clears it. The filter evaluated here is
refusal-only. Per PID it aggregates every descriptor on the path:

| Condition | Decision |
| --- | --- |
| The scan failed, was signalled, wrote stderr, or has detectable malformed/truncated output | `unknown` |
| The PID is absent from the scan | `unknown` |
| No descriptor of the PID has the bit | `reject` |
| At least one descriptor has the bit | `not_excluded` |

There is no "holder" outcome. `fg-scan.test.mjs` checks these rules
deterministically, including multi-descriptor PIDs and failed or partial
output. Entire valid records can be omitted without a detectable format error;
this filter does not prove a complete descriptor inventory.

Part 1, flag matrix. The original measurement ran 3 repeats and all were
identical. The validation runs add `holder_multi_opener`: a holder with a
second, plain descriptor next to a never-locked opener. Its result: holder
`0x4003` + `0x1` → not_excluded, opener `0x3` → reject.

| Case | Probe | Flags per role |
| --- | --- | --- |
| holder | held | holder `0x4003` not_excluded |
| holder + never-locked opener | held | holder `0x4003`; opener `0x3` reject |
| holder + failed acquirer (FD kept) | held | holder `0x4003`; failed `0x3` reject |
| former holder (LOCK_UN, FD kept) + actual holder | held | former `0x4003`; holder `0x4003`, indistinguishable |
| former holder only | **free** | former `0x4003` not_excluded |
| failed acquirer after holder exit | free | failed `0x3` reject |

Part 2 reruns the #100 wrong-target shape. The actual holder is hidden from
the product's opener scan (a modelled clean omission), and the same omission
is applied to the `+fg` view. The `+fg` scan runs in the same barrier window
as the product's opener scan. It is a separate lsof invocation, not the
product's own sample. 3 repeats, all identical:

| Scenario | Product result | Owner is holder | Filter on owner |
| --- | --- | --- | --- |
| B_failed: transient failed acquirer, barrier on the opener scan only | `live_owner`, **safe false** (`owner_holds_other_thread_locks`) | no | reject |
| B_failed_all_scans: barrier on every lsof call (the #100 setup) | `live_owner`, **safe true, wrong target** | no | **reject** |
| B_former: Codex-looking former holder with a kept FD | `live_owner`, **safe true, wrong target** | no | **not_excluded** |
| control: holder visible | `live_owner`, safe true | yes | not_excluded |

Findings:

1. The filter removes the failed-acquirer and never-locked opener cases,
   including the #100 wrong-target reproduction.
2. It does not remove a former holder that keeps its descriptor. With the actual
   holder omitted by the model, this is a wrong target accepted by the sampled
   current checks and the filter. Its
   bit is identical to the actual holder's. Because the bit is sticky, it can
   never be positive holder evidence.
3. Scope of #100: with the barrier around the opener scan only, the
   transient had already closed its thread descriptor by the per-owner
   lock-set scan, and `owner_holds_other_thread_locks` blocked. The #100
   reproduction needs the transient's descriptor to be open in **both** the
   opener-scan and the lock-set-scan sample windows; the #100 barrier held
   it open across both. No real-environment frequency was measured.
4. Whether real Codex can be a "former holder with a kept FD" is source-only.
   v0.162.1 `WriterLockGuard::drop` closes the file, and Rust std opens with
   `O_CLOEXEC`, so exec'd children do not inherit it. A child forked without
   exec would share the description, flag, and lock. No such path was found,
   but the audit was not exhaustive.

Fault checks: `M2_FAULT=early_exit` (actor exits before ready),
`ignore_eof` (stop budget shorter than the actor's lifetime: `incomplete`,
socket directory kept), and `long_socket` (path over the limit, refused before
start) must all exit nonzero.

`holder/codex` and `transient/codex` derive from the #100 fixtures. The
holder now takes both locks with bounded nonblocking polling instead of a
blocking coordination flock. Both fixtures, and `former/codex`, have a
lifetime. All three are named `codex`.

## F2: Linux non-dumpable holder (`f2-linux-nondumpable/`), prepared, not run

`codex` (Python) refuses root and differing real/effective UIDs. It declares
the `prctl` ABI (`int` option and result, `unsigned long` arguments), sets the
requested dumpable value (0 or 1), and verifies it with `PR_GET_DUMPABLE`. It
then takes both locks with bounded nonblocking polling. It reports a ready
record with pid, fd, dumpable value and UIDs, and holds the lock until stdin
EOF (exit 0) or 20 s (exit 3).

`observe.py` records the same-user access matrix for the reads #137 performs.
It has no self-alarm, because a handled signal cannot wake a killable kernel
wait. `run.mjs` validates the ready record, waits for the observer with a
bound (recording `incomplete` without signalling it). It collects only the
access matrix. `F2_DIST` is rejected before any fixture starts. The earlier
in-process inspection was removed because synchronous inspection can block
the event loop, its timeout and holder EOF cleanup. The holder's own lifetime
does not bound the parent. Outcomes are recorded rather than asserted against
the expected table.

Build inspection requires separate-process observation and a validated
dumpable=1 candidate-recognition control.
Results after holder exit cannot establish access policy.
`ok` currently describes collection completion, not satisfaction of the
expected table or a proven fail-closed decision. These are open execution gates.

Only parse and syntax checks were done. No Linux host was used.

Expected from Linux v6.17 source, all unverified until run:

| Read | dumpable=1 | dumpable=0 |
| --- | --- | --- |
| `stat /proc/PID` uid | owner | owner (the 0555 directory is exempt in `task_dump_owner`) |
| `/proc/PID/fd`, `fdinfo` directory uid | owner | root |
| `fd` listdir and readlink, `fdinfo` open, `exe` readlink | allowed | EACCES/EPERM (`ptrace_may_access` READ_FSCREDS) |
| `cmdline` | allowed | allowed (no ptrace check) |
| `stat` start ticks | allowed | allowed |

On a non-dumpable target, #137 should therefore end `unknown` at
`/proc/PID/fd`, before any participation claim.

Hardening callers, within a targeted search of pinned v0.162.1 source:
`pre_main_hardening` appears in the `codex-responses-api-proxy` and
`codex-voice-host` mains, and `disable_process_dumping` appears in the
linux-sandbox proxy bridge. No direct call was found in the `codex` CLI
main. **That does not establish that a lock-owning process is dumpable.** The
same `codex` binary dispatches to linux-sandbox code by arg0. The kernel
also resets dumpable on credential changes and on exec of an unreadable
image. Packaging or wrappers may differ from source. Real Codex's dumpable
state needs a real binary and is not claimed.

## F3: indefinite waits, source limits only

No kernel wait was induced. The following comes from source reasoning only:

- `/proc/PID/cmdline` reaches `access_remote_vm`, which takes the target's
  `mmap_lock` for read (killable) and may page in argument memory. A target
  that holds, or is queued behind a writer of, its `mmap_lock` can stall the
  reader.
- Every other read #137 makes is also a synchronous syscall with **no hard
  bound**: directory reads, readlinks, `stat` through `/proc/PID/fd/N` (which
  reaches the target file's filesystem), and `stat`/`statfs` of the lock
  path. Some are expected to be short, but none is guaranteed finite. The
  25 ms budget is checked between calls and cannot interrupt one.
- Moving cmdline out of the guard (reading before and after the guard, with no
  await before the signal) removes the coordination stall. It does not make
  the signal safe: a slow read after the guard leaves the inode,
  participation, and PID evidence from inside the guard stale by the time
  of the signal.
- #137's command fingerprint hashes the `/proc/PID/exe` readlink **string**
  and the cmdline bytes. It does not hash the executable image.
- Keeping current main is the option that keeps functionality. The most
  conservative option is a separate one: keep diagnostics and refuse unlock
  whenever evidence is insufficient.

## Run

```sh
npm ci && npm run build
export RESEARCH_TMP_ROOT="<existing approved temporary root>"
node --test experimental/126-guard-liveness/m2-macos-fwaslocked/fg-scan.test.mjs
node experimental/126-guard-liveness/f1-guard-delay/run.mjs
node experimental/126-guard-liveness/m2-macos-fwaslocked/run.mjs
```

## Evidence and review revisions

Original measurement files and validation files remain private because they
contain local paths and process identifiers. Their SHA-256 values and sanitized
outcome summaries are recorded in [evidence.md](evidence.md). The original
measurement and later runner validation are separate revisions.

Independent read-only CLI reviews used Claude Code 2.1.296 with
`claude-opus-5-5` (actual response model confirmed) and Codex CLI 0.162.1 with
its isolated default selection (actual model unconfirmed), in parallel on
revision `e782e396df3f5feebb556bfe2f371d101176e03f`. Input SHA-256:
`70db601c2d878f86621c2f153758b89ea1fbe2973ee60f7cee6deda1ff0fa6da`.
Both completed successfully without running tests. Later corrections were
checked by the integrating Codex; the CLI reviews do not certify those later
commits. F2 remains unexecuted on Linux, and product adoption is unresolved.
