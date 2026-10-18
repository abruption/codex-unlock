# Guard liveness and macOS refusal filter (research, #126/#127)

Research only. Nothing here changes `src/`, eligibility, policy, platform
support, dependencies, or the JSON contract, and nothing is published by
`npm pack` (`experimental/` is outside `files`). No experiment calls
`unlockInspectedThread`, so no Codex or lock owner is signalled by the
product's unlock path.

F1 and M2 measured on Darwin 27.0.0 arm64 (macOS 27.0.1, 26A434), Node v24.16.0,
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
  keeps its scratch, and M2 keeps its socket directory. Every
  nominal measurement and nominal validation run below recorded `incomplete: 0`.

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

## F2: Linux non-dumpable holder (`f2-linux-nondumpable/`), access matrix measured

`codex` (Python) refuses root and differing real/effective UIDs. It declares
the `prctl` ABI (`int` option and result, `unsigned long` arguments), sets the
requested dumpable value (0 or 1), and verifies it with `PR_GET_DUMPABLE`. It
then takes both locks with bounded nonblocking polling. It reports a ready
record with pid, fd, dumpable value and UIDs, and holds the lock until stdin
EOF (exit 0) or its lifetime limit (exit 3; the runner requests 60 s).

`observe.py` records the same-user access matrix for the reads #137 performs.
It has no self-alarm, because a handled signal cannot wake a killable kernel
wait. `run.mjs` validates the ready record, waits for the observer with a
bound (recording `incomplete` without signalling it). Without `F2_BUILD` it
collects only the access matrix, as in the measured run (the observer now also
records mount-namespace readlinks). `F2_BUILD` runs a separate-process
inspection, described below. The earlier
in-process inspection was removed because synchronous inspection can block
the event loop, its timeout and holder EOF cleanup. The holder's own lifetime
does not bound the parent. Access-matrix-only mode records observed permission
outcomes without asserting that they match the source-derived expected table.

Build inspection requires separate-process observation and a validated
dumpable=1 candidate-recognition control.
Results after holder exit cannot establish access policy.
Without `F2_BUILD`, `ok` describes collection completion, not satisfaction of
the permission table or a proven fail-closed decision. With `F2_BUILD`, `ok`
requires both collection completion and `report.expectations.ok`: an expected
table mismatch makes the runner exit 1 even when collection succeeded. A
successful synthetic build-mode run would still not prove native Codex safety.

The unchanged `cfa2eba` fixtures ran once on a Linux test host on 2026-10-14:
Linux `7.0.0-1013-oracle`, aarch64, Node 24.18.0, Python 3.12.3, UID/EUID
1001, effective/permitted capabilities zero, Yama `ptrace_scope=1`, ordinary
procfs mount and a local ext-family temporary filesystem. Both requested
dumpable values were verified by the holder. Collection exited 0, with no
failures or incomplete observations. Both holders exited 0 and their recorded
process instances were absent at the post-check. Raw result SHA-256 and scope
are recorded in [evidence.md](evidence.md).

Source-derived matrix below was observed on that test host:

| Read | dumpable=1 | dumpable=0 |
| --- | --- | --- |
| `stat /proc/PID` uid | owner | owner (the 0555 directory is exempt in `task_dump_owner`) |
| `/proc/PID/fd` directory uid | owner | root |
| `/proc/PID/fdinfo` directory uid | owner | owner (0555 directory exception) |
| `fd` listdir/readlink/stat, `fdinfo` open, `exe` readlink | allowed | EACCES |
| `cmdline` | allowed | allowed (no ptrace check) |
| `stat` start ticks and status UID | allowed | allowed |

The original combined fd/fdinfo ownership prediction was incorrect. Pinned
[Linux v6.17 directory definitions](https://github.com/torvalds/linux/blob/e5f0a698b34ed76002dc5cff3804a61c80233a7a/fs/proc/base.c#L3316)
give `fd` mode 0500 and `fdinfo` mode 0555. The
[dumpability ownership exception](https://github.com/torvalds/linux/blob/e5f0a698b34ed76002dc5cff3804a61c80233a7a/fs/proc/base.c#L1906)
therefore leaves fdinfo's UID unchanged. Its directory/file access still uses
a separate [ptrace permission check](https://github.com/torvalds/linux/blob/e5f0a698b34ed76002dc5cff3804a61c80233a7a/fs/proc/fd.c#L81).
Ownership alone does not establish readability. This result provides no
evidence of kernel-version drift.

The denial supports the source-derived expectation that #137 should refuse
FD discovery for this candidate. F2 did not execute #137 or validate its
classification, candidate recognition, or final signal boundary. This Python
fixture does not measure a deployed native Codex process's dumpability.

Hardening callers, within a targeted search of pinned v0.162.1 source:
`pre_main_hardening` appears in the `codex-responses-api-proxy` and
`codex-voice-host` mains, and `disable_process_dumping` appears in the
linux-sandbox proxy bridge. No direct call was found in the `codex` CLI
main. **That does not establish that a lock-owning process is dumpable.** The
same `codex` binary dispatches to linux-sandbox code by arg0. The kernel
also resets dumpable on credential changes and on exec of an unreadable
image. Packaging or wrappers may differ from source. Real Codex's dumpable
state needs a real binary and is not claimed.

### F2 isolated inspection (`F2_BUILD`), prepared, not yet run on Linux

`F2_BUILD=<build.mjs output>` enables product inspection in a **separate
child** (`inspect-child.mjs`, run through `lib/isolated-observer.mjs`). The
runner never imports a product module. Layers:

| File | Role |
| --- | --- |
| `lib/isolated-observer.mjs` | generic: handshake, two bounds, byte-limited stdout/stderr, stage-record protocol, per-instance late exits |
| `protocol.mjs` | F2: exact stage order and uniqueness, result/error shapes, `F2_CHILD_FAULT` allowlist |
| `build.mjs` | trusted build input and its verification, import-graph check |
| `inspect-child.mjs` | product calls, one stage each |
| `expectations.mjs` | expected table, kept apart from collection |
| `plumbing-smoke.mjs` | cross-platform wiring check; not an F2 result |

**Stages**, exactly once each, in this order: `dist_identity` (re-hash the
build against its manifest; stop before import on mismatch), `module_load`
(static and literal dynamic relative import graph of the imported modules
must not reach `unlock.js`, then import), `openers` (product `lsof` discovery
and `inspectProcess`), `prepare` (`prepareLinuxParticipation`),
`guarded_verify` (`guardedProbeOnce` with `verifyLinuxParticipation`) and
`inspect_thread` (`inspectThread`, policy blockers). Only `prepare` may end in
an error that counts as a product outcome. An error in any other stage, a
malformed result, a missing, duplicate or out-of-order stage, or an `end`
with both or neither of `result`/`error` is a collection fault.
`guarded_verify` returns `{ skipped: 'prepare_failed' }` after a failed
`prepare`. That is harness bookkeeping, not a product refusal.

The relative import walk parses JavaScript with the checkout's existing
TypeScript development dependency, so comments between import tokens and
escaped string literals do not hide an edge. Parse errors fail the walk. Run
`npm ci` in the research checkout before using the builder or inspector;
copying only the research scripts is not sufficient for this revision.
Nonliteral dynamic imports, `require` and `eval` are outside this targeted
walk, not proof of a complete execution graph. Historical measurements used
their recorded earlier parser and source hashes.

**Build identity.** `build.mjs --repo R --commit C [--patch P] --out O`
resolves the commit and tree with `git rev-parse` in the named local
repository and builds from that repository's `git archive`. It records the
archive, lockfile and patch SHA-256, then runs `npm ci` and `npm run build`.
It also records a sorted manifest of `dist/` files and of the native addons
(`*.node`) under `node_modules`. `run.mjs` and `inspect-child.mjs` each re-hash
that content against the manifest before use. Each child must also match the
runner's startup manifest SHA-256; a different internally consistent build
cannot be attributed to the original input. This verifies only the recorded
`dist/` and native-addon bytes; dependency JavaScript and package metadata are
not covered. It does not prove that the local
repository matches upstream. A commit string supplied by anyone else is
never used as provenance. A deployed native Codex binary is unrelated and
remains unverified.

The build helper uses bounded synchronous subprocesses for Git and npm. Their
timeout/output-limit handling can send a termination signal to those build
subprocesses; the inspector's no-owner-signal contract is not a claim that
building or collecting diagnostic output is signal-free.

**Lifecycle**, as designed and locally tested:

- The child writes a `hello` line first. The startup bound (10 s) runs until
  that line. The stage bound (15 s) starts only then, so child startup
  latency does not consume the stage budget. Exceeding either bound returns
  `incomplete` with its phase and the open stage.
- stdout (1 MiB) and stderr (64 KiB) are capped by bytes per chunk. Bytes past
  the cap are dropped and recorded as a fault, as is an unterminated last line.
  The Python observer's output is capped (256 KiB) and parsed only after its
  stdout closes.
- No cancellation guarantee. The parent sends no signal. It closes stdin,
  destroys the pipes and unrefs the child. The child has **no lifetime timer**:
  it checks its 30 s deadline and stdin EOF only between stages. It then writes
  a `stop` record, sets exit code 3 (lifetime) or 4 (parent gone) and lets
  pending work drain instead of calling `process.exit`. A refused build or
  import exits 5. A child stuck in a syscall, or awaiting work that never
  settles, can outlive the runner. Late exits are looked for with a 2 s bound
  and recorded per instance as `exited` or `unconfirmed`.
- Signals: the child sends no signal to the holder, a lock owner or any
  unlock path. Product diagnostics it calls (`lsof`, `ps`) run with the
  product's own timeout. That timeout sends SIGTERM and then SIGKILL to the
  timed-out diagnostic's own process group.

**Same instance.** The runner reads the holder's `/proc/PID/stat` start ticks
itself at readiness, after observation and after inspection. A changed or
missing instance, or a holder exit at any point before inspection ends,
invalidates the run. The holder's lifetime is 60 s
(`FIXTURE_LIFETIME_SECONDS`). Before inspection, the runner checks that the
remaining lifetime covers observer + startup + stage bounds + 5 s. Opener,
`prepare`, participation and inspection ticks are compared with the runner's
sample as decimal strings.

**Expected table.** A mismatch is recorded, never repaired by policy:

| dumpable | Row | Expected |
| --- | --- | --- |
| both | V | one opener, the holder's PID, no opener error |
| 1 | E1 | opener identity complete, no opener errors, start ticks equal to the runner's sample |
| 1 | E2 | `prepare` PID and ticks equal, holder FD listed and kept as a candidate |
| 1 | E3 | guarded probe `held`, guard `acquired`, participation PID, FD and ticks equal |
| 1 | E4 | `inspectThread` probe `held` with the same participation; owner PID and ticks equal; no `linux_participation_unproven` |
| 0 | R1 | `prepare` fails with `EACCES` or `EPERM`. `ENOENT`, `TypeError`, the product budget error or a build error fail this row |
| 0 | R2 | `safeToUnlock=false`, blockers include `linux_participation_unproven`, no participation |

R2 is a contract choice tied to source: #137 `b483cd5`
`evaluateSafety` adds that blocker when owner start ticks or a matching
participation are absent. R2 requires that blocker but allows additional
blockers; passing R2 does not establish that participation was the sole cause
of refusal. A refusal without that blocker fails R2 as "refused, not
attributed". V fails if
`lsof` does not show the non-dumpable owner. A dumpable=0 result counts only
if the same report's dumpable=1 control passed (`evaluateReport`). The
following are recorded and never asserted: `firstObservedError`,
`guardedAttempted`, participation, final eligibility (`safeToUnlock`,
blockers), owner/probe details and `fixtureIsCodex`. The fixture is `python3 …/codex`, and the
product's `isCodex` regex can match that path. That says nothing about a
native Codex binary. No allowlist or policy is changed to make it pass.

**Local evidence** (macOS 27.0.1, Node v24.16.0, not Linux). Tests:
`lib/isolated-observer.test.mjs` (13), `f2-linux-nondumpable/expectations.test.mjs`
(10: protocol order/duplicates/shapes, fault allowlist, forged ticks, changed
instance, ENOENT/TypeError/budget not counted, unrelated refusal, hidden owner,
missing control, malformed payloads and coexisting blockers),
`f2-linux-nondumpable/build.test.mjs` (4). Together with the existing common/M2
tests, all 38 focused tests passed without skips after integration. The generic tests
cover a 3 s synchronous stall after the handshake under a 300 ms stage bound,
a stall before the handshake (startup timeout), late exit 4, per-instance
unconfirmed exits, 2 MiB without a newline under a 64 KiB cap, a byte-capped
multibyte stderr, a split multibyte line, and a lifetime that does not
interrupt an async stage.

`plumbing-smoke.mjs` ran against two `build.mjs` builds of `b483cd5`
(unpatched, and with `f4-guard-scope/guard-scope.patch`). It used a
same-user Python flock holder on APFS, not the Linux `codex` fixture. Both
runs passed. Nominal reported all six stages in order with no observer or
protocol faults. `prepare` failed with ENOENT on `/proc`, a macOS artifact.
`stall:prepare` returned `incomplete` at the stage bound with open stage
`prepare`, and the stalled child later exited with code 4 on its own.
`run.mjs` itself refuses non-Linux hosts and was not run on macOS. **None of this is a
Linux result.**

**Linux isolated measurement, 2026-10-16.** On the approved unprivileged
Linux 7.0.0-1013-oracle aarch64 host (Node 24.18.0), the unpatched
`b483cd587c62329243366e64aaaac477edd36adc` build completed all stages for both
dumpability values. Collection passed, but the expected table failed and the
runner exited 1. `lsof` reported inaccessible overlay/nsfs mounts and warned
that information could be incomplete. The Python fixture also failed the
product's executable/argument verification. The dumpable=1 direct prepare and
guarded participation rows E2/E3 passed, but V/E1/E4 failed. At dumpable=0,
prepare returned EACCES and inspection refused with the participation blocker
(R1/R2 passed), but V failed and there was no passing positive control.
Consequently **no refusal success is counted**. This does not validate a native
Codex candidate or clear either #137 gate. Warnings were not suppressed and no
allowlist or policy was relaxed.

A second, `stall:prepare` run exited 1 and recorded both inspectors as
incomplete at the stage bound with open stage `prepare`. Both later exited 4
without a signal; holders exited 0. This validates the parent observation bound
for an injected finite stall, not cancellation or a real kernel hang. Raw
hashes and build identity are in [evidence.md](evidence.md#isolated-f2-linux-measurement-2026-10-16).

Reproduction commands (a mismatch must remain nonzero):

```sh
node experimental/126-guard-liveness/f2-linux-nondumpable/build.mjs \
  --repo <local codex-unlock clone> --commit b483cd587c62329243366e64aaaac477edd36adc --out "$BUILD"
F2_BUILD="$BUILD" node experimental/126-guard-liveness/f2-linux-nondumpable/run.mjs
F2_BUILD="$BUILD" F2_CHILD_FAULT=stall:prepare node experimental/126-guard-liveness/f2-linux-nondumpable/run.mjs  # must exit nonzero, incomplete 1+
```

## #126 acceptance matrix (status at this revision)

`done` means implemented with a real-lock test that runs somewhere in CI or
locally. `partial` means implemented without the required execution or with
a documented residual. `open` means not addressed.

| #126 criterion / case | Status | Evidence | Missing |
| --- | --- | --- | --- |
| Reviewed contract against pinned Codex source and measured cases | partial | #137 `docs/linux-lock-attribution.md` | final review; native Codex dumpability |
| Bounded enumeration, size, time | partial | 256 FDs, 64 KiB, 25 ms checked between calls | no hard syscall deadline (F3, F4) |
| Only held exclusive whole-file FLOCK counts | done | `parseFlockRows` rejects POSIX/OFDLCK/LEASE/`->`/READ; v6.17 `show_fd_locks` lists granted entries | — |
| Acquisition PID not required to match | done | inherited-FD real-lock test (Linux CI) | — |
| Denied evidence (non-dumpable) | partial | access matrix and isolated run measured (F2); R1/R2 observed; simulated fdinfo denial in `signal-evidence.test.mjs` | passing native-candidate control; current isolated expected table failed |
| Malformed/truncated proc records | partial | parser unit tests; 64 KiB overflow throws | no real truncated-proc fixture |
| PID/start-time change | partial | start ticks in prepare and guard; forged-ticks unit tests | PID-reuse window at `kill` (no pidfd) |
| Namespace mismatch | partial | `/proc/self` and mount ns checks, unit test; observer now records ns readlinks | no real foreign-namespace fixture |
| FD replacement / inode replacement | partial | replacement-inode guard test, descriptor-list change test | real FD-reuse race fixture; fdinfo `show_fdinfo` wait on a reused FD (F4) |
| Budget exceeded | partial | `filterCandidateDescriptors` budget unit test | no real slow-proc fixture (cannot be induced safely) |
| Inherited-description ambiguity defined | open | docs say participation ≠ sole control | eligibility and release-verification rule for shared descriptions |
| Final boundary: no await/spawn, guard not held across signal | partial | #137 structure | F4's 25 ms check covers only its confirm step, not evidence age or release-to-signal; not applied |
| Refusals send zero SIGTERM | done | nonlocking-candidate and fdinfo-denial tests count signals | — |
| JSON/exit compatibility | partial | additive optional v1 fields with schema | reviewer confirmation |
| Guard liveness (#137 gate 2) | partial | F4 proposal removes cmdline/exe and stat via FD from the guard (not applied) | fdinfo `show_fdinfo` and lock filesystem waits remain; Linux run |
| Native access (#137 gate 1) | open | F2 access matrix and isolated synthetic run; expected table failed | native binary dumpability and passing candidate control not measured |

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
  await before the signal) removes that cmdline coordination-stall path. It does not make
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
node --test experimental/126-guard-liveness/lib/*.test.mjs experimental/126-guard-liveness/m2-macos-fwaslocked/*.test.mjs \
  experimental/126-guard-liveness/f2-linux-nondumpable/*.test.mjs
node experimental/126-guard-liveness/f1-guard-delay/run.mjs
node experimental/126-guard-liveness/m2-macos-fwaslocked/run.mjs
```

## Evidence and review revisions

### Research-only pre-merge review hardening

The post-`e700770` revision closes three validation gaps without changing
production code or claiming a new measurement:

- F1 accepts only an absent/empty `F1_FAULT`, `skip_round` or
  `waiter_lifetime`. A typo, padded name or other value is rejected before
  importing product code, creating scratch or starting a waiter.
- Access-matrix collection now checks the observer's PID, FD, UID, kernel and
  all thirteen typed access outcomes, plus successful start ticks against the
  runner's instance sample. Empty/partial/malformed JSON cannot count as
  collection. Explicit errno outcomes, empty observed lists or false file
  comparisons are collected observations, not successful permission/owner
  hypotheses. Collection and expectation satisfaction remain separate.
- The research builder rejects unknown, duplicate, positional, valueless and
  blank CLI arguments before inspecting a repository or creating output.
  `--patch` stays optional, but once present must have a nonempty value.

The 49 focused tests passed on macOS (no skips), including parser/collection
counterexamples. `npm ci`, type-check, lint, the existing repository suite
(263 pass, three Linux-only skips), package smoke and whitespace checks also
passed. This revision was not run on the US host or with native Codex; all
earlier measurements below retain their original source identities.

The subsequent current-head review also tightened two runner verdicts. An M2
part-2 scenario without usable owner/filter evidence now fails the run instead
of merely recording an unavailable measurement. The nominal F2 plumbing smoke
now rejects every protocol/stage fault, including later malformed payloads and
stage errors outside the explicitly allowed `prepare` outcome. These changes
passed 56 focused tests on macOS without skips and the same five repository
checks (263 passing tests, three Linux-only skips). Only deterministic verdict
tests were added; F1/M2 nominal measurements, Linux runs and native Codex were
not rerun for these corrections.

A further review round replaced the literal-import regex with a comment-aware
JavaScript parser, validated nested inspection probes, and bound every child
build digest to the parent's startup manifest. M2 now refuses non-macOS hosts,
rejects failed/noisy wrapped diagnostics, and compares every Part 2 scenario
against the fixed recorded expectations. F2 access-only and build-mode exit
contracts are documented separately above. All 71 focused tests passed on
macOS without skips; the five repository checks passed (266 passing tests,
three Linux-only skips). These checks alone do not reproduce the nominal
experiments or establish native Codex safety.

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
checked by the integrating Codex. At `e5cf6dd`, the focused tests and one
F1/M2 nominal run each plus the five documented faults were executed; all
seven runner exit statuses and failure/incomplete records matched expectations.
The cooperating session also reviewed that revision read-only. The CLI reviews
do not certify later commits. F2's access matrix is now measured on one Linux
host; product integration and adoption remain unresolved. Barrier contention can invalidate a nominal scenario
and produce a nonzero result; successful runs do not establish a failure rate.
Cleanup can report both an earlier incomplete wait and a later nonzero exit
for the same child. These are observations, not counts of distinct processes.
