# Attribution interleaving experiment (research, #100)

Reproduces, with synthetic processes, an interleaving in which every current
`inspectThread` eligibility check passes while the selected owner is **not**
the process holding the OS lock. It is research only: no runtime behavior,
platform support, or JSON contract changes, and the experiment never calls
`unlockInspectedThread`, so no signal is ever sent to a wrong target.

## What it adds over the existing research

`docs/research-lock-attribution.md` (PR #125) measured clean lsof omission of
a foreign-UID holder and of a holder outside the observer's PID namespace on
both Linux and macOS, and concluded:

> No real Codex execution satisfying every eligibility check and producing a
> wrong-target signal has been reproduced.

Those CI fixtures used Python holders and openers, so `lock_owner_is_not_codex`
blocked recovery regardless of attribution. The gap left open was whether the
measured omission condition, combined with a visible opener that *does* look
like Codex, actually clears every gate. This experiment closes that gap.

## Fixtures

| Path | Role |
| --- | --- |
| `holder/codex` | Acquires the thread flock under the coordination lock, like Codex v0.162.1, and holds it until stdin EOF. Named `codex` so lsof reports a Codex command. |
| `codex` | Transient non-holder. Models the descriptor lifetime of a **failed** `WriterLockCoordinator::acquire`: takes coordination, opens the thread file, fails `flock(LOCK_EX|LOCK_NB)`, and drops the thread file before coordination. It never holds the thread lock. Driven over a Unix socket. It takes coordination **non-blocking** and reports `busy` on contention: real Codex blocks there, but a blocking wait here deadlocks against codex-unlock's own guarded probe. |
| `lsof-barrier.mjs` | Wrapper around the real `/usr/sbin/lsof`. Before each scan it asks the transient to enter its open window and releases it afterwards, so an independently timed scan observes the transient as an opener. With `hidePid` it removes that PID's process sets from the `-F0` output, modelling the measured clean omission (exit 0, empty stderr). |
| `orchestrator.mjs` | Creates a private scratch home per scenario, runs `inspectThread`, and records results. |

The barrier is injected only through codex-unlock's in-process diagnostic
override seam, never through `PATH` or as a system lsof replacement.
`runCommand` replaces the diagnostic environment, so the override target is a
generated shell wrapper with absolute paths that injects a config file path.

## Scenarios and measured results

Darwin 27.0.1 arm64, Node v24.16.0, lsof 4.91, APFS, same user, main `a7f7e87`.
Raw records: `results.json` and `events.jsonl` in the run's scratch directory.

| Scenario | Setup | Measured |
| --- | --- | --- |
| A (control) | Real holder only, no barrier, no omission | `live_owner`, `safeToUnlock: true`, 1 opener, owner **is** the holder, no blockers |
| B | Real holder hidden from lsof; transient visible inside its open window | **`live_owner`, `safeToUnlock: true`, no blockers, owner is the transient non-holder (pid 9036) while the actual holder is pid 9034** |
| C | Barrier, no omission | `unknown`, `safeToUnlock: false`, blockers `lock_probe_unknown`, `lock_file_not_stable`, `lock_owner_identity_not_stable` |

Scenario B is the finding: with the holder omitted, a Codex-looking
non-holding opener satisfies the unique-opener, identity-complete,
identity-stable, `isCodex`, same-uid, single-thread-lock-set, and
`task_complete` transcript checks, while the guarded probe correctly reports
`held` because the hidden holder really holds the lock. The classification
therefore attributes the lock to a process that does not hold it.

The mechanism is the sample boundary, not a faulty probe. `inspectThread`
runs `inspectLockOpeners` **outside** the native guard and the probe
**inside** it (`Promise.all` in `inspection.ts`), while every Codex path that
opens a thread file does so **inside** coordination
(`writer_lock.rs` L44/L95/L176). So the probe can correctly observe "someone
holds this" at one instant and the scan can correctly observe "only this
non-holder has it open" at another. Each observation is accurate; combining
them as if they were one atomic sample is what produces the wrong owner.

Scenario C refuses for a different reason than first expected. Rather than
"two openers", the transient's coordination attempt makes codex-unlock's own
guarded probe return busy/unknown, so `lock_probe_unknown` and the stability
checks block recovery before attribution is even considered. That is the
intended fail-closed behavior for a contended coordinator, and it shows the
refusal does not depend on seeing both processes.

`eligible_wrong_target` is recorded instead of calling unlock. The
experiment deliberately stops before the signal boundary.

Reproducibility: scenario B produced `eligible_wrong_target` in 4 of 4
consecutive runs after the socket-per-scenario and non-blocking-coordination
fixes, with no `incomplete` child.

## Limits

- The lsof omission is injected, not naturally occurring. It models the
  omission already measured in CI run 37862990217; it is not a new
  demonstration that macOS or Linux will omit a given real holder.
- Holder and transient are synthetic Node scripts named `codex`, not real
  Codex sessions. No Codex process was run or signaled.
- Timing-dependent on one platform. Four consecutive reproductions are not a
  probability estimate, and nothing here bounds how often the condition would
  arise with real Codex.
- Two earlier fixture defects were fixed and are worth recording, because both
  masked the result rather than causing it: the scenarios shared one Unix
  socket path, so the second transient failed `listen` with `EADDRINUSE` and
  never reported ready; and the transient took coordination with a blocking
  flock, which deadlocked against the guarded probe whenever a barrier request
  timed out with no `finish`. Neither affected scenario B's finding, which
  reproduced before and after the fixes.

## Run

```sh
npm ci && npm run build
node scripts/fixtures/attribution-interleaving/orchestrator.mjs
```

Scratch homes are created under `TMPDIR` with mode 0700 and removed by the
caller. Children exit on stdin EOF; the orchestrator never sends a signal.
