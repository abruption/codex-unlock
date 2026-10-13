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
| `codex` | Transient non-holder. Models the descriptor lifetime of a **failed** `WriterLockCoordinator::acquire`: takes coordination, opens the thread file, fails `flock(LOCK_EX|LOCK_NB)`, and drops the thread file before coordination. It never holds the thread lock. Driven over a Unix socket. |
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
| B | Real holder hidden from lsof; transient visible inside its open window | **`live_owner`, `safeToUnlock: true`, no blockers, owner is the transient non-holder (pid 90798) while the actual holder is pid 90797** |
| C | Both visible | `unknown`, `safeToUnlock: false`, 2 openers |

Scenario B is the finding: with the holder omitted, a Codex-looking
non-holding opener satisfies the unique-opener, identity-complete,
identity-stable, `isCodex`, same-uid, single-thread-lock-set, and
`task_complete` transcript checks, while the guarded probe correctly reports
`held` because the hidden holder really holds the lock. The classification
therefore attributes the lock to a process that does not hold it.

`eligible_wrong_target` is recorded instead of calling unlock. The
experiment deliberately stops before the signal boundary.

## Limits

- The lsof omission is injected, not naturally occurring. It models the
  omission already measured in CI run 37862990217; it is not a new
  demonstration that macOS or Linux will omit a given real holder.
- Holder and transient are synthetic Node scripts named `codex`, not real
  Codex sessions. No Codex process was run or signaled.
- Scenario C reported `lock_file_not_stable` and `lock_probe_unknown`, and its
  transient did not exit within budget (`incomplete`, pid recorded, never
  killed by the script). Cause: this transient takes coordination with a
  **blocking** flock, so when codex-unlock's guarded probe holds coordination
  first the transient waits, and a barrier request that times out leaves it
  holding coordination with no `finish`. That is a fixture artifact — real
  Codex releases coordination when `acquire` returns — but it shows the two
  coordination users do contend.
- Single run on one platform. Timing-dependent; not a probability estimate.

## Run

```sh
npm ci && npm run build
node scripts/fixtures/attribution-interleaving/orchestrator.mjs
```

Scratch homes are created under `TMPDIR` with mode 0700 and removed by the
caller. Children exit on stdin EOF; the orchestrator never sends a signal.
