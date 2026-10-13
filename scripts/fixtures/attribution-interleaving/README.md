# Synthetic inspection attribution research (#100)

This unpublished fixture uses real macOS flock and synthetic Node processes.
It calls `inspectThread` only, never unlock or process signaling. It changes no
production eligibility, JSON contract, supported-platform claim or npm artifact.

## Question and evidence boundary

Can a held guarded probe and independently timed opener scans identify a
nonholder as eligible when the actual holder is absent from diagnostic output?
The barrier extends a synthetic failed-acquisition opener's descriptor window,
and a test-only diagnostic override filters the actual holder PID out of real
system lsof output. Omission is **injected**, not naturally reproduced here.

The synthetic processes run as `node <fixture>/codex`; their executable basename
alone does not make their OS command name `codex`. Recognition is by the CLI's
existing process-evidence rules. They are not actual Codex executables.

The original `d5f3cb2` run recorded:

| Scenario | Observation |
| --- | --- |
| A: holder visible | `live_owner`, `safeToUnlock=true`, selected owner is holder |
| B: holder filtered, transient scan window | `live_owner`, `safeToUnlock=true`, selected owner is a different, nonholding transient |
| C: scan window, no omission | `unknown`, `safeToUnlock=false`; coordinator contention blocked attribution |

The result/event hashes are recorded in
[the attribution research document](../../../docs/research-lock-attribution.md).
Four consecutive reproductions were reported by the producer; the independent
review checked the supplied final result/event files, not four raw runs.
Earlier harness readiness, finalization and integrity checks were deficient.
Those historical records do not establish the amended harness's safety checks.

This is an **inspection-stage counterexample**, not proof of a final
signal-boundary failure, actual Codex trigger, or real-world occurrence rate.
No signal was sent. `safeToUnlock=true` is a measured product decision in the
fixture, not authorization to recover a real session.

## Components

- `holder/codex`: holds the thread lock until stdin EOF.
- `codex`: coordinated transient nonholder, with bounded open windows and
  cooperative EOF cleanup. A successful thread-lock acquisition invalidates
  the nonholder hypothesis.
- `lsof-barrier.mjs`: system-lsof scan and explicit process-set filtering.
- `orchestrator.mjs`: private per-scenario synthetic homes, bounded child
  readiness/cleanup, actual used-file snapshots and source/build provenance.

The transient uses nonblocking coordination rather than Codex's blocking
coordination so the research barrier cannot deliberately deadlock the probe.
This is a modeling difference, not a production implementation proposal.

## Run and interpret

Build from a known clean revision with `npm ci` and `npm run build` first.
Set `TMPDIR` to an existing writable private temporary root appropriate for
the machine. Keep it short enough for Unix socket paths. Then run:

```sh
node scripts/fixtures/attribution-interleaving/orchestrator.mjs
```

The runner preserves its own scratch/results for inspection. It never deletes
native user files or discovers a real Codex home. After verifying all fixture
children exited, the caller may remove only that recorded scratch directory.
Do not publish raw paths, environment identifiers or process records without
review and redaction. Time budgets constrain asynchronous waits, not synchronous
filesystem I/O or a hard OS-wide runtime limit.

Research findings do not close #100. Linux descriptor-level participation and
macOS holder/visibility decisions remain tracked in #126 and #127. Rust is not
an automatic solution to holder attribution.
