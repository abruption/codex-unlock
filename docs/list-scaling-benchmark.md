# Bounded list scaling benchmark

This records #102's measurement gate, not a scan-sharing or cache change.
`listThreads` still runs at most four inspections concurrently, makes independent
before/after transcript observations, and returns thread IDs in sorted order.
Failures never become partial successful lists.

## Reproduce

```sh
npm ci
node scripts/benchmark-list.mjs --quick
node scripts/benchmark-list.mjs
```

Use a private, writable temporary root through `TMPDIR` if required by local
workspace policy. The harness creates and removes only its own synthetic home.
It never inspects real Codex homes or signals processes. Quick mode has a 15-second
overall budget; standard mode has a 60-second budget. Each case runs three fresh
Node processes and reports every result plus median/minimum/maximum elapsed time.
Fixture construction, hashing, and worker startup are outside the timed list call.

The controlled variables are independent listed locks **N** and transcript files
**T**, sparse matches across sessions/archived_sessions, depth 0/4, 128-byte/64-KiB
transcripts, real system diagnostics versus fixed `/usr/bin/true` diagnostic
children, and the unmodified default 1000-ms stability window versus an internal
zero-window control. Native coordination and thread flock probes remain real in
both diagnostic modes. The zero window is not a public CLI flag or recommendation.

Each worker asserts complete ordered results, stable independent observations,
four-worker bounds, and released directory handles/diagnostic children. A traversal
failure rejects the entire list (`command_failed`, exit 3), rather than returning
partial success. A missing coordinator produces ordered `unknown` sessions with
`safeToUnlock: false`, without creating a coordinator. Content hashes, inode, UID,
mode, size, and mtime are unchanged after measurement; atime is excluded.

## Initial macOS observation

Darwin arm64, Node 24.16.0, three runs per case, standard suite 7.123 seconds.
Values below are medians from the first completed local standard run, not speed
guarantees. Baseline uses N=4, T=512, depth 0, 128 bytes, zero stability window,
and fixed `/usr/bin/true` diagnostics; each other row changes only one variable.

| Change from baseline | Median elapsed ms |
| --- | ---: |
| Baseline | 19.076 |
| N=16 | 50.639 |
| N=32 | 83.870 |
| T=64 | 12.309 |
| T=2048 | 33.334 |
| Depth=4 | 21.105 |
| Transcript=64 KiB | 18.844 |
| Actual ps/lsof | 316.902 |
| Default 1000-ms stability window | 1020.533 |

Flat fixtures visit `2*N*T` transcript entries and make `4*N` root traversals:
two transcript roots, before and after, per thread. The deepest fixture additionally
visits 64 directory entries at N=4. Peak open directory handles were 8 flat and
40 at depth four, consistent with four workers, two roots per worker, and recursive
directory depth. Maximum measured Node RSS was 69,840 KiB. Baseline spawns 12
`true` children; actual diagnostics spawn eight lsof and four ps children, so the
comparison removes process-table work but is not an equal-command-count experiment.

The fixture is hashed before timing; OS caches are not flushed. Labels distinguish
the first fresh-process run from subsequent fresh-process warm-fixture runs, **not**
cold versus warm OS caches. Linux reports sampled `/proc/self/fd` counts (including
the sampling descriptor, possibly missing short peaks); macOS reports tracked
directory handles, not all FDs. CPU/RSS exclude spawned diagnostic programs.

## Decision and follow-up

Keep the current bounded implementation and fresh observations for now. These
small fixtures establish that repeated discovery grows with N and T, but the
default stability wait and real diagnostics materially affect latency. They do
not justify a persistent/stale cache or weakening transcript checks.

Before adopting shared discovery, separately measure larger realistic N/T and
define how independent pre/post observations detect additions, removals, directory
replacement, duplicate transcripts, and scan failures. A per-call index would
need the same refusal behavior and error drainage under a low descriptor limit.
Compare identical diagnostics/windows and resource accounting against this
baseline. No runtime optimization or caching is introduced by this PR.
