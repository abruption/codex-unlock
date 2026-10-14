# Lock holder attribution research

Issue #100 investigates an attribution assumption, separate from whether a
native lock is held. The guarded flock probe remains the held/free authority.
`lsof -nP -F0pcu -- <lock>` returns openers, not a proof that a selected process
owns the lock. Current `live_owner` classification correlates a held probe with
one stable, identity-complete visible opener. This research does not assert
that actual Codex retains descriptors after a failed acquisition.

## Reproduction and scope

```sh
npm ci
python3 scripts/research-lock-attribution.py --self-test
python3 scripts/research-lock-attribution.py --cli dist/cli.js
```

Use `TMPDIR` to select an appropriate scratch root. The script creates a private
0700 home, a synthetic rollout, and native fixture files. Children close their
descriptors on stdin EOF or after ten seconds. It sends no process signals and
verifies that fixture file content, mode, mtime, UID, and inode remain unchanged;
the final guarded probe must be free. It records OS/Python/lsof versions, lsof
exit status/stdout/stderr, actual guarded flock observations, Linux inode-matched
`/proc/locks` rows, and candidate descriptor-level fdinfo records.

`--privileged-fixtures` explicitly opts into existing noninteractive sudo
rights, as used on isolated CI runners. One helper opens only the fixture FDs
as root, drops to the existing `nobody` account, and then holds the flock. The
observer remains the ordinary runner user. Linux also starts an observer with
a nonlocking FD in a new private mount/PID namespace; a host holder remains
outside that namespace. The script creates no users, changes no host mounts or
procfs settings, and never touches a user Codex home. Unsupported privilege or
namespace cases are reported as skipped, not measured negatives. A timeout or
fixture failure is an error, not evidence that visibility was complete.

## Evidence matrix

Local baseline on 2026-10-09: Darwin 27.0.0 arm64, Python 3.14.8, libproc-based
lsof 4.91. No foreign-UID or namespace claim is derived from this run.

| Case | Guarded probe | Visible lsof processes | Interpretation |
| --- | --- | --- | --- |
| Same-user holder | Held | One holder | Positive ordinary correlation |
| Same-user holder + independently opened, nonlocking FD | Held | Both processes | Opener presence alone is not lock ownership; CLI inspect is unknown and not safe to unlock |
| Original acquirer exits; forked child retains the same description | Held | Only the child | Lock lifetime is shared-description lifetime, not original-acquirer process lifetime |
| All fixture descriptions closed | Free | No holder | Fixture cleanup actually releases the OS lock |

### Dedicated CI measurements

The following observations were read directly from the completed research-job
logs in [run 37862990217](https://github.com/abruption/codex-unlock/actions/runs/37862990217).
Both jobs succeeded on 2026-10-09, using
`python3 scripts/research-lock-attribution.py --cli dist/cli.js --privileged-fixtures`.
These measurements use synthetic Python processes, not Codex sessions.

| Environment | Measured versions | Research job |
| --- | --- | --- |
| Linux x86_64 | Kernel 6.17.0-1022-azure; Python 3.12.3; lsof 4.95.0 | [113602930943](https://github.com/abruption/codex-unlock/actions/runs/37862990217/job/113602930943) |
| Darwin arm64 | Kernel 24.6.0; Python 3.14.7; libproc-based lsof 4.91 | [113602930913](https://github.com/abruption/codex-unlock/actions/runs/37862990217/job/113602930913) |

| Case | Linux observation | macOS observation |
| --- | --- | --- |
| Same-user holder | Guarded probe held; lsof exit 0, empty stderr, holder visible; candidate fdinfo has a matching FLOCK row | Guarded probe held; lsof exit 0, empty stderr, holder visible; optional `l` field blank |
| Same-user holder + nonlocking opener | Both visible; holder fdinfo has FLOCK evidence, nonholder fdinfo does not; CLI inspect returns unknown and `safeToUnlock: false` | Both visible; CLI inspect returns unknown and `safeToUnlock: false`; optional `l` field blank for both |
| Original acquirer exits; inherited descriptor retained | Original PID 2531 exited with status 0; sole visible child PID 2532 retains the held lock; global row still records PID 2531; child fdinfo positively matches that FLOCK | Original PID 3815 exited with status 0; sole visible child PID 3821 retains the held lock; optional `l` field blank |
| Foreign-UID holder + same-user nonlocking opener | Probe held; lsof exit 0 and empty stderr; **only the nonholder** PID 2539 is visible. Holder PID 2538/UID 65534 is inaccessible through procfs; visible nonholder fdinfo has no lock row | Probe held; lsof exit 0 and empty stderr; **only the nonholder** PID 3845 is visible. Holder PID 3838/UID 4294967294 is omitted; optional `l` field blank |
| Host holder outside observer PID namespace | Probe held; `/proc/locks` contains no matching row; lsof exit 0, empty stderr, and only observer PID 1 with its nonlocking FD; observer fdinfo has no lock row | Skipped explicitly: Linux-only namespace fixture |
| All fixture descriptions closed | Final guarded probe free; fixture content, mode, mtime, UID, and inode unchanged; no signals sent | Final guarded probe free; same file-invariance checks; no signals sent |

The PIDs above are the recorded synthetic fixture identifiers, not production
process identities. The Linux namespace observer intentionally runs as root
inside its private namespace; that row demonstrates namespace visibility rather
than same-user Codex eligibility. Its FD scan also records a transient
`FileNotFoundError` on another descriptor; the matching nonlocking FD was read
and had no lock row.

The foreign-UID rows on both platforms directly disprove the general assertion
that a held guarded probe, one visible opener, exit zero, and empty lsof stderr
establish holder identity. The synthetic nonholders are Python processes, so
these rows do not reproduce a `live_owner` Codex classification or a wrong-target
Codex signal. They demonstrate an OS visibility condition that the current
opener-correlation rule cannot distinguish using those observations alone.

The optional lsof `l` field was blank for the macOS real synthetic holder and
for Linux's surviving inherited holder. Requiring that field universally would
refuse these measured holders without establishing a portable holder primitive.
The Linux positive descriptor-level evidence distinguishes the nonholder in
the foreign-UID fixture even though both the guarded probe and lsof exit status
look normal. None of these results establish complete process visibility,
sole ownership of a shared description, or behavior on unmeasured platforms.

## Source evidence and limits

- [flock(2)](https://man7.org/linux/man-pages/man2/flock.2.html) associates locks
  with open file descriptions, shared by dup/fork, until the last corresponding
  descriptor closes. Separate opens of the same inode do not share that lock.
- [proc_locks(5)](https://man7.org/linux/man-pages/man5/proc_locks.5.html) documents
  PID-namespace filtering. Missing global records do not prove a lock is free.
  [Linux v6.17](https://github.com/torvalds/linux/blob/v6.17/fs/locks.c#L2080)
  preserves an exited flock acquirer's recorded PID in the initial namespace.
- Linux [fdinfo reporting](https://github.com/torvalds/linux/blob/v6.17/fs/locks.c#L2897)
  matches the descriptor's exact file description. Positive candidate FLOCK
  evidence is stronger than matching a global lock row's saved PID to an opener.
  [Procfs FD access](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html) is
  permission-controlled; same UID is not a guarantee that every entry is readable.
- [Linux lsof lock reporting](https://github.com/lsof-org/lsof/blob/1ebf257c64db1b2ece5e4d5e922ed711c692f161/lib/dialects/linux/dnode.c#L481)
  depends on global lock records and their saved PIDs. The
  [Darwin implementation](https://github.com/lsof-org/lsof/blob/1ebf257c64db1b2ece5e4d5e922ed711c692f161/lib/dialects/darwin/dfile.c#L513)
  does not collect equivalent holder evidence through this path.
- [Darwin process enumeration](https://github.com/lsof-org/lsof/blob/1ebf257c64db1b2ece5e4d5e922ed711c692f161/lib/dialects/darwin/dproc.c#L236)
  can silently skip EPERM/ESRCH observations. Exit zero with empty stderr cannot
  prove full process visibility. Kernel source is not evidence that every
  supported lsof release or APFS configuration exhibits a particular trigger.
- XNU's generic [getlock path](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_lockf.c#L1066)
  can return PID -1 for file locks. F_GETLK is therefore not established here as
  an actual-flock-to-process ownership API. APFS behavior remains unmeasured.

## Immediate refusal and proposed stronger contract

Explicit lsof diagnostic output now propagates as discovery error even on exit
zero, both for opener discovery and the per-PID thread-lock set. Real-lock warning
fixtures verify recovery refusal, no SIGTERM, and a still-live holder. Opener
warnings classify unknown; per-PID warnings leave the lock set unverified and
block recovery. Visible opener records remain available for diagnosis.
This refuses explicit diagnostic failures. It does not address the clean,
silent omission measured above and must not be described as resolving the
foreign-UID or namespace attribution condition.

Before adding stronger attribution, the supported-platform contract should be:

1. Retain native guarded probes independently of process/FD correlation.
2. On Linux, collect positive FLOCK evidence from a candidate's actual fdinfo,
   tie it to the same device/inode and revalidated process instance, and refuse
   on missing, denied, malformed, changed, or conflicting evidence. In the
   measured foreign-UID and namespace cases the visible nonholder lacks this
   positive evidence, so the proposed adapter must return unknown before any
   signal. Match the descriptor's lock row rather than requiring its saved
   acquisition PID to equal the candidate PID: the inherited case demonstrates
   that those PIDs can differ legitimately. Never use a `/proc/locks` PID or
   absence of an optional lsof field as sole authority.
3. Treat inherited descriptions as potentially shared lifetime control. A
   positive FD observation does not prove that terminating one process will
   release every inherited copy, nor that all other holders are visible.
4. Establish a macOS holder primitive and supported visibility assumptions
   before replacing its correlation contract. No supported macOS primitive
   that attributes the actual flock to a unique process is established by this
   research. Both macOS's blank `l` field and its measured clean omission rule
   out using that field or empty stderr as a substitute. Do not silently treat
   missing optional fields as proof, or claim a Linux-only technique works on
   macOS. Any support change needs an explicit reviewed contract rather than
   an incidental universal Linux check.
5. Test unique visible nonholder/hidden holder, conflicting acquisition PID,
   inherited copies, fdinfo permission failure, and namespace omission with
   deterministic zero-signal refusals before adopting a runtime adapter.

These are a proposed design, not new shipped holder guarantees. No native
dependency, forced recovery, or unguarded fallback is introduced. The research
and source evidence establish which stronger claims need a separately reviewed
implementation; they do not demonstrate a wrong-target Codex signal.

## Codex descriptor lifetime cross-check

The following source audit pins official tag `rust-v0.162.1`, annotated tag
object `7a078f6bb4ce0dc2a81408b334ce52979d92c603`, to commit
`092d3acd6bec3e3a14bdc7e7a2810ab628ab759d`. It describes that version, not an
unbounded claim about newer releases or every caller of the writer API.

| Path in the pinned `writer_lock.rs` | Descriptor lifetime and attribution implication |
| --- | --- |
| [Acquire, lines 43–86](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/rollout/src/writer_lock.rs#L43) | Coordination is acquired before opening the thread file. On success the file moves into `WriterLockGuard`. Both failed try-lock return paths drop the local thread file before the earlier coordination local. They do not retain an ordinary nonholding descriptor after returning. |
| [Publication, lines 91–106](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/rollout/src/writer_lock.rs#L91) | The temporary thread file is scoped to the match. On success only coordination is returned; on contention no guard is returned. The temporary thread descriptor is not published as an owner handle. |
| [Stale cleanup, lines 124–171](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/rollout/src/writer_lock.rs#L124) | Called from acquire while coordination is held. Successful probes explicitly close before unlink; failed probes close at iteration scope end. These opens can appear in an independently timed process scan. |
| [Normal drop, lines 174–195](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/rollout/src/writer_lock.rs#L174) | Acquires coordination, closes the stored thread file, removes its path, then releases coordination. If acquiring coordination fails, the early return still leaves the stored `File` to field destruction; it does not establish that every close is coordinated. |

Rust's [destructor and drop-scope rules](https://doc.rust-lang.org/reference/destructors.html)
explain the local and field lifetimes above. This is source reasoning, not a
new execution of actual Codex or a proof against inherited descriptors.

The ordinary failed-acquisition path therefore does **not** support a claim
that Codex keeps a failed thread open indefinitely. However, current
`inspectThread` runs opener discovery independently of the guarded probe, and
the final unlock path awaits its per-process lock-set scan before a later
process sample and synchronous probe. A temporary opener observed during
another process's coordinated cleanup or failed acquire can be gone when the
later probe observes the actual holder. Repeated identity checks reduce the
available interleavings but do not make these observations one atomic sample.
No real Codex execution satisfying every eligibility check and producing a
wrong-target signal has been reproduced. Neither the synthetic silent-omission
measurements nor this source audit justify claiming that execution impossible.

## Linux implementation boundary

The next Linux change should establish **positive participation in the held
file description**, not complete visibility or exclusive lifetime control.
Keep the existing guarded probe as the held/free authority. The proposed
adapter has this contract:

1. Discover a bounded set of candidate FD numbers outside the native guard.
   Limit descriptors, bytes per record, and total work; truncation is unknown,
   not a partial success. Retain the existing same-user process, command,
   transcript, and single-thread eligibility checks.
2. In a synchronous native-guard section, sample the candidate's process
   instance and descriptor identity, read bounded `/proc/<pid>/fdinfo/<fd>`
   records, and recheck identity. Require a granted `FLOCK ADVISORY WRITE`
   whole-file row whose file identity is bound to the held probe through a
   verified filesystem identity mapping. A row's superblock device/inode and
   filesystem stat values are not universally interchangeable. Matching the
   candidate-FD and target-path stat identities alone does not validate the
   row; unsupported or inconsistent mappings are unknown.
   A waiting row, a POSIX/OFD byte-range lock, or a path string match is not a
   substitute. Collect stat identities with bigint and parse row identities
   losslessly; converting an already-rounded JavaScript number cannot recover
   the original identity. Do not compare formatted device strings directly.
3. Bind evidence to PID, Linux process start ticks, UID, FD number, and
   device/inode. Reuse of a descriptor, process, or path during collection is
   unknown. A lock row's acquisition PID may legitimately differ after fork;
   do not require it to equal the surviving candidate PID. Opening the target
   through procfs is not a way to acquire or duplicate the candidate's lock.
4. Keep a positive/unknown attribution result separate from opener records and
   lock-held state. Missing, denied, malformed, oversized, changed, ambiguous,
   or inconsistent records cannot authorize recovery. Proposed reason names
   and any optional JSON evidence need schema/type/documentation review before
   implementation; this document does not introduce a public JSON contract.
5. Repeat positive attribution after all awaited revalidation and in the last
   synchronous guarded probe before signal. Release the native guard before
   signal, with no intervening await or child process. Never spawn `lsof` or
   retain a guard across polling, network access, or sleeps. Bounded reads
   reduce guard work but are not a hard real-time latency guarantee.
6. A forked copy may still keep the lock after the selected participant exits.
   Positive fdinfo does not enumerate every hidden copy. Preserve the existing
   post-signal process-exit, actual lock-release, and transcript-hash checks;
   do not describe this change as guaranteed recovery or unique holder proof.

Adoption requires deterministic tests using real guarded locks: hidden holder
plus sole visible nonholder refuses with zero signals; namespace-filtered
global rows do not override candidate evidence; inherited acquisition PID
mismatch is handled without false absence; denied/malformed/truncated fdinfo,
unsupported filesystem identity mappings, FD reuse, process replacement,
inode replacement, and lock release between
discovery and final sample all refuse. An eligible positive fixture must still
recover, while a surviving inherited copy must fail post-release verification.
These are proposed implementation gates, not results of this documentation PR.

## macOS decision and separate follow-up scopes

The Linux adapter must not be inserted as a universal requirement that
incidentally disables macOS. A separate macOS contract decision is needed:

- Keeping today's correlation-based support requires explicitly retaining its
  measured visibility limitation. Empty stderr, one visible opener, and a held
  probe cannot be advertised as positive holder attribution.
- Requiring positive holder attribution would leave macOS unlock unavailable
  until a validated native API or owner-cooperative mechanism exists.
  Diagnostics can retain opener evidence. Such a compatibility change needs
  an explicit reviewed support policy and migration note, not a missing-field
  fallback in Linux implementation code.
- A new macOS primitive must distinguish current holders from former holders,
  failed reacquisitions, and independently opened nonholders; it must cover
  inheritance, visibility failures, and final-sample identity races before it
  can authorize signals. The published XNU getlock behavior above does not
  establish a usable PID attribution API.

Track Linux positive-fdinfo implementation and the macOS policy/primitive
decision as separate follow-up scopes under #100. The Codex lifetime audit is
a shared prerequisite, not a replacement for either. The Rust experiment
(#122) may reuse these fixtures and contracts but does not resolve attribution
by changing implementation language. This document changes neither runtime
behavior nor platform support; #100 remains open until the adoption criteria
or an explicitly accepted research-only disposition are satisfied.

PR #115 is research plus partial hardening for explicit lsof diagnostics. It
does not establish the stronger cross-platform attribution contract. Issue #100
must not be closed as an implemented attribution fix on that evidence. Before
claiming adoption, verify Linux descriptor-level refusal in the clean-omission
fixtures, revalidate attribution before signaling, and resolve or explicitly
review the macOS support/visibility contract. An accepted research-only outcome
must state these remaining limitations rather than claiming the hypothetical
visibility condition cannot occur.

## Synthetic inspection interleaving follow-up

The unpublished research fixture in
[`scripts/fixtures/attribution-interleaving`](../scripts/fixtures/attribution-interleaving/README.md)
models a transient nonholder that opens a thread file under coordination while
another synthetic process holds its real flock. A diagnostic override removes
the actual holder from system `lsof` output. This is an injected visibility
condition, not a newly measured natural omission or an actual Codex session.

The original result, reported with fixture revision `d5f3cb2`, identifies a visible transient
as `live_owner` with `safeToUnlock: true`, while a different process holds the
lock. Its events record failed thread-lock acquisition by the transient and
the holder-filter operation. Original hashes were independently checked:

- Results: `fbd6a9adce1ed6729f8c56b2d5960540c9d166c62b63159d35c030162c0a5364`
- Events: `5b53ed3f28147bc05bdbb57b6b8efd3b715e969ddf1aa1f1168423582336f016`

This supports a **synthetic inspection-stage attribution counterexample**.
It does not establish that an actual Codex session produces the condition,
that final unlock revalidation passes, or that a wrong-target signal was sent.
The experiment never calls unlock. Existing real-Codex non-reproduction
statements remain valid. Original fixture cleanup, readiness and integrity
checks needed correction before rerunning; earlier records are not rewritten
or retrospectively promoted to satisfy the amended harness's checks. Those
records did not pin built `dist` hashes, so their exact build provenance cannot
be independently established after the fact.

After lifecycle and socket-collision corrections, one local rerun independently
recorded the same B inspection counterexample, normal exit code 0 for all five
fixture children, and unchanged bigint identities/content hashes for the three
homes actually used. Result SHA-256:
`6b16473a2007dad87cc75f07749993866d93572c2acc4827c25ff7410288c325`.
The amended output records fixture and built `dist` hashes. A prior amended
attempt failed during transient startup because its socket collided with a
scenario directory; that failure is preserved and excluded from successful
reproduction counts. In the successful amended C control, both openers were
visible and classification was unknown. Exact refusal reasons can differ with
coordinator timing; the experiment does not assert a unique C reason.

## Remaining attribution decisions

Linux descriptor evidence establishes participation in a locked open-file
description, not sole lifetime control over inherited or otherwise shared
references. The [v6.17 status formatter](https://github.com/torvalds/linux/blob/v6.17/fs/locks.c#L2817)
prints the inode's superblock device and inode number. Filesystem stat identity
and that row's identity must not be assumed interchangeable on every
filesystem. Comparing candidate-FD and target-path stat values alone does not
validate a separately parsed row. Unsupported identity mappings must stay
unknown. Use lossless integer identities; numeric Stats can round distinct
64-bit inode values before they are converted to public strings. The adapter
design and any snapshot precision fix need separate implementation review.

The studied macOS APIs did not establish a trustworthy positive holder
primitive. In supplied same-user APFS observations, `F_GETLK` family results
used PID -1 for flock and `FWASLOCKED` remained set after `LOCK_UN`. A historical
acquisition bit cannot authorize recovery: a former holder can retain its FD
while another process holds the lock. This is a bounded observation, not proof
that no possible API exists on any macOS version or filesystem. Such a bit
could only be evaluated as a refusal-side filter with explicit kernel-version
and source/runtime limitations. No filter or support-policy change ships here.

Issue #100 stays open with Linux #126 and macOS #127 as adoption scopes. The
research result must not be presented as an implemented owner-verification fix.
