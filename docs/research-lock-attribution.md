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
- Linux [fdinfo reporting](https://github.com/torvalds/linux/blob/v6.17/fs/locks.c#L2729)
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

PR #115 is research plus partial hardening for explicit lsof diagnostics. It
does not establish the stronger cross-platform attribution contract. Issue #100
must not be closed as an implemented attribution fix on that evidence. Before
claiming adoption, verify Linux descriptor-level refusal in the clean-omission
fixtures, revalidate attribution before signaling, and resolve or explicitly
review the macOS support/visibility contract. An accepted research-only outcome
must state these remaining limitations rather than claiming the hypothetical
visibility condition cannot occur.
