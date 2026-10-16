# macOS lock owner and visibility contract (decision record)

Status: **proposed, awaiting a user decision.** This record belongs to
[#127](https://github.com/abruption/codex-unlock/issues/127). It changes no
runtime behavior, platform support, JSON output, or signal path. It builds on
[macos-lock-attribution.md](macos-lock-attribution.md) (the disclosed
opener-correlation proposal and its evidence inventory),
[research-lock-attribution.md](https://github.com/abruption/codex-unlock/blob/3b89057c37e6a7028f88c7bef39c6eae9604c639/docs/research-lock-attribution.md)
(the #100 foreign-UID measurements), and the `lsof +fg` refusal-filter
research in draft [#139](https://github.com/abruption/codex-unlock/pull/139)
at [`56dc50d5`](https://github.com/abruption/codex-unlock/tree/56dc50d5f610d3356228aacee743cbd22a6706eb/experimental/126-guard-liveness)
(section M2). Facts measured there are summarized, not repeated.

Evidence levels used below:

- **Source-pinned**: read at a fixed revision. It explains behavior; it is not
  a runtime measurement and a targeted read is not an exhaustive audit.
- **Measured**: observed with same-user synthetic fixtures on the stated
  system only. Nothing here was measured with a real Codex process.
- **Not covered**: neither of the above. Treat as unverified.

## 1. Fixed-source facts

### Codex writer lock lifetimes (source-pinned)

Codex `rust-v0.162.1` is commit
[`092d3acd`](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/rollout/src/writer_lock.rs),
built with Rust 1.95.0
([`rust-toolchain.toml`](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/rust-toolchain.toml)).

| Path | Handle lifetime at that revision |
| --- | --- |
| [`acquire`](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/rollout/src/writer_lock.rs#L43-L86) | Blocking coordination lock, then opens the thread file and `try_lock`s it. On `WouldBlock` or error the file local is dropped on return, before the earlier-declared coordination local, so a failed acquirer's thread FD is closed while coordination is still held. On success the file moves into the guard. |
| [`try_acquire_for_publication`](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/rollout/src/writer_lock.rs#L91-L106) | Under coordination, opens and `try_lock`s the thread file. Both a successful (transient holder) and a failed (transient nonholder) probe drop the file at the end of the match arm; coordination is returned to the caller. |
| [`remove_stale_thread_locks`](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/rollout/src/writer_lock.rs#L124-L171) | Under coordination: a transient holder for each free lock file, dropped before the pathname is removed; a busy one is closed without removal. |
| [`Drop for WriterLockGuard`](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/rollout/src/writer_lock.rs#L174-L196) | Takes coordination (blocking), closes the file, removes the pathname, releases coordination. If taking coordination fails, it returns early: the pathname is not removed, and the `file` field is still closed afterwards by ordinary field drop, without coordination. |

Rust 1.95.0 std ([`59807616`](https://github.com/rust-lang/rust/blob/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/fs/unix.rs))
opens every `File` with
[`O_CLOEXEC`](https://github.com/rust-lang/rust/blob/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/fs/unix.rs#L1349-L1359);
on Apple targets
[`lock`](https://github.com/rust-lang/rust/blob/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/fs/unix.rs#L1434-L1449)
is `flock(LOCK_EX)` and
[`try_lock`](https://github.com/rust-lang/rust/blob/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/fs/unix.rs#L1520-L1543)
is `flock(LOCK_EX | LOCK_NB)`.

What this source reading **does not** exclude:

- Another code path in the same process holding a duplicate of the guard's
  description (`try_clone`, `dup`, raw-FD use). No such use of this type was
  checked beyond the file above.
- A `fork` without exec anywhere in the process or its dependencies; a forked
  child shares the description, its lock, and its flags. `O_CLOEXEC` only
  closes the FD at a successful exec, so a fork-then-exec launcher also has a
  short shared window. Whether Codex's spawn paths use `posix_spawn` or
  fork-then-exec was not audited.
- Descriptor passing (`SCM_RIGHTS`, Mach fileports) to another process.
- Packaging, wrappers, or a different build of Codex than the pinned source.

These are listed because a targeted search found no such path, and a targeted
search is not a proof of "no call" or "no inheritance". The 0.162.1
`WriterLockGuard::drop` and `O_CLOEXEC` statements above are source-only.

Observation interleavings: the guarded probe takes the same coordination lock,
so it never observes the transient holders and nonholders above. `lsof` opener
discovery runs outside the synchronous guard (it must, to keep the guard
invariant), so it can sample those transient openers from other Codex
processes. Each sample being individually valid does not make the combination
an atomic holder observation. #139 M2 Part 2 shows that a wrong eligible
target needs the transient descriptor open in both the opener-scan and the
lock-set-scan sample windows; no real-environment frequency was measured.

### XNU flock ownership and `FWASLOCKED` (source-pinned)

The pinned public source read here is
[`ac9718fb` (xnu-12377.121.6)](https://github.com/apple-oss-distributions/xnu/tree/ac9718fb1af618d5ce8678d0dc6e8a58f252216f).
It is not claimed to be the newest public release. The measured kernel
(`xnu-13432.1.9`) is a later version whose source was not found in this
search, so these statements are about the pinned source, not the running
kernel.

- flock locks are created with
  [`lf_owner = NULL`](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/kern/kern_lockf.c#L313-L317)
  (only `F_POSIX` locks, and confined OFD locks, record an owning process), and
  [`F_GETLK` reports `l_pid = -1`](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/kern/kern_lockf.c#L1172-L1180)
  when the owner is NULL. By construction the kernel lock record of a flock
  names an open file description, not a process.
- `FWASLOCKED` (`0x4000`, ["has or has had an advisory fcntl lock"](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/sys/fcntl.h#L136))
  is set on the description after a successful
  [`flock`](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/kern/kern_descrip.c#L6034-L6039)
  and after `open` with
  [`O_EXLOCK`/`O_SHLOCK`](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/vfs/vfs_syscalls.c#L5028-L5032).
  `LOCK_UN` does not clear it. It is consulted at
  [close](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/vfs/vfs_vnops.c#L1886-L1899)
  to decide whether to issue `F_UNLCK`.
- [`fill_fileinfo`](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/kern/proc_info.c#L2651-L2653)
  copies the description's `fg_flag` into libproc's `fi_openflags`; this is
  where `lsof +fg` obtains the `G` field. It is a per-description flag word,
  not a per-process lock record.

"Never cleared" is from a targeted read of `kern_descrip.c`, `kern_lockf.c`,
`vfs_syscalls.c`, `vfs_vnops.c`, `proc_info.c`, `uipc_usrreq.c`, and
`sys/fcntl.h`, not a whole-tree audit. The sticky behavior is **measured** on
the running kernel (#139 M2 and the 2026-10-13 inventory), which is the
evidence actually relied on.

No public macOS API found in this research maps a flock to its holding
process. The tested candidates (`F_GETLK`, `F_GETLKPID`, `F_OFD_GETLK`,
`lsof -F l`, `lsof +fg`, `proc_listpidspath`, `fuser`, `NOTE_FUNLOCK`) are
recorded in [macos-lock-attribution.md](macos-lock-attribution.md#evidence-inventory).
DTrace and Endpoint Security were not exercised. This is a bounded finding,
not a proof that no such primitive exists.

## 2. Counterexamples to opener-based attribution

All rows are measured with synthetic same-user fixtures unless marked.

| Counterexample | What the observer sees | Source |
| --- | --- | --- |
| Hidden holder + visible nonlocking opener | Held probe, one clean visible opener that is not the holder | Foreign-UID CI run (#100); same-user modelled omission (#139 M2) |
| Failed acquirer retaining its FD | Visible opener without `FWASLOCKED` | #139 M2 matrix |
| Never-locked opener | Visible opener without `FWASLOCKED` | #139 M2 matrix |
| Former holder (`LOCK_UN`, FD kept) + actual holder | Both descriptions carry `FWASLOCKED`; indistinguishable | #139 M2 matrix |
| Former holder alone, lock free | `FWASLOCKED` still set | #139 M2 matrix |
| Shared description via fork without exec | Both processes carry the bit; one lock | This record, section 5 |
| Shared description via exec of an inheritable FD | Both carry the bit; lock survives the original's close | This record, section 5 |
| Description passed with `SCM_RIGHTS` to a sibling process (not the locker's descendant) | Receiver never called `flock`, carries the bit, and becomes the sole holder | This record, section 5 |

Consequence: the bit can exclude a descriptor that never held a lock. It can
never identify the current holder, and terminating one process that shares a
description does not prove the lock will be released.

## 3. Options

| Option | What it does | Removes | Does not remove | Cost and risk |
| --- | --- | --- | --- | --- |
| **(a)** Keep current correlation with documented limits | No runtime change; [macos-lock-attribution.md](macos-lock-attribution.md) states that `live_owner` is opener correlation, not holder proof | Nothing new | Hidden holder + eligible visible nonholder (failed acquirer, never-locked opener, former holder) | No new code. The residual wrong-target risk is accepted only as disclosed, and that acceptance is a user decision |
| **(b)** Add a refusal-only `lsof +fg` filter | Before eligibility, require the candidate to have at least one description on the lock with `FWASLOCKED`. Decision values only `unknown` / `reject` / `not_excluded`; `unknown` and `reject` refuse; `not_excluded` only means "not refused by this filter" | Failed-acquirer and never-locked wrong targets, including the #100 shape (#139 M2 Part 2) | Former holder retaining an FD; shared descriptions; clean whole-record omission | An extra `lsof` invocation per candidate at the existing fixed path (no new native dependency). Relies on an undocumented libproc flag word; parser and format drift must fail as `unknown`. It is never holder evidence and must not be reported as such |
| **(c)** Restrict macOS to diagnostics | `list`, `inspect` and `check-update` keep working; `unlock` refuses on macOS | Every macOS wrong-target path | Nothing on Linux (separate fdinfo track) | Removes a supported recovery feature and changes the platform-support contract and JSON-visible behavior |

Option (b) adds only refusals, but it still changes which owners `unlock` will
signal, adds an observable refusal reason, and must be specified for JSON v1
compatibility. Option (c) removes macOS unlock support. **Both options change
the supported-platform or permission contract and require an explicit user
decision; neither is implemented here.** No option introduces a new success
or authorization claim: no available macOS evidence supports one.

### Recommendation

1. Keep (a)'s current behavior unchanged now, with the limits in
   [macos-lock-attribution.md](macos-lock-attribution.md) and this record.
   Keeping the behavior is not approval of its residual wrong-target risk.
   Accepting that risk is a separate user decision that this record does not
   make.
2. Propose (b) as the next separately reviewed change. It is refusal-only.
   In #139 M2 it rejects the failed-acquirer and never-locked-opener wrong
   targets, including the #100 failed-acquirer shape. It does **not** remove
   the former holder that keeps its FD, which #139 M2 also reproduced as a
   wrong eligible target (`B_former`). That residual must be documented with
   (b), and the [gap plan](#4-gaps-and-fixture-plan) rows marked
   "before (b)" must be measured first.
3. Choose (c) instead only if the user judges the residual former-holder and
   shared-description risk unacceptable even after (b). That trade-off is a
   policy decision, not one research can settle.
4. A stronger, holder-positive mode remains gated on a current-holder
   primitive or an authenticated cooperative owner release, per the
   acceptance gates in [macos-lock-attribution.md](macos-lock-attribution.md#acceptance-gates-for-a-stronger-contract)
   and the [upstream handoff proposal](upstream-handoff-proposal.md).

Under every option the invariants in `AGENTS.md` are unchanged: independent
nonblocking guarded probe, lock order lease → native guard → thread probe, no
native file creation or deletion, no force mode, no `SIGKILL`, and a signal
only to the exact revalidated same-user owner with a stable transcript ending
in `task_complete`.

### Transfer to the Rust experiment (#122)

Rust's `File::lock`/`try_lock` on macOS is the same `flock`, so a Rust
implementation inherits exactly these limits. A Rust port could read
`proc_pidfdinfo` directly instead of parsing `lsof`, which removes the text
format but not the semantics: the flag is still per description and sticky,
and same-user libproc visibility still does not reveal hidden holders. Rust
does not resolve holder attribution. Any chosen option transfers as the same
decision table and the same `unknown`/`reject`/`not_excluded` vocabulary; the
#122 lab must keep `safeToUnlock` false for anything it cannot attribute.

## 4. Gaps and fixture plan

"Measured" means same-user synthetic fixtures on APFS, macOS 27.0.1. Each plan
uses only processes the fixture starts, bounded waits, stdin-EOF children with
their own lifetime, zero signals, and asserts zero SIGTERM for refused cases.

| Area | Item | Status | Narrow fixture or test plan | Needed before |
| --- | --- | --- | --- | --- |
| Inherited FD | fork without exec, both alive | Measured (section 5) | — | — |
| Inherited FD | exec of inheritable FD; `O_CLOEXEC` across exec | Measured with Python's launcher (section 5) | Repeat with a Rust `std::process::Command` child to cover the launcher Codex uses | (b) |
| Inherited FD | `SCM_RIGHTS` passing to a sibling process | Measured (section 5) | — | — |
| Inherited FD | Mach fileport passing | Not covered | C fixture: `fileport_makeport` → `fileport_makefd` in a separately started same-user actor; record bit and probe | (b) |
| Inherited FD | Shared description with a visible Codex-looking sharer and a second sharer hidden | Not covered | Combine `scm_rights` with the M2 modelled omission; product must not report `safeToUnlock: true` with only one sharer killed. Expected today: possible wrong target (document, do not "fix" in the test) | (b) |
| Inherited FD | Real Codex inheritance / fork paths | Not covered (source-only) | Out of scope without a real Codex binary; requires a separately approved, isolated, synthetic-home run | Holder-positive mode |
| Process identity | Holder execs in place (same PID, new image) while keeping the FD | Not covered on macOS | Actor `execve`s itself with an inheritable lock FD between two observations; assert refusal via changed command/arguments | (b) |
| Process identity | PID reuse, start-time resolution of `ps lstart` | Covered by deterministic revalidation tests ([safety-race-matrix.md](safety-race-matrix.md)); real PID reuse not forced | Unit test with an injected process table where PID and second-resolution start time match but PPID/arguments differ | — |
| Process identity | Credential change of a holder after locking (setuid helper) | Not covered. The existing `--privileged-fixtures` CI job (`scripts/research-lock-attribution.py`) measures a hidden holder that runs under a different UID from the start (#100); it does not change a holder's credentials after it locks | A post-lock credential-change fixture needs a privileged helper; it could be added to that existing job | (c) decision input |
| Permission | Same-user process whose libproc FD info is denied (sandboxed or hardened target) | Not covered | Holder launched under `sandbox-exec` with a deny-default profile; record lsof status, stderr, and whether the record is omitted cleanly | (b) |
| Permission | codex-unlock itself running sandboxed (e.g. inside a Codex shell tool) | Not covered | Run the fixtures' observer under `sandbox-exec`; any reduced visibility must surface as `unknown`, not as a clean scan | (b) |
| Permission | `lsof +fg` field drift (Homebrew lsof, future versions) | Only lsof 4.91 at `/usr/sbin/lsof` measured | Golden-output parser tests from multiple lsof versions; unknown fields → `unknown` (the #139 parser does this) | (b) |
| Filesystem | APFS | Measured | — | — |
| Filesystem | HFS+, ExFAT, MS-DOS local volumes | Not covered | `hdiutil create -fs <fs>` image in the scratch root, attached with `-nobrowse -mountpoint` under the scratch; needs approval because it changes the mount table | (b) |
| Filesystem | SMB/NFS/AFP and FUSE (macFUSE, rclone) | Not covered | Network/FUSE flock may be local-only or emulated. Plan: report these as unsupported for unlock unless measured; detect by `statfs` type | (c) decision input |
| OS version | macOS 15 CI (kernel 24.x) sticky-bit behavior | Not covered (only foreign-UID visibility measured there) | Run `experimental/127-macos-contract/inherit.py` and #139 M2 in a research-only CI job on `macos-15` and `macos-15-intel` | (b) |

## 5. Synthetic validation (#127 fixtures)

Script: [`experimental/127-macos-contract/inherit.py`](../experimental/127-macos-contract/README.md).
Environment: Darwin 27.0.0 arm64 (macOS 27.0.1, `xnu-13432.1.9`), Python
3.15.0, lsof 4.91 (`/usr/sbin/lsof`), APFS, same user, worktree base
`3bc40919`, 2026-10-16. Raw results are private (they contain local paths and
PIDs).

Three script revisions were used in runs 1–6. Results of one revision do not
validate another. Later integrating-session corrections require a separate
run and are not validated by runs 1–6.

- **Original revision** (runs 1–4). Its `ok` checked only failures and
  incomplete waits, not the expected table. Its raw results do not record a
  script SHA-256, so the exact script is *not recorded* there. It was the
  script in the frozen READY-B input. The table below was checked against
  each raw result's per-stage `probe`, `roles`, `scan_valid` and
  `unexpected_pids` fields after the fact. The original revision used
  `subprocess.run` timeouts for `mount` and `lsof -v`. Those could send
  SIGKILL if they timed out. No raw result shows a timeout, because one would
  have aborted the run before a result was written. Its `signals_sent: 0`
  field was a constant, not a measurement.
- **Expected-table revisions** (runs 5 and 6, distinct scripts). Each records its own `script_sha256`,
  evaluates an expected table in code (`collected`, `measured`, `ok`), parses
  `lsof` strictly, and makes no kill calls or killing timeouts.

| Run | Script | Outcome | Raw result SHA-256 |
| --- | --- | --- | --- |
| 1 | original (SHA not recorded) | `ok`; all stages match the table below | `8c2460c52c9b302e0106512dc0cc3f9f71d79ef9652b3877cb9af1875ebb1d71` |
| 2 | original (SHA not recorded) | same | `9d5fed5f5eebd86ab16ec6f7512a6df23f0e7578fd41168993ec5dc8601a9e18` |
| 3 | original (SHA not recorded) | same | `925afe905d4e75f3ee2c70e49df8c635bba15e3921c7eb56be9977dc973fb341` |
| 4 | original (SHA not recorded); independent rerun by the integrating session | same; every actor exit 0 | `f4911363a73dc5ad06297ce37b1fc1d5258b8623acf03d6167318f54f4b67d2f` |
| 5 | `743269e2d8efb821f650cbe22c5fd598747e5e9fb56866cb23a7d1582fb7573c` | exit 1: `collected` true, `measured` false. Five no-opener stages were `scan_invalid`, caused by a parser bug in that revision (empty `lsof` output counted as one unterminated record). Probes and roles matched the table | `b2c44156447d9813e2e2ce0350fa7b39cc0ef60cc8e71e672375a4384aba2457` |
| 6 | `3a24810af3090b7cd60f24063134ba1f19f5ca9118a8536feeed43aeed070fb1` (bug fixed, test added) | exit 0: `ok`, `collected`, `measured`; no mismatches, no pending diagnostics | `55172c87451b32427dbc85d33ae28f7531b8c6898dc3b53671f5f771b8fb5f49` |
| 7 | `44215d458e53b7ddd038db32a65746b2fdf1402258563cac4f48f682dee51bac` (integrating-session corrections) | exit 0: `ok`, `collected`, `measured`; no failures, mismatches, incomplete waits or pending diagnostics; start/end script hashes match | `097a33f60b49e7461983d7d521286c4fa666dad83b09900413c42c847559ffdd` |

Run 5's fixture directory is kept, as designed for a failed run.
Run 7 separately validates the line-cap/partial-EOF, cleanup and script-identity
corrections. The focused helper suite passed 23 tests with no skipped tests
and ResourceWarnings treated as errors. This remains one machine's synthetic
APFS measurement, not a native Codex or production-holder attribution result.

| Scenario / stage | Probe | Bit per process |
| --- | --- | --- |
| `fork_shared` both alive | held | parent bit, forked child bit |
| `fork_shared` parent closed its FD (alive) | held | parent absent, child bit |
| `exec_inherit` both alive | held | parent bit, exec'd child bit |
| `exec_inherit` parent closed its FD (alive) | held | parent absent, child bit |
| `exec_cloexec` both alive | held | parent bit, child absent (child confirmed the FD number did not name the fixture) |
| `exec_cloexec` parent closed its FD | **free** | both absent |
| `scm_rights` both hold the description | held | sender bit, receiver bit |
| `scm_rights` sender closed its FD / exited | held | sender absent, receiver (never called `flock`) bit |
| every scenario, all closed | free | no openers |

Interpretation, within that scope:

- One kernel lock can be held simultaneously by several processes that share
  a description, and lsof shows the same bit on each. A unique-opener rule
  refuses the "both alive" stages only because two openers are visible.
- After the original locker closes, the remaining sharer is the real holder
  even though it never called `flock`. With `SCM_RIGHTS` it is a sibling
  started by the same fixture parent, not the locker's descendant. Unrelated
  lineage in general was not tested. These results show that one description
  can be shared by several processes. They do not show that real Codex takes
  any such path. Process lineage is not a holder criterion.
- The `exec_cloexec` result shows the OS mechanism the Rust std `O_CLOEXEC`
  argument depends on, for Python's launcher. It does not show that Codex
  never inherits or passes its lock FD.
- Not done here: other filesystems, other macOS versions, fileports, sandboxed
  observers, and any real Codex binary.
