# F4: narrowing the native-guard critical section of #137 (proposal, #126)

Research proposal only. `guard-scope.patch` applies to #137 head
`b483cd587c62329243366e64aaaac477edd36adc` with `git apply`. It is **not
applied to the product** or to any branch, and it does not make #137
release-ready. Status: **no-go for readiness**. The patch removes two read
paths from the guard. It does not bound the guard, and it does not change the
signal boundary in any validated way. Any change at the signal boundary
requires a separate Linux run and review first.

## Problem restated

#137 holds `.coordination.lock` during `verifyLinuxParticipation`. That
function makes synchronous syscalls with no hard deadline. Two of them wait on
state that the existing guarded probe does not touch:

1. `linuxCommandFingerprint`, called twice inside the guard. It reads
   `/proc/PID/cmdline`, which reaches `access_remote_vm` and the target's
   `mmap_lock`. It also reads `/proc/PID/exe`.
2. `statSync('/proc/PID/fd/N')` before and after the fdinfo read. It follows
   the descriptor to the target file and calls that filesystem's getattr.

A real Codex waiting on the guard with a blocking flock waits as long as the
guard is held. F1 measured this with an injected delay and one synthetic
waiter.

## Change

| Step | #137 `b483cd5` | Patch |
| --- | --- | --- |
| Pre-guard `prepareLinuxParticipation` | cmdline, exe, stat, fd list, readlinks | unchanged |
| In guard: identity | proc dir UID, mount ns, start ticks, **command fingerprint**, fd list | proc dir UID, mount ns, start ticks, fd list |
| In guard: descriptor | readlink, **stat via fd**, fdinfo, **stat via fd**, readlink | readlink, fdinfo, readlink |
| In guard: participation evidence | stat via fd and granted row device/inode | granted row device/inode vs `stat(lockPath)` only |
| After release | none | `confirmLinuxCommand`: start ticks and command fingerprint again |
| Before signal (unlock) | none | `assertFinalBoundary`: the confirm step above must take ≤ 25 ms |

The patch drops the stat through the descriptor and keeps the row comparison
that #137 already made. It is not a stronger binding. In pinned v6.17
`fs/locks.c`, `show_fd_locks` lists entries of the inode's granted
`flc_flock`/`flc_posix`/`flc_lease` lists whose `flc_file` is the descriptor's
file, and `lock_get_status` prints `MAJOR/MINOR(file_inode(file)->i_sb->s_dev)`
and `i_ino`. A matching row is therefore evidence that the **sampled**
description participated in a granted flock on that inode at the time of the
read. Blocked waiters are not on these lists. The superblock device equals
`st_dev` only on the allowlisted filesystems, which is why the allowlist stays.
The readlinks before and after remain a negative filter only.

`verifyLinuxParticipation` gains an optional `trace` callback for tests and
review; production passes none. The callback is written by hand at each call
site. It does not report `checkNamespace` or the descriptor directory's
internal reads individually, and it is not syscall instrumentation. A trace
without a path is not evidence that the path is never reached.

### Reads left inside the guard, checked against pinned Linux v6.17

Source: `torvalds/linux@e5f0a698b34ed76002dc5cff3804a61c80233a7a`, read for
this proposal. This is a targeted check, not an exhaustive audit.

| Read | Kernel path | Can wait on |
| --- | --- | --- |
| `/proc/PID/stat` | `do_task_stat`: `get_task_mm`, `lock_task_sighand`, `stats_lock` seqlock, RCU | task and signal locks; no `mmap_lock` in this function |
| `/proc/PID/fd` readdir, `fd/N` readlink | `proc_readfd_common`, `proc_fd_link`: RCU, `files->file_lock`, `d_path` | spinlocks; no target filesystem I/O |
| `/proc/PID/fdinfo/N` | `seq_show`: `task_lock`, `files->file_lock`, `show_fd_locks`, then **`file->f_op->show_fdinfo`** | the file type's `show_fdinfo`. For example `ep_show_fdinfo` (`fs/eventpoll.c`) takes `mutex_lock(&ep->mtx)` |
| `stat /proc/PID`, `ns/mnt` readlink | `pid_getattr`/`task_dump_owner`, `ns_get_name` | task lock |
| `statfs`/`stat` of the lock path | lock file's filesystem | the same filesystem that the existing guarded probe already opens and flocks |

Residual paths that the patch does not remove:

- **fdinfo through `show_fdinfo`.** The readlink before fdinfo can match the
  lock path. FD N can then be closed and reused, for example by an epoll file,
  before the fdinfo read. That read can then wait on `ep->mtx` while
  coordination is held. The readlink after the read refuses the result, but a
  refusal cannot undo a wait that already happened. This path exists in #137
  `b483cd5` as well.
- **Lock path filesystem.** It can stall the guard just as it can stall main's
  existing guarded probe. The ext/tmpfs/XFS allowlist applies only after
  `statfs` returns.
- Every remaining read is a synchronous syscall with no hard deadline.

### What `assertFinalBoundary` measures

The 25 ms check covers **only** the post-release confirm step: from the
return of `guardedProbeOnce` to the end of `confirmLinuxCommand`. A slow
confirm step is refused through the existing `unknown` path. It does not
cover:

- the time between the guard's `LOCK_UN` and the return of `guardedProbeOnce`;
- the time from the check to `process.kill`;
- the age of the in-guard evidence (the fdinfo row was read before this
  window).

So it is **not** a staleness bound and **not** a release-to-signal bound. It
only stops a slow command read after release from being followed by a signal.
`confirmLinuxCommand` refuses an exec that changes argv or the exe path. A
same-path re-exec with identical argv is still undetected. Inside and around
the measured step, nothing proves that the owner still holds the lock at
`kill`. Node exposes no pidfd, and this repository adds no native dependency,
so a PID-reuse window remains. Post-signal release and transcript verification
remain mandatory.

## Validation run

On macOS 27.0.1 arm64 with Node v24.16.0, using the exported `b483cd5` tree
with the patch applied (patch SHA-256
`ae73cacce078264e3426eed5cbebe901ac2fb9f3371bb99dc2b1471a8eed8d74`; it
supersedes `4fa037d2…` by changing comments and test names only):

| Check | Result |
| --- | --- |
| `npm ci`, `npm run check`, `npm run lint` | pass |
| `npm test` | 280 tests, 273 pass, 0 fail, 7 skipped (Linux-only) |
| `npm run smoke:package` | pass |
| `git diff --check`, `git apply` through `../f2-linux-nondumpable/build.mjs --patch` | pass |

Unpatched `b483cd5`, as recorded in #137, has 278 tests with 272 passing and
6 skipped. The new cross-platform test is the confirm-step test. The new
Linux-only trace test and the modified Linux participation test are **not
executed** on this host. A Linux run is required before any claim about them.

## Gate status after the patch

| #137 gate | `b483cd5` | With patch | Still needed |
| --- | --- | --- | --- |
| Guard held during target `mmap_lock` wait (cmdline) | exposed | cmdline/exe not read in the guard (source-checked) | Linux run of the trace test |
| Guard held during FD target getattr | exposed | stat via FD not made | same |
| Guard held during fdinfo `show_fdinfo` of a reused FD | exposed | **unchanged** | design for FD reuse between readlinks; no proposal here |
| Guard held during lock filesystem stall | exposed (same as main) | unchanged | policy decision: accept parity with main, or refuse non-local paths before the first probe |
| Slow command read after release followed by a signal | not checked | refused if the confirm step exceeds 25 ms | evidence age and release-to-signal remain unbounded; no pidfd |
| Native dumpability/access | open | unchanged | F2 isolated inspection on Linux (`../f2-linux-nondumpable`) |

The decision on the remaining gates belongs to the reviewer and the user. A
stronger review (another model or a kernel-aware reviewer) of the v6.17 call
paths above is recommended before readiness is claimed.
