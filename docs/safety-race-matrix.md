# Safety race matrix

This matrix records the evidence transitions that must fail closed between an
initial safe inspection and the final signal boundary. Tests use real advisory
locks for OS behavior and explicit fixture commands for deterministic mutation;
they do not rely on timer placement.

| Transition | Required invariant | Expected result | Coverage |
|---|---|---|---|
| Transcript append or terminal event change | Same path, snapshot, terminal record, and stable hash | Refuse; zero SIGTERM | `revalidation refuses a transcript record appended before SIGTERM` |
| Owner acquires another native thread lock | Exact same single-element owner lock set | Refuse; zero SIGTERM | `revalidation refuses a newly acquired lock in another home` |
| Owner command/arguments change | Same PID, start time, PPID, UID, command, arguments, and service classification | Refuse; zero SIGTERM | `revalidation refuses changed process arguments` |
| Lock inode is replaced and a competing owner appears | Same device/inode and exact stable owner | Refuse; both owners remain alive | `revalidation refuses a replaced lock inode and owner` |
| Two CLI unlocks inspect the same safe owner | One private advisory operation lease per native lock directory device/inode and thread | Exactly one SIGTERM; competitor refused | `concurrent CLI unlock attempts send at most one SIGTERM` |
| Competing unlocks run with different `TMPDIR` or `XDG_RUNTIME_DIR` | Lease location is derived from the native lock directory, not the environment | Exactly one SIGTERM; competitor refused | `concurrent CLI unlocks from different TMPDIR and XDG_RUNTIME_DIR send one SIGTERM` |
| Competitor names the same lock through a symlinked, linked-subdirectory, or case-variant home | Canonical lock directory and device/inode key | Refuse; zero SIGTERM from the competitor | `aliased Codex homes share one unlock lease` |
| Another local user pre-creates a shared temporary lease root | No shared or predictable temporary lease root | Unlock proceeds normally | `a squatted shared temporary lease root does not deny unlock` |
| Operation lease cannot be established | Same-user parent, private same-user non-symlink directory, and regular single-link non-symlink lock file that still names the locked inode | Refuse; owner remains alive | `coordination failure refuses without signaling the safe owner` |
| Process inspection becomes unavailable | Complete owner identity and confirmed process state | Refuse or verification failure; never report success | process observation failure tests |
| Caller exports `COLUMNS`/`PS_FORMAT` or similar | Diagnostic commands use a fixed environment and `ps -ww`; truncated Linux argv is `unknown` | Shared owner refused; truncated arguments refuse | `terminal width variables cannot hide a shared app-server owner` |
| `ps` or `lsof` shadowed on `PATH` | Process evidence only from fixed system paths | Shadow binary never runs | `ps and lsof on PATH cannot supply process evidence` |
| Diagnostic spawn fails (`EMFILE`, synchronous throw) | Structured `spawn_error`, never an unhandled error | Evidence `unknown`; refuse before signal | runCommand spawn failure tests |
| Codex home path contains non-ASCII bytes | Owner lock matched by `lsof` device/inode, not escaped name | Correct lock set; unresolvable other locks still refuse | non-ASCII Codex home tests |
| Owner acquires another lock during the final transcript hash | Exact single-element owner lock set repeated after hashing | Refuse; zero SIGTERM; both advisory locks remain held | `late evidence refuses an extra advisory lock acquired during the final hash` |
| Transcript appends after hashing during the awaited process sample | Safe synchronous path/descriptor snapshot matches final hash and inspection before final guarded probe | Refuse; zero SIGTERM | `late evidence refuses an append after hashing during the final process sample` |
| Late owner lock-set, process, or transcript evidence fails | Unavailable evidence never authorizes signaling | Refuse; owner remains untouched | `late evidence refuses` fault cases |
| Owner or lock changes during the final transcript hash | Start time, lock identity, and probe resampled after hashing, immediately before SIGTERM | Refuse; zero SIGTERM | revalidation tests and unchanged-owner control |
| SIGTERM attempt throws ESRCH or EPERM | Failed signaling provides no independent exit evidence | `termination_failed`; null signal/exit evidence; no stronger signal | `SIGTERM ESRCH/EPERM leaves process exit evidence unavailable` |
| Signaled owner exits but its parent never reaps it | Zombie state from the same `ps` sample as the start time | Counts as exited; `processObservation.zombie: true` | `an unreaped zombie owner counts as exited` |
| Another process takes the lock right after the owner exits | Re-identify the current opener by PID/start time | `verification_failed`, `lock_reacquired_by_other_owner`, successor never signaled | `an immediate successor is reported as a reacquisition, not an unreleased lock` |
| Observation fails or throws after SIGTERM (for example `EMFILE`) | Signal-boundary results keep `pid` and `signalSent` | `termination_failed`/`verification_failed`, exit 3, no stderr | `post-signal emfile/throw failure preserves the signal in the unlock result` |
| Post-signal lock observation becomes unavailable | Confirmed OS lock release | Termination failure; never report release | post-signal lock observation test |
| Probe overlaps a coordinated writer acquisition | Existing native guard serializes thread try-lock | No probe-induced WouldBlock | deterministic barrier and bounded native writer stress tests |
| Existing thread has no usable native coordinator | No unguarded fallback or native file creation | Unknown; zero SIGTERM | absent/unsafe/busy native coordinator tests |
| Native guard or its parent is replaced | Same path/FD and parent device/inode | Unknown; descriptors released | native guard/directory replacement test |
| Native or thread descriptor cleanup fails | Successful release and close | Unknown; never report free | native release and cleanup fault tests |
| Native guard is busy at the signal boundary | One synchronous try-once, no await before kill | Refuse; zero SIGTERM | signal boundary busy test |
| Guard probe precedes SIGTERM | Guard released/closed, no microtask boundary | Verified signal timing | signal boundary verify test |
| Owner drop briefly holds native coordinator | Retry only within remaining termination budget | Eventually unlocked with unchanged transcript | shutdown guard contention test |

The operation lease is separate from `~/.codex/thread-writer-locks`. It lives
in a codex-unlock-owned `codex-unlock/` directory beside the canonical native
lock directory (normally `$CODEX_HOME/codex-unlock/`) and never inside
`thread-writer-locks`. Its file is harmless residue protected by an advisory
lock; its existence is never evidence of a native writer. The native guard is
separate: the existing `thread-writer-locks/.coordination.lock` is taken for one
synchronous probe at a time, in operation lease -> native guard -> thread probe
order. No native files are created, deleted, or rewritten. A diagnostic paused
with SIGSTOP or a debugger while holding the native guard can delay coordinated
writers until it resumes or exits; the acquisition retry timeout does not bound
that pause.

Known limitations:

- The final owner lock-set lookup, process sample, transcript snapshot, and
  native lock probe are separate observations. Repeating them after hashing
  narrows independent-writer windows but does not make them atomic with
  SIGTERM. A writer can still acquire a lock or modify the transcript after
  its last observation. The transcript snapshot checks metadata and file
  identity; it is not another full hash. Post-signal verification remains
  necessary and cannot retroactively turn such a race into pre-signal refusal.
- Versions 0.4.0 and earlier placed the lease under `$XDG_RUNTIME_DIR` or the
  temporary directory. An older and a newer `codex-unlock` running at the same
  time for the same thread do not see each other's lease. Upgrade every copy
  that may run concurrently, for example in cron jobs.
- A `thread-writer-locks` directory reached through a bind mount of that
  directory alone has a different canonical parent from the original path. The
  lease key still matches, but the two paths use different lease directories.
  Aliases through symlinks, case-insensitive spellings, or a mount of the whole
  Codex home are coordinated.

## Process instance identity limits

The current macOS/Linux identity sample is `ps -ww -p <pid> -o lstart=`.
`src/process.ts` accepts a parseable start-time string and compares it for
equality; the final signal still uses Node's numeric `process.kill(pid,
"SIGTERM")`. The native guard is released before that call, with no intervening
`await`. This narrows the observation gap, but does not bind the signal atomically
to the instance observed by `ps`. PID reuse after the sample can target a
replacement. Even reuse between samples can be indistinguishable if both
instances have the same second-resolution label. Post-signal verification cannot
undo a misdirected signal. Unavailable identity is `unknown`, never evidence of
exit or permission to signal.

On Linux, [procps-ng 4.0.4's formatter](https://gitlab.com/procps-ng/procps/-/blob/v4.0.4/src/ps/output.c#L975-988)
adds boot time to integer-divided start ticks and formats seconds. A boot-time
or clock interpretation change between separate `ps` invocations can therefore
change a live instance's label. That is an earlier known concern, not a
clock-step reproduction in this work. The current exit comparator interprets
different labels as different instances; the separate lock-release check is
still required. It does not establish that every NTP correction changes a label.
macOS exposes a stored process start timestamp through its kernel interfaces;
the Linux boot-time computation must not be assumed to describe macOS.

### Bounded evidence, 2026-10-09

`node scripts/research-process-identity.mjs` launches four disposable Node
children, samples their `lstart`, and ends them through stdin EOF. Each child
also exits automatically after 10 seconds; no identity test sends a signal,
changes the clock, or uses a Codex process. Darwin 27.0.0 arm64 / Node 24.16.0
returned the same second label for all four distinct PIDs. That demonstrates
display resolution, **not** same-PID reuse or a wrong-target signal. On Linux
the script also records `/proc/<pid>/stat` field 22 so distinct ticks can be
compared within equal-label groups. No Linux measurement is claimed solely
from the macOS run; the script is reproducible on supported Linux hosts.

The pure observation tests inject distinct instance ticks with equal labels,
changed labels, absence, and unavailable identity. They demonstrate what the
existing comparator can and cannot distinguish, without trying to exhaust a
PID namespace or induce a real race. Existing real-lock refusal tests continue
to establish observed start-time changes and unavailable samples as refusals.

### Stronger evidence assessment

| Candidate | Benefit | Compatibility and remaining limits |
| --- | --- | --- |
| Linux `/proc/<pid>/stat` field 22 | Boot-relative start ticks avoid wall-clock formatting and preserve more resolution | Parse after the final `)` of `comm`; compare in one boot and PID namespace/proc mount. A missing, denied, malformed, or inconsistent sample must be unknown. Ticks are still finite-resolution samples, not an atomic signal binding. |
| Linux `pidfd_open` + `pidfd_send_signal` | A retained handle sends to the referenced process instance, not a recycled numeric PID | Requires Linux 5.3 for open and 5.1 for send, syscall access, permission, and a compatible namespace. Acquire the handle before gathering evidence and validate that evidence against it; opening after validation alone can capture a replacement. ESRCH/EPERM/ENOSYS/resource errors must refuse without numeric fallback. Descriptor inheritance does not identify which process holds a native flock. |
| macOS `proc_pidinfo(PROC_PIDTBSDINFO)` | `proc_bsdinfo` exposes start seconds and microseconds, improving a sampled identity | The public SDK's [structure](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info.h) still returns a sample keyed by numeric PID; access and size checks are required. Greater resolution does not bind a later numeric signal. |
| macOS audit-token/Mach termination APIs | Some OS interfaces carry stronger process references | They are not an established Node 22/24 SIGTERM-only equivalent here. The SDK declares audit-token termination interfaces, but their public support/permissions and chosen signal require separate investigation. Mach task termination is not SIGTERM and is outside this tool's policy. |

Sources: [Linux start ticks](https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html),
[pidfd acquisition](https://man7.org/linux/man-pages/man2/pidfd_open.2.html),
[pidfd signaling and namespaces](https://man7.org/linux/man-pages/man2/pidfd_send_signal.2.html),
and [Node numeric signaling](https://nodejs.org/docs/latest-v24.x/api/process.html#processkillpid-signal).
Node's supported API does not expose the proposed pidfd transaction; adopting
a native adapter needs a separate design, supported-platform tests, and review.
This assessment retains the current implementation and its stated residual
assumptions. It does not claim that higher-resolution samples eliminate races.
