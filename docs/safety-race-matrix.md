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
