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
| Post-signal lock observation becomes unavailable | Confirmed OS lock release | Termination failure; never report release | post-signal lock observation test |

The operation lease is separate from `~/.codex/thread-writer-locks`. It lives
in a codex-unlock-owned `codex-unlock/` directory beside the canonical native
lock directory (normally `$CODEX_HOME/codex-unlock/`) and never inside
`thread-writer-locks`. Its file is harmless residue protected by an advisory
lock; codex-unlock never deletes or interprets a native Codex lock file as
coordination state.

Known limitations:

- Versions 0.4.0 and earlier placed the lease under `$XDG_RUNTIME_DIR` or the
  temporary directory. An older and a newer `codex-unlock` running at the same
  time for the same thread do not see each other's lease. Upgrade every copy
  that may run concurrently, for example in cron jobs.
- A `thread-writer-locks` directory reached through a bind mount of that
  directory alone has a different canonical parent from the original path. The
  lease key still matches, but the two paths use different lease directories.
  Aliases through symlinks, case-insensitive spellings, or a mount of the whole
  Codex home are coordinated.
