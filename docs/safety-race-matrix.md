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
| Two CLI unlocks inspect the same safe owner | One private advisory operation lease per canonical home/thread | Exactly one SIGTERM; competitor refused | `concurrent CLI unlock attempts send at most one SIGTERM` |
| Operation lease cannot be established | Private same-user directory and regular non-symlink lock file | Refuse; owner remains alive | `coordination failure refuses without signaling the safe owner` |
| Process inspection becomes unavailable | Complete owner identity and confirmed process state | Refuse or verification failure; never report success | process observation failure tests |
| Post-signal lock observation becomes unavailable | Confirmed OS lock release | Termination failure; never report release | post-signal lock observation test |

The operation lease is separate from `~/.codex/thread-writer-locks`. Its file
is harmless residue protected by an advisory lock; codex-unlock never deletes
or interprets a native Codex lock file as coordination state.
