# Linux descriptor participation

Linux `live_owner` classification requires positive evidence of a granted,
whole-file exclusive advisory FLOCK in the candidate's `/proc/PID/fdinfo/FD`.
The kernel's acquisition PID is not compared with the candidate: inherited
descriptions can retain the acquiring PID. A positive row proves participation
by a description, not exclusive lifetime control or complete system visibility.
Existing unique-opener, same-user, process-mode, transcript and lock-set checks
remain necessary. Multiple visible candidates are refused.

Opener/identity samples are collected before attribution probes, not atomically
with those probes. Each later guarded attribution is tied to its original
inspected file snapshot and sampled process start ticks; changing evidence is
refused. This does not establish atomic visibility across both sample windows.

Descriptor names and readlink-only candidate paths are prepared outside native
coordination. Candidate and observer mount namespaces must match. Paths are
negative filters, never positive lock evidence; FD paths that do not match the
prepared target path are excluded from stat while holding coordination. This
reduces unrelated FUSE/NFS exposure but is not proof against overmounted paths
that retain identical kernel path strings. Under coordination,
the independent nonblocking thread probe must report held; synchronous reads
then verify the descriptor's actual target, granted lock row and process start
ticks, rechecking identity and descriptor enumeration afterward. Collection
allows at most 256 descriptors, 64 KiB per proc file and 25 ms of monotonic
elapsed time. These are fail-closed budgets, not a hard filesystem I/O deadline.
Even proc cmdline reads can wait for the target's memory-map lock or remote
pages; matching-path FD metadata can also block. A stalled synchronous syscall
can therefore retain native coordination beyond the advertised work budget.
This liveness risk is a remaining draft acceptance gate, not a solved bound.
No child process, await or signal runs while coordination is held.
The final budget check occurs after the final target sample, before a positive
result is returned. Linux CI must execute positive participation fixtures on a
supported filesystem; unsupported CI storage fails, not silently skips.

Only direct local ext-family, tmpfs and XFS filesystem mappings are accepted.
Btrfs, overlay, network and FUSE filesystems are unknown; their exposed stat
device/inode may differ from the lock table. Device and inode comparisons use
BigInt throughout. Missing, denied, malformed, changed, truncated, oversized,
unsupported and ambiguous evidence remains unknown. `/proc/self` must match
the running PID, rejecting a visibly inconsistent proc PID namespace.

Process start ticks are sampled around command/identity collection, across
inspection samples and in the final synchronous guarded sample before signal.
An optional SHA-256 command fingerprint of bounded raw argv bytes and the
executable readlink value is bound to these same samples. It detects observed
same-PID argv/image changes without statting the executable's filesystem, but
does not prove that an exec/re-exec never occurred between observations.
Coordination is released before the existing SIGTERM operation. `kill(pid)`
still has a residual process-replacement window; this adapter adds no pidfd.
Hidden references (including mmap, in-flight SCM_RIGHTS and io_uring registered
files) are not enumerable by this evidence. Post-signal actual release and
transcript verification remain mandatory. This is not owner-cooperative
release and does not establish Windows or macOS positive attribution.

JSON v1 adds optional `owner.startTicks` and
`owner.commandFingerprint` and `lock.probe.participation`
(`pid`, `startTicks`, `descriptor`). Consumers must
not interpret participation as independent permission to terminate a process.

## Native Codex and draft acceptance gates

The pinned Codex
[process-hardening implementation](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/process-hardening/src/lib.rs#L43-L60)
sets `PR_SET_DUMPABLE` to zero on Linux when called. This library behavior alone
does not establish that an ordinary thread-lock owner calls it. Verified callers
include the
[responses API proxy](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/responses-api-proxy/src/main.rs#L4-L7),
[voice host](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/voice-host/src/main.rs#L48-L49),
and [sandbox host bridge](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/linux-sandbox/src/proxy_lifecycle.rs#L116-L120).
The inspected [CLI entry point](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/cli/src/main.rs#L1031-L1039)
does not directly call these hardening functions. This is a targeted source
check, not an exhaustive call-graph proof or a measurement of the deployed
owner's dumpability; helper dispatch, launch context and procfs policy still
matter. If a candidate is non-dumpable, descriptor/executable access can be
denied even for a same-user observer; proc-directory UID alone is not proof of
accessibility. A passing same-user Node fixture cannot establish native access.
The implementation fails closed; it never requests elevated access or changes
dumpability. The native release binary's positive or intentionally refused
behavior has not been measured by these tests.

Before this draft can become release-ready, record actual Linux supported-FS
positive and full-unlock refusal tests, the native hardening/dumpability boundary,
and a reviewed solution or explicit policy for guard liveness exposure. A
passing Node fixture or CI build alone is insufficient. Additional denied,
namespace, budget and replacement matrix coverage remains required for closing
#126. Known PID signaling and same-executable re-exec limitations are not solved.
