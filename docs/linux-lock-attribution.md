# Linux descriptor participation

Linux `live_owner` classification requires positive evidence of a granted,
whole-file exclusive advisory FLOCK in the candidate's `/proc/PID/fdinfo/FD`.
The kernel's acquisition PID is not compared with the candidate: inherited
descriptions can retain the acquiring PID. A positive row proves participation
by a description, not exclusive lifetime control or complete system visibility.
Existing unique-opener, same-user, process-mode, transcript and lock-set checks
remain necessary. Multiple visible candidates are refused.

Descriptor names are prepared outside native coordination. Under coordination,
the independent nonblocking thread probe must report held; synchronous reads
then verify the descriptor's actual target, granted lock row and process start
ticks, rechecking identity and descriptor enumeration afterward. Collection
allows at most 256 descriptors, 64 KiB per proc file and 25 ms of monotonic
elapsed time. These are fail-closed budgets, not a hard filesystem I/O deadline.
No child process, await or signal runs while coordination is held.

Only direct local ext-family, tmpfs and XFS filesystem mappings are accepted.
Btrfs, overlay, network and FUSE filesystems are unknown; their exposed stat
device/inode may differ from the lock table. Device and inode comparisons use
BigInt throughout. Missing, denied, malformed, changed, truncated, oversized,
unsupported and ambiguous evidence remains unknown. `/proc/self` must match
the running PID, rejecting a visibly inconsistent proc PID namespace.

Process start ticks are sampled around command/identity collection, across
inspection samples and in the final synchronous guarded sample before signal.
Coordination is released before the existing SIGTERM operation. `kill(pid)`
still has a residual process-replacement window; this adapter adds no pidfd.
Hidden references (including mmap, in-flight SCM_RIGHTS and io_uring registered
files) are not enumerable by this evidence. Post-signal actual release and
transcript verification remain mandatory. This is not owner-cooperative
release and does not establish Windows or macOS positive attribution.

JSON v1 adds optional `owner.startTicks` and
`lock.probe.participation` (`pid`, `startTicks`, `descriptor`). Consumers must
not interpret participation as independent permission to terminate a process.
