# macOS lock attribution decision proposal

Issue [#127](https://github.com/abruption/codex-unlock/issues/127) concerns
**which process holds a lock**, not whether the existing guarded OS probe can
observe it. This document proposes a disclosed correlation contract for human
review. It changes no runtime policy, platform support, or signal behavior.
It does not resolve [#100](https://github.com/abruption/codex-unlock/issues/100)
as an implemented holder-attribution fix.

## Proposed decision and current limitation

Retain the current macOS behavior only as an explicitly documented
opener-correlation contract while stronger attribution is investigated. This
is a proposal, pending human review of the residual wrong-target risk, not
approval of that risk or a new recovery guarantee. Removing macOS recovery,
or requiring a new native evidence adapter, needs a separately reviewed runtime
change; neither happens incidentally through this document.

The current `live_owner` result combines a held guarded probe with a unique,
stable, identity-complete visible opener. `safeToUnlock` is the current policy's
eligibility decision, not proof that the selected process holds the flock.
Known errors, ambiguity, and changing evidence still refuse recovery. However,
clean incomplete discovery is not necessarily detected: those refusals are not
a guarantee against silent holder omission.

The [attribution research](research-lock-attribution.md) measured an omitted
foreign-UID synthetic holder with a visible same-user nonholder and no lsof
diagnostic error. The [interleaving fixture](../scripts/fixtures/attribution-interleaving/README.md)
also demonstrates an eligible synthetic Codex-looking **nonholder** when a
holder is deliberately omitted from discovery. That latter experiment injects
omission and sends no signal; it is not a reproduction of an actual Codex
wrong-target termination. Together they invalidate the stronger claim that
unique opener plus held probe necessarily establishes holder identity.

## Why native coordination alone does not establish a holder

At pinned Codex revision
[`092d3acd`](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/rollout/src/writer_lock.rs),
acquisition opens a thread file and attempts its lock under the native
coordinator. A failed acquisition's local file is dropped before that scope
exits. Stale cleanup and publication probes also run under coordination; a
successful writer retains its thread file. Writer drop reacquires coordination,
closes that retained file, and removes the stale pathname.

These source lifetimes do not show a Codex failed-acquisition FD retained
indefinitely. They do permit temporary nonholding opens during coordinated
operations. Our lock probe is coordinated; subprocess opener discovery is
outside that synchronous guard. Samples from separate moments do not become
an atomic holder observation merely because each individual sample is valid.
Holding the guard across lsof spawn or waits is not an acceptable fix: the
existing synchronous-guard invariant must remain intact.

## Evidence inventory

The additional 2026-10-13 same-user experiment used synthetic C/Python fixtures
on APFS, macOS 27.0.1 arm64 (build 26A434), running XNU 13432.1.9, with lsof
4.91. The supplied raw log was inspected without rerunning the experiment.
Its SHA-256 is
`0a310ff504b046d15caa229ec4a2cad5a3706b46b0ff3c78da72885b2f849497`.
This is separate from the older macOS CI foreign-UID measurement in
[run 37862990217](https://github.com/abruption/codex-unlock/actions/runs/37862990217).
No private account, path, or production PID is needed to interpret the results.

| Case | Evidence level | Result and limit |
| --- | --- | --- |
| Same-user actual fixture holder | Measured, same-user APFS | Guard-independent flock check reports held; `F_GETLK`, `F_GETLKPID`, and `F_OFD_GETLK` report a conflicting write lock with PID -1, even for the holder's own query |
| Independent nonlocking opener or failed acquirer retaining an FD | Measured, same-user APFS | lsof lists both processes; only the holder's description has `FWASLOCKED`; this distinction is not a portable ownership API |
| Original acquirer exits, forked child retains description | Measured, same-user APFS | Lock remains held; child retains `FWASLOCKED`; original process identity does not control the description's full lifetime |
| Former holder unlocks but retains FD; new holder acquires | Measured, same-user APFS | Both descriptions retain `FWASLOCKED`; the bit cannot select the current holder |
| Former holder alone, lock now free | Measured, same-user APFS | `FWASLOCKED` remains set despite successful free probe |
| Foreign-UID holder omitted from opener discovery | Measured, separate macOS CI fixture | Held probe plus unique visible nonholder and clean lsof output; not measured with `FWASLOCKED` in the additional same-user experiment |
| PID replacement, FD reuse, or changing file identity | Not measured by that API experiment | Existing revalidation narrows observation windows; it is not atomic holder-to-signal binding |
| Denied libproc access or non-dumpable target | Source-supported visibility concern; not a new permission experiment | A missing record must not count as a negative ownership proof; older foreign-UID CI evidence remains independently scoped |
| SMB/NFS, other filesystems, other macOS kernels | Untested | Do not extrapolate APFS or the tested kernel's flags |

`lsof -F l` was blank for the tested holder and nonholder. `lsof +fg` exposed
the same historical bit through its `G` field. `proc_listpidspath` and fuser
enumerated openers; the tested `NOTE_FUNLOCK` kqueue event indicated release,
not a process identity. This bounded investigation established no unique
current-holder primitive among those tested APIs. It is **not** an exhaustive
proof that no present or future macOS API can provide one. DTrace and Endpoint
Security were not exercised; no privileges, SIP settings, or entitlements were
changed.

The supporting public XNU source is older than the running kernel:
[`ac9718fb`, xnu-12377.121.6](https://github.com/apple-oss-distributions/xnu/tree/ac9718fb1af618d5ce8678d0dc6e8a58f252216f).
Its [getlock logic](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/kern/kern_lockf.c#L1174-L1180)
reports PID -1 for non-POSIX lock ownership; its
[flock path](https://github.com/apple-oss-distributions/xnu/blob/ac9718fb1af618d5ce8678d0dc6e8a58f252216f/bsd/kern/kern_descrip.c#L6038)
sets `FWASLOCKED`. Inspection of that source found no corresponding clearing
operation. Source supports interpretation, but the supplied runtime observations
are the evidence for sticky flags on the tested kernel.

## Rejected shortcuts

- Do not treat PID -1, blank lsof lock fields, or clean stderr as positive
  process attribution or complete visibility.
- Do not adopt `FWASLOCKED` as a holder-positive rule. Its measured sticky
  behavior allows a previous holder to look current. Even a refusal-only
  experiment would require a separate reviewed adapter, supported ABI and
  permission behavior, and a Codex descriptor-lifetime audit; none is adopted
  here.
- Do not infer unique lifetime control from one inherited-description user.
  Killing one visible process might leave another reference alive. Post-signal
  release verification cannot undo an incorrect signal.
- Do not replace these limits with a language claim. Rust can expose native
  APIs but does not manufacture unique holder evidence. This document does not
  enable Windows support or Windows automatic recovery.

## Acceptance gates for a stronger contract

1. Define the signal authorization claim and visibility assumptions separately
   from held/free detection. A candidate's unavailable, denied, ambiguous,
   malformed, changed, or unsupported evidence must refuse recovery.
2. Validate a current-holder native primitive, or an authenticated cooperative
   owner endpoint that releases the exact idle thread without selecting an
   opener for termination. The
   [upstream handoff proposal](upstream-handoff-proposal.md) is a proposal, not
   an implemented Codex API or a statement of universal impossibility.
3. Exercise hidden holder/visible nonholder, failed and former acquirers,
   inherited descriptions, permissions, PID/FD/file replacement, and supported
   filesystem/version boundaries. Assert zero signals for refused cases using
   owned synthetic processes, not real Codex sessions.
4. Preserve lock ordering and synchronous guard sections. Revalidate process
   instance, positive attribution, exact lock identity, single-thread scope,
   and completed stable transcript at the signal boundary. Document residual
   non-atomic PID signaling assumptions explicitly.
5. Require real macOS evidence plus supported CI, compatibility and packaging
   checks, independent review, and human approval before altering support or
   claiming #127 closes the attribution implementation gap. No force, native
   file deletion, unguarded fallback, or SIGKILL may be added.

Until those gates pass, this proposal records the current limitation rather
than shipping a false stronger fail-closed promise.
