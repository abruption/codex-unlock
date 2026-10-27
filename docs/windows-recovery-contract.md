# Windows holder attribution and cooperative release contract (W4/W5 design record)

Status: **proposed design, research only.** This record belongs to
[#149](https://github.com/abruption/codex-unlock/issues/149) (W4) and
[#150](https://github.com/abruption/codex-unlock/issues/150) (W5). It builds on
[windows-rust-evaluation.md](windows-rust-evaluation.md) (sections 3 and 5) and
[upstream-handoff-proposal.md](upstream-handoff-proposal.md). It does not add
Windows support, change the production CLI, JSON v1, the npm artifact or
[platform-support.md](platform-support.md). Every experimental record keeps
`safeToUnlock=false`. Nothing here authorizes unlocking, signaling,
terminating, releasing or deleting anything on Windows.

Evidence levels:

- **Source-pinned**: read at a fixed revision. The verifier checks its listed
  bytes, anchors and literal searches (section 9), not every interpretation.
  It explains code paths; it is not a runtime measurement, and a
  targeted read is not an exhaustive audit.
- **Measured**: none in this record. No Windows host, real Codex binary,
  Codex home or process was used. References to #133 are inherited fixture
  observations, not measurements repeated for this record.
- **Hypothesis**: a stated expectation that a future W7/W5 run must compare
  against. Treat as unverified.

## 1. Pins

| Item | Value |
| --- | --- |
| Upstream release | `rust-v0.163.0`, commit [`83086188ae0614bd882818ff1aa23f3194962012`](https://github.com/openai/codex/tree/83086188ae0614bd882818ff1aa23f3194962012) (same pin as [windows-rust-evaluation.md](windows-rust-evaluation.md) section 2) |
| Upstream toolchain | Rust 1.95.0 (`codex-rs/rust-toolchain.toml:2`) |
| Rust std | tag `1.95.0` → commit `59807616e1fa2540724bfbac14d7976d7e4a3860`, [`library/std/src/sys/fs/windows.rs`](https://github.com/rust-lang/rust/blob/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/fs/windows.rs), SHA-256 `e26633635161814b3e9bd75a50cf0bbe2d90d55c9342e3adcbced16d6b024099` |
| Verifier | [`experimental/windows-release-contract/verify-upstream.mjs`](../experimental/windows-release-contract/verify-upstream.mjs): 26 upstream file digests, 110 line anchors, 13 literal searches, plus 11 Rust std anchors |

Upstream paths below are relative to `codex-rs/` at the pinned commit unless
stated otherwise. Lines are paraphrased.
The toolchain configuration and Rust tag mapping are source evidence, not
proof of the std library linked into a distributed Codex binary. W7 must
record available binary/build provenance and runtime observations separately.

## 2. Source-pinned facts

### 2.1 Lock primitive on Windows (Rust std 1.95.0)

| Fact | Location | Consequence for this contract |
| --- | --- | --- |
| Default share mode is read, write **and delete** | `std sys/fs/windows.rs:206` | Including delete sharing avoids introducing a share-delete denial through that handle. Other handles, permissions and filesystem semantics can still prevent deletion or leave a name delete-pending (H5.3) |
| Handles are created non-inheritable unless requested | `std:209`, `357` | Writer-lock handles are not inherited by children created through ordinary spawning. Duplication by another party remains possible (section 5) |
| `File::lock` / `try_lock` use `LockFileEx` over offset 0, length `u32::MAX:u32::MAX`; `try_lock` adds `LOCKFILE_FAIL_IMMEDIATELY` | `std:417-422`, `458-466` | A Windows probe must test an overlapping exclusive range. The fs-ext `0..0xffff0000` emulation also conflicts (Win32 33 in the #133 fixture), but range equivalence against a real Codex is W7 |
| `remove_file` is `DeleteFileW` with a fallback | `std:1288-1289` | Delete semantics (POSIX versus delete-pending) depend on OS version and file system; unverified (W7) |

Targeted search did not find upstream code that marks writer-lock handles
inheritable or duplicates them. The matches for `SetHandleInformation` and
`DuplicateHandle` concern standard handles, pipes and sandboxed file opens
(for example `app-server-daemon/src/backend/windows.rs:77`).

### 2.2 Writer lock lifecycle

| Step | Location |
| --- | --- |
| Acquire takes the coordination lock first, opens `<thread-id>.lock`, nonblocking `try_lock`; `WouldBlock` means an active writer | `rollout/src/writer_lock.rs:43-44`, `52`, `65-67` |
| Coordination lock is a **blocking** exclusive lock on `thread-writer-locks/.coordination.lock` | `writer_lock.rs:116` |
| Publication probes under coordination and returns the coordination guard to the caller; that guard can outlive the short thread-file probe | `writer_lock.rs:88-106`; caller lifetime needs separate assessment when choosing observation budgets |
| Stale cleanup removes only unlocked thread files, once per coordinator | `writer_lock.rs:124-171` |
| `Drop`: take coordination (blocking), close the file, remove the name, release coordination. If coordination fails, it returns early and the file is closed by field drop without removal | `writer_lock.rs:174-194`, `176-180` |
| The guard lives in `Arc` clones held by the live entry and the writer task; the last clone's drop releases it | [windows-rust-evaluation.md](windows-rust-evaluation.md) section 3.1; writer task `rollout/src/recorder.rs:148`, `1018`; entry removal `thread-store/src/local/live_writer.rs:169`, `207` |

### 2.3 Ordinary non-v2-child release path (app-server)

This traces the ordinary unload branch. The separate v2-child branch calls
`try_evict_v2_thread` and handles `Busy`, `NotCurrent` and errors
(`thread_lifecycle.rs:419-470`); its complete teardown is not traced here.

1. `thread/unsubscribe` (`app-server-protocol/src/protocol/common.rs:580`) is
   handled at `app-server/src/request_processors/thread_processor.rs:1034`. It
   removes **only the calling connection** (`thread_processor.rs:1051`;
   `app-server/src/thread_state.rs:557`, `571`, `583`). It cannot remove other
   connections' subscriptions.
2. The unload target exists only with no subscribers **and** not active, plus
   `thread_unload_delay` (`thread_lifecycle.rs:59-62`). The default is 1800 s
   (`core/src/config/mod.rs:4032`), set by the owner's own
   `thread_unload_delay_secs`. A running agent defers unload (`thread_lifecycle.rs:405`).
3. `unload_thread_without_subscribers` (`thread_lifecycle.rs:559`) cancels
   pending server-to-client requests (`573`), calls `shutdown_and_wait`
   (`580`), warns after 10 s and keeps waiting without a bound (`582`, `591`).
4. `Op::Shutdown` reaches `handlers::shutdown` (`core/src/session/handlers.rs:716`,
   `350`), then the thread store's `shutdown_thread`
   (`live_writer.rs:169`). Only successful recorder shutdown and path
   synchronization reach live-entry removal (`178-192`, `207`). The handler
   can emit `ShutdownComplete` even after shutdown failed (`handlers.rs:366-391`).
5. Only if the runtime still matches (`thread_lifecycle.rs:599`; a replaced
   runtime skips it) the server emits `thread/closed` (`614`; method
   `common.rs:1958`). This notification is not a lock-release acknowledgement.
6. The guard drops when the last `Arc` clone is gone (section 2.2).

Destructive alternatives that also shut a thread down, `thread/archive` and
`thread/delete` (`prepare_thread_for_removal`, `thread_processor.rs:1069`),
change persisted state and are excluded.

### 2.4 Process-wide paths and why they are excluded

| Path | Location | Reason for exclusion |
| --- | --- | --- |
| Windows app-server shutdown signal | `app-server/src/lib.rs:218`, `233-242` | On Windows the only source in `shutdown_signal` is `tokio::signal::ctrl_c`, a **console control event**. A second forceable signal sets `forced` (`263-264`). Injecting console control events is excluded |
| Managed `/daemon/shutdown` on the control socket | `app-server-transport/src/transport/unix_socket.rs:180-181`, `221-222`; `lib.rs:1126-1127` | Managed servers only; the echoed server PID is confirmation, not a secret. It sends a Forceable signal: the first requests whole-process drain, a subsequent forceable signal can mark shutdown forced |
| Graceful versus forced exit | `lib.rs:1338-1349` | Graceful exit runs shutdown_threads for all threads with a 10 s bound each. Forced exit skips that cleanup. Actual lock release/timing and duplicated-handle effects require H4.4/H5.4; lock-file names can remain |
| Windows updater shutdown file | `app-server-transport/src/daemon_shutdown.rs:1`, `14`, `40`; `app-server-daemon/src/backend/pid.rs:205` | Daemon-private, process-wide, for the updater process |
| Daemon `stop_with_grace` | `pid.rs:162`, `199`, `221-235`; `backend/windows.rs:247` | Calls `TerminateProcess` if the tracked process remains active when the grace period expires |
| In-process app-server teardown (embedded TUI / `exec`) | `app-server/src/in_process.rs:595`, `599` | Owner-client teardown calls cleanup for every thread. It is a candidate for R1 diagnostic observation after W7; the call does not prove exactly one owned thread, normal exit or successful cleanup |

### 2.5 Transport authentication available at the pin

| Mechanism | Location | What it proves | What it does **not** prove |
| --- | --- | --- | --- |
| Private control-socket directory on Windows (owner = current SID, protected DACL, exactly one inheritable full-access ACE; final socket directory must not be a reparse point; directory handle pinned while connecting) | `unix_socket.rs:88-93`; `uds/src/windows_security.rs:38`; `uds/src/windows_socket_validation.rs:43-58`, `69`, `117`, `119` | Restricts ordinary access to the current user; ancestor junctions are canonicalized and followed, and privileged principals can bypass DACLs | That the listener holds any thread's writer lock or that all ancestors were opened no-follow |
| Client-side peer check: kernel peer PID via `SIO_AF_UNIX_GETPEERPID`, then same token user SID and neither side elevated | `uds/src/windows_peer.rs:25`, `31`, `53`, `75`, `95`; used by `app-server-client/src/remote.rs:174`, `188`, `811` and `tui/src/lib.rs:542` | Checks SID/elevation on the process subsequently opened by that numeric PID; these are separate observations | Atomic connection-to-process-instance binding (no creation-time comparison; PID reuse between ioctl and OpenProcess is not excluded); an explicit endpoint skips the check (`remote.rs:809`) |
| Server-side kernel peer check of the connecting client | not observed in the inspected control-socket accept/upgrade path (`unix_socket.rs:140-211`); this is a bounded manual read, not one of the 13 literal searches or a whole-server audit | No additional kernel peer binding established by this review | Other authentication layers have not been exhaustively traced. The auth field in run_websocket_connection is not itself evidence for or against peer authentication |
| WebSocket listener auth (`capability-token`, `signed-bearer-token`), required for non-loopback | `websocket.rs:111`, `135`; loopback banner `70` | The client holds a configured token | Owner, thread or lock binding. Loopback listeners may run without auth |

`ConnectionAuth` (`app-server-transport/src/connection_auth.rs:1`, `41`) tracks
the login owner generation for Remote Control. It is not peer identity.

### 2.6 Owner self-reports available at the pin

| Report | Location | Status for W4 |
| --- | --- | --- |
| `thread/loaded/list` | `common.rs:853`; `thread_processor.rs:2887`, `2894` | The server's `ThreadManager` view of loaded threads. A claim, not a lock measurement |
| `server/diagnostics` `process.id` | experimental (`common.rs:506-508`); `v2/diagnostics.rs:22-23`; `request_processors/diagnostics.rs:10` | Self-reported PID; requires the experimental capability; no creation time, no lock binding |
| `thread/closed` | `thread_lifecycle.rs:614` | Conditional notification; neither presence nor absence measures OS lock state |

### 2.7 Targeted searches

Literal `git grep -F` over `codex-rs/*.rs` at the pin (verifier `SEARCHES`):
`thread/release`, `thread/handoff`, `thread/unload`, `"thread/close"`,
`thread/writer`, `writerLock`, `RmGetList`, `RmStartSession`,
`GenerateConsoleCtrlEvent` and `AttachConsole` returned zero matches. Positive
controls `"thread/unsubscribe"`, `"thread/loaded/list"` and
`SIO_AF_UNIX_GETPEERPID` matched. **An external method that releases a given
thread's writer lock, or that attests which process holds it, was not found in
this targeted search.** That is not a proof of absence; recheck on every
upstream re-pin.

## 3. W4: holder attribution contract

### 3.1 Definitions

- **Holder**: the process instance responsible for the granted exclusive
  `LockFileEx` range on `<thread-id>.lock`. The relation to duplicated handles
  is still a W4 hypothesis. A busy probe establishes a conflicting lock, not
  the holder's identity or sole control of its lifetime.
- **Opener**: any process reported with an open handle to that file.
- **Positive single-holder evidence**: evidence that names exactly one process
  instance as the holder and excludes every non-holder opener, the prober and
  the orchestrator.

### 3.2 Sources evaluated

| Source | Classification | Decision |
| --- | --- | --- |
| Restart Manager (`RmGetList`) | Openers (E3 `opener_candidates_only`) | **Never promoted** to holder evidence, including a one-element list |
| System handle enumeration | Candidate handle/open-file evidence; access requirements and lock-owner semantics were not measured here | Out of scope; never promoted |
| Elimination ("exactly one other opener while busy") | Would require a provably complete opener set and known semantics for duplicated handles | **Rejected**: completeness across integrity levels, services and third-party filters cannot be established, and duplicate-handle lock semantics are unverified (H4.4) |
| OS query of a byte-range lock owner | No positive primitive was established by this research; this is not an exhaustive Win32 API survey | Unverified and unavailable to this design |
| Owner-cooperative attestation over an authenticated endpoint | Owner claim bound to kernel peer identity, thread and lock-file identity | **Only candidate.** Requires an upstream attestation that was not found at the pin (section 7) |

Research decision for this design: without established positive evidence, the
result remains `unknown` for an opener-targeted action. This is not a proof
that every Windows attribution approach is impossible. Opener lists stay
diagnostic output only.

### 3.3 Owner-cooperative binding contract (proposal)

The proposal records a bound owner claim only when **all** of B1-B8 hold, in
this order, within one operation lease. It does not yet establish the
single-holder requirement. Any failure is `unknown`; nothing is retried with a
weaker check. The following endpoint and nonce requirements are proposed
upstream behavior, not supported APIs at the pin.
Preflight the available endpoint and mode evidence before connection or
attestation: forbidden or unverified modes are refused. B8 revalidates that
decision; its position in the binding table does not postpone the preflight.

| Id | Requirement |
| --- | --- |
| B1 | Gates W1 (file identity), W2 (SID/DACL), W3 (process identity) and W6 (claimed integrity level) are resolved for the environment |
| B2 | Endpoint belongs to the target owner in the **same** `CODEX_HOME`, with private-directory validation and a directory handle pinned through connect. The default daemon socket is not evidence that a standalone embedded owner exposes an endpoint; no eligible standalone endpoint was established at the pin. Providing one is additional upstream work. Explicit, loopback WebSocket and Remote Control endpoints are refused |
| B3 | Proposed process-instance binding uses kernel peer PID, an open process handle, creation time, token SID and non-elevated context. W6 must also establish the supported integrity/AppContainer pairing; non-elevated alone does not establish equal integrity. Re-query peer PID and handle liveness as supplemental checks. Repeated numeric PID alone does not close the pre-OpenProcess reuse window or prove which instance wrote a response; W3/W7 must establish connection-to-instance binding before this condition can pass |
| B4 | Probe 1 uses the existing validated `.coordination.lock`; missing/unsafe coordination is unknown. Open guard/thread with OPEN_EXISTING, no-follow validation and FILE_SHARE_READ/WRITE/DELETE, never creating either. Record thread identity (volume serial + 128-bit file ID, link count 1), require busy, then close the thread handle before releasing coordination |
| B5 | Attestation echoes the client request ID and thread ID, names the process instance, runtime generation, guard generation, lock-file identity and transcript revision, and reports `held=true`. A fresh, expiring, single-use nonce binds this exact tuple to the authenticated connection (section 7) |
| B6 | Attested process ID/creation time equal B3 and lock identity equals B4. The attested transcript revision must map to the exact P3 transcript path/file identity, size, SHA-256 and last-record baseline; an opaque revision with no proven mapping is unknown before any request |
| B7 | Probe 2 under coordination repeats B4 with the same identity and busy state; B3 handle still unsignaled. These are two samples, not continuous ownership evidence. Request-time state and nonce validation must happen atomically at the owner (section 7) |
| B8 | Mode classification (W3): standalone owners only, unless a separate reviewed amendment of the AGENTS.md safety invariants admits a thread-scoped release from a shared app-server (R2). Daemon, Remote Control and ambiguous owners are refused |

The experimental proposal would record `owner_bound_claim`: a claim checked against selected
process and file observations. B1-B8 do not exclude duplicated handles or
hidden references and therefore do not prove a single holder. H4.4/H5.4 and
the chosen cooperative-release semantics remain gates. Even a successful
duplicate-handle experiment would not prove arbitrary third-party copies
absent. The proposal does not claim protection against a lying same-user
endpoint, nor does that trust assumption remove ordinary timing races.

### 3.4 Record forms and hypotheses (synthetic first)

Records follow the E3 JSONL shape: `case`, `hypothesis`, `outcome`
(`match`/`mismatch`/`recorded`/`error`), `classification`
(`opener_candidates_only`, `owner_bound_claim`, `unknown`),
`candidates[]` (PID, creation time, SID, integrity, role), `prober`,
`orchestrator`, `lockIdentity`, `safeToUnlock` (always `false`).

| Id | Hypothesis | Required outcome |
| --- | --- | --- |
| H4.1 | Holder fixture plus a non-holder opener fixture: Restart Manager lists both | `opener_candidates_only`, never a holder |
| H4.2 | The prober and orchestrator are excluded by validated process-instance identity (handle and creation time), not numeric PID alone | `match`; no holder inference follows |
| H4.3 | A synthetic attesting fixture checks B1-B8, including explicit models for unresolved gates | Record binding checks as a synthetic `owner_bound_claim`; partial B2-B7 tests do not satisfy W4 or authorize recovery |
| H4.4 | Candidate duplicates its handle, then closes/exits, with and without name removal | Record original-object and duplicate semantics separately; a busy or unobservable original lock remains unknown even if its name is absent |
| H4.5 | Attestation names a different PID, creation time or file ID, or the lock is free in B4/B7 | `unknown` |
| H4.6 | Holder exits after binding, or a stale socket PID is encountered before process binding | After binding the held handle must report exit. Before binding, a repeated numeric PID is insufficient. A bounded reuse attempt that observes no reuse is unverified, not a passed reuse test |

## 4. W5: cooperative release contract

### 4.1 Routes

| Route | Initiator | Upstream support at the pin | Scope |
| --- | --- | --- | --- |
| R1 user-initiated standalone exit observation | The user, inside the owner's own UI | Owner-client teardown calls cleanup (`in_process.rs:599`); this call alone does not prove normal exit | Observe process exit and lock state; the owner must own exactly the target thread for a future recovery interpretation |
| R2 thread-scoped release by the owner (`thread/release` `ifIdle`) | codex-unlock, through B2-B8 | **Not found in targeted search** | One thread; the server may stay alive |
| R3 idle unload after the owner's own clients unsubscribe | The owner's clients | Exists (section 2.3), default 1800 s delay | One thread; codex-unlock cannot drive it for other connections |

R1 and R3 are observation proposals. Only R2 would request a release, and it
needs both a suitable standalone-owner endpoint and the new protocol. The
existing daemon endpoint fails the current owner-mode policy; no exception is
adopted here.
Exactly-one-thread ownership of a deployed standalone process has not been
established by the evidence here; a loaded-thread list alone does not satisfy
that future recovery condition.

### 4.2 Preconditions for a future R2 request

R1/R3 remain diagnostic observations under their separate procedures below. None of
these conditions permits a shared-owner recovery under the current policy.

| Id | Requirement |
| --- | --- |
| P1 | W1-W3, W6/W7 and B1-B8 established for the environment, with an explicitly reviewed cooperative-binding contract. Candidate identity alone does not satisfy holder attribution |
| P2 | Same user; no elevation difference |
| P3 | Stable completed-idle transcript: same path/file identity and size, last record task_complete, two hashes equal across a settle interval. Bind this exact baseline through B6; the owner must validate it and absence of pending/unmaterialized writes at request admission. Otherwise do not send a request |
| P4 | Positive owner evidence and one target thread, unchanged since discovery; shared app-server, daemon, Remote Control, ambiguous or changing owners refused. A future policy amendment would need to revise this entire contract, not bypass P4 through B8 |
| P5 | One operation lease per thread; lock order operation lease → native guard → thread probe; guard critical sections synchronous and released before any await, connect, spawn or wait |
| P6 | A competing lease acquisition is refused without disturbing the first lease holder. The first operation refuses if its own evidence changes, including changed lock identity or an observed unexpected contender/opener change |
| P7 | Endpoint authentication alone never authorizes releasing a busy or non-idle thread |

All routes, including R1/R3 observations, use synchronous per-probe native
guard sections and release guard/thread handles before any wait, connect,
spawn or asynchronous work. Where an operation lease is used, ordering is
lease → native guard → thread probe. Windows lease storage/keying remains a
W1/W2 design prerequisite: storage must be separate from native lock and
transcript directories, with validated ownership and alias handling.

### 4.3 Procedures

R1 (diagnostic observation of a user-initiated exit):

1. Validate paths with W1/W2 and record the independently user-selected
   candidate's handle/creation time/SID under W3 and the supported W6/W7
   environment, together with baseline lock-file and transcript identities
   and transcript hash. An opener candidate is not called the holder.
2. The user may choose to exit their own UI independently. The observer does
   not choose a PID to terminate, tell the user to terminate a candidate based
   on an opener list, or send anything to the candidate.
3. Wait on that held handle within a stated budget. Timeout is unknown with
   no further action.
4. Perform V1(R1), V2-V6 and report the separate observations. Attribution
   stays unknown/opener_candidates_only: candidate exit and a free lock can
   coincide while another process actually releases it. Neither a normal
   cleanup path nor a successful recovery is established by their coincidence.

R2 (proposal; requires section 7):

1. Establish P1-P7 and B1-B8.
2. Send the bound release request described in section 7. The owner validates
   the nonce, runtime/guard generation, transcript revision, idle state and
   subscriber conditions atomically before consuming it; it excludes new work
   until release commits. Client-side P3 alone is insufficient. Do not hold
   any native lock while waiting.
3. Accept only a structured `released` for the exact operation and binding.
   `busy`, `subscribersRemain`,
   `notLoaded`, `notOwner` and `stale` responses are explicit owner rejections. An error,
   disconnect or timeout after submission has unknown outcome. Do not repeat
   an uncertain release request; only a
   bound, read-only completion query may reconcile it.
4. Run section 4.6 verification. The server process may remain alive.

R3 (diagnostic observation only):

1. Validate fixture/target paths and identities through W1/W2 and record any
   available W3 process-instance evidence. Missing owner evidence stays
   `unknown`; a shared server is not promoted to an eligible recovery owner.
   Capture the baseline lock/transcript identities and transcript hash before
   observing changes; an unavailable baseline makes comparisons unverified.
2. Observe guarded lock state within a declared budget while the owner's own
   clients control their subscriptions. Report the default 1800 s delay; do
   not shorten it or act on other clients.
3. Perform V2-V5 sampling and V6 action accounting, recording whether process
   identity was available and stable. No V1 exit is required: the server may
   stay alive. Changed or missing evidence is recorded as such.
4. Report only sampled lock/transcript/process observations, with
   `safeToUnlock=false`; neither a free observation nor `thread/closed` is a
   successful recovery or proof of which process released the lock.

### 4.4 Failure conditions

Record whether a request was not sent, sent, or its delivery is uncertain.
Pre-request refusal, an explicit owner rejection, an uncertain request and
failed verification after an action are distinct outcomes. Proposed research
outcome names below do not change the production JSON schema.

| Condition | Outcome |
| --- | --- |
| Any gate, binding or precondition unknown before submission | unknown; no request sent |
| Transcript changed, not task_complete, or unstable before submission | refused; no request sent |
| Owner mode shared/daemon/Remote Control/ambiguous | recovery/request refused; R3 diagnostic observations do not grant eligibility |
| Endpoint validation, peer PID, SID, elevation or creation-time mismatch | `unknown` |
| Attestation missing, malformed, mismatched or stale before sending | unknown; no request |
| Explicit owner rejection before release, including a stale response | rejected_by_owner; no fallback |
| Error, disconnect or timeout after request submission | unknown with submitted/uncertain delivery recorded; no repeat release or fallback |
| Candidate did not exit within the R1 observation budget | `unknown`; no fallback |
| Verification fails after an exit or release | post_verification_failed with observed cause; never describe an already issued action as refused or undo it through another action |

### 4.5 Races

| Race | Handling |
| --- | --- |
| PID reuse | After a process handle is bound, use creation time and `WaitForSingleObject(h, 0)`, never `STILL_ACTIVE`. Binding a socket's earlier numeric peer PID to that process instance remains a W3 hypothesis; a repeated numeric PID is insufficient |
| Handle inheritance or duplication | Rust std handles are non-inheritable (section 2.1), but another process can duplicate one. H4.4/H5.4 decide whether a lock survives the original owner. Until measured, a busy lock after owner exit is `unknown`, never "residue" |
| Re-acquisition by another owner | Verification takes coordination, then probes. A free probe is meaningful for that instant only. An observed busy lock, changed file identity or unexpected opener is `unknown`; no action is taken on the new owner. Acquisition and release entirely between samples can remain undetected |
| Coordination interplay | The owner's `Drop` blocks on coordination (`writer_lock.rs:176`). The prober must close its thread handle **before** releasing coordination, and keep each critical section synchronous and short. Coordination busy during verification is retried only within the remaining budget, as on Unix ([safety-race-matrix.md](safety-race-matrix.md)) |
| Delete-pending name | Closing the probe handle before releasing coordination avoids extending a normal coordinated deletion through that handle. Other handles and failed-coordination Drop paths remain relevant. Access-denied opens are `unknown`; deletion semantics are measured separately (H5.3) |
| Concurrent recovery | One lease per thread; a second acquisition is refused. The first continues unless its own evidence changes (P6) |
| Runtime replacement (`thread/revert`) | After old-runtime shutdown, upstream skips removal/notification if the current runtime no longer matches (`thread_lifecycle.rs:580-614`). This does not skip the old shutdown. Verification uses sampled identity and lock state |
| Slow or failed shutdown | `shutdown_and_wait` has no hard bound; recorder errors can skip entry removal and Drop can skip name removal. Record the observed lock/file state without inferring a unique failure cause |
| Forced exit by the candidate itself | Do not infer release from exit. Record observed handle/file/lock state; duplicated-handle effects and release timing remain H4.4/H5.4 questions. Residual files are never deleted |

### 4.6 Post-release verification and transcript invariance

All checks are required; any failure ends as described in section 4.4.

| Id | Check |
| --- | --- |
| V1 (R1) | Observe exit of the **same** instance through the held handle, creation time and recorded exit code. This does not prove normal versus forced cleanup; that route evidence remains a separate W5 requirement |
| V1 (R2) | The same server instance returns the retained completion record for the exact operation/thread/runtime/guard generation after release. It may stay alive; querying completion must not require the old guard to still exist |
| V2 | Under the existing validated coordinator, revalidate parent directory identity; open the thread file with OPEN_EXISTING and FILE_SHARE_READ/WRITE/DELETE, perform no-follow checks, require the original baseline identity, and probe the full range exclusively/nonblocking, then unlock/close before releasing coordination. A missing name is name_absent only: it does not prove the original object's lock was released. Missing/unsafe coordination and access/identity errors are unknown |
| V3 | Record name_absent or present_unlocked with identity. A name can disappear while references to the old object remain; without independently established object-release evidence, name_absent leaves actual release unknown. Never delete or modify the file |
| V4 | Transcript invariance: same path/file identity, size and SHA-256 as the pre-observation baseline (P3 for R2), last record still task_complete. A changed transcript after action is post_verification_failed, not a claim of corruption or pre-action refusal |
| V5 | Repeat V2/V4 after a settle interval. Observed busy state or identity/opener/byte changes fail verification. Two free samples do not prove continuous freedom between them; detecting every intermediate acquisition requires additional generation/event evidence |
| V6 | Planned source call audit and explicit harness instrumentation around action adapters must record zero calls to TerminateProcess/taskkill/console-control/daemon-stop paths. State which call sites are covered; this is not a system-wide signal counter, and no such runtime measurement occurred here |

### 4.7 W5 hypotheses (synthetic first, then W7 real binary)

Records use the section 3.4 shape plus `route`, `exitCode`, `lockFileState`
and `transcriptSha256Before`/`After`. Real-binary records also carry the Codex
version, binary SHA-256, token integrity and a disposable `CODEX_HOME`.

| Id | Hypothesis | Required outcome |
| --- | --- | --- |
| H5.1 | Fixture completes its normal-exit protocol (R1 model) | Record protocol and same-instance exit separately. Successful name cleanup expects name_absent; present_unlocked records cleanup irregularity. Name absence alone does not satisfy actual-object-release evidence |
| H5.2 | Owner releases one thread and stays alive (R2 model) | V1 (R2), V2-V5 `match`; owner handle unsignaled |
| H5.3 | Prober handle open while Drop removes the name | Record delete-pending versus removed name and original-object state separately; a missing name does not prove original-object release |
| H5.4 | Candidate duplicates its lock handle, then closes/exits, including a removed-name case | Record duplicate-reference and original-object lock semantics; busy or unobservable original-object state remains unknown |
| H5.5 | Second recovery run on the same thread during the first | Second refused at the lease; that attempt alone does not disturb the first. The first still refuses if its own evidence changes under P6 |
| H5.6 | Contender remains held across a verification sample | V5 unknown; no action on the contender. A separate acquire/release entirely between samples is recorded as potentially undetected |
| H5.7 | Transcript appended between the baseline and V4 | Before a request, refuse; after a request/exit, post_verification_failed with no further action. W7 must measure shutdown flush/materialization effects; a stable disk snapshot alone does not exclude queued writes |
| H5.8 | Candidate does not exit, or the proposed release endpoint answers busy | Exit timeout is unknown; explicit busy is rejected_by_owner; zero force calls in the V6 instrumented scope |

## 5. Explicit exclusions

- Promoting Restart Manager or handle-enumeration openers to holders,
  including single-element lists.
- `TerminateProcess`, `taskkill` (with or without `/F`), `NtTerminateProcess`
  or any job-object termination.
- Injected console control events (`GenerateConsoleCtrlEvent`,
  `AttachConsole` + Ctrl-C/Ctrl-Break, closing the console) and window messages
  to the owner.
- Daemon `/daemon/shutdown`, the updater shutdown file and `stop_with_grace`.
- `thread/archive`, `thread/delete` or other state-changing operations used as
  a release.
- Unsubscribing, disconnecting or closing other clients' connections.
- Deleting, renaming, truncating or re-ACLing lock files or transcripts;
  enabling privileges; changing host policy.
- Any force mode or fallback after a failed or unavailable cooperative route.

## 6. Implementable now, proposals and blockers

| Item | Class | Notes |
| --- | --- | --- |
| Source verifier for the listed digests, anchors and literal searches | **Implementable now (done)** | Section 9; does not validate every paraphrase or causal claim |
| W4 synthetic records H4.1, H4.2, H4.5, H4.6 with fixture holders and openers | Implementable now (needs a Windows host run) | Extends `experimental/windows-fixture/`; output stays `opener_candidates_only`/`unknown` |
| W5 synthetic R1-style verification (fixture owner exits on EOF; V1-V6 checked against fixture files) | Implementable now (needs a Windows host run) | Proves the verifier and harness only, not Codex behavior |
| R1/R3 observe-only verification against a real pinned Codex in a disposable `CODEX_HOME` | Implementable after W7 | No request is sent to the owner |
| H4.3 attesting fixture | Implementable now as a synthetic model | Exercises claim-binding checks with unresolved prerequisites explicitly modelled; does not satisfy W4 |
| `owner_bound_claim` against real Codex | **Proposal; blocked** | Needs endpoint/binding/nonce work (section 7); sole holder remains unproven |
| R2 thread-scoped release | **Proposal; blocked** | Needs upstream `thread/release` or equivalent, and a reviewed AGENTS.md amendment before any shared app-server case |
| Automatic standalone exit requested by codex-unlock | **Blocked** | No non-force, non-console third-party exit path was found in targeted search |
| Positive holder from OS facilities alone | **Blocked** | Section 3.2 |

## 7. Upstream proposal delta

Extends [upstream-handoff-proposal.md](upstream-handoff-proposal.md) with the
Windows binding needs. Illustrative shapes only; not supported APIs.

- `thread/writer/status` `{ requestId, threadId }` → a read-only claim echoing
  `requestId`, `threadId`, process ID/creation time, runtime and guard
  generations, file volume/128-bit identity, transcript revision, `held` and
  a server-issued nonce. `held=true` requires that exact live guard. The
  nonce is connection-bound, unguessable, expiring under a server monotonic
  budget, and single-use. It binds every field above, not just the thread ID.
  The transcript revision explicitly maps to P3's persisted file identity,
  size, SHA-256 and last-record baseline. The client rejects a different
  baseline rather than accepting a newer owner revision implicitly.
- `thread/release` `{ operationId, requestId, threadId, runtimeGeneration,
  guardGeneration, transcriptRevision, mode: "ifIdle", nonce }` → a response
  echoing the operation and binding, with
  `released | busy | subscribersRemain | notLoaded | notOwner | stale`.
  The owner atomically validates and consumes the nonce against its current
  runtime/guard, that exact persisted transcript baseline, absence of pending
  or unmaterialized writes, completed-idle state and subscriber state. It reserves
  that state against new work until release commits. This is an owner-side
  admission rule; the client must not hold native coordination while awaiting
  the response. A second free/busy sample cannot substitute for it.
- `thread/release/status` `{ operationId }` → the retained completion record
  for that connection, process instance and binding. `released` is recorded
  only after the bound guard references are dropped; the record must remain
  queryable after the guard is gone. Its retention/expiry and behavior after
  server restart need a concrete contract. Missing state is `unknown` and
  does not authorize repeating a release. The client still performs V2-V5;
  a server record alone does not prove OS lock release or sole lifetime control.
  Cross-connection recovery of a completion record is not defined here. If
  the connection is lost, the result may remain permanently unknown; any
  reconnection/resumption design needs separate authentication and operation
  binding review before it can be used.
- Server-side peer check on the control socket mirroring
  `ensure_non_elevated_peer`, so that release requests are accepted only from
  the same non-elevated user.

## 8. Remaining decisions

1. What additional evidence or separately approved cooperative contract could
   make B1-B8 sufficient for an action. `owner_bound_claim` is not presently
   W4 positive single-holder evidence; unresolved copies and connection
   instance binding cannot be waived by renaming the record.
2. Whether to file or update the upstream request in section 7.
3. Whether a thread-scoped release from a shared app-server (R2) may ever be
   admitted, which requires amending the AGENTS.md invariant that refuses
   shared app-server owners.
4. Budgets for the R1 wait, V5 settle interval and coordination retries.
5. Whether observe-only R1/R3 verification has user value without automation.

Elapsed-time checks between synchronous OS calls do not establish a hard
syscall or guard-hold deadline. Supported-storage and guard-liveness evidence
remains necessary; choosing a retry budget alone does not resolve this risk.

## 9. Reproducing the citations

```sh
git init codex && cd codex
git remote add origin https://github.com/openai/codex.git
git fetch --depth 1 origin refs/tags/rust-v0.163.0:refs/tags/rust-v0.163.0
cd -
curl -fsSLo windows.rs https://raw.githubusercontent.com/rust-lang/rust/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sys/fs/windows.rs
node experimental/windows-release-contract/verify-upstream.mjs ./codex ./windows.rs
```

The script requires both a clone and the pinned Rust std file, reads git blobs
and runs `git grep` at the pinned commit. It does not build or execute Codex
or Rust std. Use a clone with blobs: `git grep` over a blobless clone
may fetch missing blobs lazily. A pass confirms the listed file digests and
anchor strings plus the literal-search presence/absence conditions. Other
range citations are not checked for range-to-claim correspondence; a file
digest pins their bytes only. It does not confirm runtime behavior, the paraphrases, complete
causal coverage, Windows lock semantics or the holder. It is not part of
`npm test` or the npm package.
Exit 2 means required arguments were omitted or their count is wrong. Exit 1
can mean a comparison failure or an I/O/git failure; the latter may emit an
error instead of a comparison JSON report. Only exit 0 with the full report
is a successful source check.

## 10. Acceptance mapping

| Issue criterion | Status in this record |
| --- | --- |
| #149: without positive single-holder evidence, `unknown` for opener-targeted actions | Section 3.2 result; H4.1/H4.5 |
| #149: an opener list is never promoted | Sections 3.2 and 5 |
| #149: owner-cooperative design proves endpoint, thread and owner binding under a separate contract | Section 3.3 proposes necessary checks; instance/freshness/duplicate-reference evidence remains unresolved. No proof or policy approval is claimed |
| #149: records in E3 forms including prober and orchestrator exclusion | Section 3.4 defines forms and hypotheses; no host run yet |
| #150: standalone route verifies same instance's normal exit, actual release, transcript invariance | R1 + V1-V5 define observations only; causal holder attribution and the normal-exit route remain unverified W5 requirements |
| #150: thread route verifies bound thread release and invariance; server may live | R2 + V1 (R2), V2-V5; blocked upstream |
| #150: re-probe under coordination; reject changing targets and concurrent recovery | P5, P6, V2, V5, section 4.5 |
| #150: no force fallback | Sections 4.4 and 5, V6 |
| #150: same-user, stable completed-idle; endpoint auth alone insufficient | P2, P3, P7 |
| #150: evidence against a real pinned Codex in a disposable home | **Not done**; requires W7 and a Windows host |

## 11. Not done here

No Windows host was used. No Codex binary, Codex home or process was run,
opened, connected to or signaled. No upstream code was built or executed. No
issue, comment or upstream request was filed.
