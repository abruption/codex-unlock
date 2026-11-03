# Medium-integrity Windows measurement — 2026-10-21

Related: #163, W6 #151, W7 #152. Follow-up to the
[High-integrity measurement](EVIDENCE.md), after PR #164 merged as
`22857b3eb14b89976673830c601e54f52a42c217`.

Native guarded lock contention was observed under a genuine Medium token on
the designated NTFS host. This qualifies one diagnostic experiment. Holder
attribution and safe third-party recovery remain unproven; every result keeps
`safeToUnlock=false`.

## Execution context and inputs

The designated quintet-desktop host was Windows 10 22H2, NTFS, PowerShell 5.1,
Node 24.16.0, with RemoteSigned execution policy. Defender real-time protection
was already disabled and remained so.

SSH still ran with High integrity. Read-only process inspection found the same
user's Explorer in an existing, disconnected desktop session with integrity RID
`8192`. Two dedicated on-demand tasks used that user's interactive logon token
and `RunLevel=Limited`: one preflight, then one measurement. Neither had a
scheduled trigger or supplied password. Automatic hard termination was disabled.
Actual runner and native-process observations, rather than task configuration,
established Medium integrity: both were live, same-user processes with RID
`8192` in the intended desktop session.

Fresh private directories were created for this run. Old High-created objects
were not repaired or reused as native test homes. Creation-time DACLs were
protected and limited to the current user; ownership was checked. This is a
controlled local experiment, not a general adversarial ACL/path verifier.

The diagnostic, fixture, integration-test executable, native observer and
Codex 0.163.0 executable were the same bytes listed in
[the original input table](EVIDENCE.md#inputs-and-integrity). All five SHA-256
values were rechecked before execution. The Rust sources in the merged base
are unchanged from the original measurement build. No rebuild equivalence is
assumed. The task wrapper was parsed on Windows before running.

| Private evidence | SHA-256 |
| --- | --- |
| Task wrapper (`run-medium.ps1`) | `1eb515124bef6f042da6461525ec3b7af8c9cec58119e87c974471159a2a12ca` |
| Preflight result | `23191231fd6f75e1159375a988b7d309b06a781d358ed38d8b3f7fd35068fbfa` |
| Measurement wrapper result | `a8e7c45149b38071140fe8b0fc3c1f2ec954907ff2a1a161e78f1950b364e5dc` |
| Native observer result | `52c39e9d2be93d224873b3c5b10ad8e5efa2c205a6755e0ff59af4974d40f5d6` |
| Three-result transfer archive | `882fea82e670c27deb2a5c6de35a00b6d5b6885cf317191723efbaadb35eb4bc` |

The archive digest matched on Windows and the reviewing Mac. Raw results and
the host-specific wrapper remain private because they contain local paths,
process/thread identifiers and native RPC output. The table is an integrity
record, not public access to or independent provenance of those artifacts.

## Measured outcomes

The preflight and one measurement run each exited 0. Measurement ran the same
integration binary serially before starting the native observer.

| Observation | Result |
| --- | --- |
| Synthetic independent-process tests | 8 passed, 0 failed, exit 0; zero remaining synthetic fixture entries |
| Native mode | Own stdio app-server, Codex 0.163.0; initialize and thread/start only, no model turn |
| Live native PID observation | Same user, Medium RID 8192, matching desktop session; requested PID only, not holder attribution |
| Live file ownership and identity gates | Passed; current-user ownership, NTFS, regular single-link guard and thread files |
| Live lock diagnostic | Exit 0, `held`; coordination acquired and released, whole-range thread probe conflicted |
| Own server shutdown | Stdin EOF, exit 0, complete streams, zero capture faults |
| After exit: paths | Coordinator present, thread path absent |
| After exit: diagnostic | Exit 2, `unknown/open_existing_failed`, Win32 2 |
| Provider listener | Zero connections; not a system-wide network trace |

The observer confirmed the research provider/model, approval policy and
read-only sandbox. Its existing profile-skill discovery limitation and native
temporary-directory PATH-alias warning also apply to this run. No authentication
was copied and no model turn was submitted.

A whole-range **probe** conflicting with a lock demonstrates an overlapping
locked range. It does not itself measure the native lock's entire range or
prove that the supplied PID holds it. Thread-path absence after exit is not a
measured native held-to-free transition and does not exclude hidden references.

Separate manual operational checks found both temporary tasks completed with
result 0. They were then unregistered; no matching tasks remained. The recorded
runner and native PIDs were absent in a subsequent process query. These are
manual observations, not assertions encoded in the three result files. No
forced termination was used. Private evidence directories were retained and
the SSH connection was closed.

Codex checked the JSON fields and hashes locally. A separate read-only Codex
subagent independently read the raw results and wrapper and confirmed the
bounded conclusions above; it did not rerun the host experiment.

## Policy assessment and next gates

- **Diagnostic feasibility:** the earlier missing native guarded-contention
  observation is now available for this Medium/NTFS/app-server configuration.
  W6/W7 gain evidence but are not completed wholesale.
- **High ownership:** the earlier `file_owner_not_self` refusal remains valid
  for Administrators-owned objects. Medium success does not justify accepting
  group-owned objects or replacing exact-user ownership with a weaker check.
  A broader High-token policy needs an explicit owner/DACL design and tests.
- **Recovery:** still no-go. W4 requires holder attribution; W5 requires a
  separately supported cooperative release path. EOF of this experiment's own
  server is not an external thread-specific release API. Shared app-server
  refusal and the existing safety contract remain in force.
- **Coverage:** Defender-on behavior, other users, ReFS, Windows arm64, other
  Codex modes/versions and native post-exit free-lock observation remain
  unverified. No generalized Windows product-support claim follows from this
  single run.

The next product decision is whether to scope an initial Windows offering to
diagnostics under measured non-elevated conditions. Recovery and any broader
ownership policy remain separate acceptance gates.
