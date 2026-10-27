# Standalone Windows preview verification — 2026-10-22

This evidence covers the new `codex-unlock-windows.exe` release-mode preview,
not the earlier research executable. Related: #169, #170, W6 #151 and W7 #152.
All results retain `safeToUnlock=false`; recovery and holder attribution remain
unavailable.

## Build and artifact identity

| Item | Pinned value |
| --- | --- |
| PR source head | `472b390016a109007523e12c92ec431cc6054c43` |
| CI checked-out merge-test commit | `4ac388daf3268a1648795d27b417fa1704af2bfd` |
| CI run | [39705583316](https://github.com/abruption/codex-unlock/actions/runs/39705583316) |
| Preview artifact ID | `12395106574`, `windows-diagnostics-preview-windows-x86_64` |
| API-reported artifact archive digest | `sha256:c1b3d9aa33fdf3cc57a81725f03bc781b0f7ec129b380a397a9ada40d74ea466` |
| Inner ZIP SHA-256 | `77527bbddef9565bb55799a562c754093d782156d13306436c336c7c39878529` |
| Release executable SHA-256 | `15f0618b4252aa10e6c422e5966b9600aa2fc56fd93eee9505e8c5ff1d41f253` |
| Native observer SHA-256 | `bbaaae00835f5b033ec82ab24c64a0ef86ded555358fe1199de6ffb1c03c4e1e` |
| Private host wrapper SHA-256 | `7b1086fff2f5dd36f9afd2df31ed4701334bd1a4763a1286a4fd1aa478ae3309` |

The GitHub commit API confirmed that the merge-test commit's parents are main
`22857b3` and the PR source head above. The workflow records `git rev-parse HEAD`
in the manifest, so the manifest intentionally names the merge-test commit.

CI checked the executable digest before/after release smoke, required that
digest during packaging, and compared the ZIP extraction with the tested build
bytes and quickstart. The reviewing Mac independently checked the inner ZIP,
manifest, executable and payload checksums; Windows rechecked the ZIP and input
digests before execution. The quickstart has Windows-checkout CRLF line endings;
the initial Mac LF byte comparison failed, then the comparison used explicitly
derived Windows checkout bytes. The CI artifact bytes were not modified.

The ZIP contains exactly the executable, `PREVIEW.md`, `manifest.json` and
`SHA256SUMS`. Checksums establish byte integrity, not Authenticode signing or
publisher identity. No release, tag, package publication or installer was used.

## Validation and corrected failures

Windows CI passed Rust preview unit tests (9), research unit tests (6), preview
process tests (4), native independent-process tests (8), observer/generated
contract tests (18), and packaging tests (5). The actual release executable
reported High RID `12288`, elevated true, AppContainer false, and refused valid
inspection arguments with exit 2 and no nested diagnostic.

Two earlier runs failed the release context gate. The first did not log enough
context to identify the cause. The second exposed `token_information_failed`,
Win32 24 (`ERROR_BAD_LENGTH`). The aligned token buffer allocation was being
passed as the API length, including padding for fixed-size token information.
Commit `472b390` passes the API-reported byte length while retaining aligned
allocation and adds a real current-token query regression. The successful run
above includes this fix; earlier unknown-token results were not counted as
High-refusal validation.

Independent read-only reviews used Claude Code 2.1.306 with requested and
response-reported `claude-opus-5-5`, and Codex CLI 0.163.0 with its isolated
default model (actual model not exposed). Both initial and correction pairs
completed normally, each pair reading identical frozen input hashes:

- Initial: `0b89fd93f839f65bb6f9404ba721f12bddc5fc2d3cbe9b064f184a3803b86d4e`
- Correction: `e6c00a380d3c19c73692795807cf72d0ad7b11f56b0ec0ee16f31a4d2750ba93`

Review findings led to unconditional validator entry, alias regression tests,
preserved refusal/usage exits on broken pipes, deterministic writer-error
tests, invalid-encoding JSON handling, generated Rust-to-JavaScript mapping
checks, and release/measurement digest binding. The final token-length fix was
found by CI after those source reviews and verified by Windows tests and the
host observations below. Local lint/type-check/package checks and the existing
repository suite passed (275 total, 271 passed, 4 environment skips).

## Designated host: same bytes in High and Medium contexts

Host: quintet-desktop, Windows 10 22H2/x64, local NTFS, PowerShell 5.1,
RemoteSigned policy. Defender real-time protection was already disabled and
remained disabled. The preview executable itself required neither Node nor
Rust; Node 24.16.0 was used only by the native measurement harness.

High was the SSH context. Medium used the same user's existing desktop logon
through a dedicated on-demand interactive-token task with `RunLevel=Limited`.
Actual process/token observations established the contexts; task configuration
alone was not accepted as proof. The task had no scheduled trigger or supplied
password and disabled automatic hard termination. Fresh native measurement
directories were current-user-owned with protected creation-time DACLs.

| Observation | High | Medium |
| --- | --- | --- |
| Observed integrity RID | 12288 | 8192 |
| Preview elevated / AppContainer | true / false | false / false |
| Capabilities | `diagnosticsAvailable=false` | `diagnosticsAvailable=true` |
| Inspect exit / state | 2 / unknown | 0 / held while own server was live |
| Reason | `elevated_context_refused` | `diagnostic_observation_only` |
| Native-file/PID result | No nested `diagnostic`; absent test path remained absent | Guarded NTFS observation, exact-user ownership passed; requested PID observation only |
| Recovery authorization | false | false |

The Medium observer started its own pinned Codex 0.163.0 stdio app-server in a
fresh home, performed initialize/thread-start with no model turn, and required
the preview's strict JSON envelope and nested observation. The manifest's
executable digest was supplied explicitly and checked before/after every
diagnostic invocation. Path-based hash samples do not pin the launched image
against same-user replacement.

The live observation acquired/released coordination and detected contention
with a whole-range probe. This establishes an overlapping native lock, not the
native lock's entire range or its holder. The native process was observed as
same-user Medium in the intended desktop session.

The observer closed its own server stdin; server exit was 0, capture complete,
faults empty, and provider-listener connections zero. After exit, the thread
path was absent and the preview returned exit 2,
`unknown/open_existing_failed` (Win32 2). This is not a measured free-lock
transition. The original observer's profile-skill discovery and startup
isolation limits still apply.

| Private result | SHA-256 |
| --- | --- |
| High wrapper result | `1590ee522edbd3b5a29f68e815078b8a1e511d927da61502e571d6d58e3b176b` |
| Medium wrapper result | `8ae7983a7f4b451f502003e3cb6f84375d6b31605a799e8d336e1315d2f79eee` |
| Native preview result | `55013d6679f42be7a93046619230be84bc8fe207b8fdc3a58c443b4eb76a6eb4` |
| Three-result transfer ZIP | `fe1cfeca68a4efa983d5bb5efd537801a1e733704ba54b587f852375a84f33f8` |

Raw results and the host-specific wrapper remain private. Codex rechecked the
hashes and typed observations locally; a separate read-only subagent independently
confirmed them. Manual cleanup checks found the task completed with exit 0;
it was unregistered, no matching task remained, and recorded runner/native PIDs
were absent. The SSH connection was closed. Evidence directories were retained.
These cleanup observations are separate from assertions inside the result files.

## Remaining boundaries

This qualifies one preview build on the measured host. Low/AppContainer refusal
has policy/unit coverage but no corresponding designated-host measurement.
Defender-on behavior, other users, Windows versions/architectures, ReFS, other
Codex modes/versions, and adversarial same-user races are not qualified.
W4 holder attribution and W5 cooperative third-party release remain open.
High execution remains refused; no broader ownership policy was enabled.
