# Windows Rust diagnostic measurements — 2026-10-21

Related: #163, #146–#152. These results qualify an unpublished experimental
increment, not Windows production support or recovery. Every diagnostic result
retains `safeToUnlock=false`.

The later [Medium-integrity follow-up](MEDIUM-EVIDENCE.md) reached the native
guarded lock probe successfully. This document preserves the earlier High-token
results and their limits.

## Inputs and integrity

| Input | Pinned evidence |
| --- | --- |
| Repository base | `cdd4bf1769c6a24d90b1624c4c9ea8d022666b7e` (v0.4.7) |
| Rust measurement build | `5ff848eca96725bd7f8ea36adbdbd732a3cd9c8e`, Rust 1.90.0, Windows x64 MSVC |
| Build/test run | [39549173814](https://github.com/abruption/codex-unlock/actions/runs/39549173814), Windows unit tests 5/5 and integration tests 8/8 |
| GitHub artifact | `12322003632`, `windows-rust-diagnostic-research`; API-reported archive digest `336703e3d2ae35f7d318ddd146eea0994224842b6823fc5b726b726e902c6e09` |
| Diagnostic executable SHA-256 | `003d2b85a319ed5cdd97394518eb00c97cc21da271ec541967a36bdce23f6bc2` |
| Fixture executable SHA-256 | `698058b6c5b5560005fc5de69c67a81ea12167237d3063619ec0d4ee86179126` |
| Transferred integration test SHA-256 | `aec91b48a9080b268da5fc4b8e4138cd46f306febd5d37ceaca78cbe96f06a5a` |
| Final native observation runner | commit `e17088c`, SHA-256 `2b0d2a2bbb6d5a99907a7cfda5dc3887487ab0c5678f4dd75c66832a88c8a500` |
| Official Codex asset | `rust-v0.163.0/codex-x86_64-pc-windows-msvc.exe.zip`; published/downloaded archive SHA-256 `dabdb4d16aaf10fea40b74811c96efddcd9138f122163b69ed604fcb3eb704c3` |
| Native Codex executable SHA-256 | `2692c8c7bb2cf8b0aefe638741fc90236f4b824c59578ce84994f9de58200993`; measured version `codex-cli 0.163.0` |
| Final private native result SHA-256 | `646d53247b06f832a58c1b29bcffd90434e6859efb4dd9afcb184e24e6557f6a` |
| Earlier completed native run | runner `87241a0` / `b81b556d561f05bc9130d31c46d54a2bfd6c390da10fd96ed68e0634c5a60cac`; result `a596a3f26d5d77161c82b2bf165b90196456b45ecac9fa45a8b4d97a69a84c87` |

The CI manifest's three executable hashes were independently recalculated on
the Mac and matched again on the Windows host before execution. The native
Codex archive was checked against GitHub's published digest before extraction,
and the observer checked the executable digest before launch. These are byte
checks, not signed-image pinning or protection from same-user replacement.
The Rust backend, Cargo inputs and fixture/test sources are unchanged between
the measured `5ff848e` build and runner revision `e17088c`. Measurements used
the exact earlier executable bytes above; later rebuilds are not assumed to
be byte-identical merely because their Rust sources match.

## Designated-host synthetic measurement

Host: quintet-desktop, Windows 10 `10.0.19045`, x64, NTFS, PowerShell
`5.1.19041.6456`, Node `v24.16.0`, RemoteSigned policy. The SSH token was High
integrity (`12288`). Defender real-time protection was already disabled; it was
not enabled/disabled by the experiment. These conditions do not qualify Medium
integrity, Defender-on interference, ReFS or Windows arm64.

The exact transferred integration binary ran once, serially: **8 passed,
0 failed, exit 0**, with zero remaining synthetic fixture directories. It
checked real independent-process held→free contention, a busy coordinator,
missing guard/thread without creation, guard/thread hardlink refusal, a junction
ancestor refusal, invalid UUID usage, unknown missing PID, and same-user PID
metadata. Guard/thread size and modification times were unchanged. Synthetic
objects had explicit current-user ownership and private creation-time DACLs.

The first CI revision failed before the junction observation because its
`cmd /C` fixture command was incorrectly quoted. The correction used a raw
command tail only after rejecting shell metacharacters in both paths. The
subsequent CI and designated-host runs passed; no diagnostic assertion was
weakened to accommodate that setup failure.

## Native Codex observation

The installed Codex 0.155.1 was only queried for its version in a disposable
home. For interoperability, the official 0.163.0 portable bundle was placed in
the dedicated experiment directory; it did not replace the installation.

An initial runner revision stopped before Codex launch because the host has a
profile `.agents/skills` directory. That private partial result is retained.
The measured revision records normal read-only profile skill discovery, uses
a fresh file-auth store and disables hooks/plugins/shell snapshots/code-mode
prewarm. System Codex configuration, requirements and skills were observed
absent. Existing authentication was not copied, and the observer submitted no
model turn or authentication RPC. This is not a claim that CODEX_HOME alone
isolates all native profile reads.

The observer started its own stdio app-server and sent only initialization and
`thread/start`. The response confirmed `modelProvider=research`,
`model=research-no-turn`, `approvalPolicy=never`, and read-only sandbox with
network access false. The custom provider's local listener recorded **zero
connections**; this is not a system-wide network trace. Codex emitted its
temporary-directory PATH-alias warning, which was retained in the private log.

| Observation | Result |
| --- | --- |
| Collection | `collected`, observer exit 0; completion only, not a diagnostic/recovery pass |
| Before EOF: file presence | Coordinator and thread paths existed as files |
| Before EOF: requested PID | Observed live same-user PID, High integrity; evidence remains `requested_pid_only_not_holder` |
| Before EOF: lock diagnostic | Exit 2, `unknown/file_owner_not_self` |
| Owner metadata (earlier completed run, manual) | Disposable home, lock directory and remaining coordinator owned by `Administrators` |
| Own server shutdown | Stdin EOF, observed exit 0, complete streams and no capture faults |
| PID metadata (earlier completed run, manual) | Recorded PID absent in subsequent process enumeration |
| After exit: file presence | Coordinator remained; thread path absent |
| After exit: lock diagnostic | Exit 2, `unknown/file_owner_not_self` |

The exact-user ownership gate refused **before the native lock probe**. Thus
this run does not establish real Codex whole-range lock interoperability. The
thread path's disappearance after normal exit does not prove that no hidden
handle reference or kernel lock remains. No inference of holder identity or
safe recovery is made from the supplied PID, file presence, or normal exit.

Two completed native observations produced these same outcomes. The final run
also enforced the approval/sandbox response fields and UTF-8 known-folder
output, with existing plain-directory checks on both known-folder bases.
A separate PowerShell 5.1 pipe check preserved a synthetic Korean path exactly;
this did not create or test an actual non-ASCII Windows profile. Owner-category
and subsequent PID metadata checks were performed manually after the earlier
completed run, separately from the observer's automated gates.

A read-only query of the current SSH token returned `TokenElevationType=1`
and `TokenLinkedToken` error `1312`; no usable linked Medium token was obtained.
No privileges or token settings were changed. A genuine Medium measurement
requires a separately supplied normal-user execution context; it was not
simulated by relabeling the High result.

## Recovery assessment and next work

- **Rust diagnostic primitives:** viable for the measured synthetic NTFS
  conditions. The binding can observe file IDs and process tokens and perform
  guarded real lock probes.
- **Native High-integrity diagnostics:** current exact-owner rule refuses the
  observed Administrators-owned objects. Do not silently broaden ownership to
  make this experiment pass. Repeat under a genuine Medium token, then review
  the intended High-token owner/DACL policy under W2/W6.
- **Automatic recovery:** no-go. W4 holder attribution and W5 a safe cooperative
  release protocol remain unresolved. The test's stdin EOF controls only the
  server started by the observer; it is not a third-party recovery API.
- **W7:** incomplete. Native guarded contention was not measured, and the host
  did not meet Defender-on/Medium conditions. Other execution modes and
  filesystem/platform combinations remain unverified.

## Other validation and review limits

Local repository type-check/lint passed. Existing repository tests: 273 total,
270 passed, 3 platform skips. Local Rust CLI tests: 3 passed; Windows target
check/clippy passed. The native observer's protocol/schema/startup tests: 13
passed. These local Rust tests do not substitute for the separately recorded
Windows execution.

During the initial measurement, package smoke failed on unchanged packaging code: local tarball
installation resolved `nan@2.30.0` while the lockfile expects `2.29.0`.
The initial PR package jobs showed that failure too. The assertion was not relaxed and
the runtime dependency was not changed. This is a separate packaging gate,
not a passing check or evidence that the registry-published package ignores
its shrinkwrap. PR #164 subsequently corrected the registry-metadata test path
and inherited proxy handling; its final commit `af5ab64` passed all 41 GitHub
checks before merge. Runtime dependency pins were unchanged.

Independent read-only CLI reviews used Claude Code 2.1.306 (requested and
response-reported `claude-opus-5-5`) and Codex CLI 0.163.0 (isolated default
model, actual model not exposed). The Rust review and the subsequent observer
review used separate frozen inputs. The observer review found weak result/RPC
validation and entry-path handling; these were corrected with regression tests.
The later review also identified known-folder encoding and effective sandbox
validation gaps; both were fixed and the native observation was repeated.
Startup side effects were additionally traced in pinned upstream source before
measurement. These source reviews are distinct from the Windows measurements.
The correction review (frozen input SHA-256
`0106c734ae0cff40e4ea542a444f13d4989af49c7bacf2cc3fbac3b6d1b35559`)
completed normally in both CLIs with no additional mandatory findings. The
evidence table was then clarified to distinguish the earlier manual metadata
checks from automated results. Opus 5.5 reported no safety-filter interruption.

Raw host results include local paths and PIDs and remain private. This document
contains the redacted outcomes and reproducibility hashes only.
