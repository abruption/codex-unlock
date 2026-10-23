# Windows 0.5.0 qualification record

The maintained release scope is Windows 10 x64 on local NTFS, with an actual
non-elevated, non-AppContainer Medium token. The CLI reports diagnostics only;
`safeToUnlock` and `recoveryAvailable` remain false. Windows 11, High-token
diagnostics and automatic recovery are outside this release scope.

## Qualified release candidate

[`windows-v0.5.0-rc.1`](https://github.com/abruption/codex-unlock/releases/tag/windows-v0.5.0-rc.1)
was published on 2026-10-23 from
`9ea3c78fe513ea5f473f9297ac6b3229159601ba`. Its version PR #178 passed 41 checks
and Code/Security reviews. Main CI and the release build/attachment workflow
also passed.

| Artifact | SHA-256 |
| --- | --- |
| RC ZIP | `cc38df25ee4b91e759739edf6171370b21b02116ae537c3eb549be665ae8d232` |
| RC executable | `3f31892816b243b27b7ce8d20889b5249c9f67f5b9152236a45b1b02dd61aa18` |
| Matching-source fixture | `ccaef96e6b5077bdc84899b61bcd7ee3b5a0bd33731611588aa84deef2854557` |

The exact downloaded RC executable passed two High-refusal cases and all 12
Medium cases in the [qualification harness](qualification/README.md). Native
guard/thread identities and metadata matched both held/free pairs; all four
fixture processes exited normally through EOF and removed their own roots.
The unrelated requested PID remained observation-only evidence.

On the designated Windows 10 build 19045/AMD64/NTFS host, the signed vendor CLI
reported Kaspersky File Threat Protection enabled before and after the runs.
Local File Monitoring exports had an explicit empty exclusion list, and the
maintainer separately reviewed the applicable global exclusions in the current
UI. Defender remained disabled; Kaspersky evidence is not Defender-on evidence
or proof that every I/O was scanned.

An isolated native Codex 0.163.0 app-server was observed held, then exited
normally through EOF with no signal and zero provider connections. Its thread
file was absent afterwards, yielding unknown/Win32 2. This is not a native-free
or holder-attribution claim. The temporary task was removed and raw outputs
were reparsed by the integrating agent.

| Private evidence | SHA-256 |
| --- | --- |
| RC High cases | `d7097b55ca7bba8bb478a92d4e26f71887995d409bc2de1563a713b683e514db` |
| RC Medium cases | `1644dddf96a932e71a6dd2a94163eb3dd5d88ef13a9e219285650060b2897d4e` |
| RC native observation | `1fb27aff3b53647255e297fc55c791a8b521bb556a39dfa5feb7105048f6bc61` |

The [release record](https://github.com/abruption/codex-unlock/issues/174#issuecomment-6362437076)
contains the workflow/artifact references and publication checks. Account,
PID and local-path details remain private. Anonymous download after RC
publication reproduced the verified ZIP digest.

## Stable publication gate

The stable release plan may proceed from this public immutable RC. Release
Please owns the new version files and draft release. Because the version is
embedded, the stable executable has different bytes and must independently
pass the host qualification and native observation before publication. Its
final hashes and actual results belong in
[release issue #174](https://github.com/abruption/codex-unlock/issues/174);
the RC hashes above must never be used as the stable artifact's checksums.
