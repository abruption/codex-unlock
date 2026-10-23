# Windows 10 diagnostic CLI

The diagnostic-only Windows channel uses tags `windows-v<version>`. Release
candidates are marked as prereleases. This channel is separate from the macOS/Linux
npm CLI. Consult [GitHub Releases](https://github.com/abruption/codex-unlock/releases)
for publication status and asset availability.

`codex-unlock-windows.exe` inspects an explicitly selected Codex thread lock.
It is a standalone Rust CLI for Windows 10 x64, local NTFS, and a normal
non-elevated, non-AppContainer Medium-integrity terminal. No Node.js, Rust or `lsof` installation
is required to run the downloaded executable.

This CLI reports observations only. It has no unlock, process termination,
lock-file deletion or recovery command. Every JSON result retains
`safeToUnlock=false`. A PID supplied by the user is not proof of lock ownership.

## Obtain and check an artifact

Select the published Windows version you intend to use on
[GitHub Releases](https://github.com/abruption/codex-unlock/releases) and check
its publication status. If published, download
`windows-diagnostics-preview-windows-x86_64.zip`, `SHA256SUMS` and `manifest.json`
from that same release into a new directory.

For CI builds, use a reviewed run of the repository's **Windows Rust diagnostics**
workflow. Download the `windows-diagnostics-preview-windows-x86_64` artifact
and extract its outer GitHub artifact archive. Its payload uses the same ZIP,
checksum and manifest names. CI artifacts are short-lived build outputs, not
public releases;
check the run and source commit rather than treating them as the tagged release.

In PowerShell, compare the ZIP digest with the sidecar checksum before opening
it, then extract into a fresh directory:

```powershell
Get-FileHash .\windows-diagnostics-preview-windows-x86_64.zip -Algorithm SHA256
Get-Content .\SHA256SUMS
Expand-Archive .\windows-diagnostics-preview-windows-x86_64.zip .\preview
Set-Location .\preview
Get-FileHash .\codex-unlock-windows.exe -Algorithm SHA256
Get-Content .\SHA256SUMS
Get-Content .\manifest.json
```

The manifests identify the payload hashes, version, target and build source
commit. Check them against the selected release or workflow run, and confirm
the executable's `--version` below. For a pull-request workflow the source may
be GitHub's merge-test commit; compare it with the checked-out source recorded
by that run. Checksums detect changed bytes, not publisher identity. These
checksums are not a code-signing identity. Windows is distributed as a portable
ZIP, not through the npm CLI. The historical `preview` ZIP and guide filenames
remain distribution identifiers; use the release tag, version and JSON channel
to distinguish alpha, RC and stable builds.

## Use a normal terminal

Open ordinary PowerShell or Windows Terminal without **Run as administrator**.
Do not disable UAC or change ownership/permissions to make a refusal pass.

```powershell
.\codex-unlock-windows.exe --help
.\codex-unlock-windows.exe --version
.\codex-unlock-windows.exe capabilities
.\codex-unlock-windows.exe capabilities --json
.\codex-unlock-windows.exe inspect --home 'C:\Users\you\.codex' --thread '11111111-2222-4333-8444-555555555555'
.\codex-unlock-windows.exe inspect --home 'C:\Users\you\.codex' --thread '11111111-2222-4333-8444-555555555555' --pid 1234 --json
```

Replace the example path, thread UUID and optional PID with known values.
`--home` must name the exact existing Codex home; session discovery and automatic
home selection are not included. The executable does not create missing homes,
coordinators or thread lock files. Help/version do not probe native files.

Capabilities reports the current execution context. Inspection requires an
observed Medium token (RID 8192), no elevation and no AppContainer before native
file or requested-PID access. High, Low and uncertain contexts refuse. This
does not certify that a selected home is safe: ownership, path, filesystem and
file-identity checks still apply during inspection.

## Interpret the result

- `held`: the guarded probe encountered a conflicting OS lock. It does not
  identify the holder or authorize recovery.
- `free`: the probe acquired and released the existing thread lock at that
  instant; it is not a guarantee about later state.
- `unknown`: a required observation was unavailable or refused. The reason
  code explains the boundary; do not infer `free` from a missing file.

Exit 0 means the command completed its stated observations; capabilities can
complete with `diagnosticsAvailable=false`, so inspect that field. Inspection
exit 2 means an unsupported/refused/unknown diagnostic; exit 64 means invalid
arguments and exit 74 means an output I/O failure.
Machine consumers must check the exit status and JSON fields together. The
Windows schema is distinct from the published TypeScript CLI's JSON v1.
If the receiving pipe closes early, the original command exit is preserved
without a panic; a complete JSON response is still required to interpret it.
Raw JSON can include local paths and process identifiers; redact it before
sharing. Human output presents fixed summaries and reasons.

The JSON envelope identifies version, platform, architecture and the release
contract below. Check the schema identifier and version together:

| Binary version | `schema` | `schemaVersion` | `releaseChannel` | `preview` / `experimental` |
| --- | --- | --- | --- | --- |
| `0.5.0-alpha.1` | `codex-unlock-windows-preview` | 1 | absent | true / true |
| `0.5.0-rc.1` | `codex-unlock-windows` | 1 | `rc` | true / true |
| `0.5.0` | `codex-unlock-windows` | 1 | `stable` | false / false |

RC/stable use `diagnostic_available` for an eligible capabilities result;
historical alpha uses `diagnostic_preview_available`. This is an explicit new
schema identifier, not a silent reinterpretation of the alpha schema. The
Windows schema is also separate from the npm CLI's JSON v1.
`safeToUnlock` and `recoveryAvailable` are always false. A queried `context`
contains `state`, `integrityRid`, `elevated` and `appContainer`; a failed context
query instead carries its unknown reason. `diagnosticsAvailable` only describes
the caller context, not the selected home's validity.

For `inspect`, `requestedPid` is an integer or null and `requestedPidEvidence`
names the observation-only contract even when no PID was supplied. `lock`
always contains `state`, `reason` and `win32`. Context refusal omits `diagnostic`
entirely: no native-file or requested-PID observation occurred. Otherwise
`diagnostic` contains the research observation, including file identities and
optional process metadata; the outer `lock` matches that nested result. Usage
errors have `error="usage"` and a fixed reason, without probing context or files.
The nested observation keeps its research schema and `experimental:true`
marker. The public outer contract validates and exposes this evidence; that
marker is separate from the outer release channel and never grants recovery
or holder authority.

Native probes briefly take exclusive coordination/thread locks and pin
directories against rename/deletion. They can delay or conflict with other
clients; synchronous Windows calls have no hard wall-clock bound. Start with a
disposable test home and do not assume that diagnostics are operationally inert.

## Qualification and limits

The support scope is Windows 10 x64/NTFS. Windows 11 and Windows Server are
outside the qualified scope; caller eligibility alone does not establish OS
support. Native interoperability uses a genuine Medium token and an isolated
Codex 0.163.0 app-server. The alpha measurement recorded Defender disabled.
The 0.5.0 qualification procedure verifies the designated host's Kaspersky
Endpoint Security File Threat Protection and tests the exact RC/stable bytes.
See [qualification records](https://github.com/abruption/codex-unlock/issues/174)
for per-version hashes, actual results and failures. Kaspersky coverage does
not establish Defender-on coverage, other Codex modes, filesystems or security
configurations. This tool does not change antivirus policy or ask users to
disable protection. The native server was observed held and then absent/unknown
after normal shutdown; native free was not measured. Held-to-free tests use
separate synthetic fixtures. ReFS, network/UNC/device paths, reparse paths,
hardlinked native files and unsupported contexts are refused.

The separate research executable can collect other experiments; its policy is
not an alternate mode or bypass of this CLI's Medium-token boundary. High-token
diagnostics, holder attribution and cooperative third-party release are outside
this release's scope. No installer or global PATH modification is part of the
portable ZIP distribution.
