# Windows 10 release-byte qualification

This operator-run harness exercises the **downloaded product executable** in
an actual Medium token and separately proves High refusal. It does not install
tools, alter security settings, access a real Codex home, or request process
termination. The existing synthetic fixture creates its own child directory
with current-user ownership and a protected DACL and exits through stdin EOF.
Only the fixture's own guard/thread paths are renamed or hardlinked. The sole
junction points at that same fixture's home; it is unlinked without recursive
deletion. Native lock-file contents are never read while held.

The currently selected host profile is Windows 10 build 19045/x64/NTFS with
**Kaspersky Endpoint Security for Windows real-time protection active**. The
operator must independently interpret actual vendor status and definition
evidence. A running service or SecurityCenter registration alone is not that
proof. Defender's actual boolean is recorded separately; Kaspersky evidence
does not qualify Defender-on or Windows 11.
Review applicable path/process exclusions separately. Active protection and
that configuration review do not prove the vendor scanned every individual
I/O: caching and file-type heuristics remain the vendor's behavior. This is
application compatibility evidence, not an antivirus detection benchmark.
Qualification also requires a current operator UI review of applicable global
Trusted Zone exclusions and a successful local File Monitoring profile export
whose explicit `File_Monitoring/settings/ExcludeList` has no child elements.
A missing export/node is unknown, not an empty exclusions list. The local
profile export alone does not establish global Trusted Zone policy.

## Inputs and provenance

Use the final release ZIP and its source/version/hash manifest. The fixture
must come from the reviewed CI measurement artifact associated with the source
being qualified; check the Actions run/source and its artifact digest first.
The fixture is a test dependency, not a distributed runtime dependency.

Keep this file layout from one reviewed checkout:

```text
observe-native.mjs
scripts/validate-preview.mjs
qualification/run.mjs
qualification/contract.mjs
```

The transitive helper is required. Hash all four files. The previous alpha
host attempt omitted `scripts/validate-preview.mjs` and stopped at module
loading; do not copy only the observer.

The trusted host launcher captures separate metadata for each actual execution
context. Store metadata, raw security evidence, binaries and manifests outside
the fresh, empty private fixture parent. The launcher creates the parent with
current-user ownership, protected DACL and only current-user write access.

Metadata JSON (replace placeholders with measured values):

```json
{
  "schemaVersion": 1,
  "windowsBuild": "19045",
  "architecture": "x64",
  "integrityRid": 8192,
  "elevated": false,
  "appContainer": false,
  "defenderRealtimeEnabled": false,
  "security": {
    "product": "Kaspersky Endpoint Security for Windows",
    "realtimeActiveVerified": true,
    "exclusionsReviewed": true,
    "evidenceSource": "operator-verified vendor real-time status and definition output",
    "evidenceSha256": "<SHA256 of the actual raw security evidence file>"
  },
  "executionPolicy": "RemoteSigned",
  "parent": {
    "path": "C:\\path-to-fresh-private-parent",
    "ownerSelf": true,
    "protectedDacl": true,
    "writeAccessSelfOnly": true
  }
}
```

Metadata is explicitly labeled **operator-launcher-supplied, hash-bound** in
the result. The harness compares its real CLI token result with the supplied
token fields, but does not independently reconstruct ACLs or interpret vendor
output. Review those producer observations separately. Their hashes prevent
accidental input drift, not same-user forgery or false provenance claims.
`exclusionsReviewed` must be an actual boolean. False keeps `hostQualified`
false; a string or omitted field is refused. The raw security evidence must
contain the operator-review sidecar/digest and the measured export result.

Input manifest JSON has exactly these keys:

```json
{
  "schemaVersion": 1,
  "sourceSha": "<40 lowercase hex source commit>",
  "version": "0.5.0-rc.1",
  "releaseManifestSha256": "<64 lowercase hex>",
  "cliSha256": "<64 lowercase hex>",
  "fixtureSha256": "<64 lowercase hex>",
  "metadataSha256": "<64 lowercase hex>",
  "securityEvidenceSha256": "<64 lowercase hex>",
  "harness": {
    "qualification/run.mjs": "<64 lowercase hex>",
    "qualification/contract.mjs": "<64 lowercase hex>",
    "observe-native.mjs": "<64 lowercase hex>",
    "scripts/validate-preview.mjs": "<64 lowercase hex>"
  },
  "expectedHost": {
    "windowsBuild": "19045",
    "securityProduct": "Kaspersky Endpoint Security for Windows"
  }
}
```

Pass the manifest's SHA-256 independently on the command line. The release
manifest binds version, source and executable hash; all inputs are checked
before importing the observer, before every child diagnostic, and at the end.
The manifest is an operator assertion, not publisher authentication. Only the
reviewed alpha.1, RC1 and stable 0.5.0 output contracts are accepted.

## Run

Use a short private parent so the explicit product MAX_PATH limit does not
prevent the Unicode case. The result must be a new file directly in that
initially empty parent. In the corresponding Medium or High session:

```powershell
node qualification/run.mjs `
  --input $InputManifest --input-sha256 $InputManifestSha256 `
  --release-manifest $ReleaseManifest --metadata $MeasuredHostMetadata `
  --security-evidence $RawSecurityEvidence `
  --cli $ReleaseExe --fixture $FixtureExe `
  --parent $FreshPrivateParent --result $NewResult --mode medium
```

Repeat with a different fresh parent/metadata/input manifest and `--mode high`.
Actual CLI context must agree with the launcher metadata; Limited-task settings
alone are not accepted as proof of Medium execution.

Medium cases, in a closed order:

1. Independent real thread lock: held, then fixture `release` acknowledgement
   and free; both exit 0. Guard/thread size and mtime remain unchanged. The
   returned native volume serial, 128-bit FileId and final path must agree for
   both guard and thread across the held/free pair. Native `size`, `write_time`
   and `change_time` must also agree; Node numeric inode values are not used as
   identity evidence. Matching metadata snapshots do not prove content history.
2. Busy coordinator: unknown/2.
3. Missing guard and missing thread: unknown/2; absence remains absence.
4. Hardlinked guard and thread: unknown/2.
5. Junction ancestry: unknown/2.
6. Free file with unavailable requested PID: free lock evidence plus unknown
   process evidence, overall exit 2.
7. Held fixture with the runner's unrelated same-user PID: observational
   metadata only, holder remains unproven.
8. A private Unicode/space parent: held then free, exit 0, with the same native
   guard/thread identity and metadata comparison. Both successful pairs are
   required in the result coverage.

High cases are capabilities with `diagnosticsAvailable=false` and valid
inspection refused with exit 2, no nested diagnostic and no created test path.
All records retain `safeToUnlock=false` and `recoveryAvailable=false`.

The separate existing `observe-native.mjs` run remains necessary to establish
actual pinned Codex interoperability. Synthetic free-state evidence cannot turn
the native server's post-exit missing-file observation into a native free state.
Likewise, overlapping contention is not proof of a native lock's entire range
or the supplied PID's holder authority.

## Results, bounds and cleanup

Exit 0 requires all expected cases, verified inputs, normal fixture exits,
removed fixture roots, and the selected host profile. Exit 2 means a collected
failure/incomplete run or unmet host profile. Exit 3 is preflight/refusal or a
result-write failure. Public stdout contains a fixed summary; detailed errors,
local paths and PIDs remain in the private JSON result.
Mask account identifiers, paths and PIDs before publishing any raw excerpts;
prefer the allowlisted public summary.

`collected` means the ordered cases and cleanup were verified, not that an
unverified security profile became qualified. `hostQualified` is derived from
the separately supplied, hash-bound host/vendor evidence; it does not prove
that evidence's producer was truthful. The operator must inspect raw evidence.

Fixture records are capped at 16 KiB per line and 256 KiB total. Stderr is
capped at 64 KiB; malformed/partial frames, unexpected protocol, incomplete
children and cleanup errors fail the run. Ready/release waits are 10 seconds;
stdin write wait is 2 seconds; EOF completion wait is 5 seconds. Fixtures have
a 60-second own lifetime. Diagnostic waits use the existing observer's bounded
capture (10 seconds plus EOF wait). Timeout means incomplete, not guaranteed
process termination. Pipe closure may cause a child's subsequent writes to fail.
No kill/escalation is used. Synchronous filesystem calls and executable-hash
reads are not given a hard wall-clock bound. Scratch and failed reports are
preserved; do not remove them while any child remains unconfirmed.

The private-parent checks and explicit nonrecursive operations are not an
adversarial same-user race proof. RC and stable embed different version strings,
so their executable bytes differ. Always measure the final stable bytes again;
RC qualification does not substitute for that run. Tests under
`contract.test.mjs` cover malformed
inputs/framing, wrong versions/hashes/identity, missing/reordered rows, cleanup
failures and public-summary redaction. Host execution is separate evidence.

```sh
node --test experimental/windows-rust-diagnostics/qualification/*.test.mjs
```
