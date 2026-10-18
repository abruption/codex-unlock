# Windows native observer (research, W6 #151 and W7 #152)

**Statically validated; native modes remain refused.** This directory
holds a reviewable observer harness and offline evaluator for two evidence
gates from
[docs/windows-rust-evaluation.md](../../docs/windows-rust-evaluation.md):
W6 (Medium versus High integrity) and W7 (real Codex interoperability). The
PowerShell scripts were parsed, their AST gates and pure helpers checked, and
the C# compiled on a designated Windows host. No observer mode, native method
or real Codex binary was run. JavaScript tests use synthetic evidence only.

All `observer.ps1` modes — `preflight`, `observe` and `fixture-meta` —
**refuse to run** (exit 3) at the first statement of setup, before path lookups
or compilation.
The ancestor/junction and creation boundary is not closed: every check the
harness can make compares identities at two points in time instead of pinning
a path, so a same-user actor could still swap an ancestor between the check and
the use. No flag, parameter or environment variable turns that refusal off.
Closing the boundary, or accepting the residual, is a separate decision
(remaining decision 10). The native code stays in the tree to be reviewed and
statically gated, not to be run.

This is not part of the npm package, the production CLI or JSON v1. Windows
remains unsupported. Every record carries `safeToUnlock: false`, and no
result from this harness authorizes unlocking, signaling, terminating or
deleting anything.

## Dependency on later gates

- **W3 (process classification)** depends on W7 evidence. The evaluator
  reports `dependents.W3.nativeClassification = "blocked_on_W7"` unless the W7
  gate is `pass` at that integrity level. Even after a pass the state is only
  `evidence_available_decision_pending`; classifying a real standalone, app-server,
  daemon or Remote Control owner is still a separate W3 decision.
- **W5 (cooperative release)** depends on W7 evidence and on W4. The evaluator
  reports the same state for `dependents.W5.releaseDecision` and never
  authorizes release.
- **W6** covers only the levels that were actually run. A High result never
  stands in for Medium, or the reverse.

## Files

| File | Runs on | Role |
| --- | --- | --- |
| `observer.ps1` | Windows PowerShell 5.1 (designated host) | Proposed orchestrator; all three modes (`preflight`, `observe`, `fixture-meta`) are hard-refused |
| `WinObserver.cs` | Compiled by `Add-Type` inside `observer.ps1` | Read-only native calls: token integrity, file identity, no-follow ancestry, share-mode probes, guarded lock-range probes, Restart Manager, process identity |
| `check.ps1` | Windows PowerShell 5.1 | Static gate. Parses both scripts, checks the syntax tree (automatic-variable assignment, forbidden commands, gate and refusal ordering, harness list), runs the pure helper functions taken from the observer's tree, validates its own paths and `%TEMP%`, then compiles the C# without calling it |
| `expectations.mjs` | Node.js 22.13+ or 24 (any OS) | The expected-result table, typed per-step schemas with internal-consistency invariants, format validators and the path-spelling rule (single source of truth) |
| `lib.mjs` | Node.js | Pure evaluation: JSONL parsing, `collected`/`measured` split, manifest reconstruction, cross-stage binding, provenance state, verdicts, W6 pairing |
| `evaluate.mjs` | Node.js | Offline CLI over JSONL files copied off the host |
| `test/*.test.mjs` | Node.js | Host-independent unit tests, CLI failures and counterexamples with synthetic records |
| [Static CI workflow](../../.github/workflows/windows-native-observer.yml) | Windows / Linux CI | Windows static gate and synthetic evaluator tests; no observer mode |

Run the offline tests from the repository root:

```sh
node --test experimental/windows-native-observer/test/*.test.mjs
```

On macOS, set `RESEARCH_TMP_ROOT` to the approved writable temporary root
first. The CLI failure tests create a fresh private `codex-*` directory under
that root and remove only that directory. Other platforms default to their
system temporary root.

## Safety boundary

- **All observer modes are refused.** `preflight`, `observe` and `fixture-meta`
  exit 3 before path lookups or anything is compiled, created or observed.
  `check.ps1` fails if that refusal
  is removed, moved after `Add-Type`, or made conditional on a flag. It also
  constrains the actual `Refuse` and `Stop-Unknown` definitions and their
  literal exit 3/2 effects, with AST-only negative mutations, never by running
  a potentially weakened observer.
- **No user Codex home.** The user's `%USERPROFILE%\.codex` and any
  pre-set `CODEX_HOME` are compared with every path this harness touches
  **lexically only**. They are never opened, listed or statted. The disposable
  home is a new `%TEMP%\codex-win-obs-<12 hex>\home`. The parent and the home
  are each created with their own protected DACL holding a single full-control
  ACE for the current user SID (a directory created without a security
  descriptor would only inherit, and an inherited DACL is never marked
  protected, so the contract could not hold). The harness reads both ACLs back and records the owner, the
  ACE identity, its rights, its inheritance flags and its type as **raw
  fields**; the evaluator recomputes the contract and never reads an
  `aceIsCurrentUser`-style boolean.
- **Validate every path before touching it.** One gate runs before any
  `Test-Path`, read, hash, creation or `Add-Type`: `%TEMP%`, the harness
  directory, `-OutFile` and its parent, `-Manifest`, `-CodexBinary` and
  `-FixtureDir` must each be an **absolute local drive path with an accepted
  spelling** and disjoint from the actual, default and environment Codex homes.
  UNC (`\\server\share`), device (`\\?\`, `\\.\`), rooted-without-drive,
  drive-relative, `.`/`..`, double-separator, trailing-space and trailing-dot
  spellings are **refused, not normalized**. Every component containing `~`
  is also refused, including ordinary literal tilde names. This deliberately
  excludes 8.3 aliases that `GetFullPath` does not expand and that lexical
  comparisons cannot equate with a long name. If the host's TEMP uses a short
  spelling, use an independently known safe long-path compiler scratch; do not
  weaken the gate. CI creates such a private scratch under `RUNNER_TEMP` and
  overrides TEMP/TMP for that step only. `-OutFile` is additionally refused
  inside any `codex-win-obs-<12 hex>` directory on any volume, matched literally
  and case-insensitively per path component, independently of the current
  `%TEMP%`. These checks are not physical canonicalization or a proof against
  junction/ancestor replacement; native modes remain refused.
- **The compiler is a side effect, and it is honest.** `Add-Type` starts the
  .NET compiler as a child process and writes compiler temporaries into
  `%TEMP%`. Both `observer.ps1` and `check.ps1` run the path and `%TEMP%` gate
  **before** `Add-Type`, rejecting the declared real-home spellings. This is
  not a guarantee against all physical aliases; use a known safe staging
  directory for the static gate and preserve the ancestry limitations below.
  A static gate means no observation and no native method call, not no compiler
  process and no compiler files. The compiler inherits this shell's
  environment, which is why no credential may be exported into the shell that
  runs these scripts.
- **No-follow ancestry, which is a check and not a pin.** The temp root's
  ancestry is walked with `FILE_FLAG_OPEN_REPARSE_POINT`, component by
  component, before creation, and the new parent's ancestry is walked again
  before the home is created inside it. Each component's attributes and file ID
  are recorded, and the evaluator refuses the home when any component is not a
  plain directory. The components are opened one after another by path, so an
  ancestry that passes can still be replaced afterwards. That residual window
  is not asserted away; it is why the native modes are refused.
- **One manifest, reconstructed.** Observe requires exactly one manifest
  record in the whole preflight file, as the **last** record, complete, with
  every other required preflight step present exactly once and usable. A file
  with both a complete and an incomplete manifest record is refused. Each
  manifest field is then cross-checked against the raw preflight observation it
  claims to describe (home and parent paths and file IDs, the hashed binary's
  path, digest and size, the recorded version line, the harness digests, the
  measured integrity SID), and the path shape is re-derived: the home must be
  exactly the parent's `home` child and the parent must be a
  `codex-win-obs-<12 hex>` directory. A file ID alone is never treated as
  authorization or provenance. This prevents stale, partial, contradictory or
  out-of-scope inputs; it does **not** defend against an adversarial same-user
  forged manifest.
- **No credentials.** The harness does not read, copy, create or forward any
  credential, token or `auth.json`. The one child process it starts
  (`codex --version`) gets a **cleared** environment plus a narrow allowlist
  (`SystemRoot`, `SystemDrive`, `windir`, `COMSPEC`, `PATHEXT`,
  `NUMBER_OF_PROCESSORS`, `PROCESSOR_ARCHITECTURE`) with `CODEX_HOME`, `TEMP`
  and `TMP` pointed at the disposable directory, so no inherited
  authentication, proxy or `USERPROFILE` variable reaches it. The allowlist is
  recorded in the version record. How Codex is authenticated in the disposable
  home is an open decision (see below).
- **Binary before execution.** The binary's SHA-256 must equal
  `-ExpectedSha256` before it is executed. It is hashed again immediately
  before the only execution the harness performs (`--version`).
- **Read-only file access.** Identity reads use `FILE_READ_ATTRIBUTES` with
  `FILE_FLAG_OPEN_REPARSE_POINT`. Probes open existing files only (never
  `CREATE_*` or `GENERIC_WRITE`). The harness never deletes, renames,
  truncates or writes Codex files, and it never changes an ACL.
- **Gated active operations, per sample.** Before **each** sample's
  enumeration, Restart Manager, share and range operations, the declared PID is
  re-queried and must still be the same live, same-user instance at the same
  creation FILETIME, image path and integrity SID; the queried record is
  emitted either way (`process.sample`) with the refusal reason when the gate
  stopped that sample. A refused sample runs none of those operations and never
  inherits an earlier sample's verdict. Per sample, the lock directory must be a
  plain non-reparse directory and the coordination guard a single-link regular
  file that is not pending delete **before** any enumeration, and the thread
  lock must be a single-link regular file that is not pending delete before the
  probes. A failure at the end of the run (`process.identity_after`) is
  recorded, but it cannot undo operations that were already performed.
- **Locks, bound to expected identity — and not passive.** The only state the
  harness takes is a brief, fail-immediately, **exclusive** `LockFileEx` on the
  live `.coordination.lock` (Rust range). Under it, it runs fail-immediately
  exclusive probes on the thread lock, which succeed and are released at once
  whenever a range is free. Codex acquires with a fail-immediately `try_lock`,
  so a Codex acquisition that falls inside one of those windows **fails**: this
  is an effect on the observed process, not an observation of it.
  The guarded probe is given the already-validated expected file IDs of the
  lock directory, the coordination guard and the thread lock; it verifies the
  opened guard and thread handles against them **before** taking any lock
  (including that each is a regular, non-reparse, single-link, not-delete-pending
  file, with the expected link count fixed at one inside the native layer rather
  than passed in by the caller), and revalidates the guard on the same handle
  and the directory by path **after** the guard is released. A changed,
  unreadable or unreleasable identity makes the result `unknown`. There is no
  native file creation and no fallback. Each probe that succeeds is released at
  once, and the guard is released in `finally`. No await, spawn or signal
  happens while the guard is held. The lock order matches the production rule:
  native guard, then thread probe. A missing or busy guard is `unknown`.
- **RM/share observations are deferred, even in the dormant producer.**
  Path-based RM and share calls have been removed from the producer. It emits
  `unknown` with `guarded_handle_binding_not_implemented` instead of reopening
  a path outside a common guard. Implementing synchronous shared coordination
  and handle/FileId binding is a separate requirement, not satisfied by the
  current range-only guard. No new guarded native helper is introduced here.
  The reviewable C# share helpers use full sharing (read, write, delete).
  Requesting the DELETE
  access right is not a file-removal call; no delete disposition, rename or
  removal is ever issued. Restrictive-sharing probes (omitting write or delete
  sharing, which could block the holder's writes or its Drop-time delete) are a
  separate, **not-executed** proposal below.
- **Processes.** The harness queries the operator-supplied PID through a
  `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE` handle, opening a **fresh
  handle per sample** (it is not a run-long pinned handle), and every native
  result echoes the PID that was queried so the evaluator can bind it to the
  run record instead of trusting a record's position. Liveness comes only from
  `WaitForSingleObject(h, 0)`. The harness never calls `TerminateProcess`,
  `Stop-Process` or `taskkill`, and it never sends console control events. The
  `--version` run drains stdout and stderr **concurrently**, each with a byte
  cap, against one monotonic deadline that also bounds process exit, so a
  descendant that inherits the pipes cannot hang it and a full pipe on one
  stream cannot deadlock the other. A read is usable only when it reached
  end-of-stream inside the deadline without overflowing its cap (the cap is
  enforced by reading one byte more than the cap, so exactly-at-the-cap is
  end-of-stream and not an overflow); a valid first line beside a failed,
  truncated or timed-out read is never success. A timeout is reported incomplete
  with the remaining PID and the process is left running (never killed, so
  child termination is not guaranteed).
- **No host changes.** Execution policy, Defender state and the OS build are
  recorded as found **before** anything is created or executed. Defender is
  never enabled, disabled or configured. Execution policy is never changed. The
  entry point is `powershell -NoProfile -NonInteractive -File`, with no
  `Bypass`, no encoded command and no wrapper.
- **No network.** Neither the observer nor the evaluator opens a network
  connection. What Codex itself does in the disposable home is the operator's
  launch decision.
- **Outputs.** `-OutFile` must not exist and must pass the path gate. Each
  output is created with `FileMode.CreateNew` as UTF-8 without a BOM, one
  LF-terminated JSON object per line. Raw records contain local SIDs and paths,
  so do not publish them unredacted.

## Required operator environment

Recorded for review. With the native modes refused, none of this is a request
to run anything.

| Item | Requirement |
| --- | --- |
| Host | The designated Windows host. The harness does not connect to it; an operator runs every command there |
| OS / shell | Windows 10 or 11, Windows PowerShell 5.1 (`powershell.exe`), Storage module with `Get-Volume -FilePath`, `Get-MpComputerStatus` |
| Filesystem | `%TEMP%` on NTFS (ReFS is W1 scope; the volume is recorded either way), on a local drive, with no reparse point anywhere in its ancestry |
| Defender | Already enabled with real-time protection on. If it is not, preflight aborts before creating anything. Changing it needs separate authorization |
| Execution policy | Existing policy must allow `-File` on these scripts. If it blocks them, stop and report; do not change it |
| Checkout | This repository at one commit, identical for every run being paired. Record `git rev-parse HEAD` as `-SourceCommit` |
| Codex binary | The native Windows executable of the pinned release `rust-v0.163.0` (see section 2 of the evaluation document), not the npm launcher. Use its absolute path |
| Expected digest | SHA-256 of that executable, derived from the published release asset (below) |
| Sessions | W6 needs both: a **Medium** non-elevated interactive desktop PowerShell window, and a **High** session (elevated window or the SSH session used before). Each run uses one session only |
| Shell hygiene | No credential, token or proxy variable exported in the shell that runs these scripts: the .NET compiler `Add-Type` starts inherits that environment |
| Evaluator | Node.js 22.13+ or 24 on any machine; copy the JSONL files off the host |
| Baseline | A `--baseline` JSON file (source commit, binary SHA-256, version, harness digests for the exact six harness file names), established independently of the run. Without a format-valid baseline the evaluator cannot pass |

### Obtaining the expected digest (operator, before preflight)

1. On a machine with network access, list the release assets with their
   published digests, for example with
   `gh release view rust-v0.163.0 --repo openai/codex --json assets`.
   Record the asset name and its `digest`.
2. Download that asset to the designated host. Compare
   `(Get-FileHash -Algorithm SHA256 <asset>).Hash.ToLower()` with the published
   digest. If they differ, stop.
3. If the asset is an archive, extract it into a new directory. Then record the
   SHA-256 of the extracted executable as `-ExpectedSha256`, together with the
   archive digest that vouches for it.

`-ExpectedVersion` is the exact first line that the pinned binary prints for
`--version` (for example `codex-cli 0.163.0`). Confirm it against the release
before the run; the harness compares it exactly.

## Preconditions (check before step 1)

- No other Codex process uses the disposable home (it is new, so none should).
- For a same-level run, the Codex window you will open in step 3 runs at the
  **same integrity level** as the observer window. The cross-level variant
  below is a separate run.
- `%TEMP%` resolves to a local NTFS directory you own, with a plain ancestry.
- You know how Codex will be authenticated in the disposable home without
  copying credentials from the real home. If you do not, stop (remaining
  decision 1).

## Run commands (operator, on the designated host)

> **All observer modes currently refuse.** This includes `-Mode fixture-meta`
> as well as `-Mode preflight` and `-Mode observe`. They
> exit 3 with the refusal reason while remaining decision 10 is open. The
> commands are documented so the intended procedure can be reviewed, not so it
> can be run. Step 0 (static gate) and step 7 (offline evaluator) can run.
> Step 6 remains deferred even though the `fixture-meta` command exists.

Run from `experimental\windows-native-observer` in the checkout. Choose an
output directory outside `%TEMP%\codex-win-obs-*`, for example
`$out = "$env:USERPROFILE\Documents\codex-w7"`, and create it first. Repeat
steps 1–6 once per integrity level (`medium` in the desktop window, `high` in
the High session), from the same commit.

0. **Static gate** (no native calls):

   ```powershell
   powershell -NoProfile -NonInteractive -File check.ps1
   ```

   Expected: `parse ok: observer.ps1`, `parse ok: check.ps1`,
   `syntax-tree checks ok …`, `ordering ok: …`, `refusal ok: …`,
   `AST-only mutation checks ok: …`,
   `harness file-name set ok`, `pure helpers loaded …`, one
   `pure helper checks ok: <group>` line for each of the nine assertion groups,
   `path gate ok: …`, `compile ok: WinObserver.cs (no method called)`, exit 0.

1. **Preflight** (refuses today):

   ```powershell
   powershell -NoProfile -NonInteractive -File observer.ps1 -Mode preflight `
     -IntegrityLabel medium -SourceCommit <40-hex commit> `
     -CodexBinary <absolute path to codex.exe> -ExpectedSha256 <64 lowercase hex> `
     -ExpectedVersion '<exact version line>' -OutFile "$out\medium-preflight.jsonl"
   ```

   Today: `refused: all observer modes are refused …`, exit 3,
   nothing created. If the boundary is ever closed, the expected output is
   `results: …`, `disposable CODEX_HOME: C:\…\codex-win-obs-<12 hex>\home`, a
   `next:` line, and `verdicts:` with only `match` and `recorded`, exit 0, with
   `manifest` (`complete: true`) as the last record.

2. **Note the home path** that was printed. Do not reuse a home from another run
   or another integrity level.

3. **Launch Codex** in a **new window at the same integrity level**:

   ```powershell
   $env:CODEX_HOME = '<disposable home from step 1>'
   & '<absolute path to codex.exe>'
   ```

   Use the launch mode you decided on (remaining decision 2) and do whatever
   that mode needs to create **exactly one** thread (one
   `thread-writer-locks\<thread-id>.lock`). Leave Codex idle. Record the mode
   and the exact command. Then find the PID from a third window, for example
   `Get-Process | Where-Object { $_.Path -eq '<absolute path to codex.exe>' } | Select-Object Id, Path, StartTime`.
   If more than one process matches, stop: the observer needs one unambiguous
   PID.

4. **Observe** (refuses today; in the observer window from step 1):

   ```powershell
   powershell -NoProfile -NonInteractive -File observer.ps1 -Mode observe `
     -IntegrityLabel medium -CodexIntegrityLabel medium -Manifest "$out\medium-preflight.jsonl" `
     -CodexPid <pid> -Samples 3 -OutFile "$out\medium-observe.jsonl"
   ```

   `-CodexIntegrityLabel` is the level of the window that launched Codex. The
   observer checks it against the Codex token when that token can be read.

5. **Stop Codex normally** in its own window, the way the chosen mode exits.
   The harness never stops it. If it does not exit, report that; do not force it.

6. **W6 fixture pairing** (same window, same commit). Running the existing
   synthetic fixture and recording this session's integrity is possible, but the
   pairing it feeds can never complete, so this step is **deferred**: the
   fixture producer is not bound to its own bytes, run or source (remaining
   decision 4), and binding it would mean changing
   `experimental/windows-fixture/`, which is outside this change. Recorded for
   completeness:

   ```powershell
   powershell -NoProfile -NonInteractive -File ..\windows-fixture\lab.ps1 -OutFile "$out\medium-lab.jsonl"
   powershell -NoProfile -NonInteractive -File observer.ps1 -Mode fixture-meta `
     -IntegrityLabel medium -SourceCommit <same commit> -OutFile "$out\medium-meta.jsonl"
   ```

7. **Evaluate** (any machine with Node.js; files copied off the host). Supply a
   `--baseline` JSON file holding the independently established evidence, or
   provenance rows stay `unknown` and the run can never pass:

   ```json
   { "sourceCommit": "<40 hex>", "binarySha256": "<64 hex>", "version": "codex-cli 0.163.0",
     "harness": { "observer.ps1": "<64 hex>", "WinObserver.cs": "<64 hex>", "check.ps1": "<64 hex>",
                  "expectations.mjs": "<64 hex>", "lib.mjs": "<64 hex>", "evaluate.mjs": "<64 hex>" } }
   ```

   ```sh
   node experimental/windows-native-observer/evaluate.mjs run --label medium \
     --preflight medium-preflight.jsonl --observe medium-observe.jsonl --baseline baseline.json
   node experimental/windows-native-observer/evaluate.mjs pair \
     --medium-preflight medium-preflight.jsonl --medium-observe medium-observe.jsonl \
     --high-preflight high-preflight.jsonl --high-observe high-observe.jsonl \
     --baseline baseline.json [--explanations w6-explanations.json]
   node experimental/windows-native-observer/evaluate.mjs pair-fixture \
     --medium-lab medium-lab.jsonl --medium-meta medium-meta.jsonl \
     --high-lab high-lab.jsonl --high-meta high-meta.jsonl [--explanations w6-fixture-explanations.json]
   ```

   The baseline's field formats and its exact harness file-name set are
   validated; the harness map is an exact map of this checkout's bytes, line
   endings included, so a line-ending change alone makes it differ. The
   evaluator cannot prove how the operator established the baseline
   (remaining decision 5). It recomputes every provenance verdict from the raw
   recorded fields and that baseline; it never trusts a harness-written boolean
   such as `matchesManifest`, `imageMatchesBinary`, `isolated` or `sameCreate`.
   `w6-explanations.json` maps a row ID to a written explanation of a
   difference between levels, for example `{"OB-openers": "…"}`. An explanation
   can account for a difference; it can never erase a failed hypothesis (a
   mismatch at either level, in a compared row or in the provenance it rests
   on). `pair-fixture` is always `unknown`.

8. **Cleanup** (operator, after Codex has exited). Confirm that no process
   still uses the home, keep the JSONL files, then delete the
   `codex-win-obs-<random>` directory printed in step 1 by hand. The harness
   never deletes it.

### Cross-level variant (W6 only, optional)

W6 also covers cross-integrity `OpenProcess` access. To record it, run
preflight and observe from the **Medium** window as above, but launch Codex in
step 3 from a **High** window, and pass `-CodexIntegrityLabel high`. Use
separate file names (for example `medium-observer-high-codex-*.jsonl`) and a
fresh preflight and home. The evaluator reports `variant: "cross_level"`. It
never pairs a cross-level run with a same-level run, and a denied token query
stays `unknown`.

### Exit codes

| Program | 0 | 1 | 2 | 3 | 64 |
| --- | --- | --- | --- | --- | --- |
| `observer.ps1` | every hypothesis matched | at least one **measured mismatch** | incomplete, error, unknown, abort, or a setup/orchestrator failure (including an unreadable or unparsable manifest, a failed `Add-Type`, or an exception escaping setup) | refused on an input, path, host precondition or the native-mode gate, before anything was created, compiled or recorded | — |
| `evaluate.mjs` | W7 `pass` / W6 `compared` | at least one mismatch (`fail`) | `unknown` | — | usage error |
| `check.ps1` | parse, syntax-tree, pure-helper, path-gate and compile checks ok | any failure | — | — | — |

Exit 1 means a measured mismatch and nothing else. Setup problems that cannot
establish anything either way are exit 2 with an `unknown:` line, never an
accidental uncaught exit 1.

The offline evaluator also maps unexpected internal exceptions to structured
`unknown`/2 with a fixed `evaluator_internal_error` reason, without exception
messages or stack traces. In the observer an incomplete/error row takes
priority over mismatch; in a usable offline file a measured mismatch takes
priority over an unknown row, while file-global errors take priority over both.
`pair` exit 0 means W6 comparison completion only, not W7 success: W7-only
failures remain visible in each side's `w7` result and do not become W6 rows.

### Expected evaluator outcome

With the current table and a correct baseline, a perfect run still yields
**`w7: "unknown"` with `blockers: ["OB-coordination-range"]`** and exit 2. Codex
holds the coordination lock only for an instant, so a passive observer cannot
measure its range. That row is intentionally never success (remaining decision
3). Every other row is expected to be `match` or `recorded`. For a matched
observer pair with a validated provenance state on both sides, W6 `pair` is
expected to report `status: "compared"`; `pair-fixture` is always `unknown`.

## Restrictive-sharing experiment (proposal, NOT executed)

A restrictive-sharing probe would open the thread lock without granting write
or delete sharing (for example read-only with `FILE_SHARE_READ` only) to learn
the holder's access rights from the resulting `ERROR_SHARING_VIOLATION`. The
default observer does **not** run it: while Codex holds the file, an observer
handle that withholds delete sharing can block Codex's Drop-time delete, and one
that withholds write sharing can block its writes. Running it is a disruptive
active test that must be separately authorized and performed only against a
disposable home where such interference is acceptable; it is not approved here.
The generic `ShareProbe` method can express these masks, but `observer.ps1`
never calls it with a restrictive mask.

## Limitations to preserve

- **Ancestry is compared, not pinned.** The no-follow ancestry walk, the
  creation gate and every identity comparison happen at discrete points in
  time, on handles opened separately by path. A same-user actor can replace a
  component between a check and its use. This is the open boundary that keeps
  the native modes refused (remaining decision 10).
- **Sampled, not pinned.** `ProcessIdentity` opens a new handle per sample and
  again at the end; it is not a single run-long pinned handle. A PID reused
  between samples is a distinct risk; the creation FILETIME is the only
  cross-sample witness and it too is sampled. The final
  `process.identity_after` check can only report a change; it cannot undo an
  operation already performed.
- **Preflight hash is not the target's identity.** The preflight SHA-256 is of
  the binary preflight hashed and ran for `--version`. It does not establish the
  bytes of the separately operator-launched Codex process, nor that that process
  uses the disposable home. The observer binds the launched PID's image path to
  the manifest binary path, which is a path match, not a byte-identity proof.
- **Rehash race.** Re-hashing immediately before `Process.Start` narrows but
  does not close a replace-after-hash window unless the file is otherwise
  prevented from changing. This limitation is preserved rather than asserted
  away.
- **The baseline is an exact byte map, not external provenance.** The evaluator
  checks formats, the exact harness file-name set and equality with the recorded
  digests. It cannot show that the operator obtained the baseline
  independently, and a line-ending change in the checkout is enough to make it
  differ.
- **The compiler's environment is wider than the child's.** The `--version`
  child gets a cleared environment plus a narrow allowlist. The .NET compiler
  that `Add-Type` starts does not: it inherits this shell's environment.
- **Bounded reads refuse rather than guarantee.** The concurrent drain bounds
  both pipes with one deadline and caps each stream, but a producer that keeps a
  pipe open is only reported, never terminated, and the abandoned read's buffer
  is simply not reused.
- **Same-user forgery is out of scope.** Manifest reconstruction, digest
  cross-checks and the DACL contract defend against stale, partial and
  contradictory inputs, not against an adversarial same-user actor who can write
  the same files.
- **Restart Manager reports openers, never holders** (W4), and a target PID
  with a different creation FILETIME is treated as a reused PID, not as the
  launched process.
- **The range probe can make Codex fail.** The exclusive guard and thread
  probes are brief, but a concurrent Codex `try_lock` inside one of those
  windows fails. A failed release is reported as `guard_unlock_failed` (with
  its Win32 code) and is never overwritten by a later revalidation reason.
- **`DirFileId` does not say why.** A missing, unreadable, reparse or
  non-directory target all return the same `null`; the per-sample identity
  records carry the attributes and Win32 codes that tell them apart.
- **The static gate checks names, not intent.** `check.ps1` refuses forbidden
  cmdlets and a denylist of .NET member names in the syntax tree. The members
  the harness uses on purpose (`Process::Start` for `--version`,
  `Directory::CreateDirectory` for the disposable home, `StreamWriter.Write`
  for the results file) are allowed by design, and a call through reflection or
  a dynamically built name would not be caught.

## Abort conditions

Stop and report; do not work around any of these.

| Condition | Where | Effect |
| --- | --- | --- |
| Any observer mode, including `fixture-meta` | any host | exit 3 before path lookups; the ancestry/creation boundary is open and there is no bypass |
| Missing or invalid parameter, existing `-OutFile`, any path that is not an accepted absolute local drive spelling, any path inside a real Codex home, an output inside a `codex-win-obs-<12 hex>` directory, `%TEMP%` or the harness directory inside a real home, `USERPROFILE` unset | any mode | exit 3 before any file is opened or compiled |
| `Get-Volume -FilePath` or `Get-MpComputerStatus` unavailable | preflight | exit 3 before anything is created |
| `-CodexPid` missing, zero, or this observer process | observe | exit 3 |
| Own integrity unreadable, or the measured user SID differs from the current identity | any mode | exit 3 / exit 2, nothing observed |
| Manifest unreadable, unparsable, of another schema or mode, not exactly one manifest record, not last, incomplete, missing a required preflight record, or disagreeing with the raw preflight observations it describes (home, parent, file IDs, binary path, digest, size, version, commit, harness, integrity SID) | observe | exit 3 (or exit 2 when it cannot be read at all); refuse before recording |
| Temp root not an accepted absolute local path, not disjoint from a real Codex home, or with a reparse point in its ancestry | preflight | refused before any directory is created (creation callback never runs) |
| Harness digests incomplete | preflight | abort, no home created |
| Measured integrity differs from `-IntegrityLabel` | preflight, observe, fixture-meta | abort; the result is never relabelled |
| Defender not observed enabled, execution policy unreadable | preflight | abort **before** anything is created or executed; do not change either |
| Binary missing, a reparse point, SHA-256 differs, or changes before execution | preflight | abort before or instead of execution |
| New parent's ancestry not plain after creation | preflight | refused before the home is created inside it |
| Disposable home not isolated (overlapping a real home, not the parent's `home` child, parent not a disposable name, not empty, owner or DACL contract broken, missing file ID, ancestry not plain) | preflight | abort |
| `--version` does not exit within budget, or either stream fails, truncates or times out | preflight | abort; PID reported; process left running, never killed |
| Version line differs | preflight | abort |
| Observer files differ from preflight, integrity differs from the preflight, home re-validation fails (path, parent/home file ID, disjointness, owner/DACL contract or ancestry) | observe | abort before any probe |
| First process observation is not a live, same-user instance of the manifest binary at the declared integrity | observe | active operations refused for the whole run; do not retry with another PID |
| Per sample: the re-queried PID is gone, reused, unreadable, at another user, integrity or image | observe | that sample's enumeration, RM, share and range operations are skipped; the refused process record is still emitted |
| Per sample: lock directory not a plain directory, coordination guard not a single-link regular file, thread lock a reparse point, directory, hardlinked or pending delete, or not exactly one thread lock | observe | that sample's RM/share/range operations are skipped; rows become `unknown` |
| Any agent/process does not exit when the operator expects | operator | report; never force |

## Result model: `collected` versus `measured`

The evaluator ignores the harness's own verdict and booleans. It re-checks each
record against `expectations.mjs` and reports two separate facts for every row:

- **`collected`**: a record exists for the step (`all`, `partial` or `none`
  across samples).
- **`measured`**: that record holds a complete, in-schema, internally
  consistent native observation. That means `observed` is present, `ok` is
  `true`, `complete` is not `false`, the state is not `unknown`, there is no
  exception, no detected Win32 `5` (access denied) in the recursive `win32` or
  `tokenWin32` fields, the typed per-step schema
  passes (required fields present and correctly formatted — SHA-256, commit,
  file ID, SID, absolute local drive path, integer, decimal FILETIME string),
  every schema **invariant** holds, and every hypothesis field is present and
  not null.

Only range result codes 0 (acquired and released) or 33 (lock conflict) are
measured lock states. Only share-open codes 0 (opened) or 32 (sharing
violation) measure sharing behavior. Other errors, including invalid parameter,
missing file or unsupported operation, are `unknown`, not measured mismatch.
W7's `host.volume` must report `NTFS`; other filesystems remain `unknown`.
Every self/target token requires measured `elevationType` enum 1, 2 or 3. Missing
queries and null values are unknown; Full/Limited status is never inferred from
a Medium/High label.

Every record's advisory `expect` must exactly equal the canonical key/value
union for that mode and step, even for derived or recorded rows. This includes
all raw hypotheses of a shared step plus the closed legacy derived expectation
map in `lib.mjs`; extra keys, missing keys, wrong values and wrong shapes are
`expectation_drift`. Matching that metadata never makes a producer-written
boolean or verdict evidence: derivations still recompute from raw fields.

Invariants are the record's internal consistency, and a record that
contradicts itself is never evidence. For example: `opened: true` with a
nonzero Win32 code; a range with `win32: 33` and `acquired: true`, or an
acquired range that reports no release; a probed range whose guard was not
taken and released; a Restart Manager record whose `count` differs from its
`processes` length, repeats a PID and creation pair, carries a role outside the
closed set, carries a FILETIME as a JSON number instead of an exact decimal
string, or whose `interpretation` is not exactly `opener_candidates_only`; a
`thread.count` whose count does not match its own entries; a `binary.version`
record whose streams did not both complete inside the deadline without
truncation; a `binary.pe_version` record with `{ok:true}` and nothing declared;
a `run` record whose observer PID equals its target PID.

Three kinds of row:

- **Derived** rows (provenance and bindings) recompute the verdict from raw
  fields, the cross-stage bindings and the `--baseline`. Booleans the harness
  wrote are never read. Without a format-valid baseline these rows are
  `unknown`, so the gate cannot pass.
- **Raw-comparison** rows compare named observed fields with expected values.
- **Recorded** rows have no hypothesis but must still pass their typed schema
  and invariants; a bare `{ok:true}` fails and is `unknown`, never success.

| Situation | Row verdict |
| --- | --- |
| Not collected, no observation, partial, native error, exception, `unknown` state | `unknown` |
| A required field is missing or malformed for its type | `unknown` (`schema_*`) |
| A record contradicts itself | `unknown` (`schema_invariant:*`) |
| Access denied anywhere in the observation | `unknown` (`access_denied`), never `mismatch` |
| Sample count not an integer 1..10, or any missing sample | `unknown` |
| The record's `expect` differs from the table | `unknown` (`expectation_drift`) |
| A derivation cannot be established (no baseline, no manifest, no run record, missing sibling record) | `unknown` |
| Recomputed home isolation differs from the recorded flag | `unknown` (`evaluator_disagreement`) |
| Mixed integrity, label/SID disagreement, duplicate step, unexpected step, a sample index on a non-sampled step or missing/out-of-range on a sampled one, samples out of order, control or process records not bracketing the samples, `orchestrator_error`, `safeToUnlock` not `false`, preflight/observe at different levels, observe referencing another preflight, a manifest that is absent, duplicated, not last or unusable, a missing required preflight record, an unusable run record, an invalid baseline | whole file unusable / problem, rows `unknown` |
| Measured and derivation/comparison satisfied | `match` |
| Measured and a derivation or field differs | `mismatch` |
| Measured recorded row with a passing schema | `recorded` (never counted as hypothesis success) |

A **file-global problem makes the whole result `unknown` before any per-row
mismatch is reported**: when the structure, the labels or the provenance inputs
are not in a usable state, a measured contradiction cannot be attributed to the
hypothesis. Valid, complete evidence with a genuine mismatch still fails. W7 is
therefore `pass` only if there are no problems and every row is `match` or
`recorded`, `fail` on a mismatch with no problems, and `unknown` otherwise. The
unmeasurable `OB-coordination-range` row keeps a perfect run at `unknown`.

Each run also reports a **provenance state**
(`provenance.state: "validated" | "unvalidated"`). It is `validated` only when
there are no file-global problems, the baseline is format-valid with the exact
harness file-name set, and every provenance row (`PF-harness`, `PF-token`,
`PF-binary-sha256`, `PF-binary-version`, `PF-manifest`, `OB-harness`,
`OB-token`, `OB-home`, `OB-run`) is `match`.

### W6 pairing rules

- Each file must hold a single integrity level. The token integrity SID is
  measured at start and stamped on every record. `S-1-16-8192` is Medium and
  `S-1-16-12288` is High; anything else is unusable.
- Pairing requires a **validated provenance state on both sides**, byte-identical
  harness digests over the exact harness file-name set, the same source commit
  and, for observer runs, the same binary SHA-256, the same version line, a
  format-valid baseline on each side, and same-level runs (observer and Codex
  at the same level). Cross-level runs are reported alone. W6 does **not**
  require W7's unmeasurable coordination range, but it does require every
  provenance prerequisite of it.
- Only rows tagged `W6` are compared. Verdicts and selected values (hypothesis
  fields, measured token `elevationType`, and Restart Manager `count` and role list) are shown side by side
  per level. They are never merged.
- Any difference needs a written explanation. Any row that is `unknown` at
  either level keeps the pair `unknown`; it is never filled in from the other
  level. A mismatch in a compared row **or in a provenance row** at either
  level is `fail`, and no explanation changes that.
- `lab.ps1` records integrity once per run, in its `environment/host` record.
  For fixture pairing, the evaluator requires the `fixture-meta` record from
  the same shell to measure the same SID, then stamps that level on every
  derived row. But the `fixture-meta` record is not bound to the lab's bytes,
  run or source, and the fixture has no closed terminal manifest, so
  `fixtureSummary` always carries `fixture_producer_unbound`, its provenance
  state is always `unvalidated` and every fixture row is `unknown`.
  `pair-fixture` can therefore never be `compared`; it stays `unknown` until a
  separately reviewed producer proposal binds the evidence. The evaluator also
  recomputes each fixture row from raw fields and never trusts `lab.verdict` (a
  `null` observation with `verdict:"match"` is still `unknown`).

## Expected-result table

Generated from `expectations.mjs` (`node evaluate.mjs table`). A unit test
keeps this copy identical to the source.

<!-- expectations:start -->
| ID | Mode | Step | Per sample | Check | Gates |
| --- | --- | --- | --- | --- | --- |
| PF-harness | preflight | `harness` | no | derived: `harnessBaseline` | W6, W7 |
| PF-token | preflight | `token.self` | no | derived: `tokenIntegrity` | W6, W7 |
| PF-binary-sha256 | preflight | `binary.sha256` | no | derived: `binarySha256Baseline` | W7 |
| PF-binary-signature | preflight | `binary.signature` | no | recorded only (typed schema) | W7 |
| PF-binary-pe-version | preflight | `binary.pe_version` | no | recorded only (typed schema) | W7 |
| PF-home | preflight | `home.isolated` | no | derived: `homeIsolated` | W7 |
| PF-binary-version | preflight | `binary.version` | no | derived: `binaryVersion` | W7 |
| PF-home-after-version | preflight | `home.after_version` | no | recorded only (typed schema) | W7 |
| PF-execution-policy | preflight | `host.execution_policy` | no | recorded only (typed schema) | W6, W7 |
| PF-defender | preflight | `host.defender` | no | `amServiceEnabled=true`, `realTimeProtectionEnabled=true` | W7 |
| PF-volume | preflight | `host.volume` | no | recorded only (typed schema) | W7 |
| PF-os | preflight | `host.os` | no | recorded only (typed schema) | W6, W7 |
| PF-manifest | preflight | `manifest` | no | derived: `manifestBaseline` | W7 |
| OB-harness | observe | `harness` | no | derived: `harnessMatchesManifest` | W6, W7 |
| OB-token | observe | `token.self` | no | derived: `tokenMatchesManifest` | W6, W7 |
| OB-home | observe | `home.identity` | no | derived: `homeMatchesManifest` | W7 |
| OB-run | observe | `run` | no | derived: `runControl` | W6, W7 |
| OB-process | observe | `process.identity` | no | derived: `imageLive` | W3, W6, W7 |
| OB-process-token | observe | `process.identity` | no | derived: `codexToken` | W6 |
| OB-process-sample | observe | `process.sample` | yes | derived: `sampleProcess` | W3, W7 |
| OB-lockdir | observe | `lockdir.identity` | yes | `directory=true`, `reparse=false` | W7 |
| OB-guard | observe | `coordination.identity` | yes | `directory=false`, `reparse=false`, `links=1`, `deletePending=false` | W7 |
| OB-thread-count | observe | `thread.count` | yes | `count=1` | W7 |
| OB-thread-identity | observe | `thread.identity` | yes | `directory=false`, `reparse=false`, `links=1`, `deletePending=false` | W7 |
| OB-share-read-rwd | observe | `share.read_rwd` | yes | `opened=true` | W7 |
| OB-share-delete-rwd | observe | `share.delete_rwd` | yes | `opened=true` | W7 |
| OB-range-rust | observe | `range.probe` | yes | `state="probed"`, `ranges.rust.win32=33` | W7 |
| OB-range-fsext | observe | `range.probe` | yes | `state="probed"`, `ranges.fsext.win32=33` | W7 |
| OB-range-beyond-fsext | observe | `range.probe` | yes | `state="probed"`, `ranges.beyond_fsext.win32=33` | W7 |
| OB-range-tail | observe | `range.probe` | yes | recorded only (typed schema) | W7 |
| OB-range-guard | observe | `range.probe` | yes | derived: `rangeGuardBinding` | W7 |
| OB-thread-stable | observe | `thread.identity_after` | yes | derived: `threadStable` | W7 |
| OB-openers | observe | `openers.rm` | yes | derived: `openersRm` | W4, W6, W7 |
| OB-coordination-range | observe | `coordination.range` | no | not measurable (always unknown) | W7 |
| OB-process-after | observe | `process.identity_after` | no | derived: `processAfterLive` | W3, W7 |
<!-- expectations:end -->

The range rows tell the two fixture models apart. Rust std locks offset 0 with
length `u32::MAX:u32::MAX`. The fs-ext emulation locks `0..0xffff0000`. A
one-byte probe at `0xffff0000` (`beyond_fsext`) conflicts only with a holder
whose range extends past the fs-ext range. The `tail` probe at the last 64-bit
offset lies outside the Rust range. It is recorded only, because whether
Windows accepts that offset has not been established. Restart Manager rows are
`opener_candidates_only` and are never holder evidence (W4).

## Verification scope and remaining unexecuted work

| Item | Status | Reason |
| --- | --- | --- |
| `check.ps1` | executed on Windows PowerShell 5.1 | Both scripts parsed; AST checks, refusal mutations and nine pure-helper groups passed |
| `observer.ps1` body (all modes) | not executed | Only its parsed AST and selected pure helper functions were used |
| `WinObserver.cs` | compiled on Windows | `Add-Type` and method-name reflection only; no native method was called |
| All `observer.ps1` modes, including `fixture-meta` | **refused by the harness** | The ancestry/creation boundary is open (remaining decision 10). Refusal is before path checks, not just compilation |
| Real Codex binary, version, disposable home, lock observations | not executed | Requires the designated host and an operator, and the native modes refuse; no real Codex was run anywhere |
| Medium-integrity and High-integrity runs | not executed | Same |
| `lab.ps1` reruns and the `fixture-meta` pairing step | deferred | The fixture producer cannot be bound without changing `experimental/windows-fixture/` (remaining decision 4), so the paired result could never complete |
| Static CI workflow | added | Its remote CI results must be checked for the exact PR head; a local host run is not CI |
| `evaluate.mjs`, `lib.mjs`, `expectations.mjs` | executed | Unit tests with synthetic records only, including the creation and per-sample seams, path-spelling and gate rules, schema/invariant failures, manifest reconstruction and placement, PID/run binding, guard binding, baseline and provenance counterexamples, and the fixture repros |

The PowerShell path gate, creation-gate ordering, per-sample seam, path-spelling
rule, opener-role recomputation and the `check.ps1` syntax-tree checks are
mirrored in JS (`pathGateSafe`, `tempRootSafeForCreation`, `guardedCreate`,
`guardedSample`, `normalizeLocalPath`, `insideDisposableDir`, plus source
assertions over `observer.ps1` and `check.ps1`) and tested on this host. The
PowerShell and C# static checks were then executed on Windows 10 22H2
(19045), Windows PowerShell 5.1.19041.6456, NTFS, in an elevated SSH session.
The existing `RemoteSigned` policy was unchanged. A new private staging
directory outside every real Codex home held the checked inputs and compiler
temporaries. Source hashes were checked before execution.

The latest review-follow-up static run exited **0**: both parses,
automatic-variable and forbidden-call checks, the exact all-mode refusal AST
contract, eleven switch/guard mutations plus twelve definition/termination
mutations for each of `Refuse` and `Stop-Unknown`, two deferred RM/share-call
insertion checks, nine pure-helper groups (including short-name/tilde refusal,
case-insensitive disposable matching, and execution-policy failure handling),
and C# compilation passed.
Tested inputs:

- `check.ps1`: `738d4fdd8278602f2e32faa35b6d501264a8c300c27a715b501c87acae4d3360`
- `observer.ps1`: `85a84194bef9b781a8ff3b059a87616bd0e3e46d6ae8e6b3c5eb4e4a3d477c28`
- `WinObserver.cs`: `9b44dc7403368857fd7c55cdf4a596310b7b501c1343755f3adc08758f3eb83c`
- Static output SHA-256: `3d642797f734d144fdaf559ed4e2806a119b009cae6a26198f531c27c6eebaed`

The earlier static baselines (output digests
`3ea3e85a2b6f31ba4bb7a41b9273460832bd9d8667ad0ff12e1edf74ff111736` and
`5e8951d7b56c31012aadc8980b8f9694f2cfbe859fd742fc6937ce9619702fc8`)
are retained separately and are not counted as verification of these later edits.

Earlier failures were retained rather than counted as passes: the original
checker used an unavailable `VariablePath.UnqualifiedPath` property; after
switching to public `UserPath`, a faulted stream task was mistaken for EOF by
PowerShell 5.1. Explicit task fault/cancellation checks and
`GetAwaiter().GetResult()` fixed that helper. An intermediate AST-mutation
checker also rejected its own string `.Replace()` calls; literal split/join
now preserves the file-replacement denylist. These are static/pure-helper
findings, not real Codex or lock observations.

The evaluator now requires every ancestry prefix, self-token/run/home identity
binding, exact RM resource paths and share modes, and complete contiguous
sample stages. The dormant producer's late `process.sample` record does not
satisfy that ordering. It has not been loosened or enabled to make a synthetic
comparison pass. Native runtime behavior, Medium/High interoperability,
real lock operations and the creation boundary remain **unverified**.

## Remaining decisions

1. **Authentication in the disposable home.** Codex may need a login to create
   a thread. Copying credentials from the real home is excluded. A dedicated
   test login, or a credential the operator supplies only to that session,
   needs separate authorization. It is also unverified whether startup alone
   creates a thread writer lock before authentication.
2. **Launch mode.** Choose a standalone TUI, `exec` or app-server, and the
   action that creates exactly one thread. Record it. This choice also feeds
   W3 classification.
3. **Coordination lock range.** It cannot be measured passively, so it stays
   `unknown`. Choose one: accept the inference from the measured thread range
   and the shared Rust std implementation (a maintainer decision, recorded as
   inference and not as measurement), or authorize an active experiment. Such
   an experiment would hold a partial guard range while Codex acquires, which
   briefly blocks Codex, so it needs its own approval.
4. **Bound fixture producer for W6.** `pair-fixture` is always `unknown` because
   the current `experimental/windows-fixture` producer is not bound to its own
   bytes, run or source and has no terminal manifest. A separately reviewed
   producer proposal (per-record integrity and a closed, hash-bound manifest,
   which would mean changing `experimental/windows-fixture/`, outside this
   change) is required before fixture evidence can complete a comparison.
5. **Baseline provenance source.** Decide how the operator independently
   establishes the `--baseline`. The evaluator validates its formats, its exact
   harness file-name set and its equality with the recorded digests; it cannot
   show where it came from.
6. **Restrictive-sharing experiment.** Decide whether to authorize the
   proposal-only restrictive-sharing probe, which is disruptive and not run by
   the default observer.
7. **Hosts without Defender enabled.** Out of scope; enabling Defender is a
   separate authorization.
8. **Publication.** Raw JSONL contains SIDs and local paths. Decide what to
   redact before attaching results to #151 or #152.
9. **CI.** Require the checked-in static workflow on the final PR head.
   Compilation and pure-helper checks do not establish native-mode safety or
   Windows support.
10. **The ancestry and creation boundary.** This is what keeps `preflight` and
    `observe` refused. Closing it needs a mechanism that pins the path rather
    than comparing identities twice (for example opening every component
    relative to a held parent handle, or creating and then verifying by file ID
    from a handle that is never released), which Windows PowerShell 5.1 and the
    current P/Invoke surface do not give us. The alternatives are: build that
    mechanism, accept the residual explicitly as a reviewed risk on a host where
    only this harness and Codex run, or leave the native modes refused and keep
    the evaluator as the only executable part. No bypass flag will be added
    either way.
