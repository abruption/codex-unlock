# Windows identity observations (research, W1 #146, W2 #147, W3 #148)

Fixture-only research for three Windows evidence gates from
[docs/windows-rust-evaluation.md](../../docs/windows-rust-evaluation.md):
file identity (W1), owner SID and DACL (W2), and process identity (W3). It is
not part of the npm package, the production CLI, JSON v1, or `npm test`.
Windows stays unsupported. Every record and every classifier result carries
`safeToUnlock: false`, and nothing here authorizes recovery on Windows.

The existing [`experimental/windows-fixture/`](../windows-fixture/README.md)
and [`experimental/rust/`](../rust/README.md) experiments are unchanged.
This directory follows the same C#-through-`Add-Type` approach as
`windows-fixture` so that no compiler or Rust toolchain has to be installed
on a Windows host.

## Files

| File | Role |
| --- | --- |
| `WinIdentityLab.cs` | Observer (C# 5 for Windows PowerShell 5.1 `Add-Type`). Creates a private scratch tree, creates synthetic fixtures inside it, records raw observations as JSON, and removes only objects whose identity it verified |
| `lab.ps1` | Entry point. Reserves the result file, compiles the observer, runs the suite, writes JSONL, and reports scratch preservation |
| `check.ps1` | Static gate: parses both scripts and compiles the observer without calling it |
| `classify.mjs` | Pure classifier, closed case manifest and run evaluator. Single source of the `match` / `unknown` / `refuse` rules and of what a complete run contains |
| `classify.test.mjs` | Mock-observation unit tests for every rule and manifest check, plus static scans of the observer sources |
| `../../.github/workflows/windows-identity.yml` | Separate mock, parse/compile, synthetic and fault-injection CI gates |

## Evidence tiers

| Tier | What runs | Where | Status in this change |
| --- | --- | --- | --- |
| Unit / mock | `node --test experimental/windows-identity/classify.test.mjs` | Any host with Node; no install needed | Run on macOS |
| CI static | `check.ps1` parse and `Add-Type` compile | `static` job | Reported by the corresponding CI run |
| CI synthetic | `lab.ps1`, then `classify.mjs`, on a hosted `windows-2022` runner (NTFS, the runner's own token), plus the five fault-injection modes | `synthetic`, `fault-injection` jobs | Reported by the corresponding CI run |
| Real host | The same `lab.ps1` on a designated host, per integrity level and filesystem | Operator | Not done |

Local macOS validation does not compile C# or parse PowerShell; the separate
CI gates report that evidence for their tested revision. A unit pass shows only that the classifier implements
the stated rules on mock records. A CI synthetic pass would show that the
observer produces those records on one hosted NTFS volume with one token.
Neither is product support. ReFS, Medium integrity, another user's files and
a real Codex binary are **unverified**.

## Run evaluation (closed manifest)

`node classify.mjs [--fault <name>] <results.jsonl>` does not trust the
expectations the producer wrote into its records. It evaluates the run
against `MANIFEST` in `classify.mjs`:

- The first record is `environment` (with filesystem, token default owner,
  budgets and the fault mode). The last two are `suite_end`, whose
  `emitted` count must equal the number of records before it, and the
  terminal `cleanup` record.
- Every other record must be a manifest case, at most once, in manifest
  order, with the manifest's kind, track and expected kind. A producer
  `expect` that differs from the manifest expectation (or is missing, or is
  present on a recorded-only case) is `tampered_expect`.
- Every planned case must be present. A skip is accepted only for the two
  cases that allow it and only with the listed Win32 codes
  (`symlink:file`: 1314 or 87; `sec:owner_administrators`: 1307).
- `sec:default_owner` takes its expectation from the environment record's
  token default owner, and every security observation must report that same
  token owner.
- Child records are bound together: `launch:child` PID, the same recorded
  PID and creation time for the live, after-exit, fresh-open and reuse cases,
  and exactly one FILETIME tick for `proc:child_start_mismatch`.
- Setup records must be `ok`; `eof:child` and `reuse:children` must be
  internally consistent (for example `ok` only with exit code 0).
- The cleanup record must be consistent (`ok` only with nothing preserved,
  no running child, no reason, and `removed == registered`) and `ok` in a
  normal run. A `suite_error` fails a normal run.

The summary reports three things separately:

| Field | Meaning |
| --- | --- |
| `collection` | Complete or not, with every structural error |
| `hypotheses` | Matched, mismatched and recorded-only counts |
| `coverage` | Allowed skips, and PID reuse as `verified`, `unobserved`, `failed` or `not_reached` |

| Exit code (normal run) | Meaning |
| --- | --- |
| 0 | Collection complete, every hypothesis matched, full coverage |
| 4 | Collection complete and matched, coverage partial (an allowed skip, or PID reuse unobserved). Unobserved PID reuse is never W3 reuse evidence |
| 1 | Any hypothesis mismatch |
| 2 | Collection incomplete or any structural error |

With `--fault <name>`, exit 0 means the run failed exactly as that fault
specifies (see below) and anything else is a failure of the fault check.

## Classification contract

### W1 file identity

Each path is opened once with `FILE_READ_ATTRIBUTES | READ_CONTROL`, share
read/write/delete, and `FILE_FLAG_BACKUP_SEMANTICS |
FILE_FLAG_OPEN_REPARSE_POINT`. Through that one handle the observer reads
`FILE_ATTRIBUTE_TAG_INFO`, `FILE_ID_INFO` (volume serial plus the 128-bit
identifier), `FILE_STANDARD_INFO`, `GetFinalPathNameByHandleW` and the
volume's filesystem name.

**No-follow applies to the last path component only.** Ancestor directories
are traversed normally, so a reparse point or replacement higher in the path
is not detected by the open itself. The suite binds paths through the final
path of the handle and through identity comparison; it does not prove
ancestor traversal.

| Condition | Result |
| --- | --- |
| Open or any query fails, including the filesystem name | `unknown/<stage>_failed` with the Win32 code, or `unknown/filesystem_missing` |
| Reparse attribute or nonzero reparse tag (junction, symlink, mount point) | `unknown/reparse_point` |
| 128-bit identifier missing, all zero or all one | `unknown/file_id_128_missing`. The 64-bit `nFileIndex` is recorded as `legacyIndex` and is **never** used as a fallback |
| Non-directory with link count other than 1 | `unknown/hard_link` |
| Delete pending, or directory flag disagrees with attributes or expected kind | `unknown` |
| Requested or final path is not an absolute drive (`C:\...`) or UNC (`\\server\share\...`) path, contains `.`/`..`/empty components, or differs from the other | `unknown/path_handle_mismatch`. Names compare ASCII case-insensitively; any non-ASCII difference stays unequal. 8.3 short names do not match long names |
| Two observations with different requested paths (a case-only variant is the same path) | `unknown/requested_path_mismatch` |
| Identity differs between two observations (same handle or a fresh path open) | `unknown/identity_changed` |
| Everything above holds | `match` with identity `volumeSerial:fileId` |

The scratch root is recorded by its final path, so a short-name `%TEMP%`
does not produce false path mismatches. Unix lossless identity
([lossless-file-identity.md](../../docs/lossless-file-identity.md)) is not
touched.

### W2 owner and DACL

The observer reads owner and DACL through `GetSecurityInfo` on a no-follow
handle and parses them with `RawSecurityDescriptor`. SIDs never leave the
observer as raw values: they become `self` (the current token user),
`system`, `administrators`, `owner_rights`, `creator_owner`, `everyone`,
`authenticated_users`, `builtin_users`, `service:<tag>` or `other:<tag>`,
where `<tag>` is a per-run keyed hash that only distinguishes principals
within one run. The DACL is reported as `daclState`: `present`, `null` (DACL
flag set without an ACL) or `absent`.

| Condition | Result |
| --- | --- |
| Open, attribute or security query fails (for example access denied) | `unknown` |
| Reparse point | `unknown/reparse_point` |
| Owner is not exactly the current user (another user, Administrators, SYSTEM) | `refuse/owner_not_current_user` |
| Observed NULL DACL / observed absent DACL | `refuse/null_dacl` / `refuse/dacl_absent` |
| DACL state missing or unrecognized (no evidence) | `unknown/dacl_missing` |
| Unparsed, object, callback or other unsupported ACE, or an effective `CREATOR OWNER` ACE | `unknown` |
| An effective allow ACE grants a write-like right to any principal other than the owner, SYSTEM or Administrators, whether explicit or inherited | `refuse/other_writer` |
| Deny ACEs, read-only ACEs and inherit-only ACEs | Do not refuse by themselves; inherit-only ACEs are checked on the children that inherit them |
| Otherwise | `match`, with explicit and inherited ACE counts and the privileged writers present |

Write-like rights are `FILE_WRITE_DATA`/`FILE_ADD_FILE`,
`FILE_APPEND_DATA`/`FILE_ADD_SUBDIRECTORY`, `FILE_WRITE_EA`,
`FILE_DELETE_CHILD`, `FILE_WRITE_ATTRIBUTES`, `DELETE`, `WRITE_DAC`,
`WRITE_OWNER`, `MAXIMUM_ALLOWED`, `GENERIC_ALL` and `GENERIC_WRITE`.

**Threat-model limits (research assumption only).** A `match` does not
exclude privileged principals. SYSTEM, members of Administrators (once
elevated), and any holder of backup, restore or take-ownership privileges
can read or replace these files regardless of the DACL, so their ACEs are
recorded rather than refused. This is a documented assumption of this
research, never a production authorization, and it never yields
`safeToUnlock: true`. The experiment defends against other ordinary users
only.

**Scope of security changes.** Security descriptors are applied only at the
creation of new synthetic objects inside the protected scratch root. No
existing object's ACL or owner is modified, no privilege is enabled, and no
account or host policy is changed.

### W3 process identity

One handle per candidate is opened with `PROCESS_QUERY_LIMITED_INFORMATION |
SYNCHRONIZE`. Each observation records `GetProcessId(h)` for that handle,
whether it is a `held` or `fresh_open` handle, the `GetProcessTimes` creation
FILETIME, the token user class, and `WaitForSingleObject(h, 0)` before and
after identity collection. Every recorded identity (including `proc:self`)
holds the PID and creation time. An exit code such as `STILL_ACTIVE` (259) is
never evidence. A valid FILETIME is a decimal string without sign or leading
zeros in `1..2^63-1`; it is carried as a string because it exceeds the exact
integer range of a JSON number.

The manifest also fixes the handle source per case: PID-reuse and fresh-open
cases require `fresh_open`, while observations of the retained child handle
require `held`. Each mode record must equal the corresponding process sample.
A creation-time difference from a retained handle is not PID-reuse coverage.

| Condition | Result |
| --- | --- |
| Recorded PID or creation time missing or malformed | `unknown/recorded_identity_missing` |
| Open fails | `unknown/open_process_failed` |
| Handle source is not `held` or `fresh_open` | `unknown/handle_source_unknown` |
| Observed PID missing, not a positive 32-bit integer, or different from the recorded PID | `unknown/pid_missing` / `unknown/pid_mismatch` |
| Observed creation time missing / malformed | `unknown/process_times_missing` / `unknown/process_times_malformed` |
| Creation time differs from the recorded one (also when the other process has exited) | `unknown/identity_changed`; a fresh open adds `pidMayBeReused` |
| Wait on the handle is signaled | `exited` |
| Wait fails or is missing, before or after identity collection | `unknown/wait_failed` |
| Token user is not the current user | `refuse/other_user` |
| Otherwise | `live_same_user` |

Owner mode uses the image base name and the flattened command line from
`ProcessCommandLineInformation`; the returned `UNICODE_STRING` header and
text must lie inside the buffer actually returned before it is read. The
shared-service spellings are the same regular expressions as the flattened
checks in [`src/process.ts`](../../src/process.ts); a unit test fails if they
drift. `app-server`, `daemon`, `remote-control`, `exec-server` and
`--remote` are `refuse/shared_service`. A non-Codex image is
`unknown/not_codex_image`. Because no Windows Codex argument grammar has been
observed (W7), every other Codex command line stays
`unknown/windows_argv_grammar_unverified`.

## Synthetic suite (`lab.ps1`)

`powershell -NoProfile -NonInteractive -File lab.ps1 -OutFile <new file>`
under the host's existing execution policy, then
`node classify.mjs <new file>`.

- **Result file first:** the result path must be absolute after resolution,
  its parent must be an existing non-reparse directory, the file must not
  exist and must not be inside a lab scratch directory. It is created with
  `CreateNew` and no sharing before compilation or any fixture; otherwise the
  run exits 3. A later refusal is written into that file as a `refused`
  record. Write or close failures exit 2.
- **Scratch:** `%TEMP%\codex-win-identity-<random>` is created with a
  creation-time descriptor (owner is the current user, protected DACL with
  one inheritable full-control ACE for the current user), read back, and
  held for the whole run with a directory handle that has data access and no
  `FILE_SHARE_DELETE`, which makes another open that asks for `DELETE`
  (rename or delete of the root) conflict. On verification failure the run
  exits 3.
- **Partial evidence:** an exception inside the suite is recorded as
  `suite_error` after the evidence collected so far, followed by `suite_end`
  and cleanup. If an exception escapes the suite, `lab.ps1` writes the
  partial records and a `suite_error`.
- **Processes:** only `cmd.exe` children started by the suite, with the
  system directory as working directory (not scratch). Each child is
  registered immediately after `Process.Start`; identity comes from the
  creation handle and a separate limited probe handle. Every exit path runs
  stdin EOF, a bounded wait and handle cleanup. Nothing is terminated or
  signaled. A child whose exit is not confirmed keeps the run incomplete and
  the scratch directory preserved.
  The ignored-EOF fault uses `cmd.exe` running `ping`; only the direct child
  is independently registered. Its grandchild's exit is not separately proven.
- **Cleanup:** before deleting anything, the root is reopened and its
  identity, type and final path re-verified, then every registered object is
  opened (directories with data access and no `FILE_SHARE_DELETE`, held until
  the end) and its identity, type, reparse state, final path and parent
  (the root or an earlier verified directory) are checked. Any mismatch
  deletes nothing and preserves the tree. Deletion then goes through the
  verified handles (`FileDispositionInfo`), children before parents; no path
  is deleted by name and nothing is deleted recursively. This narrows races
  but is not race-free: the run-long root hold is released before the root
  is reopened for deletion (the reopen is re-verified), and privileged
  principals or other software holding handles are outside this control.
  Counts named `removed` record successful delete dispositions and closed
  handles. Another component's handle can delay physical removal; these counts
  alone do not prove immediate disappearance of every name.
- **Output:** UTF-8 JSONL without BOM, ASCII-only. Raw records contain local
  paths, per-run SID tags and command lines; do not publish them.
  Managed exceptions preserve the records collected before failure. Records
  are buffered until finalization, so a process crash, job cancellation or
  result write failure can leave an empty or partial reserved result file.
  Output-parent checks cover its last component; they do not prove all
  ancestors, exclude every replacement race or establish the output file ACL.

| Case | Track | Manifest expectation |
| --- | --- | --- |
| `file:home`, `file:lock_dir`, `file:coordination`, `file:thread_lock`, `file:transcript` | W1 | `match` |
| `same_handle:before_after`, `case_variant:path` (upper-cased leaf) | W1 | `match` |
| `path_replacement:file` (rename under an open handle, then recreate) | W1 | `unknown/identity_changed` |
| `path_replacement:same_handle` | W1 | `unknown/path_handle_mismatch` |
| `parent_replacement:dir` | W1 | `unknown/identity_changed` |
| `hard_link:target`, `hard_link:alias` | W1 | `unknown/hard_link` |
| `junction:nofollow`, `sec:junction` | W1, W2 | `unknown/reparse_point` |
| `symlink:file` | W1 | `unknown/reparse_point`, or skipped with Win32 1314 or 87 |
| `missing:path`, `sec:missing` | W1, W2 | `unknown/open_failed` |
| `sec:scratch_root` and the five Codex-shaped paths | W2 | `match` |
| `sec:default_owner` | W2 | `match` if the token default owner is the user, otherwise `refuse/owner_not_current_user` (typical for an elevated administrator token) |
| `sec:owner_administrators` | W2 | `refuse/owner_not_current_user`, or skipped with Win32 1307 |
| `sec:other_writer_explicit`, `sec:inherit_everyone_dir`, `sec:inherit_everyone_file` | W2 | `refuse/other_writer` |
| `sec:other_reader_only`, `sec:privileged_writers` | W2 | `match` |
| `sec:deny_other` (deny-all ACE for ANONYMOUS LOGON) | W2 | `match`. Hypothesis: the observer token does not contain ANONYMOUS LOGON, so the deny ACE does not affect the observer's own open. Unmeasured |
| `sec:null_dacl` | W2 | `refuse/null_dacl` |
| `proc:self`, `proc:child_live` | W3 | `live_same_user` |
| `proc:child_start_mismatch` | W3 | `unknown/identity_changed` |
| `proc:child_after_exit`, `proc:child_fresh_open_while_held` | W3 | `exited` |
| `proc:fresh_open_after_release` | W3 | recorded only |
| `proc:pid_reuse` | W3 | `unknown/identity_changed` (coverage `verified`), or a recorded `observed:false` record when the bounded budget (`-ReuseAttempts`, `-ReuseBudgetMs`) ends first (coverage `unobserved`) |
| `mode:self`, `mode:child` | W3 | `unknown/not_codex_image` |
| `cleanup:replaced_root`, `cleanup:replaced_parent` | cleanup | `preserved`: a probe tree whose root or parent was replaced by a new directory holding a sentinel at the same path; guarded deletion must delete nothing, and both the sentinel and the moved originals must keep their identities |

Setup steps (`create:*`, `rename:*`, `launch:child`, `eof:child`,
`reuse:children`) are part of the manifest and must succeed.

### Fault injection

`-FaultInjection <name>` (synthetic only) and `classify.mjs --fault <name>`:

| Fault | Injected behavior | Required outcome |
| --- | --- | --- |
| `during_file_cases` | Exception after the five `file:*` cases | Prefix up to `file:transcript`, `suite_error` naming the fault, cleanup `ok` |
| `after_child_launch` | Exception right after the child is registered | Prefix up to `launch:child`, `suite_error`, child confirmed exited, cleanup `ok` |
| `during_child_observation` | Exception after `proc:child_live` | Prefix up to `proc:child_live`, `suite_error`, child confirmed exited, cleanup `ok` |
| `child_abnormal_exit` | The child receives `exit 7` before EOF | Full manifest; `eof:child` fails with exit code 7; cleanup `ok` |
| `child_ignores_eof` | The child runs `ping -n 20` and ignores EOF; child wait budget at most 2 s | W3 cases after `eof:child` absent; `eof:child` unconfirmed; cleanup preserved with `children_running`. The child exits on its own; it is not terminated |

## Not covered (unverified)

- Compilation of `WinIdentityLab.cs` and parsing of `lab.ps1`/`check.ps1`: no
  Windows toolchain was available where this was written.
- Whether the share-mode holds behave as described on the target builds
  (including rename and hard-link target-directory opens), and whether a
  directory rename is blocked by open handles below it.
- ReFS and Dev Drive: creating such a volume is a host change and is not
  done here. The rules avoid `nFileIndex`, but no ReFS record exists.
- Files owned by another ordinary user: assigning that owner requires the
  restore privilege, which this experiment never enables. Covered by unit
  tests only.
- Medium-integrity tokens (W6), Defender or other third-party openers, and
  case-sensitive directories.
- Real Codex owner classification and argument grammar (W7), holder
  attribution (W4) and any release path (W5).
