# #127 fileport, hidden-sharer and restricted-visibility fixtures (macOS)

Unpublished research for [#127](https://github.com/abruption/codex-unlock/issues/127).
It is outside the npm `files` list and is not run by `npm test`. It changes no
runtime behavior, JSON output or signal path, and it applies no filter in
`src/`. Proposed changes to the decision record are in [HANDOFF.md](HANDOFF.md).

`visibility.py` starts only its own same-user actors on fresh fixture files in
a private scratch directory. It never touches a Codex home or a Codex process.
Nothing here reproduces a real Codex process or a wrong signal to a real PID.
It reuses the read-only [`127-macos-contract/inherit.py`](../127-macos-contract/README.md)
for framing with byte caps, bounded no-signal diagnostics, strict `lsof -F0pfG`
parsing, exclusive result creation and the `SCM_RIGHTS`/fork actors. The C
actor, `fileport_actor.c`, is compiled into the scratch directory with
`/usr/bin/clang` at run time. Its binary is never committed.

## Scenarios

| Scenario | Shape |
| --- | --- |
| `fileport` | A C sender flocks the fixture, makes a Mach fileport and moves it in a Mach message to a C receiver that the script started separately (not the sender's descendant). The sender then closes its FD. The receiver later receives the port and converts it with `fileport_makefd`. |
| `hidden_sharer` | One description shared by `SCM_RIGHTS` (either sharer hidden) or by fork without exec (child hidden). The hidden sharer is removed from the observer's view by a model, as in #139 M2 Part 2. The visible sharer then releases on its own (FD close or stdin-EOF exit, never a signal) and the lock is probed again. |
| `sandbox_observer` | A target holder and a canary holder run normally. `lsof` and the flock probe run under `sandbox-exec` profiles written to the scratch directory. |
| `sandbox_target` | The holder runs under `sandbox-exec`; the observer does not. |
| `former_vs_opener` | A former holder (`flock`, `LOCK_UN`, FD kept) next to a never-locked opener, then an actual holder is added and hidden by the model. |

Per stage the script records the independent nonblocking flock probe, the
`lsof +fg` `FWASLOCKED` bit per role, and the refusal-only filter decision.
`fileport` also records each task's `PROC_PIDLISTFILEPORTS`, including the
`FWASLOCKED` bit of a fileport that names the fixture. Each scenario's record
is registered in the result before it runs, and stages are appended as they
are observed, so an exception keeps the earlier stages.

## Decision vocabulary

Only `unknown`, `reject` and `not_excluded` are produced. `not_excluded` only
means "not refused by this filter". The bit is sticky after `LOCK_UN` and is
never treated as holder evidence. `filter_decision` follows the #139 M2 rules.
`visibility_decision` adds cross-checks that can only turn a decision into
`unknown`:

| Condition | Decision |
| --- | --- |
| Canary holder not seen exactly (when scanned) | `unknown:canary_not_visible` |
| Probe error | `unknown:probe_error` |
| Invalid scan (status, stderr, malformed or truncated output, a fileport `fp.` record) | `unknown:scan_invalid` |
| Probe `held` and no visible opener | `unknown:held_without_visible_opener` |
| PID absent | `unknown:pid_absent` |
| No descriptor of the PID has the bit | `reject:bit_absent_on_all` |
| At least one descriptor has the bit | `not_excluded:bit_present` |

The canary and held-without-opener checks catch a restriction of the whole
observer. They do not detect a selective omission of some processes. They are
candidate design inputs for option (b), not adopted product rules.

## Fileport enumeration

`listfileports` reports `ok: true` only for a complete enumeration. These
cases give `ok: false` with an error kind, never a zero count: the fixture
identity (`stat`) failing (`identity`), the list call failing (`list`,
`list_esrch`), a list length that is not whole entries (`list_length`), a
full 64-entry buffer (`saturated`, because more entries may exist), and a
vnode query that fails or returns a short record (`query`, `short_read`).
Fileports whose type is not a vnode are counted in `non_vnode` and not
queried. The fixture is a regular file, so only a vnode fileport can name it.
That exclusion is limited to this fixture. On the Python side an error becomes
`error:<kind>`, which never matches the expected `count=…` value, so the
stage mismatches. A malformed or inconsistent event becomes `invalid`.

## Results

Darwin 27.0.0 arm64 (macOS 27.0.1), Python 3.15.0, Apple clang 21.0.0, lsof
4.91 (`/usr/sbin/lsof`), APFS, same user, worktree base `6082a34a`,
2026-10-18. Raw results are private because they contain local paths, PIDs
and service names.

### Handed-off revision (before root review corrections)

Sources: `visibility.py` `9686152008f0d5a52184881af2cc7b258edd7bf27168a15a4281fd3f132b3016`,
`fileport_actor.c` `c17980bcbb230753855172a36dbb8b6272cdcf37158fb8a2d7bf66426c94c211`,
`inherit.py` `44215d458e53b7ddd038db32a65746b2fdf1402258563cac4f48f682dee51bac`.
Binary `fe7e0f80624b833729f1aefbb272d4caaf0dbb64493aad4cd6a95f88a8ca439d`.
Start and end source hashes matched in every run.

| Run | Outcome | Raw result SHA-256 | Public stdout SHA-256 |
| --- | --- | --- | --- |
| 5 | exit 1, `run_ok` false. One `lsof` diagnostic (in `hidden_sharer/fork_hide_child/all_closed`) exceeded its 5 s bound. It was recorded as incomplete and not stopped, and it later exited with status 1. That stage's scan was therefore invalid (the only mismatch). Cleanup: `preserved` (`measurement_not_ok`); the fixture directory was kept. Bootstrap name removed. | `a793d61c7fbf699c1ee1b9e7dc38a61208786f857765939809e8d28ae0583a90` | `cbe13b5f4a896e7b59f100daa6e003e1574c9b565489fd2921cba32f0796c2fe` |
| 6 | exit 0: `measurement_ok`, `run_ok`; nothing `not_executed`; no failures, incomplete waits, mismatches or pending diagnostics; cleanup `removed` (17 registered names); bootstrap name removed | `16fc95b249bc3352653bc7edbee3ec7c317d7a14e1886d5307996709a92a4347` | `6110937dc0d108ccccc4c39c71cd34555e5d19730aaf0f1c98931eb0c4832784` |
| 7 | same as run 6 | `b6188ba39201e91050fd346040f73c3a7c5ea0b716d1d72ebe7bfda067fb4997` | `6110937dc0d108ccccc4c39c71cd34555e5d19730aaf0f1c98931eb0c4832784` |

For runs 5–7, the public stdout was checked for every PID in the raw result,
the bootstrap service name, the scratch path, `/Volumes`, `/Users` and
`Traceback`. None appeared, and stderr was empty. `--summarize` on run 6's
raw result produced byte-identical output.

### Integrating reviewer validation

After the CLI reviews, the integrating reviewer strengthened restricted-probe
and case/exit evidence, captured actor stderr, and preserved setup failures.
The first nominal validation rejected two bookkeeping details in the stricter
evaluator: a fileport PID without a numeric FD, and an unused outer `stages`
field. It exited 1; raw SHA-256
`27a81c086c141e47d8ce598948ff298b74e7491e398b1b8df35be51a297546bf`.
After correcting those contracts, 80 visibility tests and 23 inheritance tests
passed, and one nominal run exited 0 with `measurement_ok`/`run_ok`, no
mismatches/errors/incomplete waits, and cleanup `removed`. Raw SHA-256:
`5133e330ad798a87ecf9120788e46ca884b7e6ec1a704bd8f5723814f00d049b`.
Start/end source hashes agreed: `visibility.py`
`9dd55023765c0f873b25d1baacd609b0862f3105f597f82049f05f06be676b2d`,
`fileport_actor.c`
`ab295109045e6ac349b069f27b7b182945b7eb715a2ed9469ee49f856c613972`.
This validates the revised harness on the same local macOS environment, not
the pending hosted runners or native Codex behavior.

### History: runs 1–4 (earlier revision)

Runs 1–4 used earlier sources (`visibility.py` `0f946d1c…` for run 1 and
`a2b2753b…` for runs 2–4; `fileport_actor.c` `22cfee78…` and `30ed3560…`).
All exited 0. Raw result SHA-256: run 1 `37829ef77aa5feb07a47da155beab7c3debd2dcc789b739a81f3f90d8844643f`,
run 2 `c8f935d07b3db1d7137855cff744ae8e80af24ed39f64d6efd50692e0666d858`,
run 3 `e10adb8f1963a3c38016996a558f43293d9da8c2c68496f92a1bf24c8f5ecc99`,
run 4 `8bfdb91959551e743fa2eae253008a7d0c16c264c7ce0ef627c851b552fc0ea3`.
Their per-stage observations are the same as below. They do not validate the
revised code, and several of their rules were weaker:

- Their fileport counts treated identity, query and short-read failures as
  zero and did not detect a full buffer.
- Their sandbox rules checked only `reduced: false` for the positive control.
- Their console summary passed raw failure, incomplete, error and stderr text.
- `ok: true` was written before cleanup ran.

Their raw results name the hidden-sharer outcome `wrong_target_possible`.
That historical name is kept inside those files, and its current
interpretation is `release_incomplete_due_to_hidden_reference` (below).

Before run 1, one unscripted exploratory run of the C actor was made by hand
to learn the shape of the fileport stages. It was not recorded, and the
expected table was written after it.

### Fileport passing

| Stage | Probe | Bit per process (`lsof +fg`) | Fileports per task | Filter decision |
| --- | --- | --- | --- | --- |
| Sender locked, receiver ready | held | sender bit, receiver absent | 0, 0 | sender `not_excluded`, receiver `unknown:pid_absent` |
| Port sent, still queued in the receiver's port | held | sender bit, receiver absent | 0, 0 | same |
| Sender closed its FD, port still queued | **held** | **no opener at all** | **0, 0** | both `unknown:held_without_visible_opener` |
| Receiver holds only the port | held | lsof prints the receiver with FD `fp.`, flags `0x4003` | receiver 1 (names the fixture, bit set) | both `unknown:scan_invalid` |
| Receiver ran `fileport_makefd` and released the port | held | sender absent, receiver bit | 0, 0 | receiver `not_excluded` (it never called `flock`) |
| Sender exited | held | receiver bit | — | receiver `not_excluded` |
| All closed | free | no openers | — | — |

The receiver accepts only the fixed sender's message shape: message ID,
complex bit, no reply port (`msgh_remote_port == MACH_PORT_NULL` and a zero
remote disposition), one descriptor, and one moved send right. Other messages
are unsupported. They are destroyed and reported as failed. This is
validation of one fixture protocol, not general Mach message validation.

After the receiver exited, `bootstrap_look_up` of its name returned 1102
(unknown service). Names from a successfully validated receiver-ready event
are registered in the result and checked in the cleanup `finally` even after
a later exception. Anything other than 1102 is `present` or `unconfirmed` and
fails the measurement. If check-in succeeds but the ready event is lost or
invalid, the parent does not know the generated name and cannot confirm its
removal. No universal exception-path removal guarantee is established.

Within this scope:

- A lock can be held while no process has a descriptor or a fileport for it.
  The description lives only in a queued Mach message. Neither `lsof` nor
  `PROC_PIDLISTFILEPORTS` showed any holder in that window.
- `lsof` 4.91 prints a fileport held in a task's port space with FD `fp.` and
  the description's flags. The strict parser makes that scan invalid.
- A fileport is another way for a process that never called `flock` to
  become the sole holder, carrying the bit. The receiver is the sender's
  sibling, not its descendant.

### Hidden shared description (modelled omission)

| Shape | Visible sharer | Filter on the visible sharer | After it released (no signal) |
| --- | --- | --- | --- |
| `SCM_RIGHTS`, receiver hidden | sender (called `flock`) | `not_excluded` | lock still **held** |
| `SCM_RIGHTS`, sender hidden | receiver (never called `flock`) | `not_excluded` | lock still **held** |
| fork without exec, child hidden | parent | `not_excluded` | lock still **held** |

All three record `release_incomplete_due_to_hidden_reference`. The visible
sharer really shares the locked description, so the filter is right not to
refuse it. The lock staying held only shows that releasing that one sharer
did not release the lock, because a hidden sharer still references the same
description. This is not a non-holding opener mistaken for the holder. That
separate counterexample is the former holder below. After the release the
evaluator returns `unknown:held_without_visible_opener`. This is documented,
not fixed.

### Restricted observer (`sandbox-exec`, no privileges)

`sandbox-exec -p '(version 1)(allow default)' /usr/bin/true` worked
unprivileged. Each profile is a file in the scratch directory; nothing is
installed.

The positive control (`allow_default`) must meet a full contract:

- not reduced, canary seen, probe `held`, target present, scan valid;
- `lsof` exit 0 with no stderr;
- decision and probe-only decision both `not_excluded`;
- classification `control_pass`.

The unrestricted reference must also be held, valid, canary-visible and
`not_excluded`. A missing, retyped or different field is a mismatch
(`control_failed:<field>` / `reference_failed:<field>`). A failed control is
classified `control_failed`, never `restricted_unknown`, and is never a
measurement success. Restricted profiles must carry every rule field with the
right type.

| Observer profile | `lsof` exit | `lsof` stderr | Target seen | Canary seen | Probe | Decision (with canary / probe only) | Classification |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `(allow default)` (control) | 0 | none | yes | yes | held | `not_excluded` / `not_excluded` | `control_pass` |
| `(deny process-info-pidfdinfo)` | **1** | **none** | no | no | held | `unknown:canary_not_visible` / `unknown:held_without_visible_opener` | `restricted_unknown` |
| `(deny process-info-pidfdinfo (target others))` | 0 | none | yes | yes | held | `not_excluded` / `not_excluded` | `unreduced` |
| `(deny process-info*)` | 1 | present | no | no | held | `unknown:canary_not_visible` / `unknown:scan_invalid` | `restricted_unknown` |
| `(deny default)` + exec of lsof/actor, `file-read*`, `sysctl-read`, `process-info*` | **1** | **none** | no | no | held | `unknown:canary_not_visible` / `unknown:held_without_visible_opener` | `restricted_unknown` |

Within this scope:

- Two restricted observers get exactly the output of "nobody has the file
  open": exit 1, empty stdout, empty stderr. Format checks cannot detect
  this. Here the held probe and the canary both turn it into `unknown`.
- The probe still worked under the deny-default profile.
- The `(target others)` variant had no visible effect. This was not
  investigated further.
- Not covered: a restriction that hides only some targets while the canary
  stays visible. Neither cross-check detects that.

### Sandboxed target

A holder started under `sandbox-exec` with `(allow default)` or with a
deny-default profile (exec of the actor, `file-read*`, `file-write*` of the
fixture only, `sysctl-read`) stayed fully visible to the unsandboxed
same-user observer: probe held, bit, `not_excluded`. Hardened runtime, App
Sandbox entitlements and other confinement were not tested.

### Former holder versus never-locked opener

Measured and unit-tested. With no holder, the probe is free, the former
holder's description keeps `0x4003` (`not_excluded`), and the opener has
`0x3` (`reject`). With an actual holder added and hidden by the model, the
former holder is still `not_excluded`, with flags identical to the holder's
(#139 M2 `B_former`). This is a non-holding process that the filter does not
refuse, a different counterexample from the hidden-sharer release above. The
opener is still `reject`. `FormerVersusOpenerTest` checks this on fixed
inputs.

## Running

```sh
root="$(mktemp -d "<approved temporary root>/codex-127v-XXXXXX")" && chmod 700 "$root"
python3 -I -B experimental/127-macos-visibility/visibility.py --scratch-root "$root" --result "<new private path>/result.json"
python3 -I -B experimental/127-macos-visibility/visibility.py --summarize "<private path>/result.json"
RESEARCH_TMP_ROOT="$root" python3 -I -B -W error::ResourceWarning experimental/127-macos-visibility/test_visibility.py
```

Result fields:

| Field | Meaning |
| --- | --- |
| `collected` | No failure, incomplete wait or exception |
| `measured` | Expected tables and rules hold |
| `measurement_ok` | Both, and no scenario is `not_executed` |
| `cleanup` | Settled before the record is written |
| `run_ok` (= `ok`) | `measurement_ok` and cleanup `removed` |

Initialization, scenario and cleanup failures are recorded when the reserved
result file remains writable. A result write failure cannot preserve a complete
record. The exit is nonzero unless `run_ok`.

Public measurement output is allowlisted; actor stderr is captured in private
unlinked temporary files, with a bounded prefix retained in the private result
after confirmed exit. These files do not bound actor disk writes or lifetime.
Unit-test failures can contain traceback values, so CI stores their raw output
privately and prints only fixed pass/fail status. A green rule check does not
mean every sandbox profile reproduced the same omission as macOS 27: each
profile's observed classification remains in the public summary.

Cleanup runs only when `measurement_ok` holds and no diagnostic is pending.
It opens the scratch directory and its parent with `O_DIRECTORY|O_NOFOLLOW`.
It compares the directory's device and inode with those recorded at creation,
and refuses any entry this run did not register. Registered names are removed
relative to the directory FD. Before `rmdir` relative to the parent FD, the
device and inode are checked again. A mismatch, an unexpected entry or a
failed delete leaves the directory and its remaining files in place as
`preserved` or `failed`. These checks narrow path races; they do not close
all of them. Nothing is deleted recursively.

Public output: standard output carries only the public summary. It is an
allowlist:

- fixed booleans;
- validated scenario, stage, role and profile identifiers;
- decisions from the closed vocabulary;
- bounded counts;
- failure, incomplete and error kinds as counts of allowlisted
  `<label>:<kind>` pairs;
- source and binary SHA-256;
- validated version strings.

Anything else becomes `other`, or is counted in `unlisted_mismatches`. Raw
error text, stderr, exception messages, PIDs, service names and paths stay in
the private raw result. A failure outside the measurement (for example an
existing result path) prints one fixed `{"ok": false, "fatal": <kind>}` line
without a traceback.

If `clang` is missing or the compile fails, `fileport`, `sandbox_observer`,
`sandbox_target` and `former_vs_opener` are recorded as `not_executed` with a
kind. If `sandbox-exec` cannot apply a trivial profile, the two sandbox
scenarios are recorded the same way. `not_executed` is never a measurement
success: `measurement_ok` and `ok` stay false.

Lifecycle and signals: actors end on stdin EOF. Their 20 s lifetime is
checked only while they wait for a command. It does not interrupt a blocking
write, file syscall or bootstrap RPC. `mach_msg` send and receive have their
own 2 s and 3 s timeouts. **The script makes no kill calls and uses no
killing subprocess timeouts.** A diagnostic that exceeds its bound is
recorded as incomplete with its PID in the raw result, polled again at the
end, and never stopped (run 5 is an example). The result file and the
sandbox profiles are created with `O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0600.

Side effect: the receiver role calls `bootstrap_check_in` with a fresh
`dev.codex-unlock.research.127v.<pid>.<random>` name. That is a transient
entry in the user's launchd bootstrap namespace, owned by the receiver's
receive right. It needs no privileges and changes no policy.

`test_visibility.py` (80 tests) checks, with fixed inputs and finite children
only:

- **Parsing**: empty output, status and stderr rules, timeouts, eight
  malformed shapes and `fp.` records.
- **Filter and visibility rules**: the closed vocabulary, modelled omission,
  canary and reduced-view comparison.
- **Former holder versus never-locked opener**, and the hidden-sharer outcome
  name.
- **Expected-table counterexamples**, including a saturated fileport stage and
  an enumeration error in the self-report.
- **Sandbox contracts**: the reviewer's control mutation (`canary_visible:
  false`, decision unknown); every control and reference field missing,
  negated or retyped; a missing control; restricted fields missing or
  retyped; `control_failed` versus `restricted_unknown`; and the rules for
  reduced and unreduced views.
- **Public summary privacy**: a raw result with injected fake paths, PIDs and
  service names in every failure path (failures, incomplete waits, errors,
  `not_executed`, mismatches, pending diagnostics, bootstrap names, cleanup,
  hashes, build, environment, stage, role, decision, probe, fileport and
  profile fields) gives a clean summary. Malformed raw input never raises or
  echoes.
- **Cleanup**: removal of registered names only; unexpected entries;
  identity mismatch; a symlinked scratch; injected `unlink` and `rmdir`
  failures; an unexpected exception. `finalize` writes `run_ok` false with
  preserved evidence, and preserves on measurement failure, `not_executed`
  and pending diagnostics.
- **CLI**: fatal output without a path or traceback, `--summarize` on a
  poisoned and on a broken file, and argument combinations.
- **One-shot framing, event shapes and process behavior**: wrong ready PID or
  kind, early exit, a `failed` event, a partial line followed by silence, and
  a diagnostic timeout recorded as pending.
- **The compiled actor**:
  - probe free and held;
  - framing failures ending with exit 3, and an unknown command;
  - failure events instead of `ready`, and a send to an unknown service;
  - fileport enumeration: 1 and 63 entries complete, 64 and 70 `saturated`,
    a missing fixture giving `identity`, an exited PID giving `list_esrch`.

Not covered by injection: `query` and `short_read`. They need a fileport
that disappears between the list and the query, or a kernel record size
change.

The checked-in [research workflow](../../.github/workflows/macos-visibility-research.yml)
runs on `macos-15` and `macos-15-intel`. It prints the public measurement
summary and fixed test status; raw diagnostics remain private. See
[HANDOFF.md](HANDOFF.md).
