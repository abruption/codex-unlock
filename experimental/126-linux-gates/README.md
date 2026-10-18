# Linux gates for #137: cause separation and guard-liveness designs (research, #126)

Research only. Nothing here changes `src/`, policy, eligibility, the
allowlist, platform support, dependencies or the JSON contract, and nothing is
published by `npm pack` (`experimental/` is outside `files`). No experiment
calls `unlockInspectedThread`. No code here signals a holder, a lock owner or
a Codex process, or uses an unlock path. Every holder is a **synthetic
fixture**. **No result here is evidence about a native Codex binary.** Its
argv, image and dumpability on Linux remain unmeasured.

It builds on `../126-guard-liveness/`, which is read-only here. That
directory's shared lifecycle helpers, isolated observer and trusted build
script are imported. #137 source was read from an isolated `git archive` of
`b483cd587c62329243366e64aaaac477edd36adc`.

| Part | Question | Status at this revision |
| --- | --- | --- |
| G1 `g1-identity-visibility/` | Which of the two causes failed the 2026-10-16 F2 positive control, and does each fail independently? | Local argv/plumbing checks and reviewer US Linux nominal/stall runs completed; see Integrating Linux validation. Positive controls remain blocked on that mount-warning host. |
| G2 `g2-guard-gaps/` | fdinfo FD reuse, lock file system stalls, evidence aging, shared descriptions | Pure models with deterministic counterexamples. **G4 is no-go** (binding unproven). The 3 kernel checks skip on macOS and passed in the US Linux run. |

## Signals and bounds

| Process | Signal behaviour |
| --- | --- |
| Holders, inherited-lock fixtures, lock owners, unlock paths | None. Stop = stdin EOF or a runner-owned release file, waited for with a bound; an expired bound is `incomplete`, never escalated |
| Inspector child (`runIsolated`) | None from the runner; past its bound it gets stdin EOF and is left running (`incomplete`) |
| Bounded `spawnSync` diagnostics: compiler, `--version`, `lsof -v`, build `git`/`npm`, the test lock prober | Node sends SIGTERM to that diagnostic process if its timeout expires |
| Product diagnostics inside the inspector (`lsof`, `ps`) | The product's timeout sends SIGTERM then SIGKILL to the timed-out diagnostic's own process group |

No recorded run proves that every one of these paths was signal-free. The
result files record diagnostic status and signals where this code captures
them, but they do not instrument product diagnostics.

## G1: separating argv identity from lsof visibility

### Why the F2 control failed

The F2 isolated run on the Linux test host (2026-10-16) failed rows V, E1 and E4
of the dumpable=1 control. Two causes were mixed:

1. **Executable/argv identity.** The F2 fixture is a `#!/usr/bin/env python3`
   script named `codex`. `env` execs `python3`, so the kernel argv is
   `[python3, <path>/codex]`.
2. **lsof visibility.** That host's lsof wrote a warning that information
   may be incomplete, because overlay/nsfs mounts were inaccessible.

### Owner lock-set availability is a separate measured cause

On the US host, the first nominal run collected every row but did not match
the original E5 prediction. In #137, a failed owner lock-set lookup returns
an empty array; policy also emits `owner_holds_other_thread_locks` for that
array. This does not establish that the owner holds another lock. G1 now
records `ownerLockFiles` and attributes this combination to
`owner_lockset_unavailable` only when the lookup-failure blocker and the
observed empty array are both present. A nonempty or unavailable array does
not receive that explanation. The E5 mount-warning predictions include this
downstream availability cause; the product refusal remains unchanged.

### Product conditions (#137 `b483cd5`, source)

| Check | Location | Condition |
| --- | --- | --- |
| Interpreter/argv shape | `process.ts` `codexArgumentOffset` | `basename(argv[0])` is `codex` or `codex-<name>`, or `node`/`nodejs` with `basename(argv[1])` `codex`. Otherwise `arguments_unverified:unsupported executable argv` |
| Argument agreement and grammar | `reconcileArguments`, `classifyCodexMode` | `ps -o args=` equals the space-joined kernel argv; every later token passes the bounded grammar |
| `isCodex` | `inspectProcess` | lsof `c`, ps `comm` basename `codex`/`codex-*`, or verified arguments matching `(^\|/)codex(\s\|$)`. An argv error nulls the arguments |
| Instance on Linux | `inspectProcess` | start ticks and the command fingerprint (the `/proc/PID/exe` readlink **string** plus cmdline) read twice and equal, else `linux_process_instance_unverified` |
| Opener lookup | `findLockOpeners` | **any** lsof stderr is `error`, even at exit 0 |
| Participation in inspection | `inspectThread` | attempted only with no opener error and exactly one process |
| Owner lock set | `lockFilesOpenedByProcess` | any lsof stderr is `owner_lock_file_lookup_failed` |
| Eligibility | `policy.ts` | opener error: `lock_opener_lookup_failed`; `classify` returns `unknown`; missing participation: `linux_participation_unproven` |

So the lsof warning can block E4 and eligibility for **any** fixture. The F2 R2
"pass" at dumpable=0 also came through the opener path, not from an
attributed permission denial. The product's lsof refusal is unchanged here.

### Variants (all synthetic)

| Variant | Kernel argv | Image | Dumpable | Purpose |
| --- | --- | --- | --- | --- |
| `script` | `python3 <f2>/codex` | python3 | 1, 0 (prctl) | reproduce F2's identity failure |
| `argv0` | `codex <f2>/codex` (spawn `argv0`) | python3 | 1, 0 (prctl) | identity passes on argv alone: the check is argv-shaped, not image-based |
| `native` | `<scratch>/native/codex` | `fixtures/codex.c`, compiled on the run host | 1, 0 (prctl) | a native image named `codex` with no arguments |
| `node` | `<node> <fixtures>/node/codex` | node | 1 (inferred from `/proc/PID/fd` ownership) | the interpreter form the product grammar names |

The runner refuses a run whose `/proc/PID/cmdline` differs from the variant.
`native` needs `/usr/bin/cc`, `gcc` or `clang`. Without one it is
`not_executed:no_compiler`, never success; nothing is installed or changed.
`G1_VARIANTS` must be nonempty, known and duplicate-free. Deselected variants
are recorded `not_selected`.

### Provenance

The runner takes the build manifest SHA-256 once, before any holder starts.
It passes that value to each inspector, and the inspector refuses to import
product code unless its own re-hash of a private copied build matches it and
the copied source retains the exact pinned commit. The protocol then checks
the inspector's reported hash against the runner's value. The runner
re-verifies the build after every run, and drift fails that run. The report
records the SHA-256 of every research input file (runner, inspector,
protocol, expectations, variants, lifecycle, fixtures, the shared helpers it
imports) and of the node and python interpreter binaries, at start and end,
with a combined input hash. **Coverage limits:** build hashing covers `dist/`
and native addons only. It does not cover dependency JavaScript, package
metadata, shared libraries or the Python standard library, and it does not
prove upstream identity.

Before starting any holder, the runner creates a private independent runtime
snapshot using the shared F2 helper. The Node holder resolves its JS/native
dependency from this copy, and inspectors receive that copy as their input;
each inspector makes its own verified private copy before walking/importing.
The cross-platform `argv-check` also imports only its verified private copy.
The original input remains subject to the post-run drift check.

The closed copy includes `manifest.json`, `source.tar`, optional `source.patch`,
`src/package.json`, `src/package-lock.json`, `src/dist/` and the full
`src/node_modules/` tree, omitting unused npm `.bin` shims. Other links and
special files are refused, and copied files do not share input inodes. The
private wrapper stays 0700, copied directories become 0500, and files 0400.
Snapshots, including partial failed copies, are retained under the approved
`RESEARCH_TMP_ROOT` (forwarded to inspection children). This isolates later
input mutation; a malicious same-UID process can chmod/replace its snapshot.
Copying dependency JS does not authenticate it against the startup manifest.
The canonical import graph rejects external paths and absolute/URL aliases,
but nonliteral imports, require/eval and bare-package resolution remain outside
its bounded analysis. Existing TypeScript dev dependencies must be installed
for the shared parser (`npm ci`; research CI uses `--ignore-scripts`).

The historical US measurements below predate this snapshot wiring and the
new shared-helper input hashes. They are not execution evidence for this
integration revision. None of these changes closes G4 or #137's NO-GO gates.

Root validation at runner source
`25d1d8384ec65c54fdfaeee2702b49917e7dc4b6` passed all five repository checks
(266 passing tests, three Linux-only skips) and the combined focused suite
(59 passed, three Linux-only skips). The post-rebase tree was byte-identical
to the checked tree. The snapshot-based cross-platform argv check also exited
0: all four fixture variants and the renamed-Node negative control matched
their predictions against unpatched source
`b483cd587c62329243366e64aaaac477edd36adc`, manifest SHA-256
`15ffaada53a40b8dc77dc81bed4f7f0433bc05bfc5730e103269b32b996138a0`.
This pure-function check is not a new Linux G1 run or native Codex evidence.

### Stages and typed evidence

`dist_identity`, `module_load`, `lsof_control`, `openers`, `identity_direct`,
`prepare`, `guarded_verify`, `held_probe`, `inspect_thread`: once each, in
order, each typed. `LockProbe` values are checked against #137 `types.ts`.
`held` needs an acquired guard, and participation is only allowed with
`held`. A failed `prepare` must be followed by the harness skip, and only then.
`identity_direct` and `prepare` must name the runner's holder PID.

- `lsof_control`: product `findLockOpeners` on a regular file nobody opens.
  It must report `processCount` 0.
- `identity_direct`: product `inspectProcess` on the holder PID even when lsof
  did not list it.
- `held_probe`: product `guardedProbeOnce` without attribution. Denial rows
  require this typed `held`/`acquired` observation.

Every start-ticks sample attributed to the holder PID must equal the
runner's readiness sample, or collection fails. These are openers,
`identity_direct`, `prepare`, guarded participation, inspection owner and
participation. A `null` sample stays unavailable and never matches.

### Narrow lsof classification

Only stderr consisting of pairs of `lsof: WARNING: can't stat() <type> file
system /<path>` and the indented `Output information may be incomplete.`
counts as the mount-visibility cause (`lsof_mount_warning`). A missing tool, a
timeout, an output limit, an exit status or any other text is
`lsof_infrastructure_error`. Host classes: `clean` (no control stderr),
`mount_warning`, or `unclassified` (anything else, or a control with
openers). An unclassified host has no prediction and never matches. A
lock-path mount warning that differs from the control is
`unexplained:lsof_mount_warning_differs`. Raw lsof text stays in the private
result; the printed summary carries classes and codes only.

### Collected, measured, predicted

- **collected**: protocol complete and typed, build manifest equal to the
  runner's, holder PID and tick bindings equal, same holder instance from
  readiness to after inspection, and every stop outcome clean;
- **measured** rows (`basis: measured`): `pass`, `fail` or `blocked`, with
  causes from the same run;
- **source prediction** rows (`basis: source_prediction`, some
  `confidence: source_only`) compared with the measured rows;
- **coverage**: exactly one run per required variant/dumpable. No
  duplicates, no extras, and no run for a not-executed variant. Coverage is
  checked before `complete`, `controlPassed` or `refusalCounted` is computed;
- **controlPassed** (every dumpable=1 row `pass`) and **refusalCounted** (H0,
  R1, R2, R3 `pass` with that variant's control passed).

A matched prediction of a failure is **not** a passing control. A `blocked`,
`fail`, missing or `not_executed` row never counts as success. At dumpable=0,
R1–R3 are `blocked` unless H0 observed `held`/`acquired`. R2 requires the
inspection probe to be `held`, or the typed acquired-guard `unknown` with
`linux_participation_unproven`, in both cases without participation. H0 still
independently requires `held`/`acquired`. R3 requires the
product's typed `unknown`/`linux_participation_unproven` probe with an
acquired guard for a listed owner.

### Predicted tables (source predictions, not measurements)

Mount-warning host (the 2026-10-16 host class). H0 is predicted `pass`
everywhere.

| Variant | d | V1 | V2 | I1 | I2 | E2 | E3 | E4 | E5 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| script | 1 | pass | fail (lsof) | fail (argv) | fail (argv) | pass | pass | blocked (lsof) | fail (argv + lsof + owner-set) |
| argv0, native, node | 1 | pass | fail (lsof) | pass | pass | pass | pass | blocked (lsof) | fail (lsof + owner-set) |

| Variant | d | V1 | V2 | I1 | R1 | R2 | R3 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| script | 0 | fail (hidden, source_only) | fail (lsof) | fail (argv + instance) | pass | pass | blocked (lsof + hidden, source_only) |
| argv0, native | 0 | fail (hidden, source_only) | fail (lsof) | fail (instance) | pass | pass | blocked (lsof + hidden, source_only) |

`lsof` = `lsof_mount_warning`, `argv` = `argv_identity`, `instance` =
`instance_unverified`, `hidden` = `owner_hidden`, `owner-set` =
`owner_lockset_unavailable` (a failed lookup and an observed empty lock set).

On a clean host, V2 passes, E4 passes for every dumpable=1 variant, and E5
passes for `argv0`, `native` and `node`. At dumpable=0, R3 stays blocked
(hidden), so **no refusal is counted on either host class** unless lsof turns
out to list non-dumpable owners. That would appear as an unmatched row.

Expected on the mount-warning host: `predictionsMatched: true`,
`controlPassed` false everywhere, `refusalCounted` false (`not_applicable`
for node). Exit 0 if a compiler exists, 2 if `native` was not executed.

### Exit status

`0`: collected, coverage valid, every prediction matched, all variants ran.
`2`: the same, but a variant was not executed (partial). `1`: anything else,
including any `incomplete`, cleanup fault, build or input drift. None of
these is a product success.

## G2: guard-liveness gaps, designs and refusal rules

`g2-guard-gaps/designs.mjs` models each gap as a pure function.
`designs.test.mjs` holds deterministic counterexamples. Their schedules are
**models**, not executions and not claims about Codex runtime paths. Every
proposed decision function validates its input types and refuses malformed or
missing fields without throwing. Comparison models named `*B483` require their
documented fixture shapes and are not general validators. `proc-locks.linux.test.mjs` has three
real-kernel checks that run only on Linux. **On macOS they are skipped and
prove nothing.** Kernel statements come from pinned Linux v6.17
(`e5f0a698b34ed76002dc5cff3804a61c80233a7a`) `fs/locks.c` and
`fs/proc/fd.c`. This was a targeted reading, not an audit.

### Gap 1: fdinfo FD reuse and `show_fdinfo` under the guard

In #137 and F4, the guard reads `/proc/PID/fdinfo/N` after a matching
readlink. If N is reused in between, `seq_show` runs the new file's
`show_fdinfo`; for epoll, `ep_show_fdinfo` takes `ep->mtx`. The later readlink
refuses the result, but only after the wait. Node has no `pidfd_getfd`, and
Yama `ptrace_scope=1` would refuse it for non-descendants.

Candidate design **G4** reads no per-descriptor fdinfo in the guard:

| Sample | Reads |
| --- | --- |
| before guard | `statfs` gate (gap 2), fd list, readlinks, start ticks, fdinfo row on the one candidate FD |
| inside guard | held probe, `stat` lock path, `/proc/PID` uid, mount and PID namespace readlinks, ticks, fd list, readlink, `/proc/locks`, readlink |
| after guard | fdinfo row, fd list, readlinks, ticks, command fingerprint |

`/proc/locks` calls no file-type callback. `locks_start` takes
`percpu_down_write(&file_rwsem)`. That is a source argument for a finite
wait, not a bound.

**G4 is no-go.** Its best result is `consistent_unproven`: the samples did
not refute participation, but they do not prove it. The `/proc/locks` PID is
`flc_pid`, the tgid that called `flock()`. It names a process, not a
description, and has no instance binding. A historical PID can be reused. The
**hidden-transfer model schedule** satisfies every G4 check while the
sampled description is unlocked inside the guard:

1. In `pre`, candidate P holds description A at FD7.
2. P unlocks A, flocks a new description B at a temporary FD, passes B to a
   hidden recipient and closes the temporary FD.
3. In the guard, FD7 is unlocked and the recipient alone holds B.
   `/proc/locks` shows B with acquirer P.
4. The recipient releases B, and P reacquires A before `post`.

Every sampled FD list, readlink and start tick matches. The pre/post fdinfo
rows match, and the guard row PID is P. Until the description binding is
solved, an equal acquirer PID is a necessary check only, never proof that the
candidate's current description participates. The test asserts the model's
outcome. It does not claim that any Codex path behaves this way, and it
asserts no continuously-held WRITE ABA execution.

Still useful refusals: another acquirer, an inherited or passed description
(`acquirer_pid_mismatch`), omitted rows, ambiguity, size, overflow, unsafe
PIDs and identity drift. The review's pure repro is now an
`evidence_malformed` refusal: all three samples without descriptors,
readlink or ticks, which previously matched as `undefined === undefined`.

Remaining options: accept the in-guard `show_fdinfo` wait as a documented
residual, find a description binding (none is available to unprivileged
Node), or refuse Linux unlock (diagnostics only). The user decides.

### Gap 2: file system I/O stalls under the guard

#137 calls `statfs`/`stat` on the lock path inside the participation guard,
and the allowlist (ext, tmpfs, XFS) applies only after `statfs` returns.
**fs-gate** moves `statfs` before the participation guard and refuses
non-allowlisted file systems without taking it. **Residual**: main's guarded
probe still opens and flocks the lock file under the guard. Refusing before
any guard also changes diagnostics on such homes, which is a policy
decision. Allowlisted local file systems can still stall, unbounded.

### Gap 3: evidence aging between observation and signal

`finalBoundary` decides at `checkAt` and reports `hardBound: false` for
every input. Timestamps must be finite and monotonically ordered. A
`killAt` before `checkAt` and a soft limit that is not a finite nonnegative
number refuse. The review's descending-time repro (1000…600) now refuses
instead of returning negative ages. **F4's 25 ms check is not a hard bound.**
It measures only the post-release confirm step, and a stale observation with
a fast confirm passes it. The proposed soft rule adds evidence age at the
check, which still bounds nothing about the signal: there is no pidfd, and
the thread can be descheduled before `process.kill`. Post-signal exit,
lock-release and transcript-hash verification stay mandatory. No output or
document may call these checks a staleness or release-to-signal bound.

### Gap 4: inherited-description participation versus sole control

A fork-without-exec child or an SCM_RIGHTS recipient shares the description,
because O_CLOEXEC only affects exec. #137 treats descendants as a warning; the
test shows such a child is eligible there. The proposal
`soleControlDecision` refuses in these cases:

- any lsof error;
- an opener set other than the candidate;
- an acquirer other than the candidate (necessary only, see G4);
- descendants that are unavailable, or any descendant;
- in `strict` mode, any unobservable same-user process.

Unknown modes and malformed PID arrays refuse; the review's `'strcit'` repro
no longer falls through to `standard`. The best outcome is `not_refused` with
`soleControlProven: false` and residuals (`description_binding_unproven`, plus
`hidden_sharer_not_excluded` in standard mode). A lock that is still held
after a signal must be reported, never escalated.

### Linux-only kernel checks

| Check | Fixture | Bound and confirmation |
| --- | --- | --- |
| direct holder | Python flock holder | ready/stop bounded; exit 0 with no signal and no stdin error required |
| inherited description | Parent takes the flock, starts a grandchild with the FD and **no inherited stdio**, then exits. The grandchild's control channel is a runner-owned directory: it writes `ready.json` (PID, start ticks, FD), holds until `release` exists or its own 20 s lifetime, closes the FD and writes `exit.json` | parent exit bounded (5 s); ready, exit record and instance end each bounded (5 s). The grandchild's start ticks are checked before and after the measurements. Exit is confirmed by its own record plus the instance no longer being live with those ticks. Lock `free` after release. Any expired bound fails as incomplete |
| epoll fdinfo | this Node process's epoll FD | reads `tfd:` lines; shows the read path reaches `show_fdinfo`, not a wait |

The earlier inheritance test kept the grandchild on the parent's stdin pipe.
It could therefore have seen EOF when that pipe closed. That race was
suspected from source, not reproduced on Linux. The handshake above removes
the dependency. On macOS only the Python handshake logic was exercised: it
reached ready, held after parent exit and closed stdin, then released and
freed. `/proc` parts are absent on macOS.

## Running

```sh
npm ci && npm run build
export RESEARCH_TMP_ROOT="<existing approved temporary root>"
g1_build_root="$(mktemp -d "$RESEARCH_TMP_ROOT/codex-126g-build-XXXXXX")"
BUILD="$g1_build_root/product"
node --test experimental/126-linux-gates/*/*.test.mjs
node experimental/126-guard-liveness/f2-linux-nondumpable/build.mjs \
  --repo <local codex-unlock clone> --commit b483cd587c62329243366e64aaaac477edd36adc --out "$BUILD"
G1_BUILD="$BUILD" node experimental/126-linux-gates/g1-identity-visibility/argv-check.mjs
G1_BUILD="$BUILD" node experimental/126-linux-gates/g1-identity-visibility/run.mjs   # Linux only
```

### Linux test host procedure (for the reviewer)

Use an unprivileged same-UID user. Make no privilege, mount, host/global package
or host-policy change, and use no real Codex process or home. The dependency
installation below is confined to the private archive workspace; stop if that
installation is not authorized. Send no holder,
owner or unlock signal. Diagnostic timeouts behave as described under
"Signals and bounds". Run from a frozen archive containing `package.json`, `package-lock.json`,
`experimental/126-guard-liveness/` and `experimental/126-linux-gates/`.
`package.json` makes the extensionless Node fixture ESM, and the lockfile is
required to install the existing TypeScript parser without lifecycle scripts.
Compare the archive's
SHA-256 with the integrating host's value before extraction.

```sh
umask 077
R="$(mktemp -d /tmp/codex-126g-run-XXXXXX)"; mkdir "$R/src"
sha256sum g1-input.tar                       # must equal the integrating host's value
tar -xf g1-input.tar -C "$R/src" && cd "$R/src"
export RESEARCH_TMP_ROOT="$R"
npm ci --ignore-scripts --no-audit --no-fund  # private research dependencies only
node experimental/126-guard-liveness/f2-linux-nondumpable/build.mjs \
  --repo <local codex-unlock clone> --commit b483cd587c62329243366e64aaaac477edd36adc --out "$R/build"; echo "build=$?"
G1_BUILD="$R/build" node experimental/126-linux-gates/g1-identity-visibility/argv-check.mjs > "$R/argv-check.json"; echo "argv=$?"   # expect 0
node --test experimental/126-linux-gates/*/*.test.mjs \
  experimental/126-guard-liveness/f2-linux-nondumpable/build.test.mjs \
  experimental/126-guard-liveness/f2-linux-nondumpable/build-binding.test.mjs \
  experimental/126-guard-liveness/f2-linux-nondumpable/build-snapshot.test.mjs \
  > "$R/tests.tap" 2>&1; echo "tests=$?"  # expect 0, 62 tests, 0 skipped on Linux
RESEARCH_TMP_ROOT="$R" G1_BUILD="$R/build" node experimental/126-linux-gates/g1-identity-visibility/run.mjs > "$R/g1-nominal.json"; echo "g1=$?"  # expect 0 (compiler) or 2 (no compiler)
RESEARCH_TMP_ROOT="$R" G1_BUILD="$R/build" G1_VARIANTS=argv0 G1_CHILD_FAULT=stall:identity_direct \
  node experimental/126-linux-gates/g1-identity-visibility/run.mjs > "$R/g1-stall.json"; echo "stall=$?"  # expect 1, incompleteCount >= 1
sha256sum "$R"/*.json "$R/tests.tap" "$R"/codex-126-g1-*/g1-results.json
jq '{exitCode, collected, inputsSha256, manifestSha256, hostClass, coverageValid, predictionsMatched, complete, notExecuted, controlPassed, refusalCounted, rows}' "$R/g1-nominal.json"
nominal_dir="$(jq -r '.resultDirectory' "$R/g1-nominal.json")"
jq '[.expectations.comparisons[] | select(.matched | not) | {variant, dumpable, reason, rows: [.rows[] | select(.matched | not)]}]' "$R/$nominal_dir/g1-results.json"
```

The stall run selects only `argv0`, so its `notExecuted` lists the others as
`not_selected`. Expected nominal `rows` on a mount-warning host are the
tables above. Any unmatched row or `unclassified` host is a finding to
report, not something to repair. The private result files contain local
paths, PIDs and raw lsof text. Publish only hashes and sanitized outcomes.

## Integrating Linux validation

The integrating reviewer ran the revised harness on the approved US Linux
host (arm64, Node 24.18.0, local ext filesystem). All 37 research tests passed,
with no skips. The source-derived argv checks passed. The build came from
the pinned #137 commit above, with no patch applied.

The first nominal run collected successfully but exited 1 because the owner
lock-set availability cause described above was absent from the prediction.
Its raw SHA-256 was
`6fc60cfb4b574a536c32ee124e7211329c41a76eb9d91fa189405da7d7e107bb`.
After adding the observed lock-set field, a source-checked cause rule and a
counterexample test for nonempty lock sets, the repeated run exited 0:
`collected=true`, `predictionsMatched=true`, no incomplete observations.
All positive controls and counted refusals remained false on this
mount-warning host. This validates cause separation, not unlock readiness.
Raw SHA-256:
`03df43dd9948d81f8e359f33d8e82b4e477c8ac0d6fa03cde5a0d700058de9b0`.

The revised `stall:identity_direct` run exited 1 as required and recorded two
incomplete inspections; it did not promote any control or refusal. Raw SHA-256:
`d451e31974538e234d5a089e8f1aa98112dac128188fc629f29c160bfc40bcd3`.
Both runs recorded research-input SHA-256
`2453ef543248d01d05bb2a9113c8b8df4627b2528b5071246036cefa6715d60b`.
Every holder was synthetic; native Codex dumpability and argv remain unmeasured.

After those measurements, a review follow-up added an explicit source-commit
gate before product imports in the runner, inspection child and argv checker.
Self-consistency with a build's own manifest is insufficient: its resolved
source must be exactly `b483cd587c62329243366e64aaaac477edd36adc`.
The added negative test raises the current research test count to 38. The US
measurement hashes above refer to the earlier 37-test revision; they do not
claim to exercise the added wrong-source rejection.

## Open decisions (no-go for readiness)

| Item | Options | Owner |
| --- | --- | --- |
| lsof stderr blocks every Linux positive control on hosts with inaccessible mounts | keep (fail closed; Linux unlock unavailable there), or a reviewed policy for known mount warnings | user/reviewer |
| Identity is argv-shaped, not image-based (`argv0`) | accept and document, or require an image check (no native dependency available) | user/reviewer |
| Native Codex argv/dumpability on Linux | needs a real binary run | user |
| Gap 1 fdinfo in guard | G4 is no-go (binding unproven); accept the residual, find a binding, or diagnostics only | user/reviewer |
| Gap 2 lock file system | fs-gate (participation only), or refuse before any guard | user/reviewer |
| Gap 3 evidence aging | accept the unbounded residual with post-signal verification, or no Linux unlock | user |
| Gap 4 sole control | standard or strict rule; descendants from warning to blocker on Linux | user/reviewer |
