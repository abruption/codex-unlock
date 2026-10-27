# Sanitized research evidence

Original F1/M2 measurements and local validation use same-user macOS/APFS
synthetic fixtures. Linux measurements are identified separately below. No
actual Codex session or Windows recovery was exercised. Raw result files were hash-checked and retained
privately; hashes identify the original files, not this sanitized summary.

## Snapshot and complete-control validation at cd9bb2e

Runner source: `cd9bb2ed5018b34ad8c2ed9f2341b8cede7282db`. The follow-up
documentation commit records this execution without changing runner bytes.

- All five repository checks passed again: 266 passing tests, three Linux-only
  skips, zero failures. All 84 focused research tests passed without skips.
- One M2 nominal repetition exited 0: all seven Part 1 matrix cases and four
  Part 2 scenarios matched their now-enforced fixed expectations, with
  failures/incomplete zero and recorded diagnostic signals zero. The former
  holder remained the documented refusal-filter counterexample. This does not
  establish a real-world failure frequency or positive holder attribution.
- One F2 macOS plumbing run using the private verified runtime-copy path
  exited 0. Nominal stages had no observer/protocol faults; macOS `prepare`
  returned the expected `/proc` ENOENT. Injected `stall:prepare` was incomplete
  at that stage, then the child exited 4 with no signal. Startup manifest was
  the same unpatched `b483cd5` build identified below. No deadline was raised
  to make the snapshot path pass.
- This does not add Linux/native Codex or Windows evidence. Private read-only
  copies isolate later mutations of the supplied build, not malicious
  same-UID tampering; dependency JavaScript is copied but not authenticated by
  the original manifest. Static import-walk limits remain documented.

| Private raw file | SHA-256 |
| --- | --- |
| M2 nominal result | 8dc60f9e04e9c07df3bf3d9c4715bf25445a013263d58b3541a0738382bf481b |
| M2 nominal events | 83d1fd5c704fb364e792f218b6135c6de261ca6f802f4d3a4188d0fa8c42f510 |
| F2 plumbing result | 46f8883a56e1d2fac7ce928f87c30eacacec84c009da64d539ec179e4a7324c4 |

## Pre-merge validation at 28925a5

Runner source: `28925a50c1df118a09d950237bf3db0012751b4c`, after the
comment-aware import walk, nested probe validation, startup-build binding and
fixed M2 scenario verdict corrections. The final follow-up commit changes
only this evidence record.

- Five repository checks passed: 269 tests total, 266 passed, three Linux-only
  skips, zero failures. All 71 focused research tests passed without skips.
  The first lint attempt found a missing test-only `URL` import; it was fixed
  before the successful rerun and before this source commit.
- M2 nominal, `M2_REPEATS=1`: actual exit 0, seven Part 1 and four Part 2
  scenarios matched, failures/incomplete zero. The all-scan failed acquirer was
  an eligible wrong target and the filter rejected it; the retained-descriptor
  former holder remained an eligible wrong target and was not excluded. The
  visible-holder control matched. Recorded diagnostic signals were zero;
  product diagnostic timeout signals were not independently instrumented.
- F2 plumbing, same-user APFS synthetic holder: actual exit 0. All six nominal
  stages were valid, with the expected macOS `prepare` ENOENT because `/proc`
  is absent. Injected `stall:prepare` was incomplete at the stage bound and
  the child later exited 4 without a signal. This is a wiring/fault check, not
  Linux access-policy or native Codex evidence.
- The unpatched research build was reverified: source
  `b483cd587c62329243366e64aaaac477edd36adc`, startup manifest SHA-256
  `15ffaada53a40b8dc77dc81bed4f7f0433bc05bfc5730e103269b32b996138a0`.
  No new Linux-host measurement, F1 measurement, M2 fault-mode run or real
  Codex observation was performed for this revision.

| Private raw file | SHA-256 |
| --- | --- |
| M2 nominal result | def54ec1fe49f6d140cd849edcd765350a3e8e5af445ebd89fc524302e623f8b |
| M2 nominal events | c1ab2c9e63dbd4d1dc291d520c288d0dca3ef7f44ee9bef711ec137d46b1d008 |
| F2 plumbing result | a05553fb60c4b3279a8c0b48741328fe13ecd71a7e38c48a23560d4de8f9d1ac |

## Original measurements

| File | SHA-256 |
| --- | --- |
| F1 result, 50 rounds | 2e27c2155a03e028cb24634feedf6b735209935a370952031c871a9a0ddb6ad4 |
| M2 run2 result | 928f8e94ed2960d0cad0a148f5f2386314d28c6be66b14160c95f8023abbf714 |
| M2 run2 events | 7c28f7fa9ecbe6ec6c9f488b3ac12d7219d4000d113229b582eca14583ba8c8c |
| M2 run3 result | 9785e60fb27b339655a995c2a8c9bd59afe2c2189e6bb2c99492b733789f67e5 |
| M2 run3 events | 25e985a5353777514948338d2f84b4e46a03de2dc200162181834309c58ae513 |
| Initial failed M2 attempt | f0a896b04df1a7dbf11af5bc4517c6a7e9540455f72085ca232de793ee5b1d67 |

F1 contains 25 guarded and 25 baseline rounds, five per delay/mode, with no
recorded errors, waiter exit 0 and unchanged fixture file identities. The
acquisition delta is relative to probe return. Across all 50 rounds it ranges
from 0.013834 to 0.158584 ms. It does not measure actual unlock time.

All three M2 run3 repetitions show: opener-only barriers are already refused
by the current lock-set check; barriers across all scans allow a wrong eligible
failed acquirer, which the flag filter rejects; an omitted actual holder plus
a former holder with a retained FD allows a wrong eligible target that the
filter does not exclude. Visible-holder controls remain eligible. The omitted
holder and barrier timing are injected; no production failure frequency follows.

The failed original attempt required one SIGTERM to the research orchestrator,
as reported by the experiment operator. The raw result does not independently
count that signal or every product diagnostic timeout signal.

## Validation at e782e39

| Run | Recorded outcome | SHA-256 |
| --- | --- | --- |
| F1 nominal | ok, 50 rounds, incomplete 0 | e17cd6ab2bfbaadf69ddc54714250b9983199fa7bd205ed7263348ed12a6473f |
| F1 missing round | failed, 2/10 rounds | 2a784f54fce47f46d4662e46bd1acc74dfe78b6d27720c7d4d582bb80ea317a0 |
| F1 waiter lifetime | failed, 9/10 rounds | b2cb35282098ae621387b747662a9f7bbd3643233d5afb6b756565752b49543b |
| M2 early exit | failed before readiness | 531b83a82eedf424f7d387423f9feb12738cea8199eec3cad5aaab90f7e27406 |
| M2 ignored EOF | incomplete 1 | 41f430e268a83c27a6d813578975ae12e1125b51edbc427305997c533592b834 |
| M2 long socket | failed before child start | d1aeffb12240ec06ee230d86cce3106a6e43f6ad79f983d4b762ee665088e5d5 |
| M2 nominal | ok, 33 records, incomplete 0 | adecdb22b9730d86d1ed1cfbf086c795285ca246caf1c169c7daad96af672b6a |

These files were checked separately from later source corrections. F2 has
syntax checks only at that revision; the later Linux matrix is recorded below.

## Runner validation at e5cf6dd

The integrating Codex executed one repetition of each nominal runner and all
five documented fault cases on unchanged script revision
`e5cf6dd7af5f61542a842527a216fa5eec918e61`. It checked actual exit status,
report `ok`, failure text and incomplete observations. No runner timed out in
the outer 60-second observation window. The original measurement tables remain
historical; these checks do not replace the original five/three repetitions.

| Run | Exit / recorded outcome | Raw result SHA-256 |
| --- | --- | --- |
| F1 nominal | 0 / ok, 10 rounds | 199adc3f3a7708e4d8f2d8d76b51c8ec25eb111e33fddcd2d3dcc749f6419a0a |
| F1 missing round | 1 / reply timeout, 2/10 rounds | 322e1e49c7938bb64456a84421b2ceccce073283fd6b74f309c71615508410fa |
| F1 waiter lifetime | 1 / waiter exit 3, 9/10 rounds | 41e243d667beb8e035c9a3dea525e406be22a71b8d5f086c9115b80aec8f26f7 |
| M2 nominal | 0 / ok, 11 records | d3a20b736e5db1a2af111c51d38ab0cb10daf57fe060479e88d9e98b8866d37b |
| M2 early exit | 1 / EOF before readiness, child exit 1 | 08d95011d17bef5e4be60838a604d57269199fe5d7b9567d41a5ded54114d915 |
| M2 ignored EOF | 1 / incomplete 1, later child exit 3 | c20e6dfcdf96f6de021f64a8fb1a865d5c06f9515ed5ea5991f029e58ef1e8cb |
| M2 long socket | 1 / length rejected before startup | b25e9fa1297b7d1ef510d4d084b489a32f33f0f31d1399de59aa5362bb5d68d0 |

This validates the measured paths, not every schedule. The later child exit in
the ignored-EOF case is a second observation of the same child; it does not
remove the recorded incomplete wait. No actual Codex session was exercised.

## F2 Linux access matrix at cfa2eba

One approved execution on 2026-10-14 used source
`cfa2eba9e3809afa060d85c15ff487f811c925e4`, transferred as a four-file archive.
Archive SHA-256: `cac2171ba9424d229a204b32a140321795fad000b6bef9fbbc709192a154ec4a`;
the remote copy matched before extraction. No dependency installation was needed.

Environment: Linux 7.0.0-1013-oracle/aarch64, Node 24.18.0, Python 3.12.3,
UID/EUID 1001, permitted/effective capabilities zero, Yama ptrace_scope 1.
Stage and result directories were 0700 and the result was 0600, owned by the
test user. No privilege or host policy change was made.

Runner exit was 0, `ok=true`, failures 0 and incomplete 0. Both ready records
matched the actual child PID, requested dumpability and observer UID. The
dumpable=1 case read one exclusive FLOCK row and matched FD/lock device+inode.
The dumpable=0 case returned EACCES for FD listing/readlink/stat, fdinfo-file
read and executable readlink. Both cases could read cmdline, start ticks and
status. The fdinfo directory retained the user's UID even with dumpable=0;
this corrects the original source expectation, as explained in the README.

Raw result SHA-256: `656c1d08d816303dfac870a87e426f4ace0f6972698a46f491a81a4c3b1900fc`.
The downloaded result matched the remote hash. Both holder exit records were
0 with no signal; neither recorded process instance remained at the post-check.
The two owned remote temporary directories were then removed; source archive,
raw result and verification records remain private on the integrating host.

This is an access-matrix result only. It does not run the #137 adapter,
establish product `unknown` behavior or candidate recognition, measure native
Codex dumpability, or reproduce a procfs hang. F2_DIST was disabled at that
revision; the later isolated inspection measurement is recorded below.

## Isolated F2 Linux measurement (2026-10-16)

Environment: unprivileged same-UID Linux 7.0.0-1013-oracle aarch64, Node
24.18.0, Python 3.12.3, ptrace_scope 1. No actual Codex process or home was
used; holders exited on EOF. No privilege, mount, visibility or host-policy
changes were made. Research dependencies were installed only inside private
build staging, using a staging-local npm cache.

The product build resolved local commit
`b483cd587c62329243366e64aaaac477edd36adc`, tree
`81d82c471a3a67560d48d4c70bce438f0ad96e29`, with no patch. Its manifest
SHA-256 was `23d5aa1f831ef5cc63e3e1c227955864ff2d3536d61d6a388158103c9f86ec92`;
48 dist files and 14 native-addon files were verified. The manifest does not
hash dependency JavaScript/package metadata or prove upstream/native-binary
identity. The remote/local runner, expectations and isolated-observer hashes
matched before interpreting results:

| Input | SHA-256 |
| --- | --- |
| run.mjs | `52b94e296c801a33fbd74cda21f41ce87789cd2f9e684764e84f16037f7d2c0e` |
| expectations.mjs | `9c09e8c28a0bc16789ea4de7d86120015d372ffa68ec7abc7472582b9735096c` |
| isolated-observer.mjs | `2d38c1aad5e96193756baed112e415df4a64b7b3c8e96b6e5b4be457debe3a72` |

| Run | Actual exit / outcome | Private raw result SHA-256 |
| --- | --- | --- |
| No fault injection | 1; collection true, expectations false, incomplete 0, refusalCounted false | `924e85a03bfc0aaedf93e5883619fd002470a028c92ae84e0839cced7c5d8b34` |
| stall:prepare | 1; collection false, both inspectors incomplete at prepare, later exit 4 without signal | `7b0042c45db6690c1fa436f03b1f32a3dd607f47ccef2f6057a1f2b79fd31743` |

The first run observed E2/E3 at dumpable=1 and R1/R2 at dumpable=0, but failed
V/E1/E4 for the control and V for refusal. `lsof` warned about incomplete
visibility of inaccessible overlay/nsfs mounts; the Python fixture was not
accepted as a Codex executable/argument combination. The control failure means
the refusal is not a passing attribution experiment. This is recorded rather
than repaired by suppressing warnings, loosening product identity rules or
changing the expected table. R2 may coexist with unrelated blockers and is not
proof of the sole cause of refusal.

All four holder exit records were 0 without signals. Both stalled inspectors
later reported exit 4 without signals. Post-checks found their recorded process
instances absent. Remote/downloaded raw-result hashes matched. Reports remain
private because they contain process IDs and local paths. No production
readiness or F4 liveness claim follows; actual native Codex evidence and the
unresolved shared-description/guard-liveness decisions remain open.
