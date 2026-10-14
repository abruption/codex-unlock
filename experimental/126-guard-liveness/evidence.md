# Sanitized research evidence

Same-user macOS/APFS synthetic fixtures only. No actual Codex session or
Windows recovery was exercised. Raw result files were hash-checked and retained
privately; hashes identify the original files, not this sanitized summary.

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
Codex dumpability, or reproduce a procfs hang. F2_DIST remains disabled.
