# Sanitized research evidence

Same-user macOS/APFS synthetic fixtures only. No actual Codex session or
Windows recovery was exercised. Raw result files were hash-checked and retained
privately; hashes identify the original files, not this sanitized summary.

## Original measurements

| File | SHA-256 |
| --- | --- |
| F1 result, 50 rounds | 2e27c2155a03e028cb24634feedf6b735209935a370952031c871a9a0ddb6ad4 |
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
syntax checks only; no Linux runtime matrix or native Codex access is proven.
