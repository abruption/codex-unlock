# Handoff: proposed follow-ups outside this directory

This directory owns no other file. The changes below are proposals only.
`docs/macos-owner-contract.md`, `experimental/127-macos-contract/` and
`experimental/127-macos-prerequisites/` were read and left unchanged. Nothing
here reproduces a real Codex process or a wrong signal to a real PID.

## 1. `docs/macos-owner-contract.md` (proposal)

Section 4, gap table:

| Row | Proposed status |
| --- | --- |
| Inherited FD / Mach fileport passing | Measured (same-user synthetic, macOS 27.0.1 arm64, APFS). Lock held while the description is only in a queued Mach message, with no opener in `lsof` and no fileport in `PROC_PIDLISTFILEPORTS`. A fileport in a task's port space is printed as FD `fp.` with the description's flags. The receiver that never called `flock` becomes the sole holder with the bit. See `experimental/127-macos-visibility/README.md`. |
| Inherited FD / shared description with a hidden sharer | Measured as a model (#139 M2 style omission). With `SCM_RIGHTS` (either sharer hidden) and with fork (child hidden), the filter returns `not_excluded` for the visible sharer, which really shares the locked description. The lock stays held after that sharer releases. Recorded as `release_incomplete_due_to_hidden_reference`: one sharer's release does not release the lock. It is not a non-holder misidentified as the holder. |
| Permission / same-user target under `sandbox-exec` | Measured for `(allow default)` and one deny-default profile: target fully visible to an unsandboxed observer. Hardened runtime and App Sandbox not covered. |
| Permission / observer running sandboxed | Measured for five profiles, against a positive control with a full contract. `(deny process-info-pidfdinfo)` and a deny-default profile give exit 1, empty stdout and empty stderr, identical to "no openers". Detected here only by cross-checks (held probe, canary holder). Selective omission of some targets not covered and not detected by these checks. |

Section 2, counterexample rows to add:

| Counterexample | What the observer sees | Source |
| --- | --- | --- |
| Description in flight in a Mach message (fileport) | Held probe, no opener, no fileport listed anywhere | `127-macos-visibility` |
| Description held only as a fileport in a task's port space | `lsof` FD `fp.` with `FWASLOCKED`; no numeric descriptor | `127-macos-visibility` |
| Fileport converted by a process that never called `flock` | Receiver carries the bit and is the sole holder | `127-macos-visibility` |
| Hidden second sharer of the locked description | Visible sharer is a real sharer, `not_excluded`; its release leaves the lock held | `127-macos-visibility` |
| Restricted observer (sandbox) | Exit 1, empty output, no stderr: indistinguishable from "no openers" | `127-macos-visibility` |

Keep the hidden-sharer row separate from the existing former-holder row: the
former holder is a non-holding process that the filter does not refuse.

Section 1 currently lists "Descriptor passing (`SCM_RIGHTS`, Mach fileports)"
as not excluded by the source reading. That stays true: these fixtures show
the OS mechanism, not that Codex uses it.

## 2. Candidate inputs for option (b), not adopted

These are design candidates for the separately reviewed (b) change. Nothing
is implemented in `src/`. Adopting them, and accepting the residual risks,
remain user decisions.

1. Parse `lsof +fg` strictly. Any non-numeric FD, including `fp.`, makes the
   scan `unknown`. It must not be skipped and must not count as a descriptor.
2. A held probe with no visible opener is `unknown`, never "stale" or clean.
3. A visibility canary: a descriptor the observer owns and must see exactly
   in the same scan mode. A missing canary is `unknown`. It catches a
   restriction of the whole observer. It does not detect selective omission.
4. Residuals that stay documented with (b):
   - a former holder that keeps its FD;
   - a hidden sharer of one description, including fileport and
     `SCM_RIGHTS` receivers that never called `flock`, where one sharer's
     release does not release the lock;
   - a description in flight;
   - clean whole-record or selective omission.

## 3. CI integration

The integrating reviewer added `.github/workflows/macos-visibility-research.yml`
from the handoff proposal. Its first hosted runs remain pending.

- Runners: `macos-15` and `macos-15-intel`, with read-only `contents`
  permission and checkout pinned to the same SHA as the existing macOS
  workflow.
- Steps: the deterministic tests of this directory and of
  `127-macos-contract`, then one measurement run.
- Summary: the SHA-256 of the raw result plus `visibility.py --summarize`
  output.
- Privacy: the measurement prints an allowlisted public summary. Actor and
  test diagnostics stay private; test steps print fixed pass/fail status.
  Raw results and logs are not uploaded.

The original proposal was checked with `git apply --check` and YAML parsing.
The integrated workflow also hides raw test/measurement stderr. `--summarize`
was run locally against a result; hosted execution is recorded separately.

A `not_executed` scenario, a failed control, an incomplete wait or a failed
cleanup exits nonzero. There is no green result for an unmeasured scope. If a
hosted runner cannot run something, the public summary names the
`not_executed` kind or the failure kind, and the unmeasured scope must be
reported from that.

Risks to check on the first CI run:

- `bootstrap_check_in` with a dynamic name worked in an interactive user
  session here. A hosted runner's launchd domain may refuse it. The receiver
  then emits `failed`, and the run fails visibly.
- `sandbox-exec` may be unusable inside the runner's own confinement. The
  sandbox scenarios are then `not_executed`, which keeps `ok` false.
- A loaded runner can push an `lsof` call over its 5 s bound. This happened
  once locally (run 5). It is recorded as incomplete, never stopped, and
  fails the run.
- The expected tables were measured only on macOS 27 / lsof 4.91. Kernel 24.x
  may differ. A mismatch there is data, not a test bug.

## 4. Policy decisions left to the user

- Whether the hidden-sharer release and in-flight fileport shapes are
  acceptable residuals for (b), or move macOS toward (c).
- Whether (b) should adopt the canary and the held-without-opener rule as
  candidates, knowing they do not detect selective omission.
- Whether to adopt the CI proposal. `not_executed` must stay a failure either
  way.
