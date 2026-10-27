# Same-PID exec identity prerequisite

Research for #127 option B, using synthetic actors only. This experiment does
not identify an actual Codex owner or authorize recovery. `safeToUnlock` is
always false. No production imports or executable allowlist changes are used.

The runner compiles one small C actor into two distinct executable paths. The
first actor acquires a genuine private `flock`, reports its PID and kernel
process start timestamp, then waits for a one-byte command. It uses `exec` to
replace its image with the second path, intentionally retaining the open lock
descriptor. The second image reports the same fields and exits on stdin EOF.
The high-resolution kernel start timestamp is reported by the trusted actor
itself through `proc_pidinfo`; the observer independently reads `ps lstart`
at second resolution. The observer checks the executable path using `proc_pidpath`, command arguments
and `lstart` with system `ps`, and actual lock contention using an independent
descriptor. These direct observations do not certify the product's
`inspectProcess` implementation or an atomic process-identity snapshot.

Expected table:

| Observation | Before exec | After exec | After EOF exit |
|---|---|---|---|
| PID and kernel start timestamp | Original | Unchanged | Exited |
| `ps lstart` | Original | Unchanged | Not sampled |
| Image and argv | actor-before / before | actor-after / after | Not sampled |
| Independent flock probe | held | held | free |

`collected` means both samples and the exit observation completed; `measured`
requires every expectation to match. `ok` also requires no errors or remaining
children. Failure preserves scratch and exits nonzero. Results include the
source and runner hashes. The result destination must not already exist and
is opened with `O_EXCL|O_NOFOLLOW`, mode 0600, before scratch creation.

```sh
python3 -m unittest discover -s experimental/127-macos-prerequisites/exec-identity -p 'test_*.py'
python3 experimental/127-macos-prerequisites/exec-identity/run.py \
  --tmp-root '<approved-private-temp-root>' --result '<new-result-file.json>'
```

macOS and system clang are required. The runner creates a fresh private
`codex-exec-*` directory and removes it only after successful completion and
confirmed child exits. The actor has a 15-second polling lifetime per image;
normal exit is EOF. Diagnostic collection and cleanup waits have deadlines,
but filesystem I/O, process creation and kernel calls do not have hard time
bounds. Timeout means incomplete reporting, not guaranteed termination. No
kill calls or subprocess killing timeouts are used; abandoned diagnostic pipes
may receive OS SIGPIPE when the parent exits. Results contain private temporary
paths and PIDs and should be summarized before publication.

Two different paths containing the same compiled program are intentional: the
experiment tests observable image-path/argv replacement, not different program
semantics. Same-path, same-argv exec is not detected by these checks. The actor
deliberately omits `FD_CLOEXEC`; this is not evidence that real Codex leaks such
a descriptor. `ps` and image sampling occur sequentially while the actor waits
for a command, rather than proving an atomic snapshot under arbitrary races.
The synthetic file is not a Codex native lock and has no native coordinator.

## Observed local result

One run on Darwin 27.0.0 arm64 completed with exit 0: `collected=true`,
`measured=true`, seven expectations matched, and all six child processes exited
0 with no pending processes. Both kernel start timestamps and `ps lstart`
remained equal across exec. Image path and argv changed, the independent probe
remained held, and EOF exit released the lock. Four protocol unit tests passed.
This run used actor SHA-256
`0088c89c4a4bcedb0551c3b71e3748640b6983fb3c2fa392d841aa6dd48583ee`
and runner SHA-256
`84da7467d84b276f826c60d92e3b510591eb3c7d8e0946b89c3fcc0079594e80`.
The raw result is retained privately; public documentation omits its paths and
PIDs. Other macOS versions are not covered by this local measurement.

After the cleanup-reporting correction, the integrating session reran the
nominal experiment with runner SHA-256
`14b2e16d04d2b8fdd4e6343c19e9fc8f869bb1875668db407ee9d4eadf0bb264`.
It exited 0, all seven checks passed, and no process remained pending.
The private raw-result SHA-256 is
`eaf8e5876ff3910a001d41e36ff592c428fb82a257b74d84e007afcb6f17fc24`.
CI measurements are reported separately through the workflow and PR checks.
