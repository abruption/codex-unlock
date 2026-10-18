# Rust `Command` descriptor inheritance prerequisite

This unpublished, dependency-free Rust 1.90.0 experiment tests one prerequisite
for #127 option B. A synthetic parent opens a fresh file with `std::fs`, obtains
a real exclusive `File::try_lock`, and launches this same executable using
`std::process::Command`. A Python observer separately probes the file using
macOS `flock` and records `/usr/sbin/lsof +fg` flags.

The default case preserves the descriptor's `FD_CLOEXEC`. The control clears
that flag with Darwin `fcntl` before `Command::spawn`. The child verifies the
inherited descriptor's device/inode before retaining it. The parent then closes
its own descriptor **without explicitly unlocking the shared description**.

Expected observations (not results until a run passes):

| Case / stage | Probe | Parent FWASLOCKED | Child FWASLOCKED |
| --- | --- | --- | --- |
| Default / before parent close | held | present | absent |
| Default / after parent close | free | absent | absent |
| Explicit inheritance / before parent close | held | present | present |
| Explicit inheritance / after parent close | held | absent | present |

The runner checks all four rows, verified child/parent identities, observed
initial and pre-spawn descriptor flags, the child's descriptor result, strict lsof parsing, unexpected
openers, stderr, both process exit outcomes, and clean stdout EOF after the
terminal child-exit record, followed by an independent free-lock probe after
both processes exit. Extra complete or partial output is rejected.
Missing or malformed evidence
does not count as absence. Any mismatch or incomplete exit makes the run fail.
FWASLOCKED remains acquisition-history evidence; no holder or recovery
eligibility conclusion is produced.

## Run

Run from this directory on macOS with Rust 1.90.0 already available:

```sh
cargo +1.90.0 build --locked
python3 -B -m unittest -v test_run.py
python3 -B run.py \
  --binary "$PWD/target/debug/macos-command-inheritance-lab" \
  --scratch-root "$RUNNER_TEMP" \
  --result "$RUNNER_TEMP/rust-inheritance.json"
```

`--scratch-root` must name an existing writable temporary root; the runner
creates a fresh 0700 child directory. `--result` must be a new path outside that
new directory; existing files and final-component symlinks are refused. Results
are written with mode 0600. The supplied binary must be the trusted fixture
built above. Its hash and both Python source hashes are recorded. Preserve the
source revision and `rustc +1.90.0 --version --verbose` with CI evidence; a binary
hash alone does not attest the compiler or source used.

The runner reuses the repository's existing
`experimental/127-macos-contract/inherit.py` strict lsof parser, byte-limited
framing, bounded diagnostic waiting, and real flock probe. Run from a full
checkout so that module is available. The package has no third-party Rust
dependencies and `publish = false`.

## Lifetime, scope, and validation limits

Only newly created synthetic files and our own parent/child are used. Normal
cleanup is stdin EOF. Rust checks a 15-second parent lifetime and a 20-second
keeper lifetime while waiting on its input channel. The parent gives the child
three seconds to finish and reports an unconfirmed exit as incomplete. Python
also bounds its waits and never sends a termination signal. Synchronous OS
calls, process creation, and the standard-library lock operation are not given
a hard wall-clock guarantee. A stalled process may remain; results and scratch
are always retained for inspection. Closing a diagnostic's pipes when the
runner exits can cause a later write to receive kernel SIGPIPE. There is no
claim that every process necessarily exits.

This does not execute a Codex binary, audit all launchers,
validate a real Codex descriptor lifetime, or establish holder attribution.
There is no native coordination-file experiment here: the synthetic actors are
held steady at explicit protocol stages. The observation is local macOS
process behavior, not a production policy change. The control shows what
explicit inheritance permits; it cannot establish that Codex uses that path.

Local preparation: Python AST checks and the initial four focused expectation tests passed.
Those tests reject missing fields, failed scans, unexpected openers, and wrong
probe/role results. **Rust compilation and the four runtime rows were not run
locally** because rustc/cargo were absent from PATH and the checked conventional
installation locations. There is no runtime success claim until the pinned
compiler and nominal experiment run in CI. No toolchain was installed locally.
The workflow explicitly selects Rust 1.90.0 and 1.95.0 on both macOS runner
architectures; its logs identify the actual compiler. The report's
`minimum_rust` is the crate requirement, not a measured compiler version.
Additional regressions check that a missing binary produces a nonzero
result with a structured failure report, and that missing measurements or
failed/incomplete cleanup cannot satisfy the final predicate. Set
`RESEARCH_TMP_ROOT` to an existing approved temporary root when running all
seven helper tests.
