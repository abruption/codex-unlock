# macOS recovery prerequisites

Research for [#127](https://github.com/abruption/codex-unlock/issues/127),
following the [owner contract](../../docs/macos-owner-contract.md).
This increment measures two prerequisites for evaluating option B, the
refusal-only `FWASLOCKED` filter. It does not implement that filter or choose
the final recovery policy.

- [Rust launcher](rust-launcher/README.md): compare default close-on-exec
  file descriptors with an explicitly inheritable control across
  `std::process::Command`. Observe real flock contention and per-description
  flags using the existing strict system-lsof observer.
- [Exec identity](exec-identity/README.md): replace a synthetic process image
  at the same PID while retaining its lock. Compare kernel start time,
  executable path and argv, then observe normal exit and lock release.

All inputs are newly created fixture files and cooperating children. The
programs do not operate on real Codex homes or signal owners. A passing
measurement does not prove production policy refusal, sole holder control,
complete process visibility or atomic sampling. The Rust experiment pins
1.90.0 by default; the Codex source audited in the owner contract uses Rust
1.95.0. The CI matrix explicitly builds with both toolchains. No equivalence
of complete Codex launch paths follows from the fixture.

The dedicated workflow runs on `macos-15` and `macos-15-intel`: Rust inheritance
uses both 1.90.0 and 1.95.0; the toolchain-independent exec case runs once per
OS architecture. Its configured matrix is not execution evidence until the
corresponding run passes. Raw reports contain paths/PIDs; CI prints only a
bounded summary, source/binary hashes, compiler metadata and result hash. The
raw CI report is ephemeral; its hash alone is not a retained measurement artifact.
The scripts send no termination signals. GitHub runner cancellation, job
timeouts and runner cleanup may terminate leftover synthetic fixture processes.

Remaining prerequisites include Mach fileport transfer, hidden shared
descriptions, permission-limited observers and targets, additional lsof
versions and filesystems, and actual Codex behavior. These remain explicit
gaps in the owner contract. The same-PID experiment records observable OS
fields; it does not exercise the production revalidation decision.
Kernel start timestamps are actor-reported; `ps lstart` is independently
observed. The fixture does not detect same-path, same-argv exec.
