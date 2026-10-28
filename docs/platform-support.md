# Supported platform evidence

The stable `codex-unlock` npm CLI supports macOS and Linux only. It requires
Node.js 22.23.4+ (22.x) or 24.22.1+ (24.x) and `lsof`; these requirements are unchanged by the
separate Windows diagnostic prerelease described below. Stable CLI support means that the published
CLI can load its native advisory-lock dependency and that CI proves the full
non-mutating evidence path, including native coordination, against a real lock
owner. It does not mean that every
Unix-like platform or architecture is assumed safe.

## Security baseline

The minimum supported patch releases are Node.js **22.23.4** and **24.22.1**,
following the [October 21, 2026 security release](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases).
Earlier patches on those lines are no longer supported. Node.js 26 remains
unsupported. Both patched minimums and the latest releases on each supported
line are tested; release tooling uses 24.22.1. This metadata change does not
upgrade an installed Node runtime. Advisory applicability depends on the actual
API and attacker-controlled inputs; it is not evidence of an exploitable CLI
path. The native dependency and lock/identity/recovery policy are unchanged.

## Verified matrix

The `supported-tests` CI gate requires every combination below to pass:

| Operating system | Architecture | GitHub runner | Node.js |
|---|---|---|---|
| Ubuntu 24.04 | x64 | `ubuntu-24.04` | 22.23.4, latest 22.x, 24.22.1, latest 24.x |
| Ubuntu 24.04 | arm64 | `ubuntu-24.04-arm` | 22.23.4, latest 22.x, 24.22.1, latest 24.x |
| macOS 15 | x64 | `macos-15-intel` | 22.23.4, latest 22.x, 24.22.1, latest 24.x |
| macOS 15 | arm64 | `macos-15` | 22.23.4, latest 22.x, 24.22.1, latest 24.x |

These explicit labels and architectures follow GitHub's
[hosted-runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
They are intentionally not expressed as `*-latest` aliases.

The published package ships a runtime-only `npm-shrinkwrap.json`, so an npm
installation receives the same exact `fs-ext-extra-prebuilt` and `nan`
versions that this matrix validated, and nothing else.

Each matrix job performs the normal type and integration suite and then runs a
platform smoke test that verifies all of the following on the runner itself:

- `fs-ext-extra-prebuilt` loads for the active OS, architecture, and Node ABI;
- a separate process holds a real exclusive advisory `flock`;
- the nonblocking lock probe observes `held` independently of `lsof`;
- the probe acquires and releases the existing native coordinator safely;
- `lsof` correlates exactly one owner PID and its only native thread lock;
- `ps` supplies a stable process start time, PPID, uid, command, and arguments;
- the lock's device, inode, ownership, type, and link count are available;
- a stable rollout ending in `event_msg/task_complete` authorizes policy.

The test does not signal the owner through the unlock path. It terminates its
own fixture during cleanup after evidence collection.

This matrix proves the tested lock detection and opener-correlation paths,
not complete process visibility or unique actual-flock-holder attribution.
On macOS a held probe and one stable visible opener can still identify a
nonholder if the actual holder is omitted. See the
[macOS attribution decision proposal](macos-lock-attribution.md) for measured
limits and the human-review gates for a stronger contract. It changes no
current platform support or runtime policy.

## Diagnostic command execution

Stable npm CLI process evidence is collected with the same rules on every supported platform:

- `ps` runs only from `/bin/ps` or `/usr/bin/ps`, and `lsof` only from
  `/usr/sbin/lsof` or `/usr/bin/lsof`. `PATH` is never consulted; when neither
  fixed location exists the evidence is `unknown`.
- Commands run with a fixed environment (`LC_ALL=C`, `LANG=C`, and a system
  `PATH`) instead of the caller's, so `COLUMNS`, `LINES`, `PS_FORMAT`,
  `PS_PERSONALITY`, and locale variables cannot change their output.
- `ps` is invoked with `-ww`, which disables width truncation for both macOS
  BSD `ps` and Linux procps-ng.
- On Linux, `ps` arguments are cross-checked against `/proc/<pid>/cmdline`. If
  the kernel argv is unreadable, or `ps` output disagrees with it, the
  owner's arguments are `null` with an `arguments_unverified:` or
  `arguments_truncated:` error, and identity is incomplete. Verified kernel
  argument boundaries distinguish execution modes from prompts and known
  single-value options: `codex exec 'fix the daemon'` or
  `codex -C /work/app-server` is not a shared-service invocation. Actual
  `app-server`, `remote-control`, `daemon`, `exec-server`, and remote connection
  options remain refused. The bounded grammar follows `codex-cli 0.159.2`
  help and CLI source for interactive, exec, resume, and fork modes, pinned to
  [upstream commit ff6aec96948b70d94983af2641a6b67c94faeff5](https://github.com/openai/codex/tree/ff6aec96948b70d94983af2641a6b67c94faeff5).
  `CODEX_GRAMMAR_BASELINE` in `src/process.ts` is internal maintenance metadata;
  it does not identify the running owner's version. Offline tests in
  `test/grammar-contract.test.mjs` use manually reviewed examples and source
  excerpts in `test/fixtures/codex-grammar.json`, recording immutable source
  links and Git blob IDs. These tests preserve the reviewed subset; they do
  not fetch upstream or automatically certify new Codex releases. Before
  adding an option, review its source declaration, arity, aliases, mode scope,
  and shared-service implications at a pinned commit, then add acceptance and
  refusal cases. Never run an owner's executable or trust local `codex --version`
  as evidence of that owner's identity or argument safety. The
  official `--yolo` and `--not-so-yolo` aliases share the recognized scope of
  their canonical flags, and exec accepts `--experimental-json` as an alias
  of `--json`. One separately reviewed extension from `codex-cli 0.162.1`
  ([source commit 092d3acd6bec3e3a14bdc7e7a2810ab628ab759d](https://github.com/openai/codex/blob/092d3acd6bec3e3a14bdc7e7a2810ab628ab759d/codex-rs/exec/src/cli.rs#L31-L34))
  recognizes `--cyber-access-program` in `exec`/`e` only, with exactly one of
  `standard`, `daybreak_blue`, or `daybreak_red`, supplied separately or with
  `=`. Missing, invalid, or repeated values and use before `exec` remain
  unverified; nested exec modes remain unsupported. This does not certify the
  rest of version 0.162.1. `CODEX_EXEC_CYBER_GRAMMAR` and the source fixture
  `test/fixtures/codex-exec-cyber.json` record this narrow extension. Baseline
  metadata stays internal; no runtime version probe or new public JSON field
  is required to authorize an argument spelling. Unknown options,
  variadic image options, unsupported modes (including service-looking root
  tokens such as `daemon-worker`), and ambiguous operands make
  identity incomplete. Exact service/subcommand-looking operands after `--`
  also remain conservatively refused; delimiter precedence has not been
  verified for every Codex version. Direct Node shebang execution is recognized only as
  `node /path/to/codex ...`, without arbitrary wrapper or interpreter flags.
  Non-ASCII or control bytes that `ps` renders differently from the kernel
  argv remain refused; the tool does not guess a lossy de-escaping rule.
- macOS supplies a flattened `ps` argument string without verified argument
  boundaries. `app-server`, `remote-control`, `daemon`, and `exec-server`
  words anywhere in that string remain a conservative refusal, including
  words inside prompts or paths. Standalone `--remote` and
  `--remote-auth-token-env` spellings also refuse, with whitespace-separated
  values or equals forms, including occurrences inside flattened prompts.
  Unrelated longer option names such as `--remote-extra` do not match those
  spellings. Synthetic owners holding real advisory locks exercise each
  service mode and remote option form on both macOS and Linux, asserting
  refusal and no `SIGTERM` before fixture cleanup. The tool
  does not infer a shell quoting grammar or split this string into argv.
- The owner's native lock set is matched to the intended lock by the `lsof`
  device (`D`) and inode (`i`) fields, not by the rendered name, because the
  C locale makes `lsof` escape non-ASCII path bytes as `\xNN`. Any other lock
  name that cannot be resolved still blocks with `owner_lock_file_lookup_failed`.
- Every spawn failure, including a synchronous throw or an `EMFILE`/`ENFILE`
  child without pipes, is reported as a `spawn_error` command failure.

## Failure and unsupported-platform policy

A parser, command, native-module, permission, or identity failure is not
treated as partial success. Inspection returns `unknown` or adds a blocker, and
`unlock` must not send `SIGTERM`. The integration suite separately replaces
`ps` with a failing command through a test-only in-process seam and proves
that this path remains refused; it also proves that a shadowing `ps` or `lsof`
on `PATH` is never executed.

For the stable npm CLI, Windows, other Unix variants, and OS/architecture
combinations absent from the matrix remain unsupported or unverified. The
separate Windows diagnostic channel below does not extend that matrix or
authorize Windows recovery. Support is not inferred from fixture-only or
cross-compiled results.

<a id="windows-diagnostic-prerelease"></a>

## Windows 10 diagnostics

The separate diagnostic-only channel uses tags `windows-v<version>`; RC tags
are prereleases and the stable target is `windows-v0.5.0`. This channel does
not change the macOS/Linux npm CLI. The
[GitHub Releases page](https://github.com/abruption/codex-unlock/releases)
is authoritative for publication status and asset availability.

For a published Windows release, download
`windows-diagnostics-preview-windows-x86_64.zip`, `SHA256SUMS` and `manifest.json`
from the same release. The ZIP contains the standalone
`codex-unlock-windows.exe`; running it needs no Node.js, Rust or `lsof`
installation. Compare the ZIP's SHA-256 with the sidecar checksum before
extracting it, then compare the executable's hash with the inner checksum and
manifest. Verify the manifest version, target and source commit against the
selected release. Checksums detect changed bytes, not publisher identity.
See the [Windows preview quickstart](https://github.com/abruption/codex-unlock/blob/main/experimental/windows-rust-diagnostics/PREVIEW.md)
for PowerShell commands and JSON/exit-code interpretation.

The supported diagnostic scope is **Windows 10 x64 on local NTFS**, with an actually
observed Medium-integrity token (RID 8192), no elevation and no AppContainer.
Path, ownership and native-file checks still apply. Windows 11 and Windows
Server are outside the qualified scope. `diagnosticsAvailable` describes caller
eligibility, not certification of an OS version or the selected home.

The alpha backend was measured on the designated Windows 10 x64/NTFS host with
a genuine Medium token and a self-started Codex 0.163.0 app-server. Its recorded
Defender real-time state was disabled. The 0.5.0 release qualification uses that
host's Kaspersky Endpoint Security protection, checked with the vendor's
File Threat Protection status command; it does not count this as Defender-on
coverage. Applicable path/process exclusions are reviewed separately; active
protection is not a claim that the vendor scans every individual file operation.
Exact executable versions/hashes, active protection evidence and
case results are recorded in [release qualification #174](https://github.com/abruption/codex-unlock/issues/174).
RC and stable files each require their own actual-host checks before publication.
The tool neither changes antivirus policy nor asks users to disable protection.
This evidence does not qualify other Codex modes or security configurations.
The native app-server observation is held followed by normal shutdown and an
absent thread file (`unknown`), not a measured native free state; separate
synthetic fixtures establish the diagnostic's held-to-free behavior.
ReFS, network/UNC/device paths, reparse paths, hardlinked native
files, and unsupported or uncertain execution contexts are refused.

This executable provides diagnostics only: no Windows unlock, process
termination, lock-file deletion or recovery command. An observed lock conflict
does not identify its holder, and an optional user-supplied PID provides only
process observations, never holder authority. `safeToUnlock` and
`recoveryAvailable` are always `false`. RC/stable use the public
`codex-unlock-windows` schema, version 1, separate from both historical alpha
output and the npm CLI's JSON v1. `releaseChannel` is `rc` or `stable`, and
`preview`/`experimental` are false only for the stable version. The nested
research observation retains its own schema and `experimental` marker; it does
not grant recovery or holder authority. Probes briefly acquire existing native locks;
diagnostics are not guaranteed to be operationally inert.
