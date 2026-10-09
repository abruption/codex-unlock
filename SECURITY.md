# Security policy

## Supported versions

Security fixes are provided for the latest published `codex-unlock` release.
Please reproduce a suspected issue on that version when it is safe to do so.

## Report a vulnerability privately

Do not open a public issue for a vulnerability or for diagnostics that may
contain sensitive local data. Use GitHub's
[private vulnerability reporting form](https://github.com/abruption/codex-unlock/security/advisories/new)
instead. It creates a private security advisory visible only to the reporter
and repository maintainers.

Include the affected version, operating system, a minimal reproduction, the
expected security invariant, and the observed result. Before attaching CLI
output, redact:

- usernames, home directories, and all other local paths;
- process IDs, parent process IDs, command lines, arguments, TTYs, and working
  directories;
- thread IDs and transcript paths or contents;
- environment variables, access tokens, npm credentials, and other secrets.

Never attach an unredacted `--json` result. Maintainers may ask for a smaller,
sanitized diagnostic privately if it is needed to reproduce the report.

General bugs that do not expose sensitive data can use the public
[issue tracker](https://github.com/abruption/codex-unlock/issues).

## Native coordination

Diagnostics leave file contents, ownership, permissions, and mtime unchanged,
but acquire the existing Codex native coordinator briefly for each thread probe.
A missing or unsafe coordinator for an existing thread lock fails closed.
Guard sections are synchronous and finish before subprocesses, waits, or signals.
If a diagnostic is paused with SIGSTOP or a debugger while holding that guard,
coordinated writers in the home can wait until it continues or exits. Acquisition
timeouts do not bound a pause while holding the guard. Access times can change.
The zero-interference guarantee applies to writers using Codex's native
coordination protocol. See the [probe contract](docs/cli-reference.md#native-coordination-during-probes).

## Process identity assumptions

Start-time revalidation uses a second-resolution `ps lstart` sample followed by
numeric PID SIGTERM. It does not atomically bind the signal to that process
instance. Rapid PID reuse and changes in Linux wall-clock/boot-time interpretation
remain assumptions of the current implementation; matching timestamps do not
eliminate them. The final synchronous boundary narrows the gap, and unavailable
identity refuses recovery, but post-signal checks cannot undo a wrong-target
signal. See the [identity assessment](docs/safety-race-matrix.md#process-instance-identity-limits)
for measured evidence, platform options, and their limits.
