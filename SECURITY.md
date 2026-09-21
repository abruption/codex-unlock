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
