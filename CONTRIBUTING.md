# Contributing

## Development

Use Node.js 22.13 or newer and install from the committed lockfile:

```bash
npm ci
npm run check
npm run lint
npm test
npm run smoke:package
```

`npm ci` runs the `prepare` build, which also keeps installation from a Git
checkout or Git dependency usable before a registry release exists.

Tests that exercise lock ownership require `lsof` and a host with POSIX advisory
locks (macOS or Linux).

## Changes and pull requests

Commit and pull-request titles follow Conventional Commits. Common types are
`feat`, `fix`, `docs`, `test`, `refactor`, `ci`, and `chore`; scopes are optional.
Use `!` plus a `BREAKING CHANGE:` footer for an incompatible behavior or JSON
schema change.

Keep each change focused. Update help text and the README when flags, output, or
safety behavior change. Include a regression test for fixes. Diagnostics can
contain process arguments and local paths, so redact them before attaching
output to an issue.

The lock-file deletion, force-unlock, and `SIGKILL` behaviors are intentionally
out of scope. A proposal to weaken an existing refusal condition must explain
how PID reuse, shared owners, and transcript mutation remain excluded.

## Releases

Do not bump versions or edit generated changelog entries in ordinary pull
requests. Release Please derives versions from Conventional Commits, opens a
release pull request, and publishes to npm only after that pull request creates
a GitHub release.
