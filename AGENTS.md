# Repository instructions

## Purpose and scope

`codex-unlock` is a fail-closed diagnostic CLI for Codex native thread writer
locks. Keep the default commands read-only. Changes to `unlock` must preserve
the safety invariants below and must include tests that exercise real advisory
locks rather than lock-file existence alone.

## Commands

- Install exactly from the lockfile: `npm ci`
- Type-check: `npm run check`
- Lint: `npm run lint`
- Build and test: `npm test`
- Validate the published artifact: `npm run smoke:package`

Run the smallest relevant check while iterating, then run all five checks before
committing changes that affect runtime, packaging, or automation.

## Safety invariants

- A lock file is not proof of a live lock. Keep the OS lock probe independent
  from `lsof` process correlation.
- Fail closed as `unknown` when owner identity, lock state, or transcript state
  cannot be established.
- Only signal the exact, revalidated same-user Codex PID that owns one thread
  lock and has a stable transcript ending in `task_complete`.
- Refuse shared app-server, Remote Control, daemon, ambiguous, or changing
  owners.
- Never delete native lock files, add a force mode, or escalate from `SIGTERM`
  to `SIGKILL`.
- Verify process exit, actual lock release, and transcript hash invariance after
  signaling.

## Code and repository conventions

- Use TypeScript ESM and retain strict compiler settings.
- Keep machine-readable output backward compatible; version schema changes and
  document them.
- Do not commit `dist/`, packed tarballs, credentials, or local `.env` files.
- Use Conventional Commit subjects such as `feat:`, `fix:`, `docs:`, `test:`,
  `refactor:`, `ci:`, and `chore:`. Mark breaking changes with `!` and a
  `BREAKING CHANGE:` footer.
- Let Release Please update `package.json`, `package-lock.json`,
  `.release-please-manifest.json`, `CHANGELOG.md`, tags, and GitHub releases.
- Never place npm tokens in files, commit messages, logs, or command arguments.
  Publication reads `NPM_TOKEN` only from GitHub Actions secrets.
