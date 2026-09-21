# Maintainer release guide

The package is published at
[`codex-unlock` on npm](https://www.npmjs.com/package/codex-unlock). Conventional
Commits on `main` feed Release Please; merging its release pull request creates
the version tag and GitHub release, which starts npm publication with
provenance. The Release Please manifest records the latest released version.

## Recurring release flow

1. Merge focused Conventional Commit pull requests into `main` only after CI
   passes.
2. Review the Release Please pull request. It owns `package.json`,
   `package-lock.json`, `.release-please-manifest.json`, and `CHANGELOG.md`.
3. Merge that pull request to create the tag and GitHub release.
4. Confirm the tagged release workflow passed `npm ci`, type checking, lint,
   tests, package smoke, and `npm publish --provenance --access public`.
5. Verify the GitHub release and npm version match, provenance is present, and
   a clean global install passes `codex-unlock --version` and `--help`.

The stable aggregate branch-protection checks are `supported-tests`, `lint`,
`security-audit`, and `package-smoke`.

## npm publishing credential

Publication reads `NPM_TOKEN` only from the GitHub Actions repository secret.
Never put a token in a file, command argument, issue, pull request, or log. To
rotate it, create the replacement in npm, update the secret interactively with
`gh secret set NPM_TOKEN --repo abruption/codex-unlock`, verify the next release,
then revoke the previous token. A failed publication should be diagnosed and
re-run from the existing release; do not create an unrelated version solely to
retry credentials.

## Installation verification

The supported user installation is:

```bash
npm install --global codex-unlock
codex-unlock --version
codex-unlock --help
```

Clone installation with `npm ci` and `npm link` is retained for source
development and is tested separately in CI. It is not a substitute for
verifying the published npm artifact.

## npm lifecycle contract

`prepare` supports fresh-clone installation and is also the single lifecycle
build used by direct packing and publication. `build` removes `dist/` before
TypeScript compilation. `npm test` compiles once through `pretest`.
`npm run smoke:package` compiles once, then its verifier calls `npm pack
--ignore-scripts`; this prevents a nested second lifecycle build while still
checking the exact allowlisted artifact and an isolated installation.
