# Maintainer release guide

The package is published at
[`codex-unlock` on npm](https://www.npmjs.com/package/codex-unlock). Conventional
Commits on `main` feed Release Please; merging its release pull request creates
the version tag and GitHub release, which starts npm publication with
provenance through npm Trusted Publisher OIDC. The Release Please manifest
records the latest released version.

## Recurring release flow

1. Merge focused Conventional Commit pull requests into `main` only after CI
   passes.
2. Review the Release Please pull request. It owns `package.json`,
   `package-lock.json`, `.release-please-manifest.json`, and `CHANGELOG.md`.
   For v0.2, confirm the generated notes agree with
   [`v0.2-migration.md`](v0.2-migration.md), including the CLI-only API boundary,
   concurrent-unlock serialization, and deliberately unsupported owners.
3. Merge that pull request to create the tag and GitHub release.
4. Confirm the tagged release workflow passed `npm ci`, type checking, lint,
   tests, package smoke, and OIDC-authenticated
   `npm publish --provenance --access public`.
5. Verify the GitHub release and npm version match, provenance is present, and
   a clean global install passes `codex-unlock --version` and `--help`.

The stable aggregate branch-protection checks are `supported-tests`, `lint`,
`security-audit`, and `package-smoke`.

`supported-tests` covers the explicit x64/arm64 macOS and Linux matrix in
[`platform-support.md`](platform-support.md). `package-smoke` requires exact
artifact contents, an offline clean tarball installation, CLI/JSON smoke tests,
and rejected package-root/internal imports on both operating systems.
It also compiles a consumer against the installed tarball's type-only JSON
declarations in NodeNext and bundler modes, without Node.js type dependencies,
and rejects `/types` as a runtime import.

Before merging the v0.2.0 Release Please pull request:

- require #26, #27, and #29 to be closed by a green implementation pull
  request;
- move the update-cache contract (#28) and update notice (#20) to the v0.2.1
  milestone rather than mixing network/cache behavior into the initial v0.2
  safety release;
- confirm the release branch is based on current `main` and includes the JSON
  contract, concurrent-unlock serialization, doctor-boundary refactor, and
  release-gate commits;
- review the generated changelog instead of editing it by hand.

## npm Trusted Publisher binding

Before merging a change that removes token authentication, a package owner must
create this binding under the npm package's **Settings → Trusted Publisher**.
The fields are case-sensitive; the workflow filename is not a path:

| npm field | Value |
| --- | --- |
| Provider | GitHub Actions |
| Organization or user | `abruption` |
| Repository | `codex-unlock` |
| Workflow filename | `release-please.yml` |
| Environment name | Blank (the publish job has no GitHub environment) |
| Allowed actions | Enable direct `npm publish` |

The publish job runs on a GitHub-hosted runner with `id-token: write`, Node 24,
and npm 11.11.0 (npm requires 11.5.1 or later and Node 22.14.0 or later).
It checks out the Release Please tag, then publishes without `NODE_AUTH_TOKEN`.
Do not add a token, copy a PassKey, or weaken the package's publishing-access/2FA
setting to make OIDC work. The npm website may ask the owner for PassKey/2FA
while creating the binding; the CI job itself needs no interactive approval.

On the first release after migration, verify the exact workflow and tag used,
the successful npm publication, provenance/attestations, and the clean-install
checks below. Only **after** that succeeds, delete the unused GitHub Actions
`NPM_TOKEN` secret and revoke the old npm publish token in npm; verify both
separately. Until the first OIDC publication succeeds, keep the old credential
for recovery but do not pass it to the new publish job. A failed publication
should be diagnosed and re-run from the existing release rather than creating
an unrelated version solely to retry credentials. `ENEEDAUTH` commonly means a
binding-field mismatch, missing `id-token: write`, or unsupported runner/npm;
check those before changing release artifacts.

See [npm's Trusted Publisher guide](https://docs.npmjs.com/trusted-publishers)
for the current setup and troubleshooting contract.

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

## Provenance and registry signatures

The release workflow's OIDC-authenticated
`npm publish --provenance --access public` generates the package provenance
statement. After registry propagation, verify the released version rather than
an unpacked workspace:

```bash
npm view codex-unlock@<version> version dist.integrity dist.attestations --json
npm install --global codex-unlock@<version>
codex-unlock --version
codex-unlock --help
```

For an isolated dependency-tree signature check, install the exact version in
a clean temporary project and run `npm audit signatures`. Report registry
signature and attestation totals separately: that command aggregates the
installed dependency tree and its counts are not a claim that the single
`codex-unlock` tarball has the same number of signatures. Missing or invalid
provenance, an integrity mismatch, or an invalid signature blocks release
verification even if installation succeeds.

## npm lifecycle contract

`prepare` supports fresh-clone installation and is also the single lifecycle
build used by direct packing and publication. `build` removes `dist/` before
TypeScript compilation. `npm test` compiles once through `pretest`.
`npm run smoke:package` compiles once, then its verifier calls `npm pack
--ignore-scripts`; this prevents a nested second lifecycle build while still
checking the exact allowlisted artifact and an isolated installation.
