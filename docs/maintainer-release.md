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
4. Confirm `build-release` passed installation, type checking, lint, tests,
   the npm tarball contract check, and package smoke without OIDC permission.
   Confirm `publish` verified the transferred SHA-256 and published that
   tarball with OIDC and `--ignore-scripts --provenance --access public`.
5. Verify the GitHub release and npm version match, provenance is present, and
   a clean global install passes `codex-unlock --version` and `--help`.

The stable aggregate branch-protection checks are `supported-tests`, `lint`,
`security-audit`, and `package-smoke`.

`supported-tests` covers the explicit x64/arm64 macOS and Linux matrix in
[`platform-support.md`](platform-support.md). `package-smoke` requires exact
artifact contents, an offline clean tarball installation, CLI/JSON smoke tests,
and rejected package-root/internal imports on both operating systems.
It generates the runtime-only `npm-shrinkwrap.json` from `package-lock.json`,
asserts that the native runtime dependency is an exact pin matching the
lockfile, that the shrinkwrap is published without development entries, that a
regular dependency installation contains exactly `codex-unlock`,
`fs-ext-extra-prebuilt`, and `nan`, and that their installed versions equal the
pins. The generated shrinkwrap is removed afterwards.
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
The `build-release` job checks out the Release Please tag and requires its
commit to equal the workflow's `GITHUB_SHA`. It has only `contents: read` and
cannot request an Actions OIDC token. The publish job has no checkout or project
dependency installation; it receives the verified tarball by immutable artifact
ID and checks its SHA-256 against the build job output before publication.
Neither job uses `NODE_AUTH_TOKEN`.
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

## Runtime dependency pinning

`package-lock.json` is the repository lockfile. The build job's package smoke
generates and validates `npm-shrinkwrap.json` with only the runtime tree,
then preserves the exact tarball that passed clean-install and content checks.
Direct directory publication retains the `prepublishOnly` check; tarball
publication skips that hook, so the build job's artifact checks are mandatory.
The published shrinkwrap makes `npm install codex-unlock`
(global or as a dependency) install exactly the `fs-ext-extra-prebuilt` and
`nan` versions that CI validated instead of the newest compatible release.
`package.json` also pins `fs-ext-extra-prebuilt` to an exact version for
package managers that ignore npm's shrinkwrap.

Never publish the full lockfile as a shrinkwrap: npm installs every entry of a
dependency's shrinkwrap, so 0.4.1 installed its development tooling into
dependency consumers (#82). `npm-shrinkwrap.json` is git-ignored; do not commit
it, because npm would then prefer it over `package-lock.json` for local
installs.

Dependabot bumps the exact pin and `package-lock.json` together in a separate
`runtime` group with a `fix(deps)` commit, so the update runs the full platform
matrix and package smoke before Release Please ships it. After a manual
runtime dependency change, run `npm install` and commit both files; package
smoke fails if they disagree.

## npm lifecycle contract

`prepare` supports fresh-clone installation and is also the single lifecycle
build used by direct packing and publication. `build` removes `dist/` before
TypeScript compilation. `npm test` compiles once through `pretest`.
`npm run smoke:package` compiles once, then its verifier calls `npm pack
--ignore-scripts`; this prevents a nested second lifecycle build while still
checking the exact allowlisted artifact and an isolated installation.

## Transferred tarball publication contract

`npm run smoke:package -- --release-artifact-directory <new-directory>` retains
the exact verified tarball after all checks. An existing output directory
refuses. The publisher never repacks it or runs package lifecycle scripts.
Both jobs use npm 11.11.0. Only the publisher has `id-token: write`; installing
that pinned npm tool with `--ignore-scripts`, downloading the artifact, checking
its digest, and invoking npm are the publisher's execution steps.

The npm 11.11.0 [publish command](https://github.com/npm/cli/blob/v11.11.0/lib/commands/publish.js)
and [packer](https://github.com/npm/cli/blob/v11.11.0/workspaces/libnpmpack/lib/index.js)
skip directory lifecycle hooks for a tarball. The
[registry publisher](https://github.com/npm/cli/blob/v11.11.0/workspaces/libnpmpublish/lib/publish.js)
uses those same bytes for its attachment, integrity, and provenance SHA-512
subject. Its [provenance generator](https://github.com/npm/cli/blob/v11.11.0/workspaces/libnpmpublish/lib/provenance.js)
uses the GitHub workflow/ref/SHA environment, not a tarball's `gitHead` or the
publisher's working directory. Keeping both jobs in `release-please.yml`
retains the [Trusted Publisher binding](https://docs.npmjs.com/trusted-publishers/).
The source equality check prevents a tag checkout from silently disagreeing
with the commit named by that environment.

Release Please can create a release for the last merged release PR while a
later `main` push supplies a newer workflow SHA. That run deliberately fails
the source equality check rather than signing the wrong source association.
Retry an unposted release using this workflow on its **existing release tag**:

```bash
gh workflow run release-please.yml --ref v<version>
```

Dispatching on a branch refuses. A tag dispatch skips Release Please, rechecks
and rebuilds that tag, and retains GitHub's actual tag ref/SHA in provenance;
it never overwrites the provenance environment or creates another release.
Do not retry a version already published to npm. Tags predating this workflow's
dispatch support require a separate reviewed recovery plan.

`node scripts/verify-npm-publication.mjs <npm-11.11.0-directory>` exercises the
actual pinned npm publication path with local tarball bytes and mocked registry,
OIDC, and signing boundaries. It checks hook exclusion, unchanged attachment
bytes, package/digest subject, and workflow/source association. CI repeats it
without OIDC permission; the required `package-smoke` aggregate also gates on
its success. This is an offline compatibility check, not a real
Trusted Publisher exchange or cryptographic signature verification. No package
is published by that check. At the next authorized release, compare npm's
attestation SHA-512 to the uploaded tarball, source SHA to the release tag, and
workflow identity to `release-please.yml`, then run `npm audit signatures`.

This reduces token access for build tools; it does not establish that dependency
code cannot tamper with build output. Artifact digest verification protects the
transfer against a mismatch, not against an already-compromised build job.
