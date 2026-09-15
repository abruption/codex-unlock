# Maintainer release setup

This repository follows the `agy-cli-usage` release pattern: Conventional
Commits feed Release Please, and merging its release pull request creates a tag
and GitHub release. npm publication runs only when that release is created.

## One-time repository setup

1. Add the npm automation token as the Actions repository secret `NPM_TOKEN`.
   With GitHub CLI, run `gh secret set NPM_TOKEN --repo abruption/codex-unlock`
   and paste the value at its prompt. Do not store it in this repository.
2. In **Settings → Actions → General**, allow GitHub Actions to create pull
   requests if the repository policy currently blocks Release Please.
3. If branch protection is enabled, use these stable aggregate required checks:
   `supported-tests`, `lint`, `security-audit`, and `package-smoke`.

The initially empty `.release-please-manifest.json` is intentional. The squash
commit that introduces this automation carries `Release-As: 0.1.0`, so Release
Please bootstraps the first release at `0.1.0` instead of inferring `1.0.0` from
the existing package version. Its release pull request then updates the
manifest, package versions, lockfile, and changelog together.

## Release flow

1. Merge Conventional Commit changes to `main`.
2. Review and merge the Release Please pull request.
3. The release workflow checks the tagged source, installs and exercises the
   packed tarball, then runs `npm publish --provenance --access public`.
4. Confirm the GitHub release, npm package version, provenance, and CLI install.

Until `NPM_TOKEN` is configured, do not merge the Release Please pull request.
Ordinary CI and release-PR preparation do not require the npm token.
Before registry publication, users can install from a clone with `npm ci` and
`npm link`; CI verifies that path independently of the packed npm artifact.
