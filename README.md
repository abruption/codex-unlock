<div align="center">

# codex-unlock

[![npm version](https://img.shields.io/npm/v/codex-unlock?color=cb3837&logo=npm)](https://www.npmjs.com/package/codex-unlock)
[![npm downloads](https://img.shields.io/npm/dm/codex-unlock?color=cb3837&logo=npm)](https://www.npmjs.com/package/codex-unlock)
[![CI](https://github.com/abruption/codex-unlock/actions/workflows/ci.yml/badge.svg)](https://github.com/abruption/codex-unlock/actions/workflows/ci.yml)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![node](https://img.shields.io/node/v/codex-unlock?color=339933&logo=node.js)](https://www.npmjs.com/package/codex-unlock)
[![platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)](docs/platform-support.md)
[![license](https://img.shields.io/npm/l/codex-unlock?color=blue)](LICENSE)

**Fail-closed diagnostics and safe recovery for Codex native thread writer locks.**

</div>

## Demo

Find a thread, inspect its writer, then request a safe unlock:

```text
codex-unlock list
codex-unlock inspect <thread-id>
codex-unlock unlock <thread-id>
```

Replace `<thread-id>` with a UUID from `list`. Add `--json` for structured output.

## Quick Start

Requires macOS or Linux, Node.js **22.13+ (22.x) or 24.x**, and `lsof`.
Windows and Node.js 26 are not supported.

`list` and `inspect` are read-only. `unlock` sends only `SIGTERM`, and only
to a revalidated same-user, single-thread owner whose stable transcript ends in
`task_complete`. Shared app-server, Remote Control, daemon, and uncertain owners
are refused. It never deletes native lock files, forces an unlock, or sends
`SIGKILL`. See the [safety model](docs/cli-reference.md#safety-model).

### Install

```bash
npm install --global codex-unlock
codex-unlock --help
```

Or run without a retained global installation:

```bash
npx --yes codex-unlock@latest list
```

### Update

```bash
codex-unlock check-update
npm install --global codex-unlock@latest
```

`check-update` checks the registry; it does not install anything.
Automatic notices are advisory only. See [update behavior](docs/cli-reference.md#updates).

## Docs

- [CLI reference](docs/cli-reference.md) — commands, safety, options, exit codes, and source installation
- [JSON v1 and TypeScript types](docs/json-v1.md) — the supported automation contract
- [Platform support](docs/platform-support.md) — verified OS, architecture, and Node combinations
- [Safety race coverage](docs/safety-race-matrix.md) and [update security](docs/update-security.md)
- [v0.2 migration](docs/v0.2-migration.md) — historical integration baseline
- [Contributing](CONTRIBUTING.md) and [maintainer releases](docs/maintainer-release.md)
- [Upstream handoff proposal](docs/upstream-handoff-proposal.md) — design only, not an implemented fallback

## License

[MIT](LICENSE).

## Support and security

For questions and non-sensitive bugs, use [GitHub Issues](https://github.com/abruption/codex-unlock/issues).
Report vulnerabilities privately using the [security policy](SECURITY.md).
Redact local paths, process arguments, thread IDs, transcripts, and credentials
before sharing diagnostics; never post unredacted JSON output.
