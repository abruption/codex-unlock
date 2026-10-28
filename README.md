<div align="center">

# codex-unlock

[한국어](README.ko.md) · [日本語](README.ja.md) · [简体中文](README.zh-CN.md)

[![npm version](https://img.shields.io/npm/v/codex-unlock?color=cb3837&logo=npm)](https://www.npmjs.com/package/codex-unlock)
[![npm downloads (last 18 months)](https://img.shields.io/npm/d18m/codex-unlock?label=downloads%20%2818%20months%29&color=cb3837&logo=npm)](https://www.npmjs.com/package/codex-unlock)
[![CI](https://github.com/abruption/codex-unlock/actions/workflows/ci.yml/badge.svg)](https://github.com/abruption/codex-unlock/actions/workflows/ci.yml)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![node](https://img.shields.io/node/v/codex-unlock?color=339933&logo=node.js)](https://www.npmjs.com/package/codex-unlock)
[![platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)](docs/platform-support.md)
[![license](https://img.shields.io/npm/l/codex-unlock?color=blue)](LICENSE)

**Fail-closed diagnostics and safe recovery for Codex native thread writer locks.**

</div>

## Demo

Find a thread and inspect whether its writer is eligible for safe recovery:

![codex-unlock v0.4.2 list and inspect diagnostics showing a live lock owner that is not safe to unlock](https://raw.githubusercontent.com/abruption/codex-unlock/main/docs/assets/codex-unlock-v0.4.2-demo.gif)

*Real macOS `list`/`inspect` output from v0.4.2, re-rendered with personal
identifiers redacted. The live lock owner is not safe to unlock; no session is
terminated in this demo.*

```text
codex-unlock list
codex-unlock inspect <thread-id>
```

Replace `<thread-id>` with a UUID from `list`. Add `--json` for structured output.
For an eligible completed session, `codex-unlock unlock <thread-id>` requests
recovery only when every safety check passes.

## Quick Start

The stable npm CLI requires macOS or Linux, Node.js **22.23.4+ (22.x) or 24.22.1+ (24.x)**, and `lsof`.
That CLI does not support Windows or Node.js 26.

`list` and `inspect` do not change the contents of Codex's native lock or
transcript files, though each probe briefly takes Codex's coordination lock.
An interactive command may separately refresh codex-unlock's advisory update
cache after printing the primary result; see [update behavior](docs/cli-reference.md#updates).
`unlock` sends `SIGTERM` only after revalidation confirms that exactly one
same-user Codex process owns the target lock. That process must hold exactly one
thread lock, and its stable transcript must end in `task_complete`. Shared
app-server, Remote Control, daemon, and uncertain owners are refused. `unlock`
never deletes native lock files, forces an unlock, or sends `SIGKILL`. See the
[safety model](docs/cli-reference.md#safety-model).

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

<a id="windows-diagnostic-prerelease"></a>

## Windows 10 diagnostics

The separate Windows diagnostic-only channel uses tags `windows-v<version>`.
Release candidates are marked as prereleases. Consult
[GitHub Releases](https://github.com/abruption/codex-unlock/releases) for its
publication status and ZIP availability. Running the standalone ZIP's executable
requires no Node.js, Rust or `lsof` installation; npm installation remains the
macOS/Linux CLI.

The support scope is **Windows 10 x64 on local NTFS**, with a verified
Medium-integrity, non-elevated, non-AppContainer token. Windows 11 and Windows
Server are outside this qualified scope. Security-product and Codex-mode
coverage is recorded in the platform guide; it does not cover every configuration.
There is no Windows unlock or recovery, a supplied
PID does not establish the lock holder, and `safeToUnlock` is always `false`.
See [Windows scope and download guidance](docs/platform-support.md#windows-diagnostic-prerelease).

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
