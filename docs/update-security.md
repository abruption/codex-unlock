# Update metadata security and failure-isolation contract

This document is the normative security boundary for the advisory update
feature tracked by issue #20. The implementation primitives live in
`src/update.ts`, but they are internal code rather than a supported JavaScript
API. The supported integration surface remains the CLI and JSON schema v1.

The update subsystem is advisory. No update fact can authorize a signal,
change lock classification, alter `safeToUnlock`, add a refusal reason, or
change a primary command's exit code. It never updates the installed package.

## Foreground and unlock isolation

Normal `list`, `inspect`, and `unlock` foreground execution may read one local
cache file. They must not synchronously access the network. A missing, stale,
invalid, or unavailable cache is equivalent to no advisory.

An automatic refresh is a separate best-effort process. It may be scheduled
only after the primary result is final. In particular, `unlock` must complete
inspection, operation-lease acquisition, complete revalidation, any `SIGTERM`,
and every post-signal process, lock, and transcript check before a refresh
process can start. Update errors and refresh-spawn errors are swallowed outside
the primary result path.

The doctor, inspection, policy, coordination, and unlock modules do not import
or call the update subsystem. A regression test instruments registry access and
the reserved refresh-process argument while exercising a real advisory-lock
unlock; both counters must remain zero throughout that safety-critical path.

## Cache location and schema

The cache is separate from `CODEX_HOME`, native writer locks, rollouts, and the
unlock operation lease:

- absolute `$XDG_CACHE_HOME`: `$XDG_CACHE_HOME/codex-unlock/update.json`;
- otherwise: `~/.cache/codex-unlock/update.json`.

A relative `XDG_CACHE_HOME` is ignored. The application directory is a
same-user, non-symlink directory with mode `0700`. The cache is a same-user,
regular, non-symlink, single-link file with mode `0600` and a maximum size of
4,096 bytes. An unsafe directory or file is rejected; it is not followed or
used as an authority.

The exact cache schema is:

```json
{
  "schemaVersion": 1,
  "latest": "0.2.1",
  "checkedAt": "2026-09-22T00:00:00.000Z"
}
```

Unknown keys, malformed JSON, non-canonical timestamps, prerelease versions,
and versions other than strict `x.y.z` are invalid. Cache entries are fresh for
24 hours. A timestamp more than five minutes in the future is invalid. The file
contains only the public stable version and registry check time; it never
contains Codex paths, process evidence, transcript data, environment values,
tokens, registry credentials, or response bodies.

Writes use a random `O_EXCL` temporary file in the application directory,
explicit `0600` permissions, file `fsync`, atomic rename, and directory
`fsync`. Existing symlinked, hard-linked, wrong-owner, wrong-type, or
non-private targets are refused. Temporary names are cleaned after failure.

## Refresh single-flight lease

`update.lock` is a same-user, regular, non-symlink, single-link `0600` file in
the private cache directory. Its existence is not evidence of a running
refresh. Contention is determined only by a nonblocking OS advisory lock. Once
acquired, the file is truncated to zero bytes; no PID, process start time,
path, or token is persisted in it.

The refresher holds the descriptor and lock for its lifetime. Process exit
releases the lock. A leftover unlocked file is stale residue and can be locked
again without deleting it or applying a wall-clock stale timeout. This avoids
PID reuse, forged timestamps, and stealing a lock from a slow live refresh.

## Registry request boundary

The only automatic network destination is the fixed HTTPS URL:

```text
https://registry.npmjs.org/codex-unlock/latest
```

The request:

- sends no authorization header or npm token;
- uses `GET` with `Accept: application/json`;
- rejects redirects instead of following them;
- has a 5,000 ms whole-operation deadline;
- rejects declared or streamed bodies larger than 65,536 bytes;
- requires an HTTP 2xx JSON response and consumes only its `version` field;
- accepts only a stable `x.y.z` version.

Timeout, DNS/TLS failure, non-2xx status, redirect, unexpected content type,
truncation, overflow, malformed JSON, and invalid version all produce a silent
internal error result. They do not overwrite a previously valid cache.

## Automatic-policy boundary

The integration in issue #20 must apply these defaults:

- `--no-update-notice` or
  `CODEX_UNLOCK_NO_UPDATE_NOTICE=1|true|yes|on` disables cache reads, notices,
  and automatic refresh;
- CI disables human notices and automatic refresh;
- non-TTY human commands do not read the cache, display a notice, or schedule
  a refresh;
- JSON commands may consume a fresh cache as an optional versioned field, but
  never print update text to stdout or stderr;
- an interactive human command may show a fresh advisory on stderr only after
  the primary result and may schedule a refresh only after command completion;
- an explicit future `check-update` command may perform the bounded foreground
  request because the user requested network access.

JSON schema v1 permits additive root fields. A future `clientUpdate` field must
remain optional and ignorable. Its presence cannot change the command result,
safety evidence, or exit status. Human notices are advisory stderr output after
the primary human result; JSON mode remains one valid JSON value with empty
stderr.

## Required regression coverage

The security suite covers fresh/stale/future/malformed/oversized/symlinked and
non-private caches, exact schema and file permissions, atomic replacement,
hard-link refusal, concurrent refreshes, unlocked stale lock residue, fixed
registry host, redirects, timeouts, registry failures, content type, malformed
and oversized responses, strict stable versions, CI/TTY/opt-out policy, and a
real-lock unlock with zero registry calls and zero update-refresh children.

Issue #20 must add end-to-end CLI tests for human stderr placement, optional
JSON metadata on success and error paths, detached-process cleanup, explicit
`check-update`, installation-specific guidance, and byte/exit-code invariance
across every update failure.
