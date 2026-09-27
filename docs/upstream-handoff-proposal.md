# Upstream proposal: owner-cooperative release and handoff for live thread writers

**Proposal only — not an implemented codex-unlock feature or a confirmed
upstream API.** `codex-unlock` does not call `thread/unsubscribe`, offer
`thread/release`, or release a shared app-server, Remote Control, daemon, or
multiple-owner writer. Those cases remain refused. A failed or unavailable
cooperative handoff must not automatically fall back to process termination.

As checked on 2026-09-27, the related upstream
[panel/CLI handoff issue](https://github.com/openai/codex/issues/45406) and
[Remote Control lock issue](https://github.com/openai/codex/issues/44449) were
both open. Their status does not establish that the proposed protocol exists;
recheck the current upstream implementation before relying on this design.

The original investigation considered the related Remote Control case and
several real lock holders on macOS. The important distinction is that these can
be live kernel locks held by a legitimate Codex process, not stale lock-file
residue. Deleting `<thread-id>.lock` cannot release such a lock and can make the
state harder to reason about.

The original source review found these owner-side lifecycle mechanisms. They
are historical design context, not a guarantee about a current Codex release:

- `WriterLockCoordinator` used a real nonblocking OS lock and removed only
  unlocked stale files.
- `thread/unsubscribe` removed a connection's subscription.
- an unsubscribed, inactive thread was observed to flush, shut down, be removed,
  and emit `thread/closed` after `thread_unload_delay_secs` (then 60 seconds by
  default, zero for immediate unloading).

What appears to be missing is an explicit, observable handoff contract between
products/processes. I suggest building that contract around cooperative release
by the process that owns the writer, rather than allowing another process to
delete files or kill the owner.

### 1. Owner-side release operation

Either add an optional immediate mode to `thread/unsubscribe`, or introduce a
small `thread/release` operation. The following request and response are
illustrative proposals, not supported API shapes:

```json
{
  "threadId": "...",
  "mode": "ifIdle"
}
```

The response should be structured rather than inferred from an error string:

```text
released | busy | subscribersRemain | notLoaded | notOwner
```

`ifIdle` should release only when the owning app-server can prove that:

- there is no active turn, delegated work, pending tool call, or elicitation;
- the requesting connection is unsubscribed and no other subscriber still
  requires the loaded runtime;
- pending rollout items have been flushed and the recorder shuts down cleanly.

Only then should it remove the runtime and drop `WriterLockGuard`. If the
upstream protocol confirms it, `thread/closed` could acknowledge that ownership
was actually released. A contender should retry `thread/resume` only after an
authoritative release acknowledgement.

### 2. Product lifecycle integration

- The panel should expose an explicit **Release / Hand off** action for an idle
  thread.
- Remote Control clients should unsubscribe when the view is closed, backgrounded,
  or disconnected, and viewing history alone should not keep unrelated threads
  resumed indefinitely.
- Reconnection should restore subscriptions only for threads the client is
  actually observing or running, rather than every recently viewed thread.

If implemented upstream, this would address the Remote Control scenario without
weakening single-writer protection.

### 3. Structured conflict diagnostics

When `thread/resume` encounters a live writer, its JSON-RPC error data could
include non-sensitive fields such as:

```json
{
  "threadId": "...",
  "reason": "liveWriter",
  "ownerKind": "cli | appServer | remoteControl | unknown",
  "retryable": true,
  "suggestedAction": "releaseInOwner"
}
```

PID, command line, TTY, and cwd are useful for an opt-in local diagnostic command,
but probably should not be exposed in normal protocol errors. Lock-file presence
alone must never be reported as proof of a live owner; the OS lock probe and
process metadata are separate evidence.

### 4. Suggested regression coverage

1. An active turn refuses `ifIdle` release and keeps its writer lock.
2. An idle final subscriber can release; the rollout is flushed and unchanged
   after shutdown.
3. Other subscribers prevent release.
4. Remote disconnect/backgrounding releases idle threads instead of retaining
   every previously viewed thread.
5. A second app-server initially receives a conflict, waits for `thread/closed`,
   then resumes successfully.
6. Crash residue is removed only when a real nonblocking lock probe succeeds.

An incremental first step could be the owner-side `ifIdle` release plus structured
conflict data; panel and Remote Control affordances could then use the same
protocol without changing the lock's safety model.

Any future codex-unlock integration needs a separate protocol and security
design review. Until then, the standalone CLI must keep refusing shared or
ambiguous owners; it must not chain a failed handoff to `SIGTERM`, delete native
lock files, add force mode, or send `SIGKILL` to an owner.
