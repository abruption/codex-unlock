# #127 synthetic description-sharing fixtures (macOS)

Unpublished research for [#127](https://github.com/abruption/codex-unlock/issues/127).
It is outside the npm `files` list and is not run by `npm test`. Results and
their interpretation are recorded in
[docs/macos-owner-contract.md](../../docs/macos-owner-contract.md#5-synthetic-validation-127-fixtures).

`inherit.py` starts only its own same-user Python actors on a fresh fixture file
and never touches a Codex home or process. It measures, per stage, an
independent nonblocking flock probe and the `lsof +fg` `FWASLOCKED` bit for:

| Scenario | Shape |
| --- | --- |
| `fork_shared` | Holder forks without exec; both processes share one description |
| `exec_inherit` | Holder marks its FD inheritable and execs a child that keeps it |
| `exec_cloexec` | Holder keeps `O_CLOEXEC` and execs a child with `close_fds=False` |
| `scm_rights` | Holder passes its FD over a socketpair to a sibling actor (started by the script, not the holder's descendant), then closes it |

Results are reported in three parts:

- `collected`: no actor failure, no incomplete wait and no exception.
- `measured`: every stage matches the expected table in `EXPECTED_STAGES`.
  The table covers probe, per-role bit, `scan_valid`, zero unexpected PIDs,
  ready, closed and keeper events, received FD count, and child exits.
- `ok`: both.

Any mismatch, invalid scan or incomplete wait exits nonzero and keeps the
fixture directory.

Framing and parsing: actor output is read from the raw FD with newline
framing, a fixed deadline, and per-line and per-stream byte caps. A partial
line is never returned as an event. A malformed event or an unexpected event
name (for example a keeper or receiver `failed` event) is recorded as a
failure, never wrapped as ready. `lsof -F0pfG` is parsed strictly. A
missing `G`, a field-order change, non-hex flags or an unterminated record
makes the scan invalid. It is never read as `no_bit`.

Lifecycle: every actor is registered when it starts. Scenario exceptions enter
cleanup, which attempts stdin EOF, a bounded output read and a bounded exit
wait for each registered actor before writing the result. These attempts do
not guarantee cleanup or result writing after arbitrary I/O failures. Actors end themselves with
exit 3 after 20 s. **The script makes no kill calls and uses no killing
subprocess timeouts.** A diagnostic (`lsof`, `mount`) that exceeds its bound
is recorded as incomplete with its PID. It is polled again at the end
(`pending_diagnostics`) and never stopped. Its pipes stay open until the
script exits, after which the kernel may deliver SIGPIPE on its next write.
Nothing here guarantees that a child actually ended.

The result file is created with `O_CREAT|O_EXCL|O_NOFOLLOW`, mode 0600, before
the fixture directory exists, so an existing path or a symlink is refused and
cleanup never removes it. It records `script_sha256` and compares start/end
script hashes (`script_identity`); a change makes the measurement fail.
The hostname is not
collected. The filesystem type is taken from `mount` for the canonical path.

```sh
root="$(mktemp -d "<approved temporary root>/codex-127-XXXXXX")" && chmod 700 "$root"
python3 -I experimental/127-macos-contract/inherit.py --scratch-root "$root" --result "<new private path>/result.json"
RESEARCH_TMP_ROOT="<approved temporary root>" python3 -I experimental/127-macos-contract/test_inherit.py
```

`test_inherit.py` checks the following deterministically with finite
synthetic children only:

- framing: two lines in one chunk, a partial line at a deadline and at EOF,
  and line and stream caps;
- event validation;
- strict `lsof` parsing, including empty output and eleven malformed shapes;
- expected-table counterexamples: a wrong bit, an invalid scan, an unexpected
  PID, a probe error, a wrong or missing keeper, a wrong received count, a
  missing closed event, a nonzero child exit, a missing scenario, the stage
  order and the same PID;
- a diagnostic timeout recorded as pending and later observed as exited;
- an output cap, early actor exit, a `failed` instead of `ready` event, a
  partial line followed by silence, and closing every registered actor;
- result-file refusal of an existing path and a symlink.

The JSON result and console output can contain local paths and PIDs; keep
both private. Run against a frozen source file; a measurement does not certify
another script revision.
