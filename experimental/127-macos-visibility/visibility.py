#!/usr/bin/env python3
"""#127 research: fileports, hidden sharers and restricted visibility (macOS).

Same-user synthetic fixtures only. Never targets a Codex process or home.
Every actor is started by this script and registered before use. Actors close
their descriptors on stdin EOF. Their 20 s lifetime (C actor and the reused
inherit.py actors) is checked only while they wait for a command: it does not
interrupt a blocking write, file syscall or bootstrap RPC.

Signals: this script never calls kill or a subprocess timeout that kills.
Diagnostics (clang, lsof, sandbox-exec, one-shot C roles) are waited for with
a bound; one that does not finish is recorded as incomplete with its PID in
the private raw result, polled again at the end, and never stopped. Nothing
here guarantees that any child actually ended.

Scenarios (each uses a fresh fixture file):
  fileport          C sender flocks, passes a Mach fileport to a separately
                    started C receiver (not its descendant), then closes; the
                    receiver later converts the port with fileport_makefd
  hidden_sharer     description shared by SCM_RIGHTS or fork (inherit.py
                    actors), with one sharer omitted from the observer's view
                    by a model; the visible sharer then releases without a
                    signal and the lock is re-probed
  sandbox_observer  lsof scans and the flock probe run under sandbox-exec
                    profiles written to the scratch directory
  sandbox_target    the holder runs under sandbox-exec; the observer does not
  former_vs_opener  former holder (LOCK_UN, FD kept) next to a never-locked
                    opener, with and without a hidden actual holder

The refusal-only filter evaluator returns only `unknown`, `reject` or
`not_excluded`. FWASLOCKED is recorded and filtered on; it is never treated
as holder evidence.

Result fields: `collected` (no failure, incomplete wait or exception),
`measured` (expected tables and rules hold), `measurement_ok` (both, and no
scenario `not_executed`), `cleanup` (settled before the record is written)
and `run_ok`/`ok` (measurement_ok and the scratch directory removed).

Output: the raw result file is private (paths, PIDs, service names, stderr,
exception text). Standard output carries only `public_summary`, an allowlist
of fixed kinds, counts and validated identifiers. `--summarize <raw>` prints
the same public summary for an existing raw result.
"""

import argparse
import copy
import hashlib
import json
import os
import platform
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONTRACT = HERE.parent / "127-macos-contract"
sys.path.insert(0, str(CONTRACT))
import inherit  # noqa: E402  read-only reuse of framing, diagnostics, lsof parsing and actors

SCRIPT = str(Path(__file__).resolve())
ACTOR_SOURCE = str(HERE / "fileport_actor.c")
ACTOR_NAME = "fileport_actor"
CLANG = "/usr/bin/clang"
SANDBOX_EXEC = "/usr/bin/sandbox-exec"
COMPILE_TIMEOUT = 120.0
BOOTSTRAP_UNKNOWN_SERVICE = 1102
SERVICE = re.compile(r"^dev\.codex-unlock\.research\.127v\.[1-9][0-9]*\.[0-9a-f]{8}$")
STDERR_KEEP = 512
DECISIONS = ("unknown", "reject", "not_excluded")
REASONS = {"bit_present", "bit_absent_on_all", "pid_absent", "scan_invalid", "flags_unreadable",
           "canary_not_visible", "probe_error", "held_without_visible_opener"}
FILEPORT_ERRORS = {"identity", "list", "list_esrch", "list_length", "saturated", "query", "short_read"}
# Historical name in raw results of runs 1-4: "wrong_target_possible".
HIDDEN_OUTCOME = "release_incomplete_due_to_hidden_reference"


# ------------------------------------------------------------ evaluators

def parse_fg(out):
    """inherit.parse_fg, plus explicit recognition of lsof fileport records.

    lsof prints a fileport held by a task as FD `fp.`. Such a record is a
    parse problem (the scan is invalid), and it is also listed in
    `fileports` so the result shows what made the scan invalid.
    """
    parsed = inherit.parse_fg(out)
    fileports = []
    pid = None
    for record in out.split(b"\n"):
        text = record.decode("ascii", "replace")
        if re.fullmatch(r"p[1-9][0-9]*\0", text):
            pid = int(text[1:-1])
            continue
        match = re.fullmatch(r"ffp\.\0G(0x[0-9a-f]+);0x[0-9a-f]+\0", text)
        if match and pid is not None:
            fileports.append({"pid": str(pid), "flags": match.group(1),
                              "was_locked": bool(int(match.group(1), 16) & inherit.FWASLOCKED)})
    problems = list(parsed["problems"])
    if fileports:
        problems.append("fileport_record")
    return {"problems": problems, "pids": parsed["pids"], "fileports": fileports}


def interpret_scan(status, stdout, stderr, problems=()):
    """Strict scan validity, as inherit.fg_scan, from raw diagnostic output."""
    problems = list(problems)
    if stderr:
        problems.append("stderr")
    # lsof exits 1 with no output when nothing it can see has the file open.
    if status is not None and (status not in (0, 1) or (status == 1 and stdout) or (status == 0 and not stdout)):
        problems.append(f"status:{status}")
    parsed = parse_fg(stdout) if status is not None else {"problems": [], "pids": {}, "fileports": []}
    problems += parsed["problems"]
    return {"valid": status is not None and not problems, "problems": problems, "status": status,
            "pids": parsed["pids"], "fileports": parsed["fileports"],
            "stderr": stderr[:STDERR_KEEP].decode("utf-8", "replace")}


def filter_decision(scan, pid):
    """Refusal-only FWASLOCKED filter (the #139 M2 rules), for one PID.

    Only `unknown`, `reject` or `not_excluded`. `not_excluded` means only
    "not refused by this filter"; the bit is sticky and never holder evidence.
    """
    if not scan["valid"]:
        return {"decision": "unknown", "reason": "scan_invalid"}
    descriptors = scan["pids"].get(str(pid)) or []
    if not descriptors:
        return {"decision": "unknown", "reason": "pid_absent"}
    if any(d.get("was_locked") is None for d in descriptors):
        return {"decision": "unknown", "reason": "flags_unreadable"}
    if any(d["was_locked"] for d in descriptors):
        return {"decision": "not_excluded", "reason": "bit_present"}
    return {"decision": "reject", "reason": "bit_absent_on_all"}


def visibility_decision(probe, scan, pid, canary_visible=None):
    """Filter decision with visibility cross-checks; they only add `unknown`.

    canary_visible: None when no canary was scanned, else whether a known
    canary holder was seen exactly. A missing canary, a probe error, an
    invalid scan, or a held lock with no visible opener is `unknown`. These
    checks catch a whole-observer restriction; they do not detect a selective
    omission of some processes.
    """
    if canary_visible is False:
        return {"decision": "unknown", "reason": "canary_not_visible"}
    if probe not in ("held", "free"):
        return {"decision": "unknown", "reason": "probe_error"}
    if not scan["valid"]:
        return {"decision": "unknown", "reason": "scan_invalid"}
    if probe == "held" and not any(scan["pids"].values()):
        return {"decision": "unknown", "reason": "held_without_visible_opener"}
    return filter_decision(scan, pid)


def label(decision):
    value = decision["decision"]
    if value not in DECISIONS:
        raise ValueError(f"decision outside the vocabulary: {value}")
    return f"{value}:{decision['reason']}"


def without_pids(scan, pids):
    """A modelled clean omission of whole process records from a scan."""
    hidden = {str(p) for p in pids}
    view = copy.deepcopy(scan)
    view["pids"] = {k: v for k, v in scan["pids"].items() if k not in hidden}
    view["fileports"] = [f for f in scan.get("fileports", []) if f["pid"] not in hidden]
    return view


def view_signature(scan):
    if not scan["valid"]:
        return None
    return {pid: sorted(d["flags"] for d in descriptors) for pid, descriptors in scan["pids"].items()}


def reduced(reference, restricted):
    """True when the restricted view differs from the unrestricted reference."""
    signature = view_signature(restricted)
    return signature is None or signature != view_signature(reference)


def canary_visible(scan, canary_pid):
    if not scan["valid"] or set(scan["pids"]) != {str(canary_pid)}:
        return False
    return any(d["was_locked"] for d in scan["pids"][str(canary_pid)])


def role_states(scan, roles):
    states, fileport_states = {}, {}
    for role, pid in roles.items():
        descriptors = scan["pids"].get(str(pid)) or []
        states[role] = "absent" if not descriptors else (
            "bit" if any(d["was_locked"] for d in descriptors) else "no_bit")
        ports = [f for f in scan.get("fileports", []) if f["pid"] == str(pid)]
        if ports:
            fileport_states[role] = "bit" if any(f["was_locked"] for f in ports) else "no_bit"
    other = sorted(set(scan["pids"]) - {str(p) for p in roles.values()})
    return states, fileport_states, len(other)


# ------------------------------------------------------------ actor events

def is_pid(value):
    return inherit.is_pid(value)


def is_count(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def check_event(event, name, **fields):
    """True when event is `name` and every field passes its predicate."""
    if not isinstance(event, dict) or event.get("event") != name:
        return False
    for key, predicate in fields.items():
        if key not in event or not predicate(event[key]):
            return False
    return True


def parse_one_shot(result, expected):
    """One-shot C role output: status 0, no stderr, exactly one framed event."""
    problems = list(result["problems"])
    if result["status"] != 0:
        problems.append(f"status:{result['status']}")
    if result["stderr"]:
        problems.append("stderr")
    out = result["stdout"]
    lines = out.split(b"\n")
    event = None
    if not out.endswith(b"\n") or len(lines) != 2:
        problems.append("framing")
    else:
        event = inherit.parse_event(lines[0])
        if event is None:
            problems.append("malformed_event")
        elif event["event"] != expected:
            problems.append(f"unexpected_event:{event['event']}")
            event = None
    return {"event": event if not problems else None, "problems": problems,
            "stderr": result["stderr"][:STDERR_KEEP].decode("utf-8", "replace")}


def fileport_summary(event):
    """`count=…` for a complete enumeration, `error:<kind>` or `invalid`.

    An incomplete enumeration (identity, list, saturation, query or short
    read) is an error, never zero.
    """
    if not check_event(event, "fileports", ok=lambda v: isinstance(v, bool)):
        return "invalid"
    if not event["ok"]:
        kind = event.get("error")
        return f"error:{kind}" if kind in FILEPORT_ERRORS else "error:other"
    keys = ("count", "vnode", "non_vnode", "matching", "matching_was_locked")
    if not all(is_count(event.get(k)) for k in keys):
        return "invalid"
    if event["vnode"] + event["non_vnode"] != event["count"] or event["matching"] > event["vnode"] \
            or event["matching_was_locked"] > event["matching"]:
        return "invalid"
    return f"count={event['count']},matching={event['matching']},was_locked={event['matching_was_locked']}"


# --------------------------------------------------------------- the lab

class State:
    """Everything recorded for the raw result, registered before use."""

    def __init__(self, run):
        self.run = run
        self.scenarios = {}
        self.not_executed = {}
        self.errors = []
        self.services = []
        self.created = set()

    def error(self, where, error):
        self.errors.append({"where": where, "kind": type(error).__name__, "detail": str(error)})


class PrivateRun(inherit.Run):
    """Keep actor diagnostics out of public stderr, without a blocking pipe.

    The temporary file is private and unlinked. Only a bounded prefix enters
    the private result; an unfinished actor retains its file until exit.
    This is not a bound on the actor's disk writes or lifetime.
    """
    def __init__(self, scratch):
        super().__init__(scratch)
        self.actor_diagnostics = []

    def start(self, label_, argv, pass_fds=()):
        stderr = tempfile.TemporaryFile(dir=self.scratch)
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=stderr, pass_fds=pass_fds, close_fds=True, bufsize=0)
        except Exception:
            stderr.close()
            raise
        actor = {"label": label_, "proc": proc, "framed": inherit.Framed(proc.stdout.fileno()),
                 "finished": None, "private_stderr": stderr}
        self.actors.append(actor)
        return actor

    def finish(self, actor):
        try:
            return super().finish(actor)
        finally:
            handle = actor.get("private_stderr")
            if handle is not None:
                try:
                    if actor["proc"].poll() is None:
                        self.actor_diagnostics.append({"label": actor["label"], "complete": False})
                    else:
                        handle.seek(0)
                        data = handle.read(STDERR_KEEP + 1)
                        if data:
                            self.failures.append(f"{actor['label']}:stderr")
                            self.actor_diagnostics.append({"label": actor["label"], "complete": True,
                                "stderr": data[:STDERR_KEEP].decode("utf-8", "replace"),
                                "truncated": len(data) > STDERR_KEEP})
                finally:
                    handle.close()
                    actor["private_stderr"] = None


class Lab:
    def __init__(self, state, actor):
        self.state = state
        self.run = state.run
        self.actor = actor

    def fixture(self, name):
        self.state.created.add(f"{name}.lock")
        return inherit.fixture(self.run, name)

    def write_profile(self, name, text):
        self.state.created.add(name)
        path = str(self.run.scratch / name)
        write_private(path, text)
        return path

    def scan(self, path, prefix=()):
        result = inherit.run_diagnostic(self.run, [*prefix, inherit.LSOF, "-nP", "+fg", "-F0pfG", "--", path])
        return interpret_scan(result["status"], result["stdout"], result["stderr"], result["problems"])

    def one_shot(self, args, expected, prefix=(), timeout=inherit.DIAGNOSTIC_TIMEOUT):
        result = inherit.run_diagnostic(self.run, [*prefix, self.actor, *args], timeout=timeout)
        parsed = parse_one_shot(result, expected)
        if parsed["problems"] and "timeout" not in parsed["problems"]:
            self.run.failures.append(f"one_shot:{args[0]}:{','.join(parsed['problems'])}")
        return parsed

    def start(self, label_, args, prefix=()):
        return self.run.start(label_, [*prefix, self.actor, *args])

    def ready(self, actor, kind, **extra):
        event = self.run.read_event(actor, "ready")
        if event is None:
            return None
        if not check_event(event, "ready", pid=is_pid, kind=lambda v: v == kind, **extra):
            self.run.failures.append(f"{actor['label']}:ready_shape")
            return None
        if event["pid"] != actor["proc"].pid:
            self.run.failures.append(f"{actor['label']}:ready_pid")
            return None
        return event

    def lookup_service(self, entry, where):
        """Check that a registered bootstrap name is gone; record the outcome."""
        entry["where"] = where
        if self.actor is None:
            entry["status"] = "unconfirmed"
            return None
        event = self.one_shot(["lookup", entry["service"]], "lookup")["event"]
        if check_event(event, "lookup", kr=lambda v: v == BOOTSTRAP_UNKNOWN_SERVICE):
            entry["status"] = "removed"
        elif check_event(event, "lookup", kr=lambda v: v == 0):
            entry["status"] = "present"
        else:
            entry["status"] = "unconfirmed"
        return event

    def observe(self, path, stage, roles, fileports_for=None, view_hidden=None):
        scan = self.scan(path)
        probe = inherit.probe(path)
        states, fileport_states, unexpected = role_states(scan, roles)
        stage_record = {
            "stage": stage, "probe": probe, "roles": states, "fileport_roles": fileport_states,
            "unexpected_pids": unexpected, "scan_valid": scan["valid"], "scan_problems": scan["problems"],
            "decisions": {role: label(visibility_decision(probe, scan, pid)) for role, pid in roles.items()},
            "raw": scan,
        }
        if fileports_for:
            stage_record["fileports"] = {
                role: fileport_summary(self.one_shot(["listfileports", str(pid), path], "fileports")["event"])
                for role, pid in fileports_for.items()}
        if view_hidden is not None:
            hidden = {role: pid for role, pid in roles.items() if role in view_hidden}
            view = without_pids(scan, hidden.values())
            stage_record["view_hidden"] = sorted(hidden)
            stage_record["view_openers"] = sum(1 for v in view["pids"].values() if v)
            stage_record["view_decisions"] = {
                role: label(visibility_decision(probe, view, pid))
                for role, pid in roles.items() if role not in hidden}
        return stage_record


# Each scenario fills a record that is already registered in the result, and
# appends stages as it goes, so an exception keeps the earlier stages.

def scenario_fileport(lab, record):
    run = lab.run
    lock = lab.fixture("fileport")
    receiver = lab.start("fp_receiver", ["receiver", lock])
    r = lab.ready(receiver, "receiver", service=lambda v: isinstance(v, str) and bool(SERVICE.fullmatch(v)))
    record["ready"] = [r]
    if r:
        entry = {"service": r["service"], "status": "unchecked", "where": None}
        lab.state.services.append(entry)
    sender = lab.start("fp_sender", ["sender", lock])
    s = lab.ready(sender, "sender")
    record["ready"].append(s)
    if not r or not s:
        record["finish"] = [run.finish(sender), run.finish(receiver)]
        return
    roles = {"sender": s["pid"], "receiver": r["pid"]}
    events = record["events"] = {}
    stages = record["stages"]
    stages.append(lab.observe(lock, "sender_locked", roles, roles))
    events["sent"] = run.command(sender, "send " + r["service"], "sent")
    stages.append(lab.observe(lock, "port_in_transit", roles, roles))
    events["closed"] = run.command(sender, "close_own_fd", "closed")
    stages.append(lab.observe(lock, "sender_closed_in_transit", roles, roles))
    events["received"] = run.command(receiver, "receive", "received")
    events["self_report"] = run.command(receiver, "fileports", "fileports")
    stages.append(lab.observe(lock, "receiver_holds_port_only", roles, roles))
    events["made_fd"] = run.command(receiver, "makefd", "made_fd")
    stages.append(lab.observe(lock, "receiver_made_fd", roles, roles))
    record["finish"] = [run.finish(sender)]
    stages.append(lab.observe(lock, "sender_exited", roles))
    record["finish"].append(run.finish(receiver))
    stages.append(lab.observe(lock, "all_closed", {}))
    # Normal completion only; names left unchecked are looked up in `finally`.
    events["lookup_after_exit"] = lab.lookup_service(entry, "normal")


def scenario_hidden_scm(lab, record, hide):
    """SCM_RIGHTS sharing; `hide` is the sharer omitted from the model view."""
    run = lab.run
    lock = lab.fixture(f"hidden_scm_{hide}")
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        receiver = run.start_actor(f"hs_{hide}_receiver", ["scm_receiver", str(right.fileno())], (right.fileno(),))
        sender = run.start_actor(f"hs_{hide}_sender", ["scm_sender", lock, str(left.fileno())], (left.fileno(),))
    finally:
        left.close()
        right.close()
    sent = run.read_event(sender, "ready")
    received = run.read_event(receiver, "ready")
    record["ready"] = [sent, received]
    if not sent or not received or not is_pid(sent.get("pid")) or received.get("received") != 1:
        record["finish"] = [run.finish(sender), run.finish(receiver)]
        return
    roles = {"sender": sent["pid"], "receiver": received["pid"]}
    stages = record["stages"]
    stages.append(lab.observe(lock, "both_hold", roles, view_hidden={hide}))
    if hide == "receiver":
        record["released"] = {"closed": run.command(sender, "close_own_fd", "closed")}
    else:
        record["released"] = {"finish": run.finish(receiver)}
    stages.append(lab.observe(lock, "visible_released", roles, view_hidden={hide}))
    record["finish"] = [run.finish(sender), run.finish(receiver)]
    stages.append(lab.observe(lock, "all_closed", {}))


def scenario_hidden_fork(lab, record):
    run = lab.run
    lock = lab.fixture("hidden_fork")
    actor = run.start_actor("hf_parent", ["fork_shared", lock])
    ready = record["ready"] = run.read_event(actor, "ready")
    if not ready or not is_pid(ready.get("pid")) or not is_pid(ready.get("child_pid")):
        record["finish"] = run.finish(actor)
        return
    roles = {"parent": ready["pid"], "forked_child": ready["child_pid"]}
    stages = record["stages"]
    stages.append(lab.observe(lock, "both_hold", roles, view_hidden={"forked_child"}))
    record["released"] = {"closed": run.command(actor, "close_parent_fd", "closed")}
    stages.append(lab.observe(lock, "visible_released", roles, view_hidden={"forked_child"}))
    record["finish"] = run.finish(actor)
    stages.append(lab.observe(lock, "all_closed", {}))


def hidden_outcome(stages, visible):
    """release_incomplete_due_to_hidden_reference: the filter did not refuse
    the visible sharer, which really shares the locked description, and the
    lock stayed held after that sharer released without any signal, because
    a hidden sharer still references the same description. This is not a
    non-holding opener mistaken for the holder (see former_vs_opener)."""
    if len(stages) < 2:
        return None
    before = stages[0].get("view_decisions", {}).get(visible, "")
    after_probe = stages[1]["probe"]
    if before.startswith("not_excluded") and after_probe == "held":
        after = stages[1]
        roles = after.get("roles", {})
        if after.get("scan_valid") is True and type(after.get("unexpected_pids")) is int and after["unexpected_pids"] == 0 \
                and roles.get(visible) == "absent" and any(role != visible and value == "bit" for role, value in roles.items()):
            return HIDDEN_OUTCOME
        return "held_unattributed"
    if before.startswith(("reject", "unknown")):
        return "refused"
    return "released"


HIDDEN_VISIBLE = {"scm_hide_receiver": "sender", "scm_hide_sender": "receiver", "fork_hide_child": "parent"}


def scenario_hidden_sharer(lab, record):
    runners = {
        "scm_hide_receiver": lambda sub: scenario_hidden_scm(lab, sub, "receiver"),
        "scm_hide_sender": lambda sub: scenario_hidden_scm(lab, sub, "sender"),
        "fork_hide_child": lambda sub: scenario_hidden_fork(lab, sub),
    }
    for name, runner in runners.items():
        sub = record[name] = {"stages": []}
        try:
            runner(sub)
        except Exception as error:  # recorded; the next shape still runs
            lab.state.error(f"hidden_sharer/{name}", error)
        finally:
            sub["outcome"] = hidden_outcome(sub["stages"], HIDDEN_VISIBLE[name])


def sbpl_string(path):
    """An SBPL string literal; refuses characters that need more than escaping."""
    if any(ord(c) < 0x20 or ord(c) == 0x7f for c in path):
        raise ValueError("control character in sandbox profile path")
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'


def observer_profiles(actor):
    exec_allow = f"(allow process-exec (literal {sbpl_string(inherit.LSOF)}) (literal {sbpl_string(actor)}))"
    return {
        "allow_default": "(version 1)(allow default)",
        "deny_pidfdinfo": "(version 1)(allow default)(deny process-info-pidfdinfo)",
        "deny_pidfdinfo_others": "(version 1)(allow default)(deny process-info-pidfdinfo (target others))",
        "deny_process_info": "(version 1)(allow default)(deny process-info*)",
        "deny_default": f"(version 1)(deny default){exec_allow}(allow file-read*)(allow sysctl-read)(allow process-info*)",
    }


PROFILE_NAMES = tuple(observer_profiles("x"))
TARGET_NAMES = ("allow_default", "deny_default")


def target_profiles(actor, lock):
    return {
        "allow_default": "(version 1)(allow default)",
        "deny_default": (f"(version 1)(deny default)(allow process-exec (literal {sbpl_string(actor)}))"
                         f"(allow file-read*)(allow file-write* (literal {sbpl_string(lock)}))(allow sysctl-read)"),
    }


def write_private(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(text)


def sandbox_usable(run):
    """sandbox-exec present and able to apply a trivial profile unprivileged."""
    if not os.access(SANDBOX_EXEC, os.X_OK):
        return False, {"kind": "sandbox_missing", "detail": "sandbox-exec not present"}
    result = inherit.run_diagnostic(run, [SANDBOX_EXEC, "-p", "(version 1)(allow default)", "/usr/bin/true"])
    if result["status"] != 0 or result["stderr"] or result["problems"]:
        return False, {"kind": "sandbox_unusable",
                       "detail": f"status={result['status']} problems={result['problems']} "
                                 f"stderr={result['stderr'][:200].decode('utf-8', 'replace')}"}
    return True, None


def classify_profile(name, record, reference_decision):
    """control_pass / control_failed / restricted_unknown / unreduced / rule_violation."""
    if name == "allow_default":
        contract = {k: v for k, v in CONTROL_CONTRACT.items() if k != "classification"}
        return "control_pass" if not control_failures(record, contract) else "control_failed"
    if record.get("reduced") is True or record.get("canary_visible") is not True:
        return "restricted_unknown" if str(record.get("decision", "")).startswith("unknown:") else "rule_violation"
    return "unreduced" if record.get("decision") == reference_decision else "rule_violation"


def scenario_sandbox_observer(lab, record):
    run = lab.run
    lock = lab.fixture("sandbox_observer")
    canary_lock = lab.fixture("sandbox_canary")
    target = lab.start("so_target", ["holder", lock])
    canary = lab.start("so_canary", ["holder", canary_lock])
    t = lab.ready(target, "holder")
    c = lab.ready(canary, "holder")
    record["ready"] = [t, c]
    if not t or not c:
        record["finish"] = [run.finish(target), run.finish(canary)]
        return
    reference = lab.scan(lock)
    reference_canary = lab.scan(canary_lock)
    reference_probe = inherit.probe(lock)
    record["reference"] = {
        "probe": reference_probe, "scan_valid": reference["valid"],
        "decision": label(visibility_decision(reference_probe, reference, t["pid"])),
        "canary_visible": canary_visible(reference_canary, c["pid"]), "raw": reference}
    profiles = record["profiles"] = {}
    for name, text in observer_profiles(lab.actor).items():
        profile = lab.write_profile(f"observer-{name}.sb", text)
        prefix = (SANDBOX_EXEC, "-f", profile)
        canary_scan = lab.scan(canary_lock, prefix)
        scan = lab.scan(lock, prefix)
        probe_event = lab.one_shot(["probe", lock], "probe", prefix)["event"]
        probe = probe_event["result"] if check_event(probe_event, "probe", result=lambda v: isinstance(v, str)) \
            else "error:invalid"
        canary_ok = canary_visible(canary_scan, c["pid"])
        entry = profiles[name] = {
            "lsof_status": scan["status"], "lsof_stderr": scan["stderr"], "scan_valid": scan["valid"],
            "scan_problems": scan["problems"], "target_present": str(t["pid"]) in scan["pids"],
            "canary_status": canary_scan["status"], "canary_stderr": canary_scan["stderr"],
            "canary_visible": canary_ok, "probe": probe, "reduced": reduced(reference, scan),
            "decision": label(visibility_decision(probe, scan, t["pid"], canary_ok)),
            "decision_without_canary": label(visibility_decision(probe, scan, t["pid"])),
            "raw": scan, "raw_canary": canary_scan,
        }
        entry["classification"] = classify_profile(name, entry, record["reference"]["decision"])
    record["finish"] = [run.finish(target), run.finish(canary)]


def scenario_sandbox_target(lab, record):
    run = lab.run
    for name in TARGET_NAMES:
        sub = record[name] = {"stages": []}
        lock = lab.fixture(f"sandbox_target_{name}")
        profile = lab.write_profile(f"target-{name}.sb", target_profiles(lab.actor, lock)[name])
        holder = lab.start(f"st_{name}", ["holder", lock], (SANDBOX_EXEC, "-f", profile))
        ready = sub["ready"] = lab.ready(holder, "holder")
        if not ready:
            sub["finish"] = run.finish(holder)
            continue
        sub["stages"].append(lab.observe(lock, "sandboxed_holder", {"holder": ready["pid"]}))
        sub["finish"] = run.finish(holder)
        sub["stages"].append(lab.observe(lock, "all_closed", {}))


def scenario_former_vs_opener(lab, record):
    run = lab.run
    lock = lab.fixture("former_vs_opener")
    former = lab.start("fo_former", ["former", lock])
    f = lab.ready(former, "former")
    opener = lab.start("fo_opener", ["opener", lock])
    o = lab.ready(opener, "opener")
    record["ready"] = [f, o]
    if not f or not o:
        record["finish"] = [run.finish(former), run.finish(opener)]
        return
    roles = {"former": f["pid"], "opener": o["pid"]}
    stages = record["stages"]
    stages.append(lab.observe(lock, "no_holder", roles))
    holder = lab.start("fo_holder", ["holder", lock])
    h = lab.ready(holder, "holder")
    record["ready"].append(h)
    if not h:
        record["finish"] = [run.finish(former), run.finish(opener), run.finish(holder)]
        return
    roles["holder"] = h["pid"]
    stages.append(lab.observe(lock, "with_holder", roles, view_hidden={"holder"}))
    record["finish"] = [run.finish(holder), run.finish(former), run.finish(opener)]
    stages.append(lab.observe(lock, "all_closed", {}))


# ------------------------------------------------------- expected tables

N = "not_excluded:bit_present"
R = "reject:bit_absent_on_all"
U_ABSENT = "unknown:pid_absent"
U_HIDDEN = "unknown:held_without_visible_opener"
U_INVALID = "unknown:scan_invalid"
U_CANARY = "unknown:canary_not_visible"
FP0 = "count=0,matching=0,was_locked=0"
FP1 = "count=1,matching=1,was_locked=1"

# Per stage, every listed key must equal the observation; scan validity and
# zero unexpected PIDs are listed explicitly.
EXPECTED = {
    "fileport": [
        {"stage": "sender_locked", "probe": "held", "scan_valid": True,
         "roles": {"sender": "bit", "receiver": "absent"}, "fileport_roles": {},
         "decisions": {"sender": N, "receiver": U_ABSENT}, "fileports": {"sender": FP0, "receiver": FP0}},
        {"stage": "port_in_transit", "probe": "held", "scan_valid": True,
         "roles": {"sender": "bit", "receiver": "absent"}, "fileport_roles": {},
         "decisions": {"sender": N, "receiver": U_ABSENT}, "fileports": {"sender": FP0, "receiver": FP0}},
        {"stage": "sender_closed_in_transit", "probe": "held", "scan_valid": True,
         "roles": {"sender": "absent", "receiver": "absent"}, "fileport_roles": {},
         "decisions": {"sender": U_HIDDEN, "receiver": U_HIDDEN}, "fileports": {"sender": FP0, "receiver": FP0}},
        {"stage": "receiver_holds_port_only", "probe": "held", "scan_valid": False,
         "roles": {"sender": "absent", "receiver": "absent"}, "fileport_roles": {"receiver": "bit"},
         "decisions": {"sender": U_INVALID, "receiver": U_INVALID}, "fileports": {"sender": FP0, "receiver": FP1}},
        {"stage": "receiver_made_fd", "probe": "held", "scan_valid": True,
         "roles": {"sender": "absent", "receiver": "bit"}, "fileport_roles": {},
         "decisions": {"sender": U_ABSENT, "receiver": N}, "fileports": {"sender": FP0, "receiver": FP0}},
        {"stage": "sender_exited", "probe": "held", "scan_valid": True,
         "roles": {"sender": "absent", "receiver": "bit"}, "decisions": {"sender": U_ABSENT, "receiver": N}},
        {"stage": "all_closed", "probe": "free", "scan_valid": True, "roles": {}, "decisions": {}},
    ],
    "hidden_sharer/scm_hide_receiver": [
        {"stage": "both_hold", "probe": "held", "scan_valid": True, "roles": {"sender": "bit", "receiver": "bit"},
         "view_openers": 1, "view_decisions": {"sender": N}},
        {"stage": "visible_released", "probe": "held", "scan_valid": True,
         "roles": {"sender": "absent", "receiver": "bit"}, "view_openers": 0, "view_decisions": {"sender": U_HIDDEN}},
        {"stage": "all_closed", "probe": "free", "scan_valid": True, "roles": {}},
    ],
    "hidden_sharer/scm_hide_sender": [
        {"stage": "both_hold", "probe": "held", "scan_valid": True, "roles": {"sender": "bit", "receiver": "bit"},
         "view_openers": 1, "view_decisions": {"receiver": N}},
        {"stage": "visible_released", "probe": "held", "scan_valid": True,
         "roles": {"sender": "bit", "receiver": "absent"}, "view_openers": 0, "view_decisions": {"receiver": U_HIDDEN}},
        {"stage": "all_closed", "probe": "free", "scan_valid": True, "roles": {}},
    ],
    "hidden_sharer/fork_hide_child": [
        {"stage": "both_hold", "probe": "held", "scan_valid": True,
         "roles": {"parent": "bit", "forked_child": "bit"}, "view_openers": 1, "view_decisions": {"parent": N}},
        {"stage": "visible_released", "probe": "held", "scan_valid": True,
         "roles": {"parent": "absent", "forked_child": "bit"}, "view_openers": 0, "view_decisions": {"parent": U_HIDDEN}},
        {"stage": "all_closed", "probe": "free", "scan_valid": True, "roles": {}},
    ],
    "sandbox_target/allow_default": [
        {"stage": "sandboxed_holder", "probe": "held", "scan_valid": True, "roles": {"holder": "bit"},
         "decisions": {"holder": N}},
        {"stage": "all_closed", "probe": "free", "scan_valid": True, "roles": {}},
    ],
    "sandbox_target/deny_default": [
        {"stage": "sandboxed_holder", "probe": "held", "scan_valid": True, "roles": {"holder": "bit"},
         "decisions": {"holder": N}},
        {"stage": "all_closed", "probe": "free", "scan_valid": True, "roles": {}},
    ],
    "former_vs_opener": [
        {"stage": "no_holder", "probe": "free", "scan_valid": True, "roles": {"former": "bit", "opener": "no_bit"},
         "decisions": {"former": N, "opener": R}},
        {"stage": "with_holder", "probe": "held", "scan_valid": True,
         "roles": {"former": "bit", "opener": "no_bit", "holder": "bit"},
         "decisions": {"former": N, "opener": R, "holder": N},
         "view_openers": 2, "view_decisions": {"former": N, "opener": R}},
        {"stage": "all_closed", "probe": "free", "scan_valid": True, "roles": {}},
    ],
}

# The positive control is a full contract, not just "not reduced". A failed
# control is never a measurement success, whatever the restricted rows say.
CONTROL_CONTRACT = {"reduced": False, "canary_visible": True, "probe": "held", "decision": N,
                    "decision_without_canary": N, "scan_valid": True, "target_present": True,
                    "lsof_status": 0, "lsof_stderr": "", "classification": "control_pass"}
REFERENCE_CONTRACT = {"probe": "held", "decision": N, "canary_visible": True, "scan_valid": True}
RESTRICTED_FIELDS = {"reduced": bool, "canary_visible": bool, "scan_valid": bool, "probe": str,
                     "decision": str, "decision_without_canary": str, "classification": str}
MISSING = object()


def control_failures(record, contract):
    """Fields of a record that do not match a contract exactly (type and value)."""
    if not isinstance(record, dict):
        return sorted(contract)
    out = []
    for key, want in contract.items():
        got = record.get(key, MISSING)
        if got is MISSING or type(got) is not type(want) or got != want:
            out.append(key)
    return out


def stage_mismatches(where, stages, expected):
    if not stages:
        return [f"{where}:no_stages"]
    if [s.get("stage") for s in stages] != [e["stage"] for e in expected]:
        return [f"{where}:stage_list"]
    out = []
    for stage, want in zip(stages, expected):
        at = f"{where}/{want['stage']}"
        if type(stage.get("unexpected_pids")) is not int or stage["unexpected_pids"] != 0:
            out.append(f"{at}:unexpected_pids")
        if where == "fileport" and want["stage"] == "receiver_holds_port_only":
            problems = stage.get("scan_problems")
            if not isinstance(problems, list) or "fileport_record" not in problems or any(
                    not isinstance(p, str) or (p != "fileport_record" and re.fullmatch(r"(?:record:[0-9]+:fG|pid_without_fd:[0-9]+)", p) is None)
                    for p in problems):
                out.append(f"{at}:scan_problems")
        for key, value in want.items():
            if stage.get(key) != value:
                out.append(f"{at}:{key}")
    return out


def finish_ok(finish, events=()):
    return isinstance(finish, dict) and finish.get("exit") == 0 and finish.get("events") == list(events)


def sandbox_rule_mismatches(result):
    """Control and reference contracts, then rules for restricted profiles:
    reduced or canary-missing views are unknown; unreduced views keep the
    reference decision."""
    out = []
    reference = result.get("reference")
    for key in control_failures(reference, REFERENCE_CONTRACT):
        out.append(f"sandbox_observer:reference_failed:{key}")
    reference_decision = (reference or {}).get("decision")
    profiles = result.get("profiles") or {}
    if not isinstance(profiles, dict) or set(profiles) != set(PROFILE_NAMES):
        out.append("sandbox_observer:profile_set")
        profiles = profiles if isinstance(profiles, dict) else {}
    if "allow_default" not in profiles:
        out.append("sandbox_observer/allow_default:control_failed:missing")
    for name, record in profiles.items():
        at = f"sandbox_observer/{name}"
        if name not in PROFILE_NAMES:
            continue
        if name == "allow_default":
            for key in control_failures(record, CONTROL_CONTRACT):
                out.append(f"{at}:control_failed:{key}")
            continue
        if not isinstance(record, dict):
            out.append(f"{at}:missing_field:record")
            continue
        missing = [k for k, kind in RESTRICTED_FIELDS.items() if type(record.get(k, MISSING)) is not kind]
        for key in missing:
            out.append(f"{at}:missing_field:{key}")
        if missing:
            continue
        if record["probe"] != "held":
            out.append(f"{at}:probe_not_held")
        decision = record["decision"]
        if decision.split(":", 1)[0] not in DECISIONS:
            out.append(f"{at}:vocabulary")
        if record["reduced"] or not record["canary_visible"]:
            if not decision.startswith("unknown:"):
                out.append(f"{at}:reduced_not_unknown")
            if record["probe"] == "held" and not record["decision_without_canary"].startswith("unknown:"):
                out.append(f"{at}:reduced_without_canary_not_unknown")
        elif decision != reference_decision or record["decision_without_canary"] != reference_decision:
            out.append(f"{at}:unreduced_decision_changed")
        if record["classification"] != classify_profile(name, record, reference_decision):
            out.append(f"{at}:classification")
    if not isinstance(result.get("finish"), list) or len(result["finish"]) != 2 or not all(finish_ok(f) for f in result["finish"]):
        out.append("sandbox_observer:finish")
    return out


def evaluate(scenarios, not_executed, services=()):
    mismatches = []
    if set(scenarios) - set(SCENARIOS) or set(not_executed) - set(SCENARIOS):
        mismatches.append("scenario_set")
    fileport = scenarios.get("fileport")
    if fileport is not None:
        mismatches += stage_mismatches("fileport", fileport.get("stages"), EXPECTED["fileport"])
        events = fileport.get("events") or {}
        if not check_event(events.get("sent"), "sent", kr=lambda v: v == 0):
            mismatches.append("fileport:sent")
        if not check_event(events.get("closed"), "closed", who=lambda v: v == "sender"):
            mismatches.append("fileport:closed")
        if not check_event(events.get("received"), "received", ports=lambda v: v == 1):
            mismatches.append("fileport:received")
        if fileport_summary(events.get("self_report")) != FP1:
            mismatches.append("fileport:self_report")
        if not check_event(events.get("made_fd"), "made_fd", matches=lambda v: v is True,
                           port_released=lambda v: v is True):
            mismatches.append("fileport:made_fd")
        if not check_event(events.get("lookup_after_exit"), "lookup", kr=lambda v: v == BOOTSTRAP_UNKNOWN_SERVICE):
            mismatches.append("fileport:service_not_removed")
        finishes = fileport.get("finish")
        if not isinstance(finishes, list) or len(finishes) != 2 or not all(finish_ok(f) for f in finishes):
            mismatches.append("fileport:finish")
    elif "fileport" not in not_executed:
        mismatches.append("fileport:missing")
    for entry in services:
        if entry.get("status") != "removed":
            mismatches.append(f"bootstrap_name:{'present' if entry.get('status') == 'present' else 'unconfirmed'}")
    hidden = scenarios.get("hidden_sharer")
    if hidden is None:
        mismatches.append("hidden_sharer:missing")
    else:
        if set(hidden) != set(HIDDEN_VISIBLE):
            mismatches.append("hidden_sharer:case_set")
        for name in HIDDEN_VISIBLE:
            result = hidden.get(name) or {}
            mismatches += stage_mismatches(f"hidden_sharer/{name}", result.get("stages"),
                                           EXPECTED[f"hidden_sharer/{name}"])
            if result.get("outcome") != HIDDEN_OUTCOME:
                mismatches.append(f"hidden_sharer/{name}:outcome")
            finish = result.get("finish")
            if name == "fork_hide_child":
                if not finish_ok(finish, [{"code": 0, "event": "child_exit"}]):
                    mismatches.append(f"hidden_sharer/{name}:finish")
            elif not isinstance(finish, list) or len(finish) != 2 or not all(finish_ok(f) for f in finish):
                mismatches.append(f"hidden_sharer/{name}:finish")
    for name in ("sandbox_observer", "sandbox_target", "former_vs_opener"):
        if scenarios.get(name) is None and name not in not_executed:
            mismatches.append(f"{name}:missing")
    if scenarios.get("sandbox_observer") is not None:
        mismatches += sandbox_rule_mismatches(scenarios["sandbox_observer"])
    if scenarios.get("sandbox_target") is not None:
        if set(scenarios["sandbox_target"]) != set(TARGET_NAMES):
            mismatches.append("sandbox_target:case_set")
        for name in TARGET_NAMES:
            result = scenarios["sandbox_target"].get(name) or {}
            mismatches += stage_mismatches(f"sandbox_target/{name}", result.get("stages"),
                                           EXPECTED[f"sandbox_target/{name}"])
            if not finish_ok(result.get("finish")):
                mismatches.append(f"sandbox_target/{name}:finish")
    if scenarios.get("former_vs_opener") is not None:
        result = scenarios["former_vs_opener"]
        mismatches += stage_mismatches("former_vs_opener", result.get("stages"), EXPECTED["former_vs_opener"])
        finishes = result.get("finish")
        if not isinstance(finishes, list) or len(finishes) != 3 or not all(finish_ok(f) for f in finishes):
            mismatches.append("former_vs_opener:finish")
    return mismatches


# ------------------------------------------------------- public summary

SCENARIOS = ("fileport", "hidden_sharer", "sandbox_observer", "sandbox_target", "former_vs_opener")
STAGES = {e["stage"] for table in EXPECTED.values() for e in table}
ROLES = {r for table in EXPECTED.values() for e in table for k in ("roles", "decisions", "view_decisions",
                                                                    "fileports", "fileport_roles")
         for r in e.get(k, {})}
STATES = {"bit", "no_bit", "absent"}
ERRNO_NAMES = {"EWOULDBLOCK", "EPERM", "EACCES", "ENOENT", "EBADF", "ELOOP", "ESRCH", "EINVAL", "other"}
ACTOR_LABELS = {"fp_receiver", "fp_sender", "hf_parent", "so_target", "so_canary", "fo_former", "fo_opener",
                "fo_holder", "one_shot", "diagnostic_timeout", "diagnostic_exit_wait"} | \
    {f"hs_{h}_{r}" for h in ("receiver", "sender") for r in ("receiver", "sender")} | \
    {f"st_{n}" for n in TARGET_NAMES}
EVENT_KINDS = {"eof", "unterminated", "limit", "timeout", "malformed_event", "unexpected_event", "output_limit",
               "exit", "exit_wait", "output_wait", "output_unterminated", "finish_error", "finish_unconfirmed",
               "no_event", "ready_shape", "ready_pid", "lsof", "clang", "sandbox-exec", "mount", ACTOR_NAME,
               "probe", "listfileports", "lookup", "makeports"}
ERROR_KINDS = {"OSError", "FileExistsError", "FileNotFoundError", "PermissionError", "IsADirectoryError",
               "NotADirectoryError", "BrokenPipeError", "TimeoutError", "ValueError", "KeyError", "TypeError",
               "IndexError", "AttributeError", "RuntimeError", "UnicodeDecodeError", "JSONDecodeError"}
ERROR_WHERE = set(SCENARIOS) | {f"hidden_sharer/{n}" for n in HIDDEN_VISIBLE} | \
    {"build", "environment", "source_hashes", "bootstrap", "cleanup", "summary", "main"}
NOT_EXECUTED_KINDS = {"clang_missing", "compile_failed", "sandbox_missing", "sandbox_unusable"}
CLEANUP_STATUS = {"removed", "preserved", "failed"}
CLEANUP_REASONS = {"measurement_not_ok", "pending_diagnostics", "open_failed", "identity_mismatch",
                   "identity_changed", "unexpected_entries", "unlink_failed", "rmdir_failed", "listing_failed",
                   "exception", None}
SERVICE_STATUS = {"removed", "present", "unconfirmed", "unchecked"}
MISMATCH_TOKENS = set(SCENARIOS) | STAGES | set(PROFILE_NAMES) | set(HIDDEN_VISIBLE) | set(TARGET_NAMES) | \
    {k for table in EXPECTED.values() for e in table for k in e} | set(CONTROL_CONTRACT) | \
    set(REFERENCE_CONTRACT) | set(RESTRICTED_FIELDS) | {
        "no_stages", "stage_list", "unexpected_pids", "sent", "closed", "received", "self_report", "made_fd",
        "service_not_removed", "finish", "missing", "outcome", "reference_failed", "control_failed",
        "profile_set", "vocabulary", "reduced_not_unknown", "reduced_without_canary_not_unknown",
        "unreduced_decision_changed", "missing_field", "record", "source_identity", "changed_or_unavailable",
        "bootstrap_name", "present", "unconfirmed", "scenario_set", "case_set", "probe_not_held"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
FILEPORT_VALUE = re.compile(r"^count=[0-9]{1,3},matching=[0-9]{1,3},was_locked=[0-9]{1,3}$")
PUBLIC_ENV = {"release": re.compile(r"^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$"),
              "mac_ver": re.compile(r"^[0-9]{1,3}(\.[0-9]{1,3}){0,2}$"),
              "python": re.compile(r"^[0-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2}([abrc]{1,2}[0-9]{1,2})?$"),
              "lsof": re.compile(r"^revision: [0-9]{1,2}\.[0-9]{1,3}(\.[0-9]{1,3})?$")}
MACHINES = {"arm64", "x86_64"}
FILESYSTEMS = {"apfs", "hfs", "msdos", "exfat", "smbfs", "nfs", "afpfs", "macfuse", "unknown"}
CLANG_LINE = re.compile(r"^Apple clang version [0-9.]{1,20} \(clang-[0-9.]{1,20}\)$")


def pick(value, allowed):
    return value if isinstance(value, str) and value in allowed else "other"


def public_probe(value):
    if value in ("held", "free", "error:invalid"):
        return value
    if isinstance(value, str):
        parts = value.split(":")
        if len(parts) == 3 and parts[0] == "error" and parts[1] in ("open", "flock") and parts[2] in ERRNO_NAMES:
            return value
    return "other"


def public_decision(value):
    if isinstance(value, str) and value.count(":") == 1:
        decision, reason = value.split(":")
        if decision in DECISIONS and reason in REASONS:
            return value
    return "other"


def public_fileport(value):
    if isinstance(value, str) and (FILEPORT_VALUE.fullmatch(value) or value == "invalid"
                                   or (value.startswith("error:") and value[6:] in FILEPORT_ERRORS | {"other"})):
        return value
    return "other"


def public_map(value, convert):
    if not isinstance(value, dict):
        return "other"
    return {pick(k, ROLES): convert(v) for k, v in value.items()}


def public_stage(stage):
    out = {"stage": pick(stage.get("stage"), STAGES) if isinstance(stage, dict) else "other"}
    if not isinstance(stage, dict):
        return out
    out["probe"] = public_probe(stage.get("probe"))
    out["scan_valid"] = stage.get("scan_valid") if isinstance(stage.get("scan_valid"), bool) else "other"
    out["roles"] = public_map(stage.get("roles"), lambda v: pick(v, STATES))
    for key, convert in (("fileport_roles", lambda v: pick(v, STATES)), ("decisions", public_decision),
                         ("view_decisions", public_decision), ("fileports", public_fileport)):
        if key in stage:
            out[key] = public_map(stage[key], convert)
    if "view_openers" in stage:
        out["view_openers"] = stage["view_openers"] if is_count(stage["view_openers"]) and \
            stage["view_openers"] < 100 else "other"
    return out


def public_kind(text, first_allowed, second_allowed):
    parts = text.split(":") if isinstance(text, str) else []
    first = pick(parts[0], first_allowed) if parts else "other"
    second = pick(parts[1], second_allowed) if len(parts) > 1 else "none"
    return f"{first}:{second}"


def counts(items):
    out = {}
    for item in items:
        out[item] = out.get(item, 0) + 1
    return dict(sorted(out.items()))


def public_mismatch(text):
    tokens = re.split(r"[:/]", text) if isinstance(text, str) else [None]
    return text if all(t in MISMATCH_TOKENS for t in tokens) else "other"


def public_hashes(value):
    if not isinstance(value, dict):
        return "other"
    names = ("visibility.py", "inherit.py", "fileport_actor.c")
    return {n: value[n] if isinstance(value.get(n), str) and HEX64.fullmatch(value[n]) else "other"
            for n in names if n in value}


def public_summary_unchecked(raw):
    scenarios = raw.get("scenarios") or {}
    stages = {}
    for name in SCENARIOS:
        scenario = scenarios.get(name)
        if not isinstance(scenario, dict):
            continue
        if name in ("hidden_sharer", "sandbox_target"):
            parts = {sub: scenario.get(sub) for sub in (HIDDEN_VISIBLE if name == "hidden_sharer" else TARGET_NAMES)}
        elif name == "sandbox_observer":
            parts = {}
        else:
            parts = {name: scenario}
        for sub, part in parts.items():
            if not isinstance(part, dict):
                continue
            stages[f"{name}/{sub}"] = [public_stage(s) for s in part.get("stages") or [] if isinstance(s, dict)]
            if "outcome" in part:
                stages[f"{name}/{sub}/outcome"] = pick(part["outcome"], {HIDDEN_OUTCOME, "refused", "released", "held_unattributed"})
    profiles = {}
    observer = scenarios.get("sandbox_observer")
    if isinstance(observer, dict) and isinstance(observer.get("profiles"), dict):
        for name, record in observer["profiles"].items():
            if name not in PROFILE_NAMES or not isinstance(record, dict):
                continue
            status = record.get("lsof_status")
            profiles[name] = {
                "lsof_status": status if status is None or (is_count(status) and status < 256) else "other",
                "lsof_stderr_present": bool(record.get("lsof_stderr")),
                "scan_valid": record.get("scan_valid") if isinstance(record.get("scan_valid"), bool) else "other",
                "target_present": record.get("target_present") if isinstance(record.get("target_present"), bool)
                else "other",
                "canary_visible": record.get("canary_visible") if isinstance(record.get("canary_visible"), bool)
                else "other",
                "reduced": record.get("reduced") if isinstance(record.get("reduced"), bool) else "other",
                "probe": public_probe(record.get("probe")),
                "decision": public_decision(record.get("decision")),
                "decision_without_canary": public_decision(record.get("decision_without_canary")),
                "classification": pick(record.get("classification"),
                                       {"control_pass", "control_failed", "restricted_unknown", "unreduced",
                                        "rule_violation"}),
            }
    environment = raw.get("environment") or {}
    public_env = {key: environment.get(key) if isinstance(environment.get(key), str) and
                  pattern.fullmatch(environment[key]) else "other" for key, pattern in PUBLIC_ENV.items()}
    public_env["machine"] = pick(environment.get("machine"), MACHINES)
    public_env["filesystem"] = pick(environment.get("filesystem"), FILESYSTEMS)
    build = raw.get("build") or {}
    clang = build.get("clang")
    cleanup = raw.get("cleanup") or {}
    not_executed = raw.get("not_executed") or {}
    services = raw.get("bootstrap_names") or []
    mismatches = [public_mismatch(m) for m in raw.get("mismatches") or []]
    bools = {k: raw.get(k) if isinstance(raw.get(k), bool) else "other"
             for k in ("ok", "run_ok", "measurement_ok", "collected", "measured")}
    return {
        **bools,
        "not_executed": {pick(k, set(SCENARIOS)): pick((v or {}).get("kind") if isinstance(v, dict) else None,
                                                       NOT_EXECUTED_KINDS) for k, v in not_executed.items()},
        "failure_kinds": counts(public_kind(f, ACTOR_LABELS, EVENT_KINDS) for f in raw.get("failures") or []),
        "incomplete_kinds": counts(public_kind(f, ACTOR_LABELS, EVENT_KINDS) for f in raw.get("incomplete") or []),
        "error_kinds": counts(f"{pick(e.get('where'), ERROR_WHERE)}:{pick(e.get('kind'), ERROR_KINDS)}"
                              if isinstance(e, dict) else "other:other" for e in raw.get("errors") or []),
        "pending_diagnostics": len(raw.get("pending_diagnostics") or []),
        "mismatches": sorted(m for m in mismatches if m != "other"),
        "unlisted_mismatches": mismatches.count("other"),
        "bootstrap_names": counts(pick(s.get("status") if isinstance(s, dict) else None, SERVICE_STATUS)
                                  for s in services),
        "cleanup": {"status": pick(cleanup.get("status"), CLEANUP_STATUS),
                    "reason": cleanup.get("reason") if cleanup.get("reason") in CLEANUP_REASONS else "other"},
        "source_identity": {
            "unchanged": (raw.get("source_identity") or {}).get("unchanged") is True,
            "start": public_hashes((raw.get("source_identity") or {}).get("start")),
            "end": public_hashes((raw.get("source_identity") or {}).get("end"))},
        "binary_sha256": build.get("binary_sha256") if isinstance(build.get("binary_sha256"), str) and
        HEX64.fullmatch(build["binary_sha256"]) else None,
        "clang": clang[0] if isinstance(clang, list) and len(clang) == 1 and isinstance(clang[0], str) and
        CLANG_LINE.fullmatch(clang[0]) else "other",
        "environment": public_env,
        "stages": stages,
        "sandbox_observer_profiles": profiles,
    }


def public_summary(raw):
    """Allowlisted, path-, PID-, service- and stderr-free summary of a raw result."""
    try:
        if not isinstance(raw, dict):
            raise TypeError("raw result is not an object")
        return public_summary_unchecked(raw)
    except Exception as error:  # never echo the raw text
        return {"ok": False, "summary_error": pick(type(error).__name__, ERROR_KINDS)}


# ------------------------------------------------------------- results

def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_hashes():
    return {"visibility.py": sha256_file(SCRIPT), "inherit.py": sha256_file(inherit.SCRIPT),
            "fileport_actor.c": sha256_file(ACTOR_SOURCE)}


def build_actor(run, out_dir, created=None):
    """Compile the C actor into the scratch directory, or say why not."""
    if not os.access(CLANG, os.X_OK):
        return None, {"kind": "clang_missing", "detail": "clang not present"}
    version = inherit.run_diagnostic(run, [CLANG, "--version"])
    binary = str(Path(out_dir) / ACTOR_NAME)
    if created is not None:
        created.add(ACTOR_NAME)
    result = inherit.run_diagnostic(run, [CLANG, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1",
                                          "-o", binary, ACTOR_SOURCE], timeout=COMPILE_TIMEOUT)
    info = {"clang": version["stdout"].decode("utf-8", "replace").splitlines()[:1],
            "status": result["status"], "problems": result["problems"],
            "stderr": result["stderr"][:STDERR_KEEP].decode("utf-8", "replace")}
    if result["status"] != 0 or result["problems"] or not os.path.isfile(binary):
        info["kind"] = "compile_failed"
        info["detail"] = f"status={result['status']} problems={result['problems']}"
        return None, info
    info["binary_sha256"] = sha256_file(binary)
    return binary, info


def cleanup_scratch(scratch, identity, created, unlink=os.unlink, rmdir=os.rmdir):
    """Remove only names this run created, relative to verified directory FDs.

    The scratch directory must still be the one created (device and inode,
    checked through an O_NOFOLLOW directory FD and again through its parent
    before rmdir) and must contain only registered names. Anything else is
    preserved. The checks narrow, but do not close, every path race.
    """
    record = {"status": "preserved", "reason": None, "detail": None, "removed": 0}
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    scratch = Path(scratch)
    try:
        parent_fd = os.open(scratch.parent, flags)
    except OSError as error:
        record.update(reason="open_failed", detail=str(error))
        return record
    try:
        try:
            fd = os.open(scratch.name, flags, dir_fd=parent_fd)
        except OSError as error:
            record.update(reason="open_failed", detail=str(error))
            return record
        try:
            st = os.fstat(fd)
            if (st.st_dev, st.st_ino) != tuple(identity):
                record.update(reason="identity_mismatch")
                return record
            try:
                entries = set(os.listdir(fd))
            except OSError as error:
                record.update(reason="listing_failed", detail=str(error))
                return record
            unexpected = entries - set(created)
            if unexpected:
                record.update(reason="unexpected_entries", detail=sorted(unexpected))
                return record
            for name in sorted(entries):
                try:
                    unlink(name, dir_fd=fd)
                except OSError as error:
                    record.update(status="failed", reason="unlink_failed", detail=f"{name}: {error}")
                    return record
                record["removed"] += 1
        finally:
            os.close(fd)
        st = os.stat(scratch.name, dir_fd=parent_fd, follow_symlinks=False)
        if (st.st_dev, st.st_ino) != tuple(identity):
            record.update(reason="identity_changed")
            return record
        try:
            rmdir(scratch.name, dir_fd=parent_fd)
        except OSError as error:
            record.update(status="failed", reason="rmdir_failed", detail=str(error))
            return record
        record.update(status="removed")
        return record
    finally:
        os.close(parent_fd)


def finalize(result_fd, result, scratch, identity, created, pending, unlink=os.unlink, rmdir=os.rmdir):
    """Settle cleanup, then write the record (always). Returns the exit code."""
    measurement_ok = bool(result.get("collected")) and bool(result.get("measured")) and \
        not result.get("not_executed")
    result["measurement_ok"] = measurement_ok
    if not measurement_ok:
        cleanup = {"status": "preserved", "reason": "measurement_not_ok", "detail": None, "removed": 0}
    elif pending:
        cleanup = {"status": "preserved", "reason": "pending_diagnostics", "detail": None, "removed": 0}
    else:
        try:
            cleanup = cleanup_scratch(scratch, identity, created, unlink, rmdir)
        except Exception as error:  # recorded; the record is still written
            cleanup = {"status": "failed", "reason": "exception", "detail": f"{type(error).__name__}: {error}",
                       "removed": None}
            result.setdefault("errors", []).append({"where": "cleanup", "kind": type(error).__name__,
                                                    "detail": str(error)})
    result["cleanup"] = cleanup
    result["run_ok"] = result["ok"] = measurement_ok and cleanup["status"] == "removed"
    with os.fdopen(result_fd, "w") as handle:
        handle.write(json.dumps(result, indent=2, sort_keys=True, default=str))
    return 0 if result["run_ok"] else 1


def measure(args):
    if platform.system() != "Darwin":
        raise SystemExit("macOS only: fileports, FWASLOCKED and lsof +fg are XNU-specific")
    result_fd = inherit.open_result(args.result)
    scratch = None
    try:
        scratch = Path(tempfile.mkdtemp(prefix="codex-127v-fixture-", dir=args.scratch_root))
        scratch.chmod(0o700)
        created_stat = os.lstat(scratch)
    except Exception as error:
        result = {"collected": False, "measured": False, "measurement_ok": False, "run_ok": False, "ok": False,
                  "errors": [{"where": "main", "kind": type(error).__name__, "detail": str(error)}],
                  "scratch": str(scratch) if scratch is not None else None,
                  "cleanup": {"status": "preserved", "reason": "measurement_not_ok", "removed": 0}}
        with os.fdopen(result_fd, "w") as handle:
            json.dump(result, handle)
        print(json.dumps(public_summary(result), sort_keys=True))
        return 2
    identity = (created_stat.st_dev, created_stat.st_ino)
    run = PrivateRun(scratch)
    state = State(run)
    build, environment = {}, {}
    start_hashes = None
    lab = Lab(state, None)
    try:
        start_hashes = source_hashes()
    except Exception as error:
        state.error("source_hashes", error)
    try:
        actor, build = build_actor(run, scratch, state.created)
        lab.actor = actor
    except Exception as error:
        state.error("build", error)
        actor, build = None, {"kind": "compile_failed", "detail": f"{type(error).__name__}"}

    def scenario(name, function):
        record = state.scenarios[name] = {} if name == "sandbox_target" else {"stages": []}
        try:
            function(lab, record)
        except Exception as error:  # recorded, then reported nonzero
            state.error(name, error)

    try:
        if actor is None:
            for name in ("fileport", "sandbox_observer", "sandbox_target", "former_vs_opener"):
                state.not_executed[name] = {"kind": build.get("kind", "compile_failed"),
                                            "detail": build.get("detail")}
        else:
            scenario("fileport", scenario_fileport)
        state.scenarios["hidden_sharer"] = {}
        try:
            scenario_hidden_sharer(lab, state.scenarios["hidden_sharer"])
        except Exception as error:
            state.error("hidden_sharer", error)
        if actor is not None:
            try:
                usable, why = sandbox_usable(run)
            except Exception as error:
                state.error("sandbox_observer", error)
                usable, why = False, {"kind": "sandbox_unusable", "detail": type(error).__name__}
            if usable:
                scenario("sandbox_observer", scenario_sandbox_observer)
                scenario("sandbox_target", scenario_sandbox_target)
            else:
                state.not_executed["sandbox_observer"] = state.not_executed["sandbox_target"] = why
            scenario("former_vs_opener", scenario_former_vs_opener)
    finally:
        run.finish_all()
        # Names a scenario registered but did not check (for example after an
        # exception) are looked up here; failures stay unconfirmed.
        for entry in state.services:
            if entry["status"] == "unchecked":
                try:
                    lab.lookup_service(entry, "finally")
                except Exception as error:
                    entry["status"] = "unconfirmed"
                    state.error("bootstrap", error)
    try:
        version = inherit.run_diagnostic(run, [inherit.LSOF, "-v"])
        environment = {
            # Hostname deliberately omitted.
            "system": platform.system(), "release": platform.release(), "machine": platform.machine(),
            "mac_ver": platform.mac_ver()[0], "python": platform.python_version(),
            "lsof": next((l.strip() for l in version["stderr"].decode("utf-8", "replace").splitlines()
                          if "revision:" in l and "latest" not in l), None),
            "filesystem": inherit.filesystem_of(run, scratch),
        }
    except Exception as error:
        state.error("environment", error)
    try:
        mismatches = evaluate(state.scenarios, state.not_executed, state.services)
    except Exception as error:
        state.error("summary", error)
        mismatches = ["scenario_set"]
    end_hashes = None
    try:
        end_hashes = source_hashes()
    except Exception as error:
        state.error("source_hashes", error)
    unchanged = start_hashes is not None and start_hashes == end_hashes
    if not unchanged:
        mismatches.append("source_identity:changed_or_unavailable")
    pending = run.poll_pending()
    collected = not run.failures and not run.incomplete and not state.errors
    result = {
        "collected": collected, "measured": not mismatches, "not_executed": state.not_executed,
        "failures": run.failures, "incomplete": run.incomplete, "errors": state.errors,
        "mismatches": mismatches, "pending_diagnostics": pending, "bootstrap_names": state.services,
        "signals_sent_by_script": "none: no kill calls and no killing timeouts; see module docstring",
        "script_sha256": (end_hashes or {}).get("visibility.py"),
        "source_identity": {"start": start_hashes, "end": end_hashes, "unchanged": unchanged},
        "build": build, "environment": environment, "scenarios": state.scenarios,
        "scratch_identity": list(identity),
        "actor_diagnostics": run.actor_diagnostics,
    }
    code = finalize(result_fd, result, scratch, identity, state.created, pending)
    print(json.dumps(public_summary(result), indent=1, sort_keys=True))
    return code


def summarize(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as handle:
        raw = json.loads(handle.read(64 << 20))
    print(json.dumps(public_summary(raw), indent=1, sort_keys=True))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--scratch-root", help="existing directory; a private child is created")
    parser.add_argument("--result", help="new JSON result path, outside the scratch directory")
    parser.add_argument("--summarize", help="print the public summary of an existing raw result")
    args = parser.parse_args(argv)
    if bool(args.summarize) == bool(args.scratch_root or args.result) or \
            (not args.summarize and not (args.scratch_root and args.result)):
        parser.error("use --summarize RAW, or --scratch-root DIR --result NEW")
    try:
        return summarize(args.summarize) if args.summarize else measure(args)
    except SystemExit:
        raise
    except Exception as error:  # no traceback: it could carry private paths
        print(json.dumps({"ok": False, "fatal": pick(type(error).__name__, ERROR_KINDS)}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
