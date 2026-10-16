#!/usr/bin/env python3
"""#127 research: macOS open-file-description sharing and FWASLOCKED.

Same-user synthetic fixtures only. Never targets a Codex process or home.
Every actor is started by this script and registered before use. Actors close
their descriptors on stdin EOF (the forked child on its control pipe's EOF)
and end themselves with exit 3 after ACTOR_LIFETIME seconds.

Signals: this script never calls kill or a subprocess timeout that kills.
Diagnostics (lsof, mount) are waited for with a bound; one that does not
finish is recorded as incomplete with its PID and polled again at the end.
It is not stopped. Its pipes stay open until this script exits, after which
the kernel may deliver SIGPIPE to it on its next write. Nothing here
guarantees that any child actually ended.

Scenarios (each uses a fresh fixture file):
  fork_shared   actor flocks, forks WITHOUT exec; both share one description
  exec_inherit  actor flocks an inheritable FD, execs a child that keeps it
  exec_cloexec  actor flocks an O_CLOEXEC FD, execs a child with close_fds off
  scm_rights    actor A flocks and passes the FD over a socketpair to sibling
                actor B (started by this script, not A's descendant), then A
                closes its FD

Per stage: an independent nonblocking flock probe (held/free) and
`lsof +fg -F0pfG` per-PID FWASLOCKED bits. The bit is recorded only; it is
never treated as holder evidence. Collection (`collected`) and the expected
table (`measured`) are reported separately; `ok` needs both.
"""

import argparse
import array
import errno
import fcntl
import hashlib
import json
import os
import platform
import re
import select
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


FWASLOCKED = 0x4000
ACTOR_LIFETIME = 20.0
READY_TIMEOUT = 5.0
EXIT_TIMEOUT = 5.0
DIAGNOSTIC_TIMEOUT = 5.0
LINE_LIMIT = 16 << 10
STREAM_LIMIT = 256 << 10
LSOF = "/usr/sbin/lsof"
MOUNT = "/sbin/mount"
SCRIPT = str(Path(__file__).resolve())


# ------------------------------------------------------------------ framing

class Framed:
    """Newline framing over a raw fd with a fixed deadline and byte caps.

    read_line returns ("line", bytes), ("eof", None), ("timeout", None) or
    ("limit", None) or ("unterminated", None). Bytes after a returned line
    stay buffered for the next call; a partial line at a deadline is kept,
    never returned. EOF with a partial line is a framing failure.
    """

    def __init__(self, fd, line_limit=LINE_LIMIT, stream_limit=STREAM_LIMIT):
        self.fd = fd
        self.buffer = b""
        self.total = 0
        self.line_limit = line_limit
        self.stream_limit = stream_limit
        self.eof = False
        self.overflow = False

    def read_line(self, deadline):
        while True:
            if self.overflow:
                return ("limit", None)
            if b"\n" in self.buffer:
                if self.buffer.index(b"\n") > self.line_limit:
                    self.overflow = True
                    return ("limit", None)
                line, self.buffer = self.buffer.split(b"\n", 1)
                return ("line", line)
            if len(self.buffer) > self.line_limit:
                self.overflow = True
                return ("limit", None)
            if self.eof:
                return ("unterminated" if self.buffer else "eof", None)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return ("timeout", None)
            ready, _, _ = select.select([self.fd], [], [], remaining)
            if not ready:
                continue
            chunk = os.read(self.fd, 4096)
            if not chunk:
                self.eof = True
                continue
            # Bytes past the stream cap are dropped, never buffered.
            room = self.stream_limit - self.total
            if len(chunk) > room:
                self.overflow = True
                chunk = chunk[:max(0, room)]
            self.total += len(chunk)
            self.buffer += chunk


def parse_event(line):
    """A JSON object with a string `event`, or None."""
    try:
        value = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(value, dict) or not isinstance(value.get("event"), str):
        return None
    return value


# ---------------------------------------------------------------- actor side

def emit(value):
    data = (json.dumps(value, sort_keys=True) + "\n").encode()
    while data:
        data = data[os.write(1, data):]


def wait_readable(fd, deadline):
    """True when fd is readable (data or EOF), False at deadline."""
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        ready, _, _ = select.select([fd], [], [], remaining)
        if ready:
            return True


def run_commands(deadline, handlers):
    """Serve stdin commands until EOF (True) or lifetime/limit (False)."""
    framed = Framed(0)
    while True:
        status, line = framed.read_line(deadline)
        if status == "eof":
            return True
        if status != "line":
            return False
        handler = handlers.get(line.decode("utf-8", "replace").strip())
        emit(handler() if handler else {"event": "error", "error": "unknown command"})


def lock_exclusive(fd):
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


def bounded_waitpid(pid, deadline):
    while time.monotonic() < deadline:
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            return os.waitstatus_to_exitcode(status)
        time.sleep(0.01)
    return None


def actor_fork_shared(lock_path, deadline):
    fd = os.open(lock_path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    lock_exclusive(fd)
    control_r, control_w = os.pipe()
    child = os.fork()
    if child == 0:
        # Forked child, no exec: shares the parent's description of fd.
        os.close(control_w)
        code = 0 if wait_readable(control_r, deadline) else 3
        os.close(fd)
        os._exit(code)
    os.close(control_r)
    state = {"fd": fd}

    def close_parent_fd():
        os.close(state["fd"])
        state["fd"] = None
        return {"event": "closed", "who": "parent"}

    try:
        emit({"event": "ready", "pid": os.getpid(), "child_pid": child})
        clean = run_commands(deadline, {"close_parent_fd": close_parent_fd})
    finally:
        os.close(control_w)
        if state["fd"] is not None:
            os.close(state["fd"])
    child_exit = bounded_waitpid(child, time.monotonic() + EXIT_TIMEOUT)
    emit({"event": "child_exit", "code": child_exit})
    return 0 if clean and child_exit == 0 else 3


def actor_exec(lock_path, deadline, inheritable):
    fd = os.open(lock_path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    lock_exclusive(fd)
    if inheritable:
        os.set_inheritable(fd, True)
    # close_fds=False isolates the O_CLOEXEC flag: nothing else closes fd.
    child = subprocess.Popen(
        [sys.executable, "-I", SCRIPT, "actor", "keeper", lock_path, str(fd)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, close_fds=False, bufsize=0)
    state = {"fd": fd}

    def close_parent_fd():
        os.close(state["fd"])
        state["fd"] = None
        return {"event": "closed", "who": "parent"}

    clean = False
    try:
        status, line = Framed(child.stdout.fileno()).read_line(time.monotonic() + READY_TIMEOUT)
        keeper = parse_event(line) if status == "line" else None
        if not keeper or keeper.get("event") != "keeper_ready" or not isinstance(keeper.get("has_fd"), bool):
            # A keeper that is not ready is a failure, never a ready actor.
            emit({"event": "failed", "reason": f"keeper_not_ready:{status}", "child_pid": child.pid})
        else:
            emit({"event": "ready", "pid": os.getpid(), "child_pid": child.pid, "keeper": keeper})
            clean = run_commands(deadline, {"close_parent_fd": close_parent_fd})
    finally:
        child.stdin.close()
        if state["fd"] is not None:
            os.close(state["fd"])
    child_exit = bounded_waitpid(child.pid, time.monotonic() + EXIT_TIMEOUT)
    child.returncode = child_exit
    if child_exit is not None:
        child.stdout.close()
    emit({"event": "child_exit", "code": child_exit})
    return 0 if clean and child_exit == 0 else 3


def actor_keeper(lock_path, fd_text, deadline):
    """Exec'd child: report whether the inherited fd is the fixture file."""
    fd = int(fd_text)
    try:
        st = os.fstat(fd)
        expected = os.stat(lock_path)
        has_fd = (st.st_dev, st.st_ino) == (expected.st_dev, expected.st_ino)
    except OSError as error:
        if error.errno != errno.EBADF:
            raise
        has_fd = False
    emit({"event": "keeper_ready", "pid": os.getpid(), "has_fd": has_fd})
    clean = run_commands(deadline, {})
    if has_fd:
        os.close(fd)
    return 0 if clean else 3


def actor_scm_sender(lock_path, sock_fd, deadline):
    fd = os.open(lock_path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    lock_exclusive(fd)
    sock = socket.socket(fileno=sock_fd)
    sock.sendmsg([b"x"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                           array.array("i", [fd]))])
    state = {"fd": fd}

    def close_own_fd():
        os.close(state["fd"])
        state["fd"] = None
        return {"event": "closed", "who": "sender"}

    try:
        emit({"event": "ready", "pid": os.getpid()})
        clean = run_commands(deadline, {"close_own_fd": close_own_fd})
    finally:
        if state["fd"] is not None:
            os.close(state["fd"])
        sock.close()
    return 0 if clean else 3


def actor_scm_receiver(sock_fd, deadline):
    sock = socket.socket(fileno=sock_fd)
    if not wait_readable(sock.fileno(), time.monotonic() + READY_TIMEOUT):
        emit({"event": "failed", "reason": "not_received"})
        return 3
    _, ancdata, _, _ = sock.recvmsg(1, socket.CMSG_SPACE(array.array("i").itemsize))
    fds = array.array("i")
    for level, kind, data in ancdata:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            fds.frombytes(data[:len(data) - (len(data) % fds.itemsize)])
    try:
        if len(fds) != 1:
            emit({"event": "failed", "reason": f"received:{len(fds)}"})
            return 3
        emit({"event": "ready", "pid": os.getpid(), "received": len(fds)})
        clean = run_commands(deadline, {})
    finally:
        for fd in fds:
            os.close(fd)
        sock.close()
    return 0 if clean else 3


def actor_main(argv):
    deadline = time.monotonic() + ACTOR_LIFETIME
    role = argv[0]
    if role == "fork_shared":
        return actor_fork_shared(argv[1], deadline)
    if role == "exec_inherit":
        return actor_exec(argv[1], deadline, True)
    if role == "exec_cloexec":
        return actor_exec(argv[1], deadline, False)
    if role == "keeper":
        return actor_keeper(argv[1], argv[2], deadline)
    if role == "scm_sender":
        return actor_scm_sender(argv[1], int(argv[2]), deadline)
    if role == "scm_receiver":
        return actor_scm_receiver(int(argv[1]), deadline)
    raise SystemExit(f"unknown role {role}")


# ---------------------------------------------------------- diagnostics

def run_diagnostic(run, argv, timeout=DIAGNOSTIC_TIMEOUT, limit=STREAM_LIMIT):
    """Run a diagnostic with a bound and byte caps, never signalling it.

    Returns {"status", "stdout", "stderr", "problems"}; on timeout the process
    is registered in run.pending and reported with status None.
    """
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, bufsize=0,
                            env={"LC_ALL": "C", "LANG": "C", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"})
    out_fd, err_fd = proc.stdout.fileno(), proc.stderr.fileno()
    streams = {out_fd: bytearray(), err_fd: bytearray()}
    problems = []
    deadline = time.monotonic() + timeout
    open_fds = set(streams)
    while open_fds:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            run.pending.append({"argv0": argv[0], "pid": proc.pid, "proc": proc})
            run.incomplete.append(f"diagnostic_timeout:{os.path.basename(argv[0])}:{proc.pid}")
            return {"status": None, "stdout": b"", "stderr": b"", "problems": ["timeout"]}
        ready, _, _ = select.select(list(open_fds), [], [], remaining)
        for fd in ready:
            chunk = os.read(fd, 65536)
            if not chunk:
                open_fds.discard(fd)
                continue
            room = limit - len(streams[fd])
            if len(chunk) > room and "output_limit" not in problems:
                problems.append("output_limit")
            streams[fd] += chunk[:max(0, room)]
    status = None
    while time.monotonic() < deadline and status is None:
        status = proc.poll()
        if status is None:
            time.sleep(0.005)
    if status is None:
        run.pending.append({"argv0": argv[0], "pid": proc.pid, "proc": proc})
        run.incomplete.append(f"diagnostic_exit_wait:{os.path.basename(argv[0])}:{proc.pid}")
        problems.append("exit_wait")
    proc.stdout.close()
    proc.stderr.close()
    return {"status": status, "stdout": bytes(streams[out_fd]), "stderr": bytes(streams[err_fd]), "problems": problems}


FLAGS = re.compile(r"^0x[0-9a-f]+;0x[0-9a-f]+$")


def parse_fg(out):
    """Strict `lsof -F0pfG` parse. Any deviation is a problem, never no_bit."""
    problems = []
    pids = {}
    pid = None
    if not out:
        return {"problems": problems, "pids": {}}
    if not out.endswith(b"\n"):
        problems.append("unterminated_output")
    for number, record in enumerate(out.split(b"\n")[:-1] if out.endswith(b"\n") else out.split(b"\n")):
        try:
            text = record.decode("ascii")
        except UnicodeDecodeError:
            problems.append(f"non_ascii:{number}")
            continue
        if not text.endswith("\0"):
            problems.append(f"unterminated_record:{number}")
            continue
        fields = text[:-1].split("\0")
        tags = "".join(f[:1] for f in fields)
        if tags == "p" and re.fullmatch(r"[1-9][0-9]*", fields[0][1:]):
            pid = int(fields[0][1:])
            if pid in pids:
                problems.append(f"duplicate_pid:{pid}")
            pids.setdefault(pid, [])
        elif tags == "fG" and pid is not None and re.fullmatch(r"[0-9]+", fields[0][1:]) and FLAGS.match(fields[1][1:]):
            head = fields[1][1:].split(";", 1)[0]
            pids[pid].append({"fd": fields[0][1:], "flags": fields[1][1:],
                              "was_locked": bool(int(head, 16) & FWASLOCKED)})
        else:
            problems.append(f"record:{number}:{tags}")
    for p, descriptors in pids.items():
        if not descriptors:
            problems.append(f"pid_without_fd:{p}")
    return {"problems": problems, "pids": {str(k): v for k, v in pids.items()}}


def fg_scan(run, lock_path):
    result = run_diagnostic(run, [LSOF, "-nP", "+fg", "-F0pfG", "--", lock_path])
    problems = list(result["problems"])
    if result["stderr"]:
        problems.append("stderr")
    status, out = result["status"], result["stdout"]
    # lsof exits 1 with no output when nothing has the file open.
    if status is not None and (status not in (0, 1) or (status == 1 and out) or (status == 0 and not out)):
        problems.append(f"status:{status}")
    parsed = parse_fg(out) if status is not None else {"problems": [], "pids": {}}
    problems += parsed["problems"]
    return {"valid": status is not None and not problems, "problems": problems, "status": status, "pids": parsed["pids"]}


def probe(lock_path):
    fd = os.open(lock_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        if error.errno in (errno.EWOULDBLOCK, errno.EAGAIN):
            return "held"
        return f"error:{errno.errorcode.get(error.errno, error.errno)}"
    finally:
        os.close(fd)
    return "free"


def classify(scan, roles):
    seen = {}
    for role, pid in roles.items():
        descriptors = scan["pids"].get(str(pid))
        if descriptors is None:
            seen[role] = "absent"
        else:
            seen[role] = "bit" if any(d["was_locked"] for d in descriptors) else "no_bit"
    other = sorted(set(scan["pids"]) - {str(p) for p in roles.values()})
    return seen, len(other)


def observe(run, lock_path, stage, roles):
    scan = fg_scan(run, lock_path)
    seen, unexpected = classify(scan, roles)
    return {"stage": stage, "probe": probe(lock_path), "roles": seen,
            "unexpected_pids": unexpected, "scan_valid": scan["valid"],
            "scan_problems": scan["problems"], "raw": scan}


# --------------------------------------------------------- orchestrator

class Run:
    def __init__(self, scratch):
        self.scratch = scratch
        self.incomplete = []
        self.failures = []
        self.pending = []
        self.actors = []

    def start(self, label, argv, pass_fds=()):
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                pass_fds=pass_fds, close_fds=True, bufsize=0)
        actor = {"label": label, "proc": proc, "framed": Framed(proc.stdout.fileno()), "finished": None}
        self.actors.append(actor)
        return actor

    def start_actor(self, label, args, pass_fds=()):
        return self.start(label, [sys.executable, "-I", SCRIPT, "actor", *args], pass_fds)

    def read_event(self, actor, expected):
        """Next event; it must be `expected`. Anything else is recorded."""
        status, line = actor["framed"].read_line(time.monotonic() + READY_TIMEOUT)
        label = actor["label"]
        if status == "timeout":
            self.incomplete.append(f"{label}:no_event")
            return None
        if status != "line":
            self.failures.append(f"{label}:{status}")
            return None
        event = parse_event(line)
        if event is None:
            self.failures.append(f"{label}:malformed_event")
            return None
        if event["event"] != expected:
            self.failures.append(f"{label}:unexpected_event:{event['event']}:{event.get('reason', '')}")
            return None
        return event

    def command(self, actor, text, expected):
        actor["proc"].stdin.write(text.encode() + b"\n")
        actor["proc"].stdin.flush()
        return self.read_event(actor, expected)

    def finish(self, actor):
        """stdin EOF, bounded read of remaining events, bounded exit wait."""
        if actor["finished"] is not None:
            return actor["finished"]
        proc, label = actor["proc"], actor["label"]
        try:
            proc.stdin.close()
        except OSError:
            pass
        events = []
        deadline = time.monotonic() + EXIT_TIMEOUT
        while True:
            status, line = actor["framed"].read_line(deadline)
            if status == "line":
                event = parse_event(line)
                if event is None:
                    self.failures.append(f"{label}:malformed_event")
                else:
                    events.append(event)
                continue
            if status == "timeout":
                self.incomplete.append(f"{label}:output_wait")
            elif status == "limit":
                self.failures.append(f"{label}:output_limit")
            elif status != "eof":
                self.failures.append(f"{label}:output_{status}")
            break
        code = None
        while time.monotonic() < deadline and code is None:
            code = proc.poll()
            if code is None:
                time.sleep(0.01)
        if code is None:
            self.incomplete.append(f"{label}:exit_wait:{proc.pid}")
        elif code != 0:
            self.failures.append(f"{label}:exit:{code}")
        if code is not None:
            proc.stdout.close()
        actor["finished"] = {"exit": code, "events": events}
        return actor["finished"]

    def finish_all(self):
        for actor in self.actors:
            try:
                self.finish(actor)
            except Exception as error:
                # A broken actor's output must not skip EOF for later actors.
                self.failures.append(f"{actor['label']}:finish_error:{type(error).__name__}")
                try:
                    actor["proc"].stdin.close()
                except OSError:
                    pass
                self.incomplete.append(f"{actor['label']}:finish_unconfirmed:{actor['proc'].pid}")

    def poll_pending(self):
        states = []
        for item in self.pending:
            code = item["proc"].poll()
            states.append({"argv0": item["argv0"], "pid": item["pid"],
                           "state": "running" if code is None else f"exited:{code}"})
        return states


def fixture(run, name):
    path = run.scratch / f"{name}.lock"
    path.write_bytes(b"")
    path.chmod(0o600)
    return str(path)


def scenario_fork_shared(run):
    lock = fixture(run, "fork_shared")
    actor = run.start_actor("fork_shared", ["fork_shared", lock])
    ready = run.read_event(actor, "ready")
    if not ready:
        return {"ready": None, "finish": run.finish(actor)}
    roles = {"parent": ready["pid"], "forked_child": ready["child_pid"]}
    stages = [observe(run, lock, "both_alive", roles)]
    closed = run.command(actor, "close_parent_fd", "closed")
    stages.append(observe(run, lock, "parent_closed_fd_alive", roles))
    finish = run.finish(actor)
    stages.append(observe(run, lock, "all_closed", {}))
    return {"ready": ready, "closed": closed, "stages": stages, "finish": finish}


def scenario_exec(run, role):
    lock = fixture(run, role)
    actor = run.start_actor(role, [role, lock])
    ready = run.read_event(actor, "ready")
    if not ready:
        return {"ready": None, "finish": run.finish(actor)}
    roles = {"parent": ready["pid"], "exec_child": ready["child_pid"]}
    stages = [observe(run, lock, "both_alive", roles)]
    closed = run.command(actor, "close_parent_fd", "closed")
    stages.append(observe(run, lock, "parent_closed_fd_alive", roles))
    finish = run.finish(actor)
    stages.append(observe(run, lock, "all_closed", {}))
    return {"ready": ready, "keeper": ready.get("keeper"), "closed": closed, "stages": stages, "finish": finish}


def scenario_scm_rights(run):
    lock = fixture(run, "scm_rights")
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        receiver = run.start_actor("scm_receiver", ["scm_receiver", str(right.fileno())], (right.fileno(),))
        sender = run.start_actor("scm_sender", ["scm_sender", lock, str(left.fileno())], (left.fileno(),))
    finally:
        left.close()
        right.close()
    sent = run.read_event(sender, "ready")
    received = run.read_event(receiver, "ready")
    if not sent or not received:
        return {"sent": sent, "received": received, "finish": [run.finish(sender), run.finish(receiver)]}
    roles = {"sender_flock_caller": sent["pid"], "receiver_never_flocked": received["pid"]}
    stages = [observe(run, lock, "both_hold_description", roles)]
    closed = run.command(sender, "close_own_fd", "closed")
    stages.append(observe(run, lock, "sender_closed_fd_alive", roles))
    finish_sender = run.finish(sender)
    stages.append(observe(run, lock, "sender_exited", roles))
    finish_receiver = run.finish(receiver)
    stages.append(observe(run, lock, "all_closed", {}))
    return {"sent": sent, "received": received, "closed": closed, "stages": stages,
            "finish": [finish_sender, finish_receiver]}


# ------------------------------------------------------- expected table

# (stage, probe, {role: bit | no_bit | absent}) in order, per scenario.
EXPECTED_STAGES = {
    "fork_shared": [
        ("both_alive", "held", {"parent": "bit", "forked_child": "bit"}),
        ("parent_closed_fd_alive", "held", {"parent": "absent", "forked_child": "bit"}),
        ("all_closed", "free", {}),
    ],
    "exec_inherit": [
        ("both_alive", "held", {"parent": "bit", "exec_child": "bit"}),
        ("parent_closed_fd_alive", "held", {"parent": "absent", "exec_child": "bit"}),
        ("all_closed", "free", {}),
    ],
    "exec_cloexec": [
        ("both_alive", "held", {"parent": "bit", "exec_child": "absent"}),
        ("parent_closed_fd_alive", "free", {"parent": "absent", "exec_child": "absent"}),
        ("all_closed", "free", {}),
    ],
    "scm_rights": [
        ("both_hold_description", "held", {"sender_flock_caller": "bit", "receiver_never_flocked": "bit"}),
        ("sender_closed_fd_alive", "held", {"sender_flock_caller": "absent", "receiver_never_flocked": "bit"}),
        ("sender_exited", "held", {"sender_flock_caller": "absent", "receiver_never_flocked": "bit"}),
        ("all_closed", "free", {}),
    ],
}
KEEPER_HAS_FD = {"exec_inherit": True, "exec_cloexec": False}
CLOSED_WHO = {"fork_shared": "parent", "exec_inherit": "parent", "exec_cloexec": "parent", "scm_rights": "sender"}


def is_pid(value):
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def evaluate(scenarios):
    """Mismatches between collected scenarios and the expected table."""
    mismatches = []
    for name, expected in EXPECTED_STAGES.items():
        result = scenarios.get(name) or {}
        stages = result.get("stages")
        if not stages:
            mismatches.append(f"{name}:no_stages")
            continue
        if [s["stage"] for s in stages] != [e[0] for e in expected]:
            mismatches.append(f"{name}:stage_list")
            continue
        for stage, (label, want_probe, want_roles) in zip(stages, expected):
            where = f"{name}/{label}"
            if not stage["scan_valid"]:
                mismatches.append(f"{where}:scan_invalid")
            if stage["unexpected_pids"]:
                mismatches.append(f"{where}:unexpected_pids:{stage['unexpected_pids']}")
            if stage["probe"] != want_probe:
                mismatches.append(f"{where}:probe:{stage['probe']}")
            if stage["roles"] != want_roles:
                mismatches.append(f"{where}:roles")
        closed = result.get("closed")
        if not closed or closed.get("who") != CLOSED_WHO[name]:
            mismatches.append(f"{name}:closed_event")
        if name == "scm_rights":
            sent, received = result.get("sent") or {}, result.get("received") or {}
            if not is_pid(sent.get("pid")) or not is_pid(received.get("pid")) or received.get("received") != 1:
                mismatches.append(f"{name}:ready_events")
            finishes = result.get("finish") or []
            if len(finishes) != 2 or any(f.get("exit") != 0 or f.get("events") for f in finishes):
                mismatches.append(f"{name}:finish")
        else:
            ready = result.get("ready") or {}
            if not is_pid(ready.get("pid")) or not is_pid(ready.get("child_pid")) or ready["pid"] == ready["child_pid"]:
                mismatches.append(f"{name}:ready_event")
            if name in KEEPER_HAS_FD:
                keeper = ready.get("keeper") or {}
                if keeper.get("event") != "keeper_ready" or keeper.get("has_fd") is not KEEPER_HAS_FD[name] or \
                        keeper.get("pid") != ready.get("child_pid"):
                    mismatches.append(f"{name}:keeper")
            finish = result.get("finish") or {}
            if finish.get("exit") != 0 or finish.get("events") != [{"code": 0, "event": "child_exit"}]:
                mismatches.append(f"{name}:finish")
    return mismatches


# ------------------------------------------------------------- results

def filesystem_of(run, path):
    """Filesystem type of the mount containing the canonical path."""
    canonical = os.path.realpath(path)
    result = run_diagnostic(run, [MOUNT])
    if result["status"] != 0 or result["problems"]:
        return "unknown"
    best = ("", "unknown")
    for line in result["stdout"].decode("utf-8", "replace").splitlines():
        if " on " not in line or " (" not in line:
            continue
        point = line.split(" on ", 1)[1].rsplit(" (", 1)[0]
        kind = line.rsplit(" (", 1)[1].split(",", 1)[0].rstrip(")")
        if (canonical + "/").startswith(point.rstrip("/") + "/") and len(point) >= len(best[0]):
            best = (point, kind)
    return best[1]


def open_result(path):
    """Create the result file exclusively, 0600, refusing symlinks."""
    return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)


def script_sha256():
    return hashlib.sha256(Path(SCRIPT).read_bytes()).hexdigest()


def script_identity(start_sha256):
    """Compare the on-disk script at the start and end of a run."""
    end_sha256 = script_sha256()
    return {"start_sha256": start_sha256, "end_sha256": end_sha256,
            "unchanged": start_sha256 == end_sha256}


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "actor":
        return actor_main(sys.argv[2:])
    parser = argparse.ArgumentParser()
    parser.add_argument("--scratch-root", required=True,
                        help="existing directory; a private child is created")
    parser.add_argument("--result", required=True,
                        help="new JSON result path, outside the scratch directory")
    args = parser.parse_args()
    if platform.system() != "Darwin":
        raise SystemExit("macOS only: FWASLOCKED and lsof +fg are XNU-specific")
    # Created before the fixture directory, so it is never inside it and is
    # never removed by fixture cleanup.
    result_fd = open_result(args.result)
    scratch = Path(tempfile.mkdtemp(prefix="codex-127-fixture-", dir=args.scratch_root))
    scratch.chmod(0o700)
    run = Run(scratch)
    scenarios = {}
    errors = []
    environment = {}
    start_sha256 = None
    try:
        # Actors exec SCRIPT later, so bracket the run rather than relying on
        # an import-time hash or hashing only after measurements complete.
        start_sha256 = script_sha256()
        scenarios["fork_shared"] = scenario_fork_shared(run)
        scenarios["exec_inherit"] = scenario_exec(run, "exec_inherit")
        scenarios["exec_cloexec"] = scenario_exec(run, "exec_cloexec")
        scenarios["scm_rights"] = scenario_scm_rights(run)
    except Exception as error:  # recorded, then reported nonzero
        errors.append(f"{type(error).__name__}: {error}")
    finally:
        run.finish_all()
    try:
        version = run_diagnostic(run, [LSOF, "-v"])
        environment = {
            # Hostname deliberately omitted.
            "system": platform.system(), "release": platform.release(), "machine": platform.machine(),
            "mac_ver": platform.mac_ver()[0], "python": platform.python_version(),
            "lsof": next((l.strip() for l in version["stderr"].decode("utf-8", "replace").splitlines()
                          if "revision:" in l and "latest" not in l), None),
            "filesystem": filesystem_of(run, scratch),
        }
    except Exception as error:
        errors.append(f"environment: {type(error).__name__}: {error}")
    mismatches = evaluate(scenarios)
    identity = {"start_sha256": start_sha256, "end_sha256": None, "unchanged": False}
    try:
        if start_sha256 is not None:
            identity = script_identity(start_sha256)
    except Exception as error:
        errors.append(f"script_identity: {type(error).__name__}: {error}")
    if not identity["unchanged"]:
        mismatches.append("script_identity:changed_or_unavailable")
    pending = run.poll_pending()
    collected = not run.failures and not run.incomplete and not errors
    measured = not mismatches
    result = {
        "ok": collected and measured,
        "collected": collected,
        "measured": measured,
        "failures": run.failures,
        "incomplete": run.incomplete,
        "errors": errors,
        "mismatches": mismatches,
        "pending_diagnostics": pending,
        "signals_sent_by_script": "none: no kill calls and no killing timeouts; see module docstring",
        "script_sha256": identity["end_sha256"],
        "script_identity": identity,
        "environment": environment,
        "scenarios": scenarios,
    }
    with os.fdopen(result_fd, "w") as handle:
        handle.write(json.dumps(result, indent=2, sort_keys=True, default=str))
    for name, scenario in scenarios.items():
        for stage in scenario.get("stages", []):
            roles = ", ".join(f"{k}={v}" for k, v in stage["roles"].items())
            print(f"{name}/{stage['stage']}: probe={stage['probe']} {roles} "
                  f"unexpected={stage['unexpected_pids']} scan_valid={stage['scan_valid']}")
    print(json.dumps({"ok": result["ok"], "collected": collected, "measured": measured,
                      "failures": run.failures, "incomplete": run.incomplete, "errors": errors,
                      "mismatches": mismatches, "filesystem": environment.get("filesystem")}))
    if result["ok"] and not pending:
        for child in scratch.iterdir():
            child.unlink()
        scratch.rmdir()
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
