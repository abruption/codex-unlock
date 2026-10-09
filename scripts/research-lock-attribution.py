#!/usr/bin/env python3
"""Measure synthetic flock attribution; never target a real Codex process.

Fixture children close their descriptors on stdin EOF or after ten seconds.
Optional privilege/namespace fixtures need existing noninteractive sudo rights;
they never alter accounts, mounts outside their namespace, or host settings.
The JSON is research evidence, not permission to signal any process.
"""

import argparse
import errno
import fcntl
import hashlib
import json
import os
import platform
import pwd
import select
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


THREAD_ID = "10000000-0000-4000-8000-000000000001"
SCRIPT = str(Path(__file__).resolve())
LSOF = next((p for p in ("/usr/sbin/lsof", "/usr/bin/lsof")
             if os.path.isfile(p) and os.access(p, os.X_OK)), None)


def emit(value):
    print(json.dumps(value, sort_keys=True), flush=True)


def wait_for_eof():
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        ready, _, _ = select.select([sys.stdin], [], [],
                                    max(0, deadline - time.monotonic()))
        if ready and not os.read(sys.stdin.fileno(), 1024):
            return


def child(role, lock_path):
    """Only called by this script with explicitly created fixture paths."""
    if role == "failure":
        raise RuntimeError("injected_fixture_startup_failure")
    fd = os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW)
    guard_path = str(Path(lock_path).parent / ".coordination.lock")
    guard = os.open(guard_path, os.O_RDONLY | os.O_NOFOLLOW)
    if role == "hidden":
        # Open while root, then discard privilege before taking the fixture lock.
        account = pwd.getpwnam("nobody")
        os.setgroups([])
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
    if role != "opener":
        fcntl.flock(guard, fcntl.LOCK_EX)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            fcntl.flock(guard, fcntl.LOCK_UN)
    acquisition_pid = os.getpid()
    if role == "inherited":
        retained = os.fork()
        if retained:
            os._exit(0)
    emit({"ready": True, "pid": os.getpid(), "uid": os.getuid(),
          "acquisitionPid": acquisition_pid, "role": role})
    try:
        wait_for_eof()
    finally:
        # No explicit LOCK_UN: last-close lifetime is part of the experiment.
        os.close(fd)
        os.close(guard)
        emit({"closed": True, "pid": os.getpid()})


def redact(text, scratch):
    return (text.replace(str(scratch), "<synthetic-home>")
            .replace(SCRIPT, "<research-script>")
            .replace(str(Path.home()), "<observer-home>"))


def run(command, scratch):
    # Fixed diagnostic commands; fixture subprocesses have their own deadline.
    result = subprocess.run(command, text=True, capture_output=True, check=False, timeout=4)
    return {"exitStatus": result.returncode,
            "stdout": redact(result.stdout, scratch),
            "stderr": redact(result.stderr, scratch)}


def process_records(output):
    records = []
    current = None
    for field in output.replace("\0", "\n").splitlines():
        if field.startswith("p") and field[1:].isdigit():
            current = {"pid": int(field[1:])}
            records.append(current)
        elif current is not None and field.startswith("u"):
            current["uid"] = int(field[1:]) if field[1:].isdigit() else None
        elif current is not None and field.startswith("c"):
            current["command"] = field[1:]
    return records


def lsof_evidence(path, scratch):
    if not LSOF:
        return {"status": "skipped", "reason": "fixed_system_lsof_not_found"}
    ordinary = run([LSOF, "-nP", "-F0pcu", "--", str(path)], scratch)
    ordinary["processRecords"] = process_records(ordinary["stdout"])
    fields = run([LSOF, "-nP", "-F0pcuflDi", "--", str(path)], scratch)
    return {"status": "measured", "processQuery": ordinary,
            "optionalLockFieldQuery": fields}


def matches_inode(line, snapshot):
    identity = f"{os.major(snapshot.st_dev):02x}:{os.minor(snapshot.st_dev):02x}:{snapshot.st_ino}"
    # Kernel minor/major width can grow; compare values rather than strings.
    for token in line.split():
        if token.count(":") == 2:
            try:
                major, minor, inode = token.split(":")
                if (int(major, 16), int(minor, 16), int(inode)) == (
                    os.major(snapshot.st_dev), os.minor(snapshot.st_dev), snapshot.st_ino
                ):
                    return True
            except ValueError:
                continue
    return identity in line.split()


def proc_evidence(path, candidates):
    if sys.platform != "linux":
        return {"status": "skipped", "reason": "linux_proc_only"}
    snapshot = path.stat()
    evidence = {"status": "measured", "globalLockRecords": [], "candidateFdinfo": []}
    try:
        evidence["globalLockRecords"] = [line for line in Path("/proc/locks").read_text().splitlines()
                                         if matches_inode(line, snapshot)]
    except OSError as error:
        evidence["globalLocksError"] = error.__class__.__name__
    for pid in candidates:
        item = {"pid": pid, "descriptors": []}
        try:
            for entry in Path(f"/proc/{pid}/fd").iterdir():
                try:
                    target = entry.stat()
                    if (target.st_dev, target.st_ino) != (snapshot.st_dev, snapshot.st_ino):
                        continue
                    info = Path(f"/proc/{pid}/fdinfo/{entry.name}").read_text()
                    lock_lines = [line for line in info.splitlines()
                                  if line.startswith("lock:") and matches_inode(line, snapshot)]
                    item["descriptors"].append({"fd": int(entry.name), "lockRecords": lock_lines,
                                                "positiveFlockEvidence": any(" FLOCK " in line for line in lock_lines)})
                except OSError as error:
                    item.setdefault("descriptorErrors", []).append(error.__class__.__name__)
        except OSError as error:
            item["error"] = error.__class__.__name__
        evidence["candidateFdinfo"].append(item)
    return evidence


def guarded_probe(path):
    guard = fd = None
    try:
        guard = os.open(path.parent / ".coordination.lock", os.O_RDONLY | os.O_NOFOLLOW)
        fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                return "held"
            raise
        fcntl.flock(fd, fcntl.LOCK_UN)
        return "free"
    except OSError:
        return "unknown"
    finally:
        if fd is not None:
            os.close(fd)
        if guard is not None:
            os.close(guard)


def start_fixture(role, path, privileged=False):
    command = [sys.executable, SCRIPT, "--child", role, "--lock-path", str(path)]
    if privileged:
        command = ["/usr/bin/sudo", "-n", *command]
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    ready, _, _ = select.select([process.stdout], [], [], 5)
    if not ready:
        process.stdin.close()
        process.wait(timeout=12)
        raise RuntimeError("fixture_ready_timeout")
    line = process.stdout.readline()
    if not line:
        process.stdin.close()
        process.wait(timeout=12)
        diagnostic = redact(process.stderr.read(), Path(path).parent.parent).strip()
        raise RuntimeError(f"fixture_failed_before_ready: exit={process.returncode}; {diagnostic}")
    try:
        event = json.loads(line)
        if not event.get("ready"):
            raise ValueError("not_ready")
    except (ValueError, TypeError):
        process.stdin.close()
        process.wait(timeout=12)
        raise RuntimeError("fixture_invalid_ready") from None
    return process, event


def stop_fixture(process):
    process.stdin.close()
    # communicate() cannot flush an already-closed stdin; detach it first.
    process.stdin = None
    stdout, stderr = process.communicate(timeout=12)
    if stderr or not any(json.loads(line).get("closed") for line in stdout.splitlines()):
        raise RuntimeError("fixture_did_not_close_cleanly")


def snapshot(path, scratch, events, cli=None):
    pids = [event["pid"] for event in events]
    observation = {"status": "measured", "guardedProbe": guarded_probe(path),
                   "syntheticProcesses": events, "lsof": lsof_evidence(path, scratch),
                   "linuxProc": proc_evidence(path, pids)}
    if cli:
        node = shutil.which("node")
        if not node:
            raise RuntimeError("node_not_available")
        result = run([node, str(Path(cli).resolve()), "inspect", THREAD_ID,
                      "--codex-home", str(scratch), "--json"], scratch)
        decoded = json.loads(result["stdout"])
        observation["cliInspection"] = {"exitStatus": result["exitStatus"],
                                         "classification": decoded["classification"],
                                         "safeToUnlock": decoded["safeToUnlock"],
                                         "stderr": result["stderr"]}
    return observation


def metadata(paths):
    return [{"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
             "mode": path.stat().st_mode, "mtimeNs": path.stat().st_mtime_ns,
             "uid": path.stat().st_uid, "inode": path.stat().st_ino} for path in paths]


def observer(path):
    # Invoked only inside a fresh private Linux PID/mount namespace.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        emit({"guardedProbe": guarded_probe(Path(path)),
              "nonlockingObserverPid": os.getpid(),
              "lsof": lsof_evidence(Path(path), Path(path).parent.parent),
              "linuxProc": proc_evidence(Path(path), [os.getpid()])})
    finally:
        os.close(fd)


def privilege_preflight():
    """Test only privilege dropping, in a short-lived separate process."""
    if os.geteuid() != 0:
        raise RuntimeError("privilege_preflight_did_not_run_as_root")
    try:
        account = pwd.getpwnam("nobody")
    except KeyError:
        emit({"available": False, "reason": "existing_nobody_account_unavailable"})
        return 0
    try:
        os.setgroups([])
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
    except OSError as error:
        if error.errno != errno.EPERM:
            raise
        emit({"available": False, "reason": "privilege_drop_capability_unavailable"})
        return 0
    emit({"available": True})
    return 0


def sudo_availability(scratch, executable="/usr/bin/sudo", runner=run):
    if not os.path.isfile(executable) or not os.access(executable, os.X_OK):
        return {"available": False, "reason": "fixed_system_sudo_not_found"}
    command = [sys.executable, SCRIPT, "--privilege-preflight"]
    # Query policy before launching the helper. A denial here is an unavailable
    # prerequisite; failure after the helper launches must fail the research.
    permission = runner([executable, "-n", "-l", "--", *command], scratch)
    if permission["exitStatus"] != 0:
        if permission["exitStatus"] < 0:
            raise RuntimeError("sudo_policy_query_terminated_unexpectedly")
        return {"available": False, "reason": "noninteractive_sudo_policy_unavailable",
                "preflight": permission}
    result = runner([executable, "-n", "--", *command], scratch)
    if result["exitStatus"] != 0:
        raise RuntimeError("privilege_preflight_helper_failed")
    value = json.loads(result["stdout"])
    if value.get("available") is True:
        return {"available": True}
    if value.get("available") is False and value.get("reason") in (
        "existing_nobody_account_unavailable", "privilege_drop_capability_unavailable"
    ):
        return value
    raise RuntimeError("invalid_privilege_preflight_result")


def namespace_availability(scratch, sudo, runner=run, unshare_executable=None):
    if not sudo["available"]:
        return sudo
    unshare = unshare_executable or next((p for p in ("/usr/bin/unshare", "/bin/unshare")
                                         if os.path.isfile(p) and os.access(p, os.X_OK)), None)
    if not unshare:
        return {"available": False, "reason": "fixed_system_unshare_not_found"}
    command = ["/usr/bin/sudo", "-n", "--", unshare, "--mount", "--propagation", "private",
               "--pid", "--fork", "--mount-proc", "/usr/bin/true"]
    permission = runner(["/usr/bin/sudo", "-n", "-l", "--", *command[3:]], scratch)
    if permission["exitStatus"] != 0:
        if permission["exitStatus"] < 0:
            raise RuntimeError("namespace_sudo_policy_query_terminated_unexpectedly")
        return {"available": False, "reason": "namespace_sudo_policy_unavailable",
                "preflight": permission}
    preflight = runner(command, scratch)
    if preflight["exitStatus"] == 0:
        return {"available": True, "unshare": unshare}
    if preflight["exitStatus"] > 0 and any(
        diagnostic in preflight["stderr"]
        for diagnostic in ("Operation not permitted", "Permission denied", "unrecognized option")
    ):
        return {"available": False, "reason": "namespace_capability_or_option_unavailable",
                "preflight": preflight}
    raise RuntimeError("namespace_preflight_failed_unexpectedly")


def checked_observer(result):
    if result["exitStatus"] != 0:
        raise RuntimeError("namespace_observer_failed")
    value = json.loads(result["stdout"])
    if value.get("guardedProbe") != "held" or not isinstance(value.get("lsof"), dict):
        raise RuntimeError("namespace_observer_invalid_evidence")
    return result


def self_test():
    """Check skipped prerequisites versus failed measurements without sudo."""
    with tempfile.TemporaryDirectory(prefix="codex-unlock-attribution-self-test-",
                                     dir=os.environ.get("TMPDIR")) as temporary:
        scratch = Path(temporary).resolve()
        os.chmod(scratch, 0o700)
        unavailable = sudo_availability(scratch, executable=str(scratch / "absent-sudo"))
        if unavailable != {"available": False, "reason": "fixed_system_sudo_not_found"}:
            raise RuntimeError("self_test_prerequisite_skip_failed")
        def failed_preflight(command, _scratch):
            return {"exitStatus": 0 if "-l" in command else 1,
                    "stdout": "", "stderr": "injected_preflight_helper_failure"}
        try:
            sudo_availability(scratch, executable=sys.executable, runner=failed_preflight)
        except RuntimeError as error:
            if str(error) != "privilege_preflight_helper_failed":
                raise
        else:
            raise RuntimeError("self_test_preflight_failure_was_not_fatal")
        def unavailable_namespace(command, _scratch):
            if "-l" in command:
                if command[4] != sys.executable:
                    raise RuntimeError("self_test_namespace_policy_command_incorrect")
                return {"exitStatus": 0, "stdout": "", "stderr": ""}
            return {"exitStatus": 1, "stdout": "",
                    "stderr": "unshare: unshare failed: Operation not permitted"}
        prerequisite = namespace_availability(scratch, {"available": True},
                                             runner=unavailable_namespace,
                                             unshare_executable=sys.executable)
        if prerequisite["available"] is not False or prerequisite["reason"] != "namespace_capability_or_option_unavailable":
            raise RuntimeError("self_test_namespace_capability_skip_failed")
        try:
            namespace_availability(scratch, {"available": True}, runner=failed_preflight,
                                   unshare_executable=sys.executable)
        except RuntimeError as error:
            if str(error) != "namespace_preflight_failed_unexpectedly":
                raise
        else:
            raise RuntimeError("self_test_unexpected_namespace_failure_was_not_fatal")
        for output in (
            {"exitStatus": 1, "stdout": "", "stderr": "injected_observer_failure"},
            {"exitStatus": 0, "stdout": "{}", "stderr": ""},
        ):
            try:
                checked_observer(output)
            except RuntimeError:
                pass
            else:
                raise RuntimeError("self_test_observer_failure_was_not_fatal")
        try:
            start_fixture("failure", scratch / "unopened-fixture")
        except RuntimeError as error:
            if not any(reason in str(error) for reason in (
                "fixture_failed_before_ready", "fixture_invalid_ready"
            )):
                raise
        else:
            raise RuntimeError("self_test_child_failure_was_not_fatal")
    emit({"status": "passed", "checks": ["missing_sudo_prerequisite_is_skipped",
         "launched_privilege_preflight_nonzero_is_fatal",
         "known_namespace_capability_denial_is_skipped",
         "unexpected_namespace_preflight_failure_is_fatal",
         "launched_observer_nonzero_is_fatal", "invalid_observer_evidence_is_fatal",
         "unexpected_child_startup_failure_is_fatal"], "signalsSent": 0})
    return 0


def main(args):
    if args.self_test:
        return self_test()
    if args.privilege_preflight:
        return privilege_preflight()
    if args.child:
        child(args.child, args.lock_path)
        return 0
    if args.namespace_observer:
        observer(args.lock_path)
        return 0
    report = {"schemaVersion": 1, "purpose": "synthetic_flock_attribution_research",
              "platform": platform.system(), "machine": platform.machine(),
              "kernel": platform.release(), "python": platform.python_version(),
              "lsofVersion": None, "cases": [], "signalsSent": 0}
    with tempfile.TemporaryDirectory(prefix="codex-unlock-attribution-",
                                     dir=os.environ.get("TMPDIR")) as temporary:
        scratch = Path(temporary).resolve()
        os.chmod(scratch, 0o700)
        locks = scratch / "thread-writer-locks"
        locks.mkdir()
        path = locks / f"{THREAD_ID}.lock"
        guard = locks / ".coordination.lock"
        path.write_text("")
        guard.write_text("")
        sessions = scratch / "sessions" / "2026" / "10" / "09"
        sessions.mkdir(parents=True)
        rollout = sessions / f"rollout-2026-10-09T00-00-00-{THREAD_ID}.jsonl"
        rollout.write_text(json.dumps({"type": "event_msg", "payload": {"type": "task_complete"}}) + "\n")
        before = metadata([path, guard, rollout])
        sudo = sudo_availability(scratch) if args.privileged_fixtures else {
            "available": False, "reason": "requires_explicit_privileged_opt_in"}
        if LSOF:
            report["lsofVersion"] = run([LSOF, "-v"], scratch)
        holder, event = start_fixture("held", path)
        try:
            report["cases"].append({"case": "same_uid_holder",
                                    **snapshot(path, scratch, [event])})
            opener, opened = start_fixture("opener", path)
            try:
                measured = snapshot(path, scratch, [event, opened], args.cli)
                records = measured["lsof"].get("processQuery", {}).get("processRecords", [])
                measured["bothSyntheticProcessesVisible"] = {event["pid"], opened["pid"]}.issubset(
                    {record["pid"] for record in records})
                if args.cli and (measured["cliInspection"]["classification"] != "unknown"
                                 or measured["cliInspection"]["safeToUnlock"] is not False):
                    raise RuntimeError("multiple_opener_cli_did_not_refuse")
                report["cases"].append({"case": "same_uid_holder_and_nonlocking_opener", **measured})
            finally:
                stop_fixture(opener)
            if args.privileged_fixtures and sys.platform == "linux":
                namespace = namespace_availability(scratch, sudo)
                if namespace["available"]:
                    result = run(["/usr/bin/sudo", "-n", "--", namespace["unshare"], "--mount", "--propagation", "private", "--pid", "--fork",
                                  "--mount-proc", sys.executable, SCRIPT, "--namespace-observer",
                                  "--lock-path", str(path)], scratch)
                    report["cases"].append({"case": "holder_outside_observer_pid_namespace",
                                            "status": "measured", "result": checked_observer(result)})
                else:
                    report["cases"].append({"case": "holder_outside_observer_pid_namespace",
                                            "status": "skipped", "prerequisite": namespace})
            else:
                report["cases"].append({"case": "holder_outside_observer_pid_namespace", "status": "skipped",
                                        "reason": "requires_explicit_privileged_linux_opt_in"})
        finally:
            stop_fixture(holder)
        inherited, retained = start_fixture("inherited", path)
        try:
            inherited.wait(timeout=5)
            report["cases"].append({"case": "acquirer_exited_inherited_descriptor_retained",
                                    "originalProcessExitStatus": inherited.returncode,
                                    **snapshot(path, scratch, [retained])})
        finally:
            stop_fixture(inherited)
        if sudo["available"]:
            hidden, hidden_event = start_fixture("hidden", path, privileged=True)
            try:
                opener, opened = start_fixture("opener", path)
                try:
                    report["cases"].append({"case": "foreign_uid_holder_and_visible_nonholder",
                                            **snapshot(path, scratch, [hidden_event, opened])})
                finally:
                    stop_fixture(opener)
            finally:
                stop_fixture(hidden)
        else:
            report["cases"].append({"case": "foreign_uid_holder", "status": "skipped",
                                    "prerequisite": sudo})
        report["finalGuardedProbe"] = guarded_probe(path)
        report["fixtureFilesUnchanged"] = before == metadata([path, guard, rollout])
        if report["finalGuardedProbe"] != "free" or not report["fixtureFilesUnchanged"]:
            raise RuntimeError("fixture_cleanup_or_file_invariance_failed")
    emit(report)
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--privileged-fixtures", action="store_true")
    parser.add_argument("--cli", help="built dist/cli.js; runs inspect only")
    parser.add_argument("--self-test", action="store_true", help="check prerequisite and fixture failure handling without sudo")
    parser.add_argument("--privilege-preflight", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--child", choices=("held", "opener", "inherited", "hidden", "failure"), help=argparse.SUPPRESS)
    parser.add_argument("--namespace-observer", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--lock-path", help=argparse.SUPPRESS)
    parsed = parser.parse_args()
    try:
        sys.exit(main(parsed))
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as failure:
        emit({"schemaVersion": 1, "status": "failed", "reason": failure.__class__.__name__,
              "message": str(failure) if isinstance(failure, RuntimeError) else "research_fixture_failed",
              "signalsSent": 0})
        sys.exit(1)
