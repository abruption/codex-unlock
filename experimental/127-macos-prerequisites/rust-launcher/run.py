#!/usr/bin/env python3
"""Run only the supplied synthetic Rust binary; never discover real owners."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace

SHARED = Path(__file__).resolve().parents[2] / "127-macos-contract" / "inherit.py"
spec = importlib.util.spec_from_file_location("macos_contract", SHARED)
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)


def expectation(mode, stage):
    inherited = mode == "inheritable"
    return {
        "probe": "held" if stage == "before_close" or inherited else "free",
        "roles": {"parent": "bit" if stage == "before_close" else "absent",
                  "child": "bit" if inherited else "absent"},
        "scan_valid": True, "unexpected_pids": 0,
    }


def matches(observed, expected):
    return all(key in observed and observed[key] == value for key, value in expected.items())


def ready_errors(mode, parent_pid, keeper, ready):
    errors = []
    if type(ready.get("pid")) is not int or ready["pid"] != parent_pid:
        errors.append("ready_parent_pid_mismatch")
    child_pid = ready.get("child_pid")
    if type(child_pid) is not int or child_pid <= 0 or child_pid == parent_pid:
        errors.append("ready_child_pid_invalid")
    if type(keeper.get("pid")) is not int or keeper["pid"] != child_pid:
        errors.append("keeper_pid_mismatch")
    if keeper.get("has_fd") is not (mode == "inheritable"):
        errors.append("keeper_fd_inheritance_mismatch")
    initial = ready.get("initial_fd_flags")
    before_spawn = ready.get("pre_spawn_fd_flags")
    if type(initial) is not int or initial < 0:
        errors.append("initial_fd_flags_invalid")
    elif initial & 1 == 0:
        errors.append("initial_cloexec_missing")
    if type(before_spawn) is not int or before_spawn < 0:
        errors.append("pre_spawn_fd_flags_invalid")
    elif bool(before_spawn & 1) != (mode == "default"):
        errors.append("pre_spawn_cloexec_mismatch")
    return errors


def complete(report):
    rows = report.get("measurements", [])
    children = report.get("children", [])
    expected_rows = {(m, s) for m in ("default", "inheritable")
                     for s in ("before_close", "after_close")}
    return (len(rows) == 4 and
            {(r.get("mode"), r.get("stage")) for r in rows} == expected_rows and
            all(r.get("matches") is True for r in rows) and len(children) == 2 and
            {c.get("mode") for c in children} == {"default", "inheritable"} and
            all(type(c.get("code")) is int and c["code"] == 0 and
                c.get("keeper_exit") == {"event": "child_exit", "ok": True, "code": 0} and
                c.get("after_exit_probe") == "free" for c in children) and
            report.get("errors") == [] and report.get("incomplete") == [])


def event(reader, expected):
    kind, line = reader.read_line(time.monotonic() + 5)
    if kind != "line":
        raise RuntimeError(f"protocol:{kind}")
    value = json.loads(line)
    if not isinstance(value, dict) or value.get("event") != expected:
        raise RuntimeError(f"expected:{expected}:{value}")
    return value


def require_eof(reader):
    kind, _ = reader.read_line(time.monotonic() + 1)
    if kind != "eof":
        raise RuntimeError(f"unexpected_stdout_tail:{kind}")


def run(binary, result_path, tmp_root):
    # Open result exclusively before starting any process or fixture.
    result_fd = os.open(result_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                        os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    report = {"ok": False, "safeToUnlock": False, "measurements": [], "errors": [], "children": [],
              "startup_events": [],
              "environment": {"system": platform.system(), "release": platform.release(),
                              "machine": platform.machine(), "python": sys.version,
                              "minimum_rust": "1.90.0",
                              "actual_rust": "not inferred; record compiler metadata in CI"}}
    state = SimpleNamespace(pending=[], incomplete=[])
    scratch = None
    try:
        report["script_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        report["shared_sha256"] = hashlib.sha256(SHARED.read_bytes()).hexdigest()
        report["binary_sha256"] = hashlib.sha256(Path(binary).read_bytes()).hexdigest()
        scratch = Path(tempfile.mkdtemp(prefix="codex-rust-inherit-", dir=tmp_root))
        if scratch.stat().st_mode & 0o777 != 0o700:
            raise RuntimeError("scratch_mode")
        for mode in ("default", "inheritable"):
            lock = scratch / f"{mode}.lock"
            # stderr goes to a private regular file, so a full pipe cannot stall
            # the Rust parent. This fixed fixture emits only bounded messages.
            with (scratch / f"{mode}.stderr").open("xb") as err:
                proc = subprocess.Popen([binary, mode, str(lock)], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=err, bufsize=0)
                reader = shared.Framed(proc.stdout.fileno())
                child_exit = None
                try:
                    keeper = event(reader, "keeper")
                    report["startup_events"].append({"mode": mode, "record": keeper})
                    ready = event(reader, "ready")
                    report["startup_events"].append({"mode": mode, "record": ready})
                    failures = ready_errors(mode, proc.pid, keeper, ready)
                    if failures:
                        report["errors"].extend(f"{mode}:{failure}" for failure in failures)
                        raise RuntimeError("startup_validation_failed")
                    roles = {"parent": proc.pid, "child": ready["child_pid"]}
                    for stage in ("before_close", "after_close"):
                        if stage == "after_close":
                            proc.stdin.write(b"close\n")
                            event(reader, "closed")
                        observed = shared.observe(state, str(lock), stage, roles)
                        observed["mode"] = mode
                        observed["expected"] = expectation(mode, stage)
                        observed["matches"] = matches(observed, observed["expected"])
                        report["measurements"].append(observed)
                finally:
                    proc.stdin.close()
                    try:
                        child_exit = event(reader, "child_exit")
                    except Exception as error:
                        report["errors"].append(str(error))
                    try:
                        code = proc.wait(timeout=5)  # wait never sends a signal
                    except subprocess.TimeoutExpired:
                        code = None
                        state.incomplete.append(f"rust_parent:{proc.pid}")
                    report["children"].append({"mode": mode, "pid": proc.pid, "code": code,
                                               "keeper_exit": child_exit})
                    if code != 0 or child_exit != {"event": "child_exit", "ok": True, "code": 0}:
                        report["errors"].append("exit_unconfirmed_or_failed")
                    else:
                        released = shared.probe(str(lock))
                        report["children"][-1]["after_exit_probe"] = released
                        if released != "free":
                            report["errors"].append(f"lock_not_free_after_exit:{mode}:{released}")
                    try:
                        require_eof(reader)
                    except Exception as error:
                        report["errors"].append(str(error))
                    proc.stdout.close()
            if (scratch / f"{mode}.stderr").stat().st_size:
                report["errors"].append(f"stderr:{mode}")
    except Exception as error:
        report["errors"].append(f"{type(error).__name__}:{error}")
    finally:
        report["incomplete"] = state.incomplete
        report["pending_diagnostics"] = [{"pid": p["pid"], "exit": p["proc"].poll()}
                                         for p in state.pending]
        report["scratch"] = str(scratch) if scratch else None
        report["ok"] = complete(report)
        with os.fdopen(result_fd, "w") as output:
            json.dump(report, output, indent=2)
            output.write("\n")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--result", required=True)
    parser.add_argument("--scratch-root", required=True)
    args = parser.parse_args()
    if platform.system() != "Darwin":
        parser.error("macOS only")
    raise SystemExit(run(str(Path(args.binary).resolve()), args.result, args.scratch_root))
