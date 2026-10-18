"""Darwin-only same-PID exec experiment; never signals child processes."""
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time


def parse_record(line, stage, pid):
    match = re.fullmatch(rb"(before|after) ([0-9]+) ([0-9]+) ([0-9]+)\n", line)
    if not match or match[1].decode() != stage or int(match[2]) != pid:
        raise ValueError("invalid actor record")
    if int(match[3]) <= 0 or int(match[4]) >= 1000000:
        raise ValueError("invalid start timestamp")
    return {"stage": stage, "pid": pid, "start": [int(match[3]), int(match[4])]}


class Reader:
    def __init__(self, stream):
        self.stream, self.pending, self.total = stream, b"", 0

    def line(self, seconds=3):
        deadline = time.monotonic() + seconds
        while True:
            if b"\n" in self.pending:
                line, self.pending = self.pending.split(b"\n", 1)
                if len(line) > 1024:
                    raise ValueError("line limit")
                return line + b"\n"
            if len(self.pending) > 1024:
                raise ValueError("line limit")
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.stream], [], [], remaining)[0]:
                raise TimeoutError("record timeout")
            chunk = os.read(self.stream.fileno(), 4096)
            if not chunk:
                raise ValueError("EOF before complete record")
            self.total += len(chunk)
            if self.total > 8192:
                raise ValueError("stream limit")
            self.pending += chunk


def capture(argv, children, seconds=15):
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
    children.append(child)
    output = bytearray()
    deadline = time.monotonic() + seconds
    eof = False
    while time.monotonic() < deadline:
        if not eof and select.select([child.stdout], [], [], 0.05)[0]:
            block = os.read(child.stdout.fileno(), 8192)
            if not block:
                eof = True
            output.extend(block)
            if len(output) > 65536:
                raise ValueError("diagnostic output limit")
        if eof and child.poll() is not None:
            if child.returncode != 0:
                raise ValueError("diagnostic failed: " + bytes(output).decode(errors="replace"))
            child.stdout.close()
            return bytes(output).decode().strip()
        if eof:
            time.sleep(0.01)
    raise TimeoutError("diagnostic incomplete; no signal sent")


def probe(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return "held"
        fcntl.flock(fd, fcntl.LOCK_UN)
        return "free"
    finally:
        os.close(fd)


def image(pid):
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    library.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    library.proc_pidpath.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(4096)
    if library.proc_pidpath(pid, buffer, len(buffer)) <= 0:
        raise OSError("proc_pidpath failed")
    return os.fsdecode(buffer.value)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--result", required=True)
    parser.add_argument("--tmp-root", required=True)
    args = parser.parse_args()
    if sys.platform != "darwin":
        raise SystemExit("Darwin required")
    result_fd = os.open(args.result, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                        os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    children, actor, scratch = [], None, None
    result = {"ok": False, "collected": False, "measured": False,
              "safeToUnlock": False, "errors": [], "observations": []}
    try:
        scratch = Path(tempfile.mkdtemp(prefix="codex-exec-", dir=args.tmp_root)).resolve()
        source = Path(__file__).with_name("actor.c")
        result["sourceSha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
        result["runnerSha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        result["platform"] = {"system": os.uname().sysname, "release": os.uname().release,
                              "machine": os.uname().machine}
        a, b, lock = scratch / "actor-before", scratch / "actor-after", scratch / "fixture.lock"
        capture(["/usr/bin/clang", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(a)], children)
        shutil.copyfile(a, b)
        b.chmod(0o700)
        actor = subprocess.Popen([str(a), "before", str(lock), str(b)], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        children.append(actor)
        reader = Reader(actor.stdout)
        for stage, executable in [("before", a), ("after", b)]:
            row = parse_record(reader.line(), stage, actor.pid)
            row["image"] = image(actor.pid)
            row["args"] = capture(["/bin/ps", "-ww", "-p", str(actor.pid), "-o", "args="], children, 3)
            row["lstart"] = capture(["/bin/ps", "-p", str(actor.pid), "-o", "lstart="], children, 3)
            row["probe"] = probe(lock)
            row["expectedImage"] = str(executable)
            result["observations"].append(row)
            if stage == "before":
                actor.stdin.write(b"x")
                actor.stdin.flush()
        actor.stdin.close()
        actor.wait(timeout=3)
        tail = actor.stdout.read(8193)
        if tail or reader.pending:
            raise ValueError("unexpected trailing actor output")
        result["exitCode"] = actor.returncode
        result["afterExitProbe"] = probe(lock)
        result["collected"] = True
        before, after = result["observations"]
        checks = {
            "samePid": before["pid"] == after["pid"],
            "sameKernelStart": before["start"] == after["start"],
            "samePsStart": bool(before["lstart"]) and before["lstart"] == after["lstart"],
            "imagesMatch": all(row["image"] == row["expectedImage"] for row in [before, after]),
            "argvChanged": before["args"] != after["args"] and " before " in before["args"] and " after " in after["args"],
            "lockHeldAcrossExec": before["probe"] == after["probe"] == "held",
            "normalExitAndRelease": actor.returncode == 0 and result["afterExitProbe"] == "free",
        }
        result["checks"] = checks
        result["measured"] = all(checks.values())
    except Exception as error:
        result["errors"].append(f"{type(error).__name__}: {error}")
    finally:
        if actor and actor.stdin and not actor.stdin.closed:
            try:
                actor.stdin.close()
            except OSError as error:
                result["errors"].append(f"stdin_cleanup:{type(error).__name__}")
        deadline = time.monotonic() + 3
        while any(child.poll() is None for child in children) and time.monotonic() < deadline:
            time.sleep(0.02)
        result["pendingPids"] = [child.pid for child in children if child.poll() is None]
        result["childExitCodes"] = [child.poll() for child in children]
        result["ok"] = result["collected"] and result["measured"] and not result["errors"] and not result["pendingPids"]
        if result["ok"] and scratch:
            try:
                shutil.rmtree(scratch)
            except OSError as error:
                result["errors"].append(f"scratch_cleanup:{type(error).__name__}")
                result["ok"] = False
                result["preservedScratch"] = str(scratch)
        elif scratch:
            result["preservedScratch"] = str(scratch)
        with os.fdopen(result_fd, "w") as output:
            json.dump(result, output, indent=2)
            output.write("\n")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
