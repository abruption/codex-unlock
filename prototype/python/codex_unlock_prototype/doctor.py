"""Test-only Python implementation of the codex-unlock safety path.

This module is intentionally not installed or published. It must only be run
against synthetic owners in the cross-language tests. No live Codex home is
used by the test runner.
"""

from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path


THREAD_RE = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$", re.I)
LOCK_NAME_RE = re.compile(r"^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\.lock(?: \(deleted\))?$", re.I)
MAX_LAST_RECORD = 8 * 1024 * 1024


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def error_text(exc: BaseException) -> str:
    if isinstance(exc, OSError) and exc.errno is not None:
        return f"{exc.strerror or exc.__class__.__name__}: {exc}"
    return str(exc)


def snapshot(value: os.stat_result) -> dict:
    modified_ms = value.st_mtime_ns / 1_000_000
    return {
        "device": str(value.st_dev), "inode": str(value.st_ino),
        "mode": value.st_mode, "uid": value.st_uid, "links": value.st_nlink,
        "size": value.st_size, "modifiedAt": dt.datetime.fromtimestamp(
            value.st_mtime_ns / 1_000_000_000, dt.timezone.utc
        ).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "modifiedMs": modified_ms,
    }


def same_snapshot(left: dict | None, right: dict | None) -> bool:
    return left is not None and right is not None and all(
        left[field] == right[field] for field in ("device", "inode", "size", "modifiedMs")
    )


def command(executable: str, args: list[str]) -> tuple[int | None, str, str, str | None]:
    """Bounded diagnostic command; never sends a signal to a Codex owner."""
    try:
        child = subprocess.Popen(
            [executable, *args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"},
        )
    except OSError as exc:
        return None, "", "", f"spawn_error: {error_text(exc)}"
    limits = {child.stdout: 1024 * 1024, child.stderr: 256 * 1024}
    captured = {child.stdout: bytearray(), child.stderr: bytearray()}
    sel = selectors.DefaultSelector()
    for pipe in limits:
        os.set_blocking(pipe.fileno(), False)
        sel.register(pipe, selectors.EVENT_READ)
    deadline = time.monotonic() + 5
    failure = None
    try:
        while sel.get_map():
            if time.monotonic() >= deadline:
                failure = "timeout: command exceeded 5000 ms"
                break
            for key, _ in sel.select(max(0, min(0.1, deadline - time.monotonic()))):
                pipe = key.fileobj
                try:
                    chunk = os.read(pipe.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    sel.unregister(pipe)
                    continue
                room = limits[pipe] - len(captured[pipe])
                captured[pipe].extend(chunk[:room])
                if len(chunk) > room:
                    kind = "stdout" if pipe is child.stdout else "stderr"
                    failure = f"{kind}_limit: {kind} exceeded {limits[pipe]} bytes"
                    break
            if failure:
                break
        if not failure:
            try:
                child.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                failure = "timeout: command exceeded 5000 ms"
        if failure:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=0.25)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(child.pid, signal.SIGKILL)  # Diagnostic subprocess only.
                except ProcessLookupError:
                    pass
                child.wait()
    finally:
        sel.close()
        child.stdout.close()
        child.stderr.close()
    return (child.returncode, captured[child.stdout].decode("utf-8", "replace"),
            captured[child.stderr].decode("utf-8", "replace"), failure)


def lsof_executable() -> str | None:
    for candidate in ("/usr/sbin/lsof", "/usr/bin/lsof"):
        if os.access(candidate, os.X_OK):
            return candidate
    from shutil import which
    return which("lsof")


def observe_lock(path: str) -> dict:
    try:
        value = os.lstat(path)
        return {"status": "present", "exists": True,
                "regularFile": stat.S_ISREG(value.st_mode),
                "symlink": stat.S_ISLNK(value.st_mode),
                "ownedByCurrentUser": value.st_uid == os.getuid(),
                "snapshot": snapshot(value)}
    except FileNotFoundError:
        return {"status": "absent", "exists": False, "regularFile": None,
                "symlink": None, "ownedByCurrentUser": None, "snapshot": None}
    except OSError as exc:
        return {"status": "unknown", "exists": False, "regularFile": None,
                "symlink": None, "ownedByCurrentUser": None, "snapshot": None,
                "error": error_text(exc)}


def probe_lock(path: str, before: dict | None = None) -> dict:
    before = before or observe_lock(path)
    result = {"status": "unknown", "method": "flock_exclusive_nonblocking"}
    if before["status"] == "unknown":
        return {**result, "error": before.get("error", "lock file observation failed")}
    if not before["exists"]:
        return {**result, "status": "free"}
    if before["symlink"] or not before["regularFile"] or not before["snapshot"]:
        return {**result, "error": "refusing to probe a symlink or non-regular lock file"}
    fd = None
    try:
        fd = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
        opened = snapshot(os.fstat(fd))
        if (opened["device"], opened["inode"]) != (before["snapshot"]["device"], before["snapshot"]["inode"]):
            return {**result, "error": "lock file changed while it was opened"}
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in (11, 13, 35):
                return {**result, "status": "held"}
            return {**result, "error": error_text(exc)}
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError as exc:
            return {**result, "error": f"probe acquired the lock but unlock failed: {error_text(exc)}"}
        return {**result, "status": "free"}
    except OSError as exc:
        return {**result, "error": error_text(exc)}
    finally:
        if fd is not None:
            os.close(fd)


def lsof_processes(output: str) -> list[dict]:
    found: dict[int, dict] = {}
    current = None
    for token in re.split("[\\x00\\n]", output):
        if len(token) < 2:
            continue
        field, value = token[0], token[1:].strip()
        if field == "p":
            try:
                pid = int(value)
            except ValueError:
                current = None
                continue
            current = found.setdefault(pid, {"pid": pid, "command": None, "uid": None}) if pid > 0 else None
        elif current is not None and field == "c":
            current["command"] = value or None
        elif current is not None and field == "u":
            try:
                current["uid"] = int(value)
            except ValueError:
                pass
    return [found[pid] for pid in sorted(found)]


def ps_field(pid: int, field: str) -> tuple[str, str | None, str | None]:
    status, out, err, failure = command("ps", ["-p", str(pid), "-o", f"{field}="])
    if failure:
        return "unknown", None, failure
    value = out.strip()
    if status == 0:
        return ("present", value, None) if value else ("unknown", None, f"ps returned empty {field} output")
    if status == 1 and not value:
        return "absent", None, None
    return "unknown", None, err.strip() or f"ps exited with status {status}"


def start_time(pid: int) -> dict:
    status, value, error = ps_field(pid, "lstart")
    if status == "absent":
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return {"status": "absent", "startTime": None}
        except OSError as exc:
            return {"status": "unknown", "startTime": None, "error": f"could not confirm PID absence: {error_text(exc)}"}
        return {"status": "unknown", "startTime": None, "error": "ps reported absence while the PID still exists"}
    if status != "present":
        return {"status": "unknown", "startTime": None, "error": error or "process observation failed"}
    try:
        dt.datetime.strptime(value, "%a %b %d %H:%M:%S %Y")
    except ValueError:
        return {"status": "unknown", "startTime": None, "error": "ps returned malformed process start time"}
    return {"status": "present", "startTime": value}


def process_cwd(pid: int) -> str | None:
    if sys.platform == "linux":
        try:
            return os.readlink(f"/proc/{pid}/cwd")
        except OSError:
            pass
    executable = lsof_executable()
    if executable:
        status, out, _, failure = command(executable, ["-a", "-p", str(pid), "-d", "cwd", "-Fn"])
        if status == 0 and not failure:
            return next((token[1:] for token in re.split("[\\x00\\n]", out) if token.startswith("n")), None)
    return None


def process_info(candidate: dict) -> dict:
    pid = candidate["pid"]
    ppid_field, uid_field, tty_field, comm_field, args_field = (
        ps_field(pid, field) for field in ("ppid", "uid", "tty", "comm", "args")
    )
    observed_start = start_time(pid)
    def number(field):
        try:
            return int(field[1])
        except (TypeError, ValueError):
            return None
    ppid, uid = number(ppid_field), number(uid_field)
    tty = tty_field[1] if tty_field[1] not in ("?", "??", "-") else None
    comm, args = comm_field[1], args_field[1]
    base = os.path.basename(comm or "").lower()
    is_codex = (candidate["command"] or "").lower() == "codex" or base == "codex" or base.startswith("codex-") or bool(re.search(r"(^|/)codex(?:\s|$)", args or "", re.I))
    errors = []
    for label, field, missing in (("ppid", ppid_field, ppid is None), ("uid", uid_field, uid is None),
                                  ("command", comm_field, comm is None), ("arguments", args_field, args is None)):
        if missing:
            errors.append(f"{label}_{field[0]}" + (f":{field[2]}" if field[2] else ""))
    if observed_start["status"] != "present":
        errors.append(f"start_time_{observed_start['status']}" + (f":{observed_start.get('error')}" if observed_start.get("error") else ""))
    return {"pid": pid, "ppid": ppid, "uid": uid, "startTime": observed_start["startTime"],
            "tty": tty, "command": comm, "arguments": args, "cwd": process_cwd(pid),
            "lsofCommand": candidate["command"], "identityComplete": all(
                value is not None for value in (ppid, uid, observed_start["startTime"], comm, args)),
            "isCodex": is_codex, "isSharedService": bool(re.search(r"\b(?:app-server|remote-control|daemon)\b", args or "", re.I)),
            "errors": errors}


def lock_openers(path: str) -> tuple[list[dict], str | None]:
    executable = lsof_executable()
    if not executable:
        return [], "lsof is not installed"
    status, out, err, failure = command(executable, ["-nP", "-F0pcu", "--", path])
    if failure:
        return [], failure
    processes = lsof_processes(out)
    if status not in (0, 1) or (status == 1 and processes):
        return [process_info(p) for p in processes], err.strip() or f"lsof exited with status {status}"
    return [process_info(p) for p in processes], None


def owner_lock_files(pid: int, intended: str) -> tuple[list[str], str | None]:
    executable = lsof_executable()
    if not executable:
        return [], "lsof is not installed"
    status, out, err, failure = command(executable, ["-a", "-p", str(pid), "-Fn"])
    if failure or status != 0:
        return [], failure or err.strip() or f"lsof exited with status {status}"
    paths = []
    try:
        intended_canonical = str(Path(intended).parent.resolve(strict=True) / Path(intended).name)
    except OSError as exc:
        return [], f"intended lock directory is unresolved: {error_text(exc)}"
    for token in re.split("[\\x00\\n]", out):
        if not token.startswith("n"):
            continue
        path = token[1:]
        if not LOCK_NAME_RE.fullmatch(os.path.basename(path)) or os.path.basename(os.path.dirname(path)) != "thread-writer-locks":
            continue
        if path.endswith(" (deleted)") or not os.path.isabs(path):
            return [], f"open lock path is unresolved: {path}"
        try:
            value = os.lstat(path)
            if not stat.S_ISREG(value.st_mode) or stat.S_ISLNK(value.st_mode):
                return [], f"open lock path is a symlink or non-regular file: {path}"
            canonical = str(Path(path).parent.resolve(strict=True) / Path(path).name)
        except OSError as exc:
            return [], f"open lock path is unresolved: {error_text(exc)}"
        paths.append(intended if canonical == intended_canonical else canonical)
    return sorted(set(paths)), None


def process_table() -> dict[int, int] | None:
    status, out, _, failure = command("ps", ["-axo", "pid=,ppid="])
    if status != 0 or failure:
        return None
    table = {}
    for line in out.splitlines():
        match = re.fullmatch(r"\s*(\d+)\s+(\d+)\s*", line)
        if match:
            table[int(match[1])] = int(match[2])
    return table or None


def process_family(table: dict[int, int] | None) -> set[int] | None:
    if table is None:
        return None
    family = set()
    current = os.getpid()
    while current > 0 and current not in family:
        family.add(current)
        current = table.get(current, 0)
    return family


def descendants(pid: int, table: dict[int, int] | None) -> list[int] | None:
    if table is None:
        return None
    result, queue = set(), [pid]
    while queue:
        parent = queue.pop(0)
        for candidate, ppid in table.items():
            if ppid == parent and candidate not in result:
                result.add(candidate)
                queue.append(candidate)
    return sorted(result)


def transcript_candidates(home: str, thread_id: str) -> list[str]:
    found = []
    suffix = f"-{thread_id}.jsonl"
    for area in ("sessions", "archived_sessions"):
        root = Path(home) / area
        if not root.exists():
            continue
        for directory, _, files in os.walk(root, followlinks=False):
            found.extend(str(Path(directory) / name) for name in files if name.endswith(suffix))
    return sorted(found)


def last_line(path: str, size: int) -> str | None:
    if size == 0:
        return None
    with open(path, "rb") as stream:
        position, buffer = size, b""
        while position > 0 and len(buffer) < MAX_LAST_RECORD:
            length = min(65536, position)
            position -= length
            stream.seek(position)
            buffer = stream.read(length) + buffer
            end = len(buffer)
            while end and buffer[end - 1] in (10, 13):
                end -= 1
            if end == 0:
                continue
            newline = buffer.rfind(b"\n", 0, end)
            if newline >= 0 or position == 0:
                return buffer[newline + 1:end].decode("utf-8", "replace")
    raise ValueError(f"last rollout record exceeds {MAX_LAST_RECORD} bytes or is incomplete")


def inspect_transcript(candidates: list[str]) -> dict:
    if not candidates:
        return {"status": "missing", "path": None, "candidates": [], "snapshot": None,
                "lastRecord": None, "stable": None}
    if len(candidates) != 1:
        return {"status": "ambiguous", "path": None, "candidates": candidates, "snapshot": None,
                "lastRecord": None, "stable": None,
                "error": f"found {len(candidates)} rollout files ending in {Path(candidates[0]).name}"}
    path = candidates[0]
    try:
        before_stat = os.lstat(path)
        before = snapshot(before_stat)
        if not stat.S_ISREG(before_stat.st_mode) or stat.S_ISLNK(before_stat.st_mode):
            return {"status": "unreadable", "path": path, "candidates": candidates,
                    "snapshot": before, "lastRecord": None, "stable": None,
                    "error": "transcript is a symlink or non-regular file"}
        line = last_line(path, before_stat.st_size)
        record = None
        if line is not None:
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError("last rollout record is not a JSON object")
            payload = value.get("payload")
            payload = payload if isinstance(payload, dict) else {}
            record = {"recordType": value.get("type") if isinstance(value.get("type"), str) else None,
                      "eventType": payload.get("type") if isinstance(payload.get("type"), str) else None,
                      "timestamp": value.get("timestamp") if isinstance(value.get("timestamp"), str) else None,
                      "ordinal": value.get("ordinal") if isinstance(value.get("ordinal"), (int, float)) and not isinstance(value.get("ordinal"), bool) else None}
        after = snapshot(os.lstat(path))
        return {"status": "found", "path": path, "candidates": candidates,
                "snapshot": after, "lastRecord": record, "stable": same_snapshot(before, after)}
    except (OSError, ValueError, UnicodeError) as exc:
        return {"status": "unreadable", "path": path, "candidates": candidates,
                "snapshot": None, "lastRecord": None, "stable": None, "error": error_text(exc)}


def stable_hash(path: str) -> tuple[str, dict]:
    before_stat = os.lstat(path)
    if not stat.S_ISREG(before_stat.st_mode) or stat.S_ISLNK(before_stat.st_mode):
        raise ValueError("transcript is a symlink or non-regular file")
    before = snapshot(before_stat)
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    after = snapshot(os.lstat(path))
    if not same_snapshot(before, after):
        raise ValueError("transcript changed while hashing")
    return digest.hexdigest(), after


def evaluate_safety(result: dict, family: set[int] | None, opener_error: str | None,
                    owner_lock_error: str | None) -> tuple[list[str], list[str]]:
    blockers, warnings = [], []
    def block(value):
        if value not in blockers:
            blockers.append(value)
    def warn(value):
        if value not in warnings:
            warnings.append(value)
    lock, owner, transcript = result["lock"], result["owner"], result["transcript"]
    if result["classification"] != "live_owner":
        block(f"classification_{result['classification']}")
    if not lock["exists"]: block("lock_file_absent")
    if lock["observation"] == "unknown": block("lock_file_observation_failed")
    if lock["regularFile"] is not True: block("lock_file_not_regular")
    if lock["symlink"] is not False: block("lock_file_symlink_or_unknown")
    if lock["ownedByCurrentUser"] is not True: block("lock_file_wrong_owner")
    if lock["snapshot"] and lock["snapshot"]["links"] != 1: block("lock_file_has_multiple_links")
    if lock["stable"] is not True: block("lock_file_not_stable")
    if lock["probe"]["status"] != "held": block(f"lock_probe_{lock['probe']['status']}")
    if opener_error: block("lock_opener_lookup_failed")
    if len(result["openers"]) != 1: block("lock_owner_not_unique")
    if result["ownerIdentityStable"] is not True: block("lock_owner_identity_not_stable")
    if owner is None:
        block("lock_owner_unavailable")
    else:
        if not owner["identityComplete"]: block("lock_owner_identity_incomplete")
        if not owner["isCodex"]: block("lock_owner_is_not_codex")
        if owner["isSharedService"]: block("lock_owner_is_shared_service")
        if owner["uid"] != os.getuid(): block("lock_owner_wrong_user")
        if family is None: block("current_process_family_unavailable")
        elif owner["pid"] in family: block("lock_owner_is_current_process_family")
        if owner["tty"] is None: warn("lock_owner_has_no_tty")
    if owner_lock_error: block("owner_lock_file_lookup_failed")
    if result["ownerLockFiles"] is None:
        block("owner_lock_files_unavailable")
    elif result["ownerLockFiles"] != [lock["path"]]:
        block("owner_holds_other_thread_locks")
    if result["descendantPids"] is None:
        warn("owner_descendants_unavailable")
    elif result["descendantPids"]:
        warn("owner_has_descendants:" + ",".join(map(str, result["descendantPids"])))
    if transcript["status"] != "found": block(f"transcript_{transcript['status']}")
    if transcript["stable"] is not True: block("transcript_not_stable")
    record = transcript["lastRecord"]
    if not record or record["recordType"] != "event_msg" or record["eventType"] != "task_complete":
        block("transcript_last_event_not_task_complete")
    return blockers, warnings


def inspect_thread(thread_id: str, home: str, stability_ms: int) -> dict:
    thread_id = thread_id.lower()
    if not THREAD_RE.fullmatch(thread_id):
        raise ValueError(f"invalid Codex thread id: {thread_id}")
    path = str(Path(home) / "thread-writer-locks" / f"{thread_id}.lock")
    def sample():
        candidates = transcript_candidates(home, thread_id)
        lock = observe_lock(path)
        probe = probe_lock(path, lock)
        openers, opener_error = lock_openers(path)
        transcript = inspect_transcript(candidates)
        return candidates, lock, probe, openers, opener_error, transcript
    first = sample()
    time.sleep(stability_ms / 1000)
    candidates, lock, probe, openers, opener_error, transcript = sample()
    lock_stable = (first[1]["status"] != "unknown" and lock["status"] != "unknown" and
                   (not first[1]["exists"] and not lock["exists"] or same_snapshot(first[1]["snapshot"], lock["snapshot"])))
    probe_stable = first[2]["status"] == probe["status"]
    transcript["stable"] = (first[0] == candidates and first[5]["status"] == "found" and
                            transcript["status"] == "found" and first[5]["path"] == transcript["path"] and
                            first[5]["stable"] is True and transcript["stable"] is True and
                            same_snapshot(first[5]["snapshot"], transcript["snapshot"]) and
                            first[5]["lastRecord"] == transcript["lastRecord"])
    identity_stable = ((first[3][0]["pid"] == openers[0]["pid"] and
                        first[3][0]["startTime"] is not None and
                        first[3][0]["startTime"] == openers[0]["startTime"])
                       if len(first[3]) == len(openers) == 1 else
                       None if len(first[3]) == len(openers) == 0 else False)
    owner_error = first[4] or opener_error
    if lock["status"] == "unknown" or (lock["status"] == "present" and (not lock_stable or not probe_stable or probe["status"] == "unknown")):
        classification = "unknown"
    elif lock["status"] == "absent":
        classification = "absent" if lock_stable and probe_stable else "unknown"
    elif probe["status"] == "free":
        classification = "stale_residue"
    elif not owner_error and len(openers) == 1 and openers[0]["identityComplete"] and identity_stable is True:
        classification = "live_owner"
    else:
        classification = "unknown"
    owner = openers[0] if len(openers) == 1 else None
    owner_files, owner_lock_error = owner_lock_files(owner["pid"], path) if owner else (None, None)
    table = process_table()
    result = {"schemaVersion": 1, "command": "inspect", "inspectedAt": now(),
              "codexHome": home, "threadId": thread_id, "classification": classification,
              "lock": {"path": path, "observation": lock["status"], "exists": lock["exists"],
                       "regularFile": lock["regularFile"], "symlink": lock["symlink"],
                       "ownedByCurrentUser": lock["ownedByCurrentUser"], "snapshot": lock["snapshot"],
                       "stable": lock_stable and probe_stable, "probe": probe,
                       **({"observationError": lock["error"]} if lock.get("error") else {})},
              "owner": owner, "openers": openers, "ownerIdentityStable": identity_stable,
              "ownerLockFiles": owner_files, "descendantPids": descendants(owner["pid"], table) if owner else None,
              "transcript": transcript}
    blockers, warnings = evaluate_safety(result, process_family(table), owner_error, owner_lock_error)
    result.update(safeToUnlock=not blockers, blockers=blockers, warnings=warnings)
    return result


def list_threads(home: str, stability_ms: int) -> dict:
    directory = Path(home) / "thread-writer-locks"
    try:
        names = os.listdir(directory)
    except FileNotFoundError:
        names = []
    ids = sorted({name[:-5].lower() for name in names if name.endswith(".lock") and THREAD_RE.fullmatch(name[:-5])})
    sessions = [inspect_thread(thread_id, home, stability_ms) for thread_id in ids]
    return {"schemaVersion": 1, "command": "list", "inspectedAt": now(),
            "codexHome": home, "count": len(sessions), "sessions": sessions}


class Lease:
    def __init__(self, fd: int):
        self.fd = fd

    def release(self) -> None:
        if self.fd < 0:
            return
        try:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
        finally:
            os.close(self.fd)
            self.fd = -1


def acquire_lease(home: str, thread_id: str) -> tuple[str, Lease | str]:
    uid = os.getuid()
    configured = os.environ.get("XDG_RUNTIME_DIR")
    if configured:
        try:
            base = os.lstat(configured)
            if (not os.path.isabs(configured) or not stat.S_ISDIR(base.st_mode) or
                    stat.S_ISLNK(base.st_mode) or base.st_uid != uid or base.st_mode & 0o077):
                return "unknown", "coordination_directory_unavailable"
        except OSError:
            return "unknown", "coordination_directory_unavailable"
        root = Path(configured) / "codex-unlock"
    else:
        root = Path(tempfile.gettempdir()) / f"codex-unlock-{uid}"
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        root_stat = os.lstat(root)
        if (not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode) or
                root_stat.st_uid != uid or root_stat.st_mode & 0o077):
            return "unknown", "coordination_directory_is_not_private"
        os.chmod(root, 0o700)
        canonical = str(Path(home).resolve(strict=True))
    except OSError:
        return "unknown", "coordination_directory_unavailable"
    key = hashlib.sha256((canonical + "\0" + thread_id).encode()).hexdigest()
    fd = None
    try:
        fd = os.open(root / f"{key}.lock", os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
        value = os.fstat(fd)
        if (not stat.S_ISREG(value.st_mode) or value.st_uid != uid or value.st_nlink != 1 or
                value.st_mode & 0o077):
            return "unknown", "coordination_file_is_not_private"
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            return ("contended", "") if exc.errno in (11, 13, 35) else ("unknown", "coordination_lock_failed")
        lease = Lease(fd)
        fd = None
        return "acquired", lease
    except OSError:
        return "unknown", "coordination_file_unavailable"
    finally:
        if fd is not None:
            os.close(fd)


def result(inspection: dict, outcome: str, *, changed=False, pid=None, signal_sent=None,
           process_exited=None, process_observation=None, lock_released=False,
           transcript_unchanged=None, reasons=None) -> dict:
    return {"schemaVersion": 1, "command": "unlock", "attemptedAt": now(),
            "threadId": inspection["threadId"], "lockFileRemovedByTool": False,
            "inspection": inspection, "outcome": outcome, "changed": changed,
            "pid": pid, "signalSent": signal_sent, "processExited": process_exited,
            "processObservation": process_observation, "lockReleased": lock_released,
            "transcriptUnchanged": transcript_unchanged, "reasons": reasons or []}


def same_owner(before: dict, after: dict) -> bool:
    fields = ("pid", "ppid", "uid", "startTime", "command", "arguments",
              "identityComplete", "isCodex", "isSharedService")
    return before["startTime"] is not None and all(before[key] == after[key] for key in fields)


def original_exited(original: str, observed: dict) -> bool | None:
    if observed["status"] == "unknown":
        return None
    return observed["status"] == "absent" or observed["startTime"] != original


def unlock_inspected(inspection: dict, home: str, stability_ms: int, timeout_ms: int) -> dict:
    classification = inspection["classification"]
    if classification in ("absent", "stale_residue"):
        return result(inspection, "not_locked", lock_released=True, reasons=[classification])
    owner = inspection["owner"]
    path = inspection["transcript"]["path"]
    if not inspection["safeToUnlock"] or not owner or not path:
        return result(inspection, "refused", pid=owner["pid"] if owner else None,
                      reasons=inspection["blockers"])
    reasons = []
    before_hash = None
    try:
        before_hash, before_snapshot = stable_hash(path)
        if not same_snapshot(before_snapshot, inspection["transcript"]["snapshot"]):
            reasons.append("transcript_changed_after_inspection")
    except (OSError, ValueError) as exc:
        reasons.append(f"transcript_hash_failed:{error_text(exc)}")
    final = inspect_thread(inspection["threadId"], home, stability_ms)
    if not final["safeToUnlock"]:
        reasons.extend(f"revalidation_{blocker}" for blocker in final["blockers"])
    if not final["owner"] or not same_owner(owner, final["owner"]):
        reasons.append("owner_identity_changed")
    if not same_snapshot(inspection["lock"]["snapshot"], final["lock"]["snapshot"]):
        reasons.append("lock_file_changed")
    if final["lock"]["probe"]["status"] != "held" or final["lock"]["observation"] != "present":
        reasons.append("lock_no_longer_held")
    if (inspection["ownerLockFiles"] is None or final["ownerLockFiles"] is None or
            inspection["ownerLockFiles"] != final["ownerLockFiles"]):
        reasons.append("owner_lock_set_changed")
    if (path != final["transcript"]["path"] or
            not same_snapshot(inspection["transcript"]["snapshot"], final["transcript"]["snapshot"]) or
            inspection["transcript"]["lastRecord"] != final["transcript"]["lastRecord"]):
        reasons.append("transcript_changed_after_inspection")
    if final["transcript"]["path"] and before_hash is not None:
        try:
            final_hash, final_snapshot = stable_hash(final["transcript"]["path"])
            if final_hash != before_hash or not same_snapshot(final_snapshot, final["transcript"]["snapshot"]):
                reasons.append("transcript_changed_during_revalidation")
        except (OSError, ValueError) as exc:
            reasons.append(f"transcript_revalidation_hash_failed:{error_text(exc)}")
    if reasons:
        return result(inspection, "refused", pid=owner["pid"], reasons=list(dict.fromkeys(reasons)))
    try:
        os.kill(owner["pid"], signal.SIGTERM)
    except OSError as exc:
        return result(inspection, "termination_failed", pid=owner["pid"],
                      reasons=[f"sigterm_failed:{error_text(exc)}"])
    deadline = time.monotonic() + timeout_ms / 1000
    observed = {"status": "present", "startTime": owner["startTime"]}
    exited, released = False, False
    lock_probe = probe_lock(inspection["lock"]["path"])
    while time.monotonic() <= deadline:
        observed = start_time(owner["pid"])
        lock_probe = probe_lock(inspection["lock"]["path"])
        exited = original_exited(owner["startTime"], observed)
        released = lock_probe["status"] == "free"
        if exited is True and released:
            break
        time.sleep(0.1)
    unchanged = None
    reasons = []
    try:
        unchanged = stable_hash(path)[0] == before_hash
        if not unchanged:
            reasons.append("transcript_changed_during_unlock")
    except (OSError, ValueError) as exc:
        reasons.append(f"post_unlock_transcript_hash_failed:{error_text(exc)}")
    if exited is None:
        reasons.append(f"owner_exit_unknown:{observed.get('error', 'process observation failed')}")
    elif not exited:
        reasons.append("owner_did_not_exit_before_timeout")
    if not released:
        reasons.append(f"lock_release_unknown:{lock_probe.get('error', 'lock probe failed')}" if lock_probe["status"] == "unknown" else "lock_was_not_released")
    verified = exited is True and released and unchanged is True
    outcome = "unlocked" if verified else "verification_failed" if exited and released else "termination_failed"
    return result(inspection, outcome, changed=True, pid=owner["pid"], signal_sent="SIGTERM",
                  process_exited=exited, process_observation=observed, lock_released=released,
                  transcript_unchanged=unchanged, reasons=reasons)


def unlock_thread(thread_id: str, home: str, stability_ms: int, timeout_ms: int,
                  after_inspect=None, after_lease=None) -> dict:
    inspection = inspect_thread(thread_id, home, stability_ms)
    if after_inspect is not None:
        after_inspect(inspection)  # Deterministic test-only mutation seam.
    if not inspection["safeToUnlock"] or not inspection["owner"] or not inspection["transcript"]["path"]:
        return unlock_inspected(inspection, home, stability_ms, timeout_ms)
    status, lease = acquire_lease(home, inspection["threadId"])
    if status != "acquired":
        reason = "concurrent_unlock_in_progress" if status == "contended" else f"unlock_coordination_failed:{lease}"
        return result(inspection, "refused", pid=inspection["owner"]["pid"], reasons=[reason])
    try:
        if after_lease is not None:
            after_lease(inspection)
        return unlock_inspected(inspection, home, stability_ms, timeout_ms)
    finally:
        lease.release()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="codex-unlock Python safety prototype")
    parser.add_argument("command", choices=("list", "inspect", "unlock"))
    parser.add_argument("thread_id", nargs="?")
    parser.add_argument("--codex-home", required=True)
    parser.add_argument("--stability-ms", type=int, default=1000)
    parser.add_argument("--timeout-ms", type=int, default=5000)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--test-gate", help=argparse.SUPPRESS)
    parser.add_argument("--test-gate-stage", choices=("after-inspect", "after-lease"),
                        default="after-inspect", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if not args.json or args.stability_ms < 250 or args.stability_ms > 30_000 or args.timeout_ms < 100 or args.timeout_ms > 60_000:
        parser.error("prototype requires --json and valid timing options")
    if (args.command == "list") != (args.thread_id is None):
        parser.error("list takes no thread ID; inspect and unlock require one")
    home = os.path.abspath(args.codex_home)
    try:
        def test_gate(_inspection):
            if args.test_gate is None:
                return
            gate = Path(args.test_gate)
            if not gate.is_dir() or not gate.resolve().is_relative_to(Path(home).resolve()):
                raise ValueError("test gate must be inside the explicit fixture home")
            (gate / "ready").touch(exist_ok=False)
            deadline = time.monotonic() + 10
            while not (gate / "go").exists():
                if time.monotonic() >= deadline:
                    raise ValueError("test gate timed out")
                time.sleep(0.025)
        value = (list_threads(home, args.stability_ms) if args.command == "list" else
                 inspect_thread(args.thread_id, home, args.stability_ms) if args.command == "inspect" else
                 unlock_thread(args.thread_id, home, args.stability_ms, args.timeout_ms,
                               test_gate if args.test_gate and args.test_gate_stage == "after-inspect" else None,
                               test_gate if args.test_gate and args.test_gate_stage == "after-lease" else None))
    except (OSError, ValueError) as exc:
        value = {"schemaVersion": 1, "command": args.command, "status": "error", "error": error_text(exc),
                 "errorCode": "command_failed", "exitCode": 3, "retryable": False, "suggestedAction": None}
    print(json.dumps(value, separators=(",", ":")))
    return value.get("exitCode", 2 if value.get("outcome") == "refused" else
                     3 if value.get("outcome") in ("termination_failed", "verification_failed") else 0)
