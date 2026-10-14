#!/usr/bin/env python3
"""Same-user /proc access matrix for one target (#126 research, F2). NOT RUN YET.

Usage: python3 -I observe.py PID FD LOCK_PATH
Records, per read, either a short result or the errno name. Nothing here
treats an error as negative evidence; it only reports which reads fail.
Reads are the ones #137's Linux adapter performs.
"""
import errno
import json
import os
import sys

if sys.platform != "linux" or os.getuid() == 0 or os.getuid() != os.geteuid():
    raise RuntimeError("observer requires unprivileged same-user Linux")
pid, fd, lock_path = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
if pid <= 0 or fd < 0:
    raise ValueError("invalid PID or FD")
base = f"/proc/{pid}"
out = {"pid": pid, "fd": fd, "observer_uid": os.getuid(), "kernel": os.uname().release}


# No self-alarm: a non-fatal signal with a Python handler cannot wake a
# killable kernel wait in a /proc read, so it would not bound this process.
# The runner waits for this observer with a bound and records `incomplete`
# without signalling it.


def attempt(name, fn):
    try:
        out[name] = {"ok": fn()}
    except OSError as error:
        out[name] = {"errno": errno.errorcode.get(error.errno, str(error.errno))}


def read(path, limit=65536):
    with open(path, "rb") as handle:
        return handle.read(limit)


attempt("proc_dir_uid", lambda: os.stat(base).st_uid)
attempt("fd_dir_uid", lambda: os.stat(f"{base}/fd").st_uid)
attempt("fdinfo_dir_uid", lambda: os.stat(f"{base}/fdinfo").st_uid)
attempt("fd_listdir", lambda: sorted(os.listdir(f"{base}/fd"), key=int))
attempt("fd_readlink", lambda: os.readlink(f"{base}/fd/{fd}"))
attempt("fd_stat_matches_lock", lambda: (lambda a, b: [a.st_dev == b.st_dev, a.st_ino == b.st_ino])(os.stat(f"{base}/fd/{fd}"), os.stat(lock_path)))
attempt("fdinfo_lock_rows", lambda: [l for l in read(f"{base}/fdinfo/{fd}").decode().splitlines() if l.startswith("lock:")])
attempt("exe_readlink", lambda: os.readlink(f"{base}/exe"))
attempt("cmdline", lambda: read(f"{base}/cmdline").decode(errors="replace").split("\0"))
attempt("stat_start_ticks", lambda: read(f"{base}/stat").decode().rsplit(") ", 1)[1].split()[19])
attempt("status_uid_line", lambda: [l for l in read(f"{base}/status").decode().splitlines() if l.startswith("Uid:")])
print(json.dumps(out, indent=2))
