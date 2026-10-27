#!/usr/bin/env python3
"""Deterministic tests for inherit.py helpers (#127 research).

  RESEARCH_TMP_ROOT=<approved root> python3 -I experimental/127-macos-contract/test_inherit.py

Uses only finite synthetic children started here. No signals are sent.
"""

import copy
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import inherit  # noqa: E402

ROOT = os.environ.get("RESEARCH_TMP_ROOT")
PY = sys.executable


def scratch():
    if not ROOT:
        raise unittest.SkipTest("RESEARCH_TMP_ROOT is required")
    path = Path(tempfile.mkdtemp(prefix="codex-127-test-", dir=ROOT))
    path.chmod(0o700)
    return path


class FramedTest(unittest.TestCase):
    def pipe(self, data, close=True):
        r, w = os.pipe()
        os.write(w, data)
        if close:
            os.close(w)
            w = None
        return r, w

    def test_two_lines_in_one_chunk_are_both_returned(self):
        r, _ = self.pipe(b'{"a":1}\n{"b":2}\n')
        f = inherit.Framed(r)
        self.assertEqual(f.read_line(time.monotonic() + 1), ("line", b'{"a":1}'))
        self.assertEqual(f.read_line(time.monotonic() + 1), ("line", b'{"b":2}'))
        self.assertEqual(f.read_line(time.monotonic() + 1), ("eof", None))
        os.close(r)

    def test_partial_line_times_out_and_is_kept(self):
        r, w = self.pipe(b'{"a":', close=False)
        f = inherit.Framed(r)
        self.assertEqual(f.read_line(time.monotonic() + 0.1), ("timeout", None))
        os.write(w, b"1}\n")
        self.assertEqual(f.read_line(time.monotonic() + 1), ("line", b'{"a":1}'))
        os.close(w)
        os.close(r)

    def test_partial_line_at_eof_is_not_a_line(self):
        r, _ = self.pipe(b'{"a":1}')
        self.assertEqual(inherit.Framed(r).read_line(time.monotonic() + 1), ("unterminated", None))
        os.close(r)

    def test_complete_line_boundary(self):
        for size in (63, 64, 65):
            with self.subTest(size=size):
                r, _ = self.pipe(b"x" * size + b"\n")
                try:
                    expected = ("line", b"x" * size) if size <= 64 else ("limit", None)
                    self.assertEqual(inherit.Framed(r, line_limit=64).read_line(time.monotonic() + 1), expected)
                finally:
                    os.close(r)

    def test_newline_in_next_chunk_cannot_bypass_line_cap(self):
        for tail, expected in ((b"\n", "line"), (b"x\n", "limit")):
            with self.subTest(tail=tail):
                framed = inherit.Framed(123, line_limit=64)
                with mock.patch.object(inherit.select, "select", return_value=([123], [], [])), \
                        mock.patch.object(inherit.os, "read", side_effect=[b"x" * 64, tail]):
                    self.assertEqual(framed.read_line(time.monotonic() + 1)[0], expected)

    def test_stream_overflow_rejects_buffered_valid_event(self):
        event = b'{"event":"ready"}\n'
        r, _ = self.pipe(event + b"x")
        try:
            framed = inherit.Framed(r, stream_limit=len(event))
            self.assertEqual(framed.read_line(time.monotonic() + 1), ("limit", None))
            self.assertEqual(framed.read_line(time.monotonic() + 1), ("limit", None))
        finally:
            os.close(r)

    def test_line_and_stream_limits(self):
        r, _ = self.pipe(b"x" * 200)
        self.assertEqual(inherit.Framed(r, line_limit=64).read_line(time.monotonic() + 1), ("limit", None))
        os.close(r)
        r, _ = self.pipe(b"ok\n" * 100)
        f = inherit.Framed(r, line_limit=64, stream_limit=10)
        statuses = [f.read_line(time.monotonic() + 1)[0] for _ in range(5)]
        self.assertIn("limit", statuses)
        os.close(r)

    def test_events_must_be_objects_with_a_string_event(self):
        self.assertEqual(inherit.parse_event(b'{"event":"ready","pid":1}'), {"event": "ready", "pid": 1})
        for bad in (b"", b"nope", b"[1]", b'{"pid":1}', b'{"event":3}', b"\xff"):
            self.assertIsNone(inherit.parse_event(bad), bad)


class ParseFgTest(unittest.TestCase):
    GOOD = b"p100\0\nf3\0G0x4003;0x3\0\np200\0\nf4\0G0x3;0x0\0\n"

    def test_valid_output(self):
        parsed = inherit.parse_fg(self.GOOD)
        self.assertEqual(parsed["problems"], [])
        self.assertTrue(parsed["pids"]["100"][0]["was_locked"])
        self.assertFalse(parsed["pids"]["200"][0]["was_locked"])

    def test_empty_output_has_no_records(self):
        # lsof exits 1 with no output when nothing has the file open.
        self.assertEqual(inherit.parse_fg(b""), {"problems": [], "pids": {}})

    def test_deviations_are_problems_never_no_bit(self):
        cases = {
            "missing G": b"p100\0\nf3\0\n",
            "G before f": b"p100\0\nG0x4003;0x3\0f3\0\n",
            "non-hex flags": b"p100\0\nf3\0G0xzz;0x3\0\n",
            "flags without second field": b"p100\0\nf3\0G0x4003\0\n",
            "unknown tag": b"p100\0\nn/tmp/x\0\n",
            "non-numeric pid": b"pabc\0\nf3\0G0x4003;0x3\0\n",
            "fd before pid": b"f3\0G0x4003;0x3\0\n",
            "unterminated record": b"p100\0\nf3\0G0x4003;0x3\n",
            "unterminated output": b"p100\0\nf3\0G0x4003;0x3\0",
            "pid without fd": b"p100\0\n",
            "duplicate pid": b"p100\0\nf3\0G0x3;0x0\0\np100\0\nf4\0G0x3;0x0\0\n",
        }
        for name, out in cases.items():
            with self.subTest(name):
                self.assertNotEqual(inherit.parse_fg(out)["problems"], [], name)


def stage(name, probe, roles, valid=True, unexpected=0):
    return {"stage": name, "probe": probe, "roles": roles, "scan_valid": valid, "unexpected_pids": unexpected}


def nominal():
    scenarios = {}
    for name, expected in inherit.EXPECTED_STAGES.items():
        stages = [stage(*e) for e in expected]
        closed = {"event": "closed", "who": inherit.CLOSED_WHO[name]}
        if name == "scm_rights":
            scenarios[name] = {"stages": stages, "closed": closed, "sent": {"event": "ready", "pid": 10},
                               "received": {"event": "ready", "pid": 11, "received": 1},
                               "finish": [{"exit": 0, "events": []}, {"exit": 0, "events": []}]}
        else:
            ready = {"event": "ready", "pid": 10, "child_pid": 11}
            if name in inherit.KEEPER_HAS_FD:
                ready["keeper"] = {"event": "keeper_ready", "pid": 11, "has_fd": inherit.KEEPER_HAS_FD[name]}
            scenarios[name] = {"stages": stages, "closed": closed, "ready": ready,
                               "finish": {"exit": 0, "events": [{"code": 0, "event": "child_exit"}]}}
    return scenarios


class EvaluateTest(unittest.TestCase):
    def test_script_identity_compares_start_and_end_hashes(self):
        with mock.patch.object(inherit, "script_sha256", return_value="a" * 64):
            self.assertTrue(inherit.script_identity("a" * 64)["unchanged"])
            changed = inherit.script_identity("b" * 64)
            self.assertFalse(changed["unchanged"])
            self.assertEqual(changed["start_sha256"], "b" * 64)
            self.assertEqual(changed["end_sha256"], "a" * 64)

    def test_nominal_table_passes(self):
        self.assertEqual(inherit.evaluate(nominal()), [])

    def mutate(self, fn):
        scenarios = copy.deepcopy(nominal())
        fn(scenarios)
        return inherit.evaluate(scenarios)

    def test_counterexamples_fail(self):
        def bit(s):
            s["fork_shared"]["stages"][0]["roles"]["forked_child"] = "no_bit"

        def invalid(s):
            s["scm_rights"]["stages"][1]["scan_valid"] = False

        def unexpected(s):
            s["exec_inherit"]["stages"][0]["unexpected_pids"] = 1

        def probe_error(s):
            s["exec_cloexec"]["stages"][1]["probe"] = "error:EIO"

        def keeper(s):
            s["exec_cloexec"]["ready"]["keeper"]["has_fd"] = True

        def keeper_missing(s):
            del s["exec_inherit"]["ready"]["keeper"]

        def received(s):
            s["scm_rights"]["received"]["received"] = 2

        def closed(s):
            s["fork_shared"]["closed"] = None

        def child_exit(s):
            s["exec_inherit"]["finish"]["events"] = [{"code": 3, "event": "child_exit"}]

        def missing(s):
            del s["scm_rights"]

        def stage_order(s):
            s["fork_shared"]["stages"].reverse()

        def same_pid(s):
            s["fork_shared"]["ready"]["child_pid"] = 10

        for fn in (bit, invalid, unexpected, probe_error, keeper, keeper_missing, received, closed,
                   child_exit, missing, stage_order, same_pid):
            with self.subTest(fn.__name__):
                self.assertNotEqual(self.mutate(fn), [], fn.__name__)


class ProcessTest(unittest.TestCase):
    def setUp(self):
        self.dir = scratch()
        self.run = inherit.Run(self.dir)

    def tearDown(self):
        shutil.rmtree(self.dir)

    def test_diagnostic_timeout_is_incomplete_and_unsignalled(self):
        result = inherit.run_diagnostic(self.run, [PY, "-I", "-c", "import time; time.sleep(1.0)"], timeout=0.2)
        self.assertIsNone(result["status"])
        self.assertTrue(self.run.incomplete[0].startswith("diagnostic_timeout:"))
        self.assertEqual(self.run.poll_pending()[0]["state"], "running")
        time.sleep(1.5)
        self.assertEqual(self.run.poll_pending()[0]["state"], "exited:0")
        for item in self.run.pending:
            item["proc"].stdout.close()
            item["proc"].stderr.close()

    def test_diagnostic_output_is_capped(self):
        result = inherit.run_diagnostic(self.run, [PY, "-I", "-c", "import sys; sys.stdout.write('x' * 300000)"], limit=1000)
        self.assertEqual(result["status"], 0)
        self.assertEqual(len(result["stdout"]), 1000)
        self.assertIn("output_limit", result["problems"])

    def test_early_exit_is_a_failure_not_ready(self):
        actor = self.run.start("early", [PY, "-I", "-c", "pass"])
        self.assertIsNone(self.run.read_event(actor, "ready"))
        self.assertEqual(self.run.failures, ["early:eof"])
        self.assertEqual(self.run.finish(actor)["exit"], 0)

    def test_not_ready_event_is_not_ready(self):
        body = "import json,sys; print(json.dumps({'event':'failed','reason':'keeper_not_ready:timeout'})); sys.stdout.flush(); sys.stdin.read()"
        actor = self.run.start("keeper", [PY, "-I", "-c", body])
        self.assertIsNone(self.run.read_event(actor, "ready"))
        self.assertEqual(self.run.failures, ["keeper:unexpected_event:failed:keeper_not_ready:timeout"])
        self.assertEqual(self.run.finish(actor)["exit"], 0)

    def test_partial_line_then_silence_is_incomplete(self):
        body = "import sys,time; sys.stdout.write('{\"event\":'); sys.stdout.flush(); sys.stdin.read()"
        actor = self.run.start("partial", [PY, "-I", "-c", body])
        old = inherit.READY_TIMEOUT
        inherit.READY_TIMEOUT = 0.3
        try:
            self.assertIsNone(self.run.read_event(actor, "ready"))
        finally:
            inherit.READY_TIMEOUT = old
        self.assertEqual(self.run.incomplete, ["partial:no_event"])
        self.assertEqual(self.run.finish(actor)["exit"], 0)

    def test_finish_all_closes_every_registered_actor(self):
        body = "import sys; sys.stdin.read()"
        actors = [self.run.start(f"a{i}", [PY, "-I", "-c", body]) for i in range(2)]
        self.run.finish_all()
        self.assertEqual([a["finished"]["exit"] for a in actors], [0, 0])

    def test_valid_event_followed_by_partial_tail_fails_finish(self):
        body = "import sys; sys.stdout.write('{\"event\":\"ready\"}\\n{\"event\":'); sys.stdout.flush(); sys.stdin.read()"
        actor = self.run.start("tail", [PY, "-I", "-c", body])
        self.assertEqual(self.run.read_event(actor, "ready"), {"event": "ready"})
        self.assertEqual(self.run.finish(actor)["exit"], 0)
        self.assertIn("tail:output_unterminated", self.run.failures)

    def test_finish_all_continues_after_actor_exception(self):
        body = "import sys; sys.stdin.read()"
        actors = [self.run.start(f"a{i}", [PY, "-I", "-c", body]) for i in range(2)]
        finish = self.run.finish

        def faulty(actor):
            if actor is actors[0]:
                raise OSError("synthetic broken output")
            return finish(actor)

        try:
            with mock.patch.object(self.run, "finish", side_effect=faulty):
                self.run.finish_all()
            self.assertEqual(actors[1]["finished"]["exit"], 0)
            self.assertIn("a0:finish_error:OSError", self.run.failures)
            self.assertTrue(self.run.incomplete[0].startswith("a0:finish_unconfirmed:"))
        finally:
            finish(actors[0])

    def test_result_file_refuses_existing_and_symlink(self):
        existing = self.dir / "existing.json"
        existing.write_text("{}")
        with self.assertRaises(FileExistsError):
            inherit.open_result(str(existing))
        link = self.dir / "link.json"
        link.symlink_to(self.dir / "target.json")
        with self.assertRaises(OSError):
            inherit.open_result(str(link))
        self.assertFalse((self.dir / "target.json").exists())
        fd = inherit.open_result(str(self.dir / "new.json"))
        os.close(fd)
        self.assertEqual((self.dir / "new.json").stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main(verbosity=1)
