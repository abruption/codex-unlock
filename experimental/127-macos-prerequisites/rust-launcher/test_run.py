import json
import copy
import os
from pathlib import Path
import tempfile
import unittest
import run


class Expectations(unittest.TestCase):
    def test_complete_requires_rows_exits_free_probes_and_clean_collection(self):
        good = {"errors": [], "incomplete": [],
                "measurements": [{"mode": mode, "stage": stage, "matches": True}
                                 for mode in ("default", "inheritable")
                                 for stage in ("before_close", "after_close")],
                "children": [{"mode": mode, "code": 0, "after_exit_probe": "free",
                              "keeper_exit": {"event": "child_exit", "ok": True, "code": 0}}
                             for mode in ("default", "inheritable")]}
        self.assertTrue(run.complete(good))
        for fault in ("missing_row", "mismatch", "missing_child", "unknown_exit",
                      "keeper_failed", "held_after_exit", "incomplete", "error"):
            bad = copy.deepcopy(good)
            if fault == "missing_row":
                bad["measurements"].pop()
            elif fault == "mismatch":
                bad["measurements"][0]["matches"] = False
            elif fault == "missing_child":
                bad["children"].pop()
            elif fault == "unknown_exit":
                bad["children"][0]["code"] = None
            elif fault == "keeper_failed":
                bad["children"][0]["keeper_exit"]["ok"] = False
            elif fault == "held_after_exit":
                bad["children"][0]["after_exit_probe"] = "held"
            elif fault == "incomplete":
                bad["incomplete"].append("child")
            else:
                bad["errors"].append("scan")
            with self.subTest(fault=fault):
                self.assertFalse(run.complete(bad))

    def test_ready_validation_uses_observed_flags_and_specific_failures(self):
        keeper = {"pid": 11, "has_fd": False}
        ready = {"pid": 10, "child_pid": 11, "initial_fd_flags": 1,
                 "pre_spawn_fd_flags": 1}
        self.assertEqual(run.ready_errors("default", 10, keeper, ready), [])
        self.assertEqual(run.ready_errors("inheritable", 10, keeper | {"has_fd": True},
                                         ready | {"pre_spawn_fd_flags": 0}), [])
        for change, expected in (({"pid": 12}, "ready_parent_pid_mismatch"),
                                 ({"initial_fd_flags": 0}, "initial_cloexec_missing"),
                                 ({"pre_spawn_fd_flags": 0}, "pre_spawn_cloexec_mismatch"),
                                 ({"initial_fd_flags": True}, "initial_fd_flags_invalid")):
            self.assertIn(expected, run.ready_errors("default", 10, keeper, ready | change))
        self.assertIn("keeper_fd_inheritance_mismatch", run.ready_errors(
            "default", 10, keeper | {"has_fd": True}, ready))

    @unittest.skipUnless(os.environ.get("RESEARCH_TMP_ROOT"), "research temp root required")
    def test_missing_binary_writes_failure_report(self):
        with tempfile.TemporaryDirectory(prefix="codex-rust-report-", dir=os.environ["RESEARCH_TMP_ROOT"]) as root:
            result = Path(root) / "result.json"
            self.assertEqual(run.run(str(Path(root) / "missing-binary"), result, root), 1)
            report = json.loads(result.read_text())
            self.assertFalse(report["ok"])
            self.assertFalse(report["safeToUnlock"])
            self.assertEqual(report["children"], [])
            self.assertTrue(any("FileNotFoundError" in e for e in report["errors"]))

    def test_stdout_tail_requires_clean_eof(self):
        class Reader:
            def __init__(self, kind):
                self.kind = kind

            def read_line(self, _deadline):
                return self.kind, b'{}'

        run.require_eof(Reader("eof"))
        for kind in ("line", "unterminated", "timeout", "limit"):
            with self.assertRaisesRegex(RuntimeError, "unexpected_stdout_tail"):
                run.require_eof(Reader(kind))

    def test_default_closes_after_parent(self):
        self.assertEqual(run.expectation("default", "after_close")["probe"], "free")
        self.assertEqual(run.expectation("default", "before_close")["roles"]["child"], "absent")

    def test_explicit_inheritance_keeps_shared_description(self):
        self.assertEqual(run.expectation("inheritable", "after_close")["probe"], "held")
        self.assertEqual(run.expectation("inheritable", "after_close")["roles"],
                         {"parent": "absent", "child": "bit"})

    def test_missing_or_uncertain_observation_is_failure(self):
        expected = run.expectation("default", "after_close")
        for change in ({"probe": "held"}, {"scan_valid": False},
                       {"unexpected_pids": 1}, {"roles": {}}):
            self.assertFalse(run.matches(expected | change, expected))
        self.assertFalse(run.matches({}, expected))


if __name__ == "__main__":
    unittest.main()
