#!/usr/bin/env python3
"""Deterministic tests for visibility.py and fileport_actor.c (#127 research).

  RESEARCH_TMP_ROOT=<approved root> python3 -I -B experimental/127-macos-visibility/test_visibility.py

Pure evaluator tests use finite fixed inputs. Process tests start only finite
synthetic children (they end on stdin EOF or by themselves). No signals are
sent. Tests that need RESEARCH_TMP_ROOT, clang or macOS skip without them.
"""

import copy
import contextlib
import io
import json
import os
import platform
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import visibility as v  # noqa: E402

inherit = v.inherit
ROOT = os.environ.get("RESEARCH_TMP_ROOT")
PY = sys.executable

N, R = v.N, v.R


def clear_flat(root):
    """Remove a test directory this suite created: regular files and symlinks
    directly inside it, then the directory. Not recursive; anything else stays."""
    root = Path(root)
    for name in os.listdir(root):
        mode = os.lstat(root / name).st_mode
        if stat.S_ISREG(mode) or stat.S_ISLNK(mode):
            os.unlink(root / name)
    os.rmdir(root)


def scratch():
    if not ROOT:
        raise unittest.SkipTest("RESEARCH_TMP_ROOT is required")
    path = Path(tempfile.mkdtemp(prefix="codex-127v-test-", dir=ROOT))
    path.chmod(0o700)
    return path


def lsof_out(*records):
    """Build `lsof -F0pfG` bytes from (pid, [(fd, flags), ...]) records."""
    out = b""
    for pid, files in records:
        out += f"p{pid}\0\n".encode()
        for fd, flags in files:
            out += f"f{fd}\0G{flags};0x2\0\n".encode()
    return out


def scan_of(*records):
    out = lsof_out(*records)
    return v.interpret_scan(0 if out else 1, out, b"")


class ParseTest(unittest.TestCase):
    def test_empty_output_with_status_1_is_a_valid_empty_scan(self):
        # This is also exactly what a restricted observer sees (clean omission).
        scan = v.interpret_scan(1, b"", b"")
        self.assertTrue(scan["valid"])
        self.assertEqual(scan["pids"], {})

    def test_status_and_stderr_rules(self):
        good = lsof_out((10, [(3, "0x4003")]))
        cases = {
            "status_1_with_output": (1, good, b""),
            "status_0_without_output": (0, b"", b""),
            "status_2": (2, b"", b""),
            "stderr": (1, b"", b"lsof: can't get PID byte count: Operation not permitted\n"),
            "timeout": (None, b"", b""),
        }
        for name, (status, out, err) in cases.items():
            with self.subTest(name=name):
                self.assertFalse(v.interpret_scan(status, out, err)["valid"])

    def test_diagnostic_problems_make_the_scan_invalid(self):
        self.assertFalse(v.interpret_scan(0, lsof_out((10, [(3, "0x3")])), b"", ["output_limit"])["valid"])

    def test_malformed_shapes_are_invalid_never_no_bit(self):
        shapes = {
            "partial_last_line": b"p10\0\nf3\0G0x4003;0x2\0",
            "unterminated_record": b"p10\0\nf3\0G0x4003;0x2\n",
            "missing_g": b"p10\0\nf3\0\n",
            "non_hex_flags": b"p10\0\nf3\0G0xZZ;0x2\0\n",
            "file_before_pid": b"f3\0G0x3;0x2\0\n",
            "extra_field": b"p10\0\nf3\0G0x3;0x2\0n/x\0\n",
            "pid_without_fd": b"p10\0\n",
            "bad_pid": b"p0\0\nf3\0G0x3;0x2\0\n",
        }
        for name, out in shapes.items():
            with self.subTest(name=name):
                scan = v.interpret_scan(0, out, b"")
                self.assertFalse(scan["valid"])
                self.assertEqual(v.filter_decision(scan, 10)["decision"], "unknown")

    def test_fileport_record_is_listed_and_invalidates_the_scan(self):
        out = b"p20\0\nffp.\0G0x4003;0x0\0\n"
        scan = v.interpret_scan(0, out, b"")
        self.assertFalse(scan["valid"])
        self.assertIn("fileport_record", scan["problems"])
        self.assertEqual(scan["fileports"], [{"pid": "20", "flags": "0x4003", "was_locked": True}])
        self.assertEqual(v.label(v.visibility_decision("held", scan, 20)), v.U_INVALID)
        states, ports, unexpected = v.role_states(scan, {"receiver": 20})
        self.assertEqual((states, ports, unexpected), ({"receiver": "absent"}, {"receiver": "bit"}, 0))


class FilterDecisionTest(unittest.TestCase):
    def test_rules(self):
        scan = scan_of((10, [(3, "0x4003")]), (11, [(4, "0x3")]), (12, [(3, "0x3"), (5, "0x4001")]),
                       (13, [(3, "0x1"), (4, "0x3")]))
        self.assertEqual(v.label(v.filter_decision(scan, 10)), N)
        self.assertEqual(v.label(v.filter_decision(scan, 11)), R)
        self.assertEqual(v.label(v.filter_decision(scan, 12)), N)
        self.assertEqual(v.label(v.filter_decision(scan, 13)), R)
        self.assertEqual(v.label(v.filter_decision(scan, 99)), v.U_ABSENT)

    def test_invalid_scan_is_unknown(self):
        scan = scan_of((10, [(3, "0x4003")]))
        scan["valid"] = False
        self.assertEqual(v.label(v.filter_decision(scan, 10)), v.U_INVALID)

    def test_unreadable_flags_are_unknown(self):
        scan = scan_of((10, [(3, "0x4003")]))
        scan["pids"]["10"][0]["was_locked"] = None
        self.assertEqual(v.label(v.filter_decision(scan, 10)), "unknown:flags_unreadable")

    def test_vocabulary_is_closed(self):
        with self.assertRaises(ValueError):
            v.label({"decision": "holder", "reason": "x"})
        with self.assertRaises(ValueError):
            v.label({"decision": "safe", "reason": "x"})

    def test_bit_never_becomes_more_than_not_excluded(self):
        scan = scan_of((10, [(3, "0x4003"), (4, "0x4003")]))
        decision = v.filter_decision(scan, 10)
        self.assertEqual(decision, {"decision": "not_excluded", "reason": "bit_present"})


class FormerVersusOpenerTest(unittest.TestCase):
    """#139 M2 former-holder counterexample versus a never-locked opener."""

    def setUp(self):
        # former: flock then LOCK_UN, FD kept -> the sticky bit stays (0x4003).
        # opener: never called flock -> 0x3. holder: current holder -> 0x4003.
        self.former, self.opener, self.holder = 101, 202, 303
        self.full = scan_of((self.former, [(3, "0x4003")]), (self.opener, [(3, "0x3")]),
                            (self.holder, [(3, "0x4003")]))

    def test_former_holder_is_not_excluded_and_opener_is_rejected_without_a_holder(self):
        scan = scan_of((self.former, [(3, "0x4003")]), (self.opener, [(3, "0x3")]))
        self.assertEqual(v.label(v.visibility_decision("free", scan, self.former)), N)
        self.assertEqual(v.label(v.visibility_decision("free", scan, self.opener)), R)

    def test_hidden_holder_leaves_the_former_holder_not_excluded(self):
        view = v.without_pids(self.full, [self.holder])
        self.assertEqual(v.label(v.visibility_decision("held", view, self.former)), N)
        self.assertEqual(v.label(v.visibility_decision("held", view, self.opener)), R)

    def test_former_and_actual_holder_are_indistinguishable(self):
        self.assertEqual(v.filter_decision(self.full, self.former), v.filter_decision(self.full, self.holder))
        self.assertEqual(self.full["pids"][str(self.former)][0]["flags"],
                         self.full["pids"][str(self.holder)][0]["flags"])


class VisibilityDecisionTest(unittest.TestCase):
    def test_cross_checks(self):
        visible = scan_of((10, [(3, "0x4003")]))
        empty = scan_of()
        self.assertEqual(v.label(v.visibility_decision("held", visible, 10, False)), "unknown:canary_not_visible")
        self.assertEqual(v.label(v.visibility_decision("error:open:EPERM", visible, 10)), "unknown:probe_error")
        self.assertEqual(v.label(v.visibility_decision("held", empty, 10)), v.U_HIDDEN)
        self.assertEqual(v.label(v.visibility_decision("free", empty, 10)), v.U_ABSENT)
        self.assertEqual(v.label(v.visibility_decision("held", visible, 10, True)), N)
        self.assertEqual(v.label(v.visibility_decision("held", visible, 10)), N)

    def test_pid_with_only_a_fileport_counts_as_no_visible_opener(self):
        scan = {"valid": True, "pids": {"10": []}, "fileports": []}
        self.assertEqual(v.label(v.visibility_decision("held", scan, 10)), v.U_HIDDEN)

    def test_reduced_and_canary(self):
        reference = scan_of((10, [(3, "0x4003")]))
        self.assertFalse(v.reduced(reference, scan_of((10, [(3, "0x4003")]))))
        self.assertTrue(v.reduced(reference, scan_of()))
        self.assertTrue(v.reduced(reference, scan_of((10, [(3, "0x3")]))))
        invalid = copy.deepcopy(reference)
        invalid["valid"] = False
        self.assertTrue(v.reduced(reference, invalid))
        self.assertTrue(v.canary_visible(scan_of((7, [(3, "0x4003")])), 7))
        self.assertFalse(v.canary_visible(scan_of(), 7))
        self.assertFalse(v.canary_visible(scan_of((7, [(3, "0x3")])), 7))
        self.assertFalse(v.canary_visible(scan_of((7, [(3, "0x4003")]), (8, [(3, "0x3")])), 7))
        self.assertFalse(v.canary_visible(invalid, 10))

    def test_modelled_omission_does_not_mutate_the_scan(self):
        scan = scan_of((10, [(3, "0x4003")]), (11, [(3, "0x4003")]))
        view = v.without_pids(scan, [11])
        self.assertEqual(set(view["pids"]), {"10"})
        self.assertEqual(set(scan["pids"]), {"10", "11"})


class HiddenOutcomeTest(unittest.TestCase):
    def test_outcomes(self):
        def stages(before, probe):
            return [{"view_decisions": {"a": before}}, {"probe": probe, "roles": {"a": "absent", "b": "bit"},
                    "scan_valid": True, "unexpected_pids": 0}]
        self.assertEqual(v.hidden_outcome(stages(N, "held"), "a"), "release_incomplete_due_to_hidden_reference")
        self.assertEqual(v.HIDDEN_OUTCOME, "release_incomplete_due_to_hidden_reference")
        self.assertEqual(v.hidden_outcome(stages(N, "free"), "a"), "released")
        self.assertEqual(v.hidden_outcome(stages(R, "held"), "a"), "refused")
        self.assertEqual(v.hidden_outcome(stages(v.U_ABSENT, "held"), "a"), "refused")
        self.assertIsNone(v.hidden_outcome([], "a"))


# ---------------------------------------------------------- expected tables

def good_stage(expected):
    stage = {"unexpected_pids": 0, "fileport_roles": {}}
    stage.update(copy.deepcopy(expected))
    if expected["stage"] == "receiver_holds_port_only":
        stage["scan_problems"] = ["record:2:fG", "pid_without_fd:42", "fileport_record"]
    return stage


def good_scenarios():
    fp0 = {"event": "fileports", "ok": True, "count": 1, "vnode": 1, "non_vnode": 0, "matching": 1,
           "matching_was_locked": 1}
    scenarios = {
        "fileport": {
            "stages": [good_stage(e) for e in v.EXPECTED["fileport"]],
            "events": {"sent": {"event": "sent", "kr": 0}, "closed": {"event": "closed", "who": "sender"},
                       "received": {"event": "received", "ports": 1}, "self_report": fp0,
                       "made_fd": {"event": "made_fd", "matches": True, "port_released": True},
                       "lookup_after_exit": {"event": "lookup", "kr": v.BOOTSTRAP_UNKNOWN_SERVICE}},
            "finish": [{"exit": 0, "events": []}, {"exit": 0, "events": []}],
        },
        "hidden_sharer": {},
        "former_vs_opener": {"stages": [good_stage(e) for e in v.EXPECTED["former_vs_opener"]],
                             "finish": [{"exit": 0, "events": []}] * 3},
        "sandbox_target": {name: {"stages": [good_stage(e) for e in v.EXPECTED[f"sandbox_target/{name}"]],
                                  "finish": {"exit": 0, "events": []}} for name in ("allow_default", "deny_default")},
        "sandbox_observer": {
            "reference": {"probe": "held", "decision": N, "canary_visible": True, "scan_valid": True},
            "profiles": {name: {"reduced": False, "canary_visible": True, "decision": N,
                                "decision_without_canary": N, "probe": "held", "scan_valid": True,
                                "target_present": True, "lsof_status": 0, "lsof_stderr": "",
                                "classification": "unreduced"}
                         for name in v.observer_profiles("x")},
            "finish": [{"exit": 0, "events": []}] * 2,
        },
    }
    for name in ("scm_hide_receiver", "scm_hide_sender", "fork_hide_child"):
        finish = {"exit": 0, "events": [{"code": 0, "event": "child_exit"}]} if name == "fork_hide_child" \
            else [{"exit": 0, "events": []}] * 2
        scenarios["hidden_sharer"][name] = {
            "stages": [good_stage(e) for e in v.EXPECTED[f"hidden_sharer/{name}"]],
            "outcome": v.HIDDEN_OUTCOME, "finish": finish}
    profiles = scenarios["sandbox_observer"]["profiles"]
    profiles["allow_default"]["classification"] = "control_pass"
    for name in ("deny_pidfdinfo", "deny_default"):
        profiles[name].update(reduced=True, canary_visible=False, decision=v.U_CANARY, target_present=False,
                              decision_without_canary=v.U_HIDDEN, lsof_status=1, classification="restricted_unknown")
    profiles["deny_process_info"].update(reduced=True, canary_visible=False, decision=v.U_CANARY,
                                         decision_without_canary=v.U_INVALID, scan_valid=False, lsof_status=1,
                                         target_present=False, lsof_stderr="x", classification="restricted_unknown")
    return scenarios


class EvaluateTest(unittest.TestCase):
    def test_good_input_has_no_mismatches(self):
        self.assertEqual(v.evaluate(good_scenarios(), {}), [])

    def test_closed_case_and_actor_exit_evidence(self):
        for mutate in (
            lambda s: s.update(extra={}),
            lambda s: s["hidden_sharer"].update(extra={}),
            lambda s: s["sandbox_target"].update(extra={}),
            lambda s: s["sandbox_observer"].update(finish=[{"exit": 0, "events": []}]),
            lambda s: s["fileport"]["stages"][0].pop("unexpected_pids"),
        ):
            result = good_scenarios()
            mutate(result)
            self.assertTrue(v.evaluate(result, {}))

    def test_restricted_probe_failure_is_not_a_measured_success(self):
        result = good_scenarios()
        profile = result["sandbox_observer"]["profiles"]["deny_pidfdinfo"]
        profile.update(probe="error:open:EACCES", decision_without_canary="unknown:probe_error")
        self.assertIn("sandbox_observer/deny_pidfdinfo:probe_not_held", v.evaluate(result, {}))

    def test_unrelated_scan_failure_is_not_the_fileport_observation(self):
        result = good_scenarios()
        stage = next(s for s in result["fileport"]["stages"] if s["stage"] == "receiver_holds_port_only")
        stage["scan_problems"].append("stderr")
        self.assertIn("fileport/receiver_holds_port_only:scan_problems", v.evaluate(result, {}))

    def mutated(self, mutate):
        scenarios = good_scenarios()
        mutate(scenarios)
        return v.evaluate(scenarios, {})

    def test_counterexamples(self):
        def bit(s):
            s["fileport"]["stages"][4]["roles"]["receiver"] = "no_bit"

        def probe(s):
            s["fileport"]["stages"][2]["probe"] = "free"

        def order(s):
            st = s["former_vs_opener"]["stages"]
            st[0], st[1] = st[1], st[0]

        def unexpected(s):
            s["hidden_sharer"]["scm_hide_sender"]["stages"][0]["unexpected_pids"] = 1

        def outcome(s):
            s["hidden_sharer"]["fork_hide_child"]["outcome"] = "released"

        def lookup(s):
            s["fileport"]["events"]["lookup_after_exit"]["kr"] = 0

        def sent(s):
            s["fileport"]["events"]["sent"]["kr"] = 268435459

        def self_report(s):
            s["fileport"]["events"]["self_report"]["matching_was_locked"] = 0

        def finish(s):
            s["sandbox_target"]["deny_default"]["finish"]["exit"] = 3

        def fork_finish(s):
            s["hidden_sharer"]["fork_hide_child"]["finish"]["events"] = []

        def invalid_scan(s):
            s["fileport"]["stages"][0]["scan_valid"] = False

        def missing(s):
            del s["former_vs_opener"]

        def view(s):
            s["former_vs_opener"]["stages"][1]["view_decisions"]["former"] = R

        def made(s):
            s["fileport"]["events"]["made_fd"]["matches"] = False

        cases = {
            bit: "fileport/receiver_made_fd:roles", probe: "fileport/sender_closed_in_transit:probe",
            order: "former_vs_opener:stage_list", unexpected: "hidden_sharer/scm_hide_sender/both_hold:unexpected_pids",
            outcome: "hidden_sharer/fork_hide_child:outcome", lookup: "fileport:service_not_removed",
            sent: "fileport:sent", self_report: "fileport:self_report", finish: "sandbox_target/deny_default:finish",
            fork_finish: "hidden_sharer/fork_hide_child:finish", invalid_scan: "fileport/sender_locked:scan_valid",
            missing: "former_vs_opener:missing", view: "former_vs_opener/with_holder:view_decisions",
            made: "fileport:made_fd",
        }
        def saturated(s):
            s["fileport"]["stages"][3]["fileports"]["receiver"] = "error:saturated"

        def self_error(s):
            s["fileport"]["events"]["self_report"] = {"event": "fileports", "ok": False, "error": "query",
                                                      "count": 1}
        cases[saturated] = "fileport/receiver_holds_port_only:fileports"
        cases[self_error] = "fileport:self_report"
        for mutate, expected in cases.items():
            with self.subTest(expected=expected):
                self.assertIn(expected, self.mutated(mutate))

    def test_not_executed_is_not_a_mismatch_but_is_not_ok(self):
        scenarios = good_scenarios()
        for name in ("fileport", "sandbox_observer", "sandbox_target", "former_vs_opener"):
            del scenarios[name]
        not_executed = {name: "C actor unavailable: clang not present"
                        for name in ("fileport", "sandbox_observer", "sandbox_target", "former_vs_opener")}
        self.assertEqual(v.evaluate(scenarios, not_executed), [])
        self.assertIn("fileport:missing", v.evaluate(scenarios, {}))

    def test_hidden_sharer_is_always_required(self):
        scenarios = good_scenarios()
        del scenarios["hidden_sharer"]
        self.assertIn("hidden_sharer:missing", v.evaluate(scenarios, {}))


class SandboxRuleTest(unittest.TestCase):
    def result(self):
        return good_scenarios()["sandbox_observer"]

    def test_reduced_view_that_is_not_unknown_is_a_mismatch(self):
        result = self.result()
        result["profiles"]["deny_pidfdinfo"]["decision"] = N
        self.assertIn("sandbox_observer/deny_pidfdinfo:reduced_not_unknown", v.sandbox_rule_mismatches(result))

    def test_missing_canary_that_is_not_unknown_is_a_mismatch(self):
        result = self.result()
        result["profiles"]["deny_pidfdinfo_others"].update(canary_visible=False)
        self.assertIn("sandbox_observer/deny_pidfdinfo_others:reduced_not_unknown", v.sandbox_rule_mismatches(result))

    def test_reduced_held_view_without_canary_must_still_be_unknown(self):
        result = self.result()
        result["profiles"]["deny_default"]["decision_without_canary"] = R
        self.assertIn("sandbox_observer/deny_default:reduced_without_canary_not_unknown",
                      v.sandbox_rule_mismatches(result))

    def test_unreduced_decision_must_match_reference(self):
        result = self.result()
        result["profiles"]["deny_pidfdinfo_others"]["decision"] = R
        self.assertIn("sandbox_observer/deny_pidfdinfo_others:unreduced_decision_changed",
                      v.sandbox_rule_mismatches(result))

    def test_control_and_reference_and_profile_set(self):
        result = self.result()
        result["profiles"]["allow_default"].update(reduced=True, decision="unknown:canary_not_visible")
        result["reference"]["probe"] = "free"
        del result["profiles"]["deny_default"]
        mismatches = v.sandbox_rule_mismatches(result)
        for expected in ("sandbox_observer/allow_default:control_failed:reduced",
                         "sandbox_observer/allow_default:control_failed:decision",
                         "sandbox_observer:reference_failed:probe", "sandbox_observer:profile_set"):
            self.assertIn(expected, mismatches)

    def test_good_result_has_no_mismatches(self):
        self.assertEqual(v.sandbox_rule_mismatches(self.result()), [])

    def test_reviewer_control_mutation_is_a_mismatch(self):
        # The review case: control canary missing and decision unknown, while
        # `reduced` stays False. A failed control is never a success.
        result = self.result()
        result["profiles"]["allow_default"].update(canary_visible=False, decision=v.U_CANARY)
        mismatches = v.sandbox_rule_mismatches(result)
        self.assertIn("sandbox_observer/allow_default:control_failed:canary_visible", mismatches)
        self.assertIn("sandbox_observer/allow_default:control_failed:decision", mismatches)
        self.assertEqual(v.classify_profile("allow_default", result["profiles"]["allow_default"], N),
                         "control_failed")
        self.assertIn("sandbox_observer/allow_default:control_failed:decision",
                      v.evaluate({**good_scenarios(), "sandbox_observer": result}, {}))

    def test_control_contract_rejects_missing_negated_and_retyped_fields(self):
        for key, want in v.CONTROL_CONTRACT.items():
            for mode in ("missing", "negated", "retyped"):
                with self.subTest(key=key, mode=mode):
                    result = self.result()
                    record = result["profiles"]["allow_default"]
                    if mode == "missing":
                        del record[key]
                    elif mode == "negated":
                        record[key] = (not want) if isinstance(want, bool) else (
                            want + 1 if isinstance(want, int) else want + "x")
                    else:
                        record[key] = int(want) if isinstance(want, bool) else (
                            float(want) if isinstance(want, int) else None)
                    self.assertIn(f"sandbox_observer/allow_default:control_failed:{key}",
                                  v.sandbox_rule_mismatches(result))

    def test_reference_contract_rejects_missing_negated_and_retyped_fields(self):
        for key, want in v.REFERENCE_CONTRACT.items():
            for value in (v.MISSING, (not want) if isinstance(want, bool) else want + "x",
                          int(want) if isinstance(want, bool) else None):
                with self.subTest(key=key, value=value):
                    result = self.result()
                    if value is v.MISSING:
                        del result["reference"][key]
                    else:
                        result["reference"][key] = value
                    self.assertIn(f"sandbox_observer:reference_failed:{key}", v.sandbox_rule_mismatches(result))
        result = self.result()
        del result["reference"]
        self.assertIn("sandbox_observer:reference_failed:probe", v.sandbox_rule_mismatches(result))

    def test_missing_control_profile_is_a_mismatch(self):
        result = self.result()
        del result["profiles"]["allow_default"]
        self.assertIn("sandbox_observer/allow_default:control_failed:missing", v.sandbox_rule_mismatches(result))

    def test_restricted_fields_must_be_present_and_typed(self):
        for key in v.RESTRICTED_FIELDS:
            with self.subTest(key=key):
                result = self.result()
                del result["profiles"]["deny_pidfdinfo"][key]
                self.assertIn(f"sandbox_observer/deny_pidfdinfo:missing_field:{key}",
                              v.sandbox_rule_mismatches(result))
        result = self.result()
        result["profiles"]["deny_pidfdinfo"]["reduced"] = 1
        self.assertIn("sandbox_observer/deny_pidfdinfo:missing_field:reduced", v.sandbox_rule_mismatches(result))

    def test_restricted_unknown_is_distinguished_from_a_failed_control(self):
        profiles = self.result()["profiles"]
        self.assertEqual(profiles["deny_pidfdinfo"]["classification"], "restricted_unknown")
        self.assertEqual(v.classify_profile("deny_pidfdinfo", profiles["deny_pidfdinfo"], N), "restricted_unknown")
        self.assertEqual(v.classify_profile("allow_default", profiles["deny_pidfdinfo"], N), "control_failed")
        wrong = dict(profiles["deny_pidfdinfo"], decision=N)
        self.assertEqual(v.classify_profile("deny_pidfdinfo", wrong, N), "rule_violation")

    def test_vocabulary_outside_decisions_is_a_mismatch(self):
        result = self.result()
        result["profiles"]["deny_default"]["decision"] = "holder:bit_present"
        mismatches = v.sandbox_rule_mismatches(result)
        self.assertIn("sandbox_observer/deny_default:vocabulary", mismatches)
        self.assertIn("sandbox_observer/deny_default:reduced_not_unknown", mismatches)


class EventTest(unittest.TestCase):
    def diag(self, stdout=b"", stderr=b"", status=0, problems=()):
        return {"status": status, "stdout": stdout, "stderr": stderr, "problems": list(problems)}

    def test_one_shot_framing(self):
        good = b'{"event":"probe","result":"free"}\n'
        self.assertEqual(v.parse_one_shot(self.diag(good), "probe")["event"], {"event": "probe", "result": "free"})
        cases = {
            "status": self.diag(good, status=3), "stderr": self.diag(good, b"x"),
            "two_lines": self.diag(good + good), "partial": self.diag(good[:-1]),
            "malformed": self.diag(b"{nope\n"), "wrong_event": self.diag(b'{"event":"failed"}\n'),
            "timeout": self.diag(status=None, problems=["timeout"]), "empty": self.diag(b""),
            "array": self.diag(b"[1]\n"),
        }
        for name, diag in cases.items():
            with self.subTest(name=name):
                parsed = v.parse_one_shot(diag, "probe")
                self.assertIsNone(parsed["event"])
                self.assertTrue(parsed["problems"])

    def test_fileport_summary_shapes(self):
        ok = {"event": "fileports", "ok": True, "count": 1, "vnode": 1, "non_vnode": 0, "matching": 1,
              "matching_was_locked": 1}
        self.assertEqual(v.fileport_summary(ok), v.FP1)
        for kind in sorted(v.FILEPORT_ERRORS):
            with self.subTest(kind=kind):
                # An incomplete enumeration is an error, never a zero count.
                event = {"event": "fileports", "ok": False, "error": kind, "count": 0}
                self.assertEqual(v.fileport_summary(event), f"error:{kind}")
        self.assertEqual(v.fileport_summary({"event": "fileports", "ok": False, "error": "/x/9876543"}),
                         "error:other")
        for bad in (None, {}, {"event": "fileports"}, dict(ok, count=True), dict(ok, matching="1"),
                    {k: x for k, x in ok.items() if k != "count"}, dict(ok, event="probe"),
                    dict(ok, vnode=0), dict(ok, matching=2, vnode=1), dict(ok, matching_was_locked=2),
                    dict(ok, non_vnode=-1, vnode=2)):
            with self.subTest(bad=bad):
                self.assertEqual(v.fileport_summary(bad), "invalid")

    def test_check_event(self):
        self.assertTrue(v.check_event({"event": "sent", "kr": 0}, "sent", kr=lambda x: x == 0))
        self.assertFalse(v.check_event({"event": "sent"}, "sent", kr=lambda x: x == 0))
        self.assertFalse(v.check_event({"event": "failed", "kr": 0}, "sent", kr=lambda x: x == 0))
        self.assertFalse(v.check_event("sent", "sent"))
        self.assertFalse(v.is_pid(True))
        self.assertTrue(v.SERVICE.fullmatch("dev.codex-unlock.research.127v.123.0a1b2c3d"))
        self.assertFalse(v.SERVICE.fullmatch("dev.codex-unlock.research.127v.123.0a1b2c3d\n"))
        self.assertFalse(v.SERVICE.fullmatch("com.apple.something"))


class ProfileTest(unittest.TestCase):
    def test_sbpl_string(self):
        self.assertEqual(v.sbpl_string('/a b/"c"\\d'), '"/a b/\\"c\\"\\\\d"')
        for bad in ("/a\nb", "/a\0b", "/a\x7fb"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    v.sbpl_string(bad)

    def test_profiles_are_deterministic(self):
        self.assertEqual(v.observer_profiles("/x"), v.observer_profiles("/x"))
        self.assertIn("(deny default)", v.observer_profiles("/x")["deny_default"])
        self.assertIn('(literal "/l")', v.target_profiles("/x", "/l")["deny_default"])

    def test_write_private_refuses_existing_and_symlink(self):
        root = scratch()
        try:
            path = root / "p.sb"
            v.write_private(str(path), "(version 1)")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                v.write_private(str(path), "(version 1)")
            link = root / "link.sb"
            link.symlink_to(root / "target.sb")
            with self.assertRaises(FileExistsError):
                v.write_private(str(link), "(version 1)")
            self.assertFalse((root / "target.sb").exists())
        finally:
            clear_flat(root)


class ProcessTest(unittest.TestCase):
    """Finite synthetic children only; nothing is signalled."""

    def setUp(self):
        self.root = scratch()
        self.runner = inherit.Run(self.root)
        self.lab = v.Lab(v.State(self.runner), PY)

    def tearDown(self):
        self.runner.finish_all()
        for item in self.runner.pending:
            deadline = time.monotonic() + 5
            while item["proc"].poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            for stream in (item["proc"].stdout, item["proc"].stderr):
                if stream and not stream.closed:
                    stream.close()
        clear_flat(self.root)

    def child(self, code):
        return self.runner.start("child", [PY, "-I", "-c", code])

    def test_ready_with_wrong_pid_is_a_failure(self):
        actor = self.child('import sys; print(\'{"event":"ready","pid":1,"kind":"holder"}\', flush=True); sys.stdin.read()')
        self.assertIsNone(self.lab.ready(actor, "holder"))
        self.assertIn("child:ready_pid", self.runner.failures)

    def test_ready_with_wrong_kind_is_a_failure(self):
        actor = self.child('import os, sys; print(\'{"event":"ready","pid":%d,"kind":"opener"}\' % os.getpid(), '
                           'flush=True); sys.stdin.read()')
        self.assertIsNone(self.lab.ready(actor, "holder"))
        self.assertIn("child:ready_shape", self.runner.failures)

    def test_early_exit_is_a_failure(self):
        actor = self.child("pass")
        self.assertIsNone(self.lab.ready(actor, "holder"))
        self.assertIn("child:eof", self.runner.failures)

    def test_failed_event_is_never_ready(self):
        actor = self.child('print(\'{"event":"failed","reason":"check_in"}\', flush=True)')
        self.assertIsNone(self.lab.ready(actor, "receiver"))
        self.assertTrue(any(f.startswith("child:unexpected_event:failed") for f in self.runner.failures))

    def test_partial_line_then_silence_is_incomplete(self):
        actor = self.child('import sys; sys.stdout.write(\'{"event":"re\'); sys.stdout.flush(); sys.stdin.read()')
        start = time.monotonic()
        self.assertIsNone(self.lab.ready(actor, "holder"))
        self.assertGreaterEqual(time.monotonic() - start, inherit.READY_TIMEOUT - 0.5)
        self.assertIn("child:no_event", self.runner.incomplete)

    def test_one_shot_timeout_is_pending_and_later_exited(self):
        parsed = self.lab.one_shot(["-I", "-c", "import time; time.sleep(1)"], "probe", timeout=0.1)
        self.assertIsNone(parsed["event"])
        self.assertIn("timeout", parsed["problems"])
        self.assertEqual(len(self.runner.pending), 1)
        self.assertTrue(any(i.startswith("diagnostic_timeout:") for i in self.runner.incomplete))
        deadline = time.monotonic() + 5
        while self.runner.pending[0]["proc"].poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(self.runner.poll_pending()[0]["state"], "exited:0")

    def test_one_shot_malformed_output_is_a_failure(self):
        parsed = self.lab.one_shot(["-I", "-c", "print('{oops')"], "probe")
        self.assertIsNone(parsed["event"])
        self.assertTrue(any(f.startswith("one_shot:-I:malformed_event") for f in self.runner.failures))


@unittest.skipUnless(platform.system() == "Darwin" and os.access(v.CLANG, os.X_OK), "macOS with clang only")
class ActorTest(unittest.TestCase):
    """The compiled C actor with finite inputs; each child ends on EOF or by itself."""

    @classmethod
    def setUpClass(cls):
        cls.root = scratch()
        cls.runner = inherit.Run(cls.root)
        cls.actor, cls.build = v.build_actor(cls.runner, cls.root)
        if cls.actor is None:
            clear_flat(cls.root)
            raise unittest.SkipTest(f"actor not built: {cls.build}")

    @classmethod
    def tearDownClass(cls):
        clear_flat(cls.root)

    def call(self, args, data=b""):
        proc = subprocess.Popen([self.actor, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        out, err = proc.communicate(data)
        return proc.returncode, out, err

    def fixture(self, name):
        path = self.root / name
        path.write_bytes(b"")
        return str(path)

    def test_build_recorded_binary_hash(self):
        self.assertRegex(self.build["binary_sha256"], r"^[0-9a-f]{64}$")

    def test_probe_free_and_held(self):
        lock = self.fixture("probe.lock")
        self.assertEqual(self.call(["probe", lock]), (0, b'{"event":"probe","result":"free"}\n', b""))
        holder = subprocess.Popen([self.actor, "holder", lock], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        try:
            self.assertEqual(json.loads(holder.stdout.readline())["kind"], "holder")
            self.assertEqual(self.call(["probe", lock])[1], b'{"event":"probe","result":"held"}\n')
        finally:
            holder.stdin.close()
            self.assertEqual(holder.wait(), 0)
            holder.stdout.close()
        self.assertEqual(self.call(["probe", lock])[1], b'{"event":"probe","result":"free"}\n')

    def test_framing_failures_end_with_exit_3(self):
        lock = self.fixture("frame.lock")
        for name, data in (("partial_at_eof", b"close_own_fd"), ("overlong", b"x" * 600 + b"\n")):
            with self.subTest(name=name):
                code, out, _ = self.call(["sender", lock], data)
                self.assertEqual(code, 3)
                self.assertEqual(json.loads(out.splitlines()[0])["event"], "ready")

    def test_unknown_command_and_eof(self):
        lock = self.fixture("cmd.lock")
        code, out, _ = self.call(["opener", lock], b"nope\n")
        self.assertEqual(code, 0)
        self.assertEqual([json.loads(line)["event"] for line in out.splitlines()], ["ready", "error"])

    def test_failures_are_reported_not_ready(self):
        missing = str(self.root / "missing.lock")
        self.assertEqual(self.call(["holder", missing])[:2], (3, b'{"event":"failed","reason":"open:ENOENT"}\n'))
        self.assertEqual(self.call(["listfileports", "0", missing])[:2], (3, b'{"event":"failed","reason":"pid"}\n'))
        self.assertEqual(self.call(["lookup", "bad name"])[:2], (3, b'{"event":"failed","reason":"service_name"}\n'))
        self.assertEqual(self.call(["nope"])[:2], (2, b'{"event":"failed","reason":"usage"}\n'))
        self.assertEqual(json.loads(self.call(["probe", missing])[1])["result"], "error:open:ENOENT")

    def test_send_with_unknown_service_keeps_the_sender_usable(self):
        lock = self.fixture("send.lock")
        code, out, _ = self.call(["sender", lock], b"send dev.codex-unlock.research.127v.1.00000000\nclose_own_fd\n")
        events = [json.loads(line) for line in out.splitlines()]
        self.assertEqual(code, 0)
        self.assertEqual([e["event"] for e in events], ["ready", "failed", "closed"])
        self.assertEqual(events[1]["reason"], "look_up")

    def fileports_event(self, args):
        code, out, err = self.call(args)
        self.assertEqual((code, err), (0, b""))
        return json.loads(out)

    def test_fileport_enumeration_complete_and_saturated(self):
        lock = self.fixture("ports.lock")
        one = self.fileports_event(["makeports", "1", lock])
        # makeports never calls flock, so the description has no FWASLOCKED.
        self.assertEqual(v.fileport_summary(one), "count=1,matching=1,was_locked=0")
        self.assertEqual((one["vnode"], one["non_vnode"]), (1, 0))
        below = self.fileports_event(["makeports", "63", lock])
        self.assertEqual(v.fileport_summary(below), "count=63,matching=63,was_locked=0")
        for n in ("64", "70"):
            with self.subTest(n=n):
                # A full buffer may hide more entries: an error, never a count.
                full = self.fileports_event(["makeports", n, lock])
                self.assertEqual(full["ok"], False)
                self.assertEqual(v.fileport_summary(full), "error:saturated")

    def test_fileport_identity_and_list_failures_are_errors(self):
        missing = str(self.root / "missing.lock")
        event = self.fileports_event(["listfileports", str(os.getpid()), missing])
        self.assertEqual(v.fileport_summary(event), "error:identity")
        lock = self.fixture("gone.lock")
        child = subprocess.Popen([PY, "-I", "-c", "pass"])
        self.assertEqual(child.wait(), 0)
        event = self.fileports_event(["listfileports", str(child.pid), lock])
        self.assertEqual(v.fileport_summary(event), "error:list_esrch")


# ------------------------------------------------------------ privacy

# Fixed synthetic privacy markers, not credentials or observations from a real
# account, process or bootstrap service. These values deliberately enter the
# raw-file CLI fixture; the assertions below require their exclusion from the
# public summary. No file at SYNTHETIC_PRIVATE_PATH is read or written.
SYNTHETIC_PRIVATE_PATH = "/Users/fixture-owner/.codex/sessions/x.lock"
FIXTURE_PID = "9876543"
SYNTHETIC_SERVICE = "dev.codex-unlock.research.127v.9876543.deadbeef"
PRIVATE_MARKERS = ("fixture-owner", FIXTURE_PID, "deadbeef", "/Users", ".codex", "Traceback")


def poisoned_raw():
    scenarios = good_scenarios()
    stage = scenarios["fileport"]["stages"][0]
    stage.update(stage=SYNTHETIC_PRIVATE_PATH, probe="error:open:" + SYNTHETIC_PRIVATE_PATH, raw={"pids": {FIXTURE_PID: SYNTHETIC_PRIVATE_PATH}},
                 scan_problems=[SYNTHETIC_PRIVATE_PATH])
    stage["roles"][SYNTHETIC_PRIVATE_PATH] = FIXTURE_PID
    stage["decisions"]["sender"] = "unknown:" + SYNTHETIC_PRIVATE_PATH
    stage["fileports"]["receiver"] = f"count={FIXTURE_PID},matching=0,was_locked=0"
    stage["view_openers"] = int(FIXTURE_PID)
    scenarios["fileport"]["ready"] = [{"pid": int(FIXTURE_PID), "service": SYNTHETIC_SERVICE}]
    scenarios["hidden_sharer"]["fork_hide_child"]["outcome"] = SYNTHETIC_PRIVATE_PATH
    profiles = scenarios["sandbox_observer"]["profiles"]
    profiles["deny_process_info"].update(lsof_stderr=SYNTHETIC_PRIVATE_PATH, lsof_status=int(FIXTURE_PID),
                                         classification=SYNTHETIC_PRIVATE_PATH, probe=FIXTURE_PID)
    profiles[SYNTHETIC_PRIVATE_PATH] = {"decision": SYNTHETIC_SERVICE}
    return {
        "ok": True, "run_ok": SYNTHETIC_PRIVATE_PATH, "measurement_ok": True, "collected": False, "measured": False,
        "failures": [f"fp_sender:exit:{FIXTURE_PID}", f"{SYNTHETIC_PRIVATE_PATH}:eof", f"one_shot:{SYNTHETIC_PRIVATE_PATH}:stderr",
                     f"fp_receiver:unexpected_event:failed:{SYNTHETIC_SERVICE}"],
        "incomplete": [f"diagnostic_timeout:lsof:{FIXTURE_PID}", f"fp_receiver:exit_wait:{FIXTURE_PID}",
                       f"{SYNTHETIC_SERVICE}:no_event", f"diagnostic_timeout:{SYNTHETIC_PRIVATE_PATH}:{FIXTURE_PID}"],
        "errors": [{"where": SYNTHETIC_PRIVATE_PATH, "kind": "OSError", "detail": SYNTHETIC_PRIVATE_PATH},
                   {"where": "cleanup", "kind": SYNTHETIC_PRIVATE_PATH, "detail": SYNTHETIC_SERVICE}, SYNTHETIC_PRIVATE_PATH],
        "not_executed": {"fileport": {"kind": SYNTHETIC_PRIVATE_PATH, "detail": SYNTHETIC_PRIVATE_PATH},
                         SYNTHETIC_PRIVATE_PATH: {"kind": "clang_missing", "detail": FIXTURE_PID}},
        "mismatches": [f"fileport:{SYNTHETIC_PRIVATE_PATH}", f"fileport/sender_locked:unexpected_pids:{FIXTURE_PID}",
                       "fileport:sent", SYNTHETIC_SERVICE],
        "pending_diagnostics": [{"argv0": SYNTHETIC_PRIVATE_PATH, "pid": int(FIXTURE_PID)}],
        "bootstrap_names": [{"service": SYNTHETIC_SERVICE, "status": SYNTHETIC_PRIVATE_PATH}, {"service": SYNTHETIC_SERVICE,
                                                                                 "status": "removed"}],
        "cleanup": {"status": "failed", "reason": SYNTHETIC_PRIVATE_PATH, "detail": SYNTHETIC_PRIVATE_PATH},
        "source_identity": {"unchanged": True, "start": {"visibility.py": SYNTHETIC_PRIVATE_PATH},
                            "end": {"visibility.py": "a" * 64, "inherit.py": FIXTURE_PID}},
        "build": {"clang": [SYNTHETIC_PRIVATE_PATH], "stderr": SYNTHETIC_PRIVATE_PATH, "binary_sha256": SYNTHETIC_PRIVATE_PATH},
        "environment": {"release": SYNTHETIC_PRIVATE_PATH, "machine": SYNTHETIC_PRIVATE_PATH, "lsof": f"revision: {SYNTHETIC_PRIVATE_PATH}",
                        "filesystem": SYNTHETIC_PRIVATE_PATH, "python": FIXTURE_PID, "mac_ver": SYNTHETIC_PRIVATE_PATH},
        "scratch_identity": [int(FIXTURE_PID), int(FIXTURE_PID)],
        "scenarios": scenarios,
    }


class PrivacyTest(unittest.TestCase):
    def assert_clean(self, text):
        for marker in PRIVATE_MARKERS:
            self.assertNotIn(marker, text)

    def test_poisoned_raw_result_gives_a_clean_public_summary(self):
        public = v.public_summary(poisoned_raw())
        self.assert_clean(json.dumps(public))
        self.assertEqual(public["mismatches"], ["fileport:sent"])
        self.assertEqual(public["unlisted_mismatches"], 3)
        self.assertEqual(public["failure_kinds"], {"fp_receiver:unexpected_event": 1, "fp_sender:exit": 1,
                                                   "one_shot:other": 1, "other:eof": 1})
        self.assertEqual(public["incomplete_kinds"], {"diagnostic_timeout:lsof": 1, "diagnostic_timeout:other": 1,
                                                      "fp_receiver:exit_wait": 1, "other:no_event": 1})
        self.assertEqual(public["error_kinds"], {"cleanup:other": 1, "other:OSError": 1, "other:other": 1})
        self.assertEqual(public["not_executed"], {"fileport": "other", "other": "clang_missing"})
        self.assertEqual(public["cleanup"], {"status": "failed", "reason": "other"})
        self.assertEqual(public["bootstrap_names"], {"other": 1, "removed": 1})
        self.assertEqual(public["run_ok"], "other")
        self.assertIsNone(public["binary_sha256"])
        self.assertEqual(public["pending_diagnostics"], 1)
        profile = public["sandbox_observer_profiles"]["deny_process_info"]
        self.assertEqual((profile["lsof_status"], profile["lsof_stderr_present"], profile["probe"]),
                         ("other", True, "other"))
        self.assertNotIn(SYNTHETIC_PRIVATE_PATH, public["sandbox_observer_profiles"])

    def test_good_raw_result_keeps_the_needed_fields(self):
        raw = {"ok": True, "run_ok": True, "measurement_ok": True, "collected": True, "measured": True,
               "scenarios": good_scenarios(), "cleanup": {"status": "removed", "reason": None},
               "bootstrap_names": [{"service": SYNTHETIC_SERVICE, "status": "removed"}]}
        public = v.public_summary(raw)
        self.assert_clean(json.dumps(public))
        self.assertEqual(public["stages"]["fileport/fileport"][3]["fileports"], {"sender": v.FP0, "receiver": v.FP1})
        self.assertEqual(public["stages"]["hidden_sharer/fork_hide_child/outcome"], v.HIDDEN_OUTCOME)
        self.assertEqual(public["sandbox_observer_profiles"]["allow_default"]["classification"], "control_pass")
        self.assertEqual(public["bootstrap_names"], {"removed": 1})

    def test_summary_never_raises_or_echoes(self):
        for raw in ([], None, SYNTHETIC_PRIVATE_PATH, {"scenarios": SYNTHETIC_PRIVATE_PATH}, {"failures": SYNTHETIC_PRIVATE_PATH},
                    {"errors": [None, 3]}, {"scenarios": {"fileport": {"stages": [SYNTHETIC_PRIVATE_PATH, None]}}}):
            with self.subTest(raw=type(raw).__name__):
                self.assert_clean(json.dumps(v.public_summary(raw)))


class CleanupTest(unittest.TestCase):
    def setUp(self):
        self.root = scratch()
        self.dir = Path(tempfile.mkdtemp(prefix="codex-127v-fixture-", dir=self.root))
        self.created = {"a.lock", "observer-x.sb", v.ACTOR_NAME}
        for name in self.created:
            (self.dir / name).write_bytes(b"")
        st = os.lstat(self.dir)
        self.identity = (st.st_dev, st.st_ino)

    def tearDown(self):
        if self.dir.is_symlink():
            os.unlink(self.dir)
        if self.dir.exists():
            clear_flat(self.dir)
        for name in os.listdir(self.root):
            if os.path.isdir(self.root / name) and not os.path.islink(self.root / name):
                clear_flat(self.root / name)
        clear_flat(self.root)

    def remaining(self):
        return set(os.listdir(self.dir)) if self.dir.exists() else None

    def test_removes_only_registered_names(self):
        record = v.cleanup_scratch(self.dir, self.identity, self.created)
        self.assertEqual((record["status"], record["removed"]), ("removed", 3))
        self.assertFalse(self.dir.exists())

    def test_unexpected_entry_preserves_everything(self):
        (self.dir / "stranger").write_bytes(b"")
        record = v.cleanup_scratch(self.dir, self.identity, self.created)
        self.assertEqual((record["status"], record["reason"]), ("preserved", "unexpected_entries"))
        self.assertEqual(self.remaining(), self.created | {"stranger"})

    def test_identity_mismatch_preserves_everything(self):
        record = v.cleanup_scratch(self.dir, (self.identity[0], self.identity[1] + 1), self.created)
        self.assertEqual((record["status"], record["reason"]), ("preserved", "identity_mismatch"))
        self.assertEqual(self.remaining(), self.created)

    def test_symlinked_scratch_is_refused(self):
        moved = self.root / "moved"
        os.rename(self.dir, moved)
        os.symlink(moved, self.dir)
        record = v.cleanup_scratch(self.dir, self.identity, self.created)
        self.assertEqual((record["status"], record["reason"]), ("preserved", "open_failed"))
        self.assertEqual(set(os.listdir(moved)), self.created)

    def test_unlink_failure_is_failed_and_preserves(self):
        def unlink(name, dir_fd):
            raise PermissionError(1, "Operation not permitted", SYNTHETIC_PRIVATE_PATH)
        record = v.cleanup_scratch(self.dir, self.identity, self.created, unlink=unlink)
        self.assertEqual((record["status"], record["reason"]), ("failed", "unlink_failed"))
        self.assertEqual(self.remaining(), self.created)

    def test_rmdir_failure_is_failed_and_keeps_the_directory(self):
        def rmdir(name, dir_fd):
            raise OSError(66, "Directory not empty", SYNTHETIC_PRIVATE_PATH)
        record = v.cleanup_scratch(self.dir, self.identity, self.created, rmdir=rmdir)
        self.assertEqual((record["status"], record["reason"]), ("failed", "rmdir_failed"))
        self.assertEqual(self.remaining(), set())

    def finalize(self, result, pending=(), **ops):
        path = self.root / "result.json"
        fd = inherit.open_result(str(path))
        code = v.finalize(fd, result, self.dir, self.identity, self.created, list(pending), **ops)
        written = json.loads(path.read_text())
        os.unlink(path)
        return code, written

    def good_result(self):
        return {"collected": True, "measured": True, "not_executed": {}, "errors": []}

    def test_finalize_success_writes_ok_after_cleanup(self):
        code, written = self.finalize(self.good_result())
        self.assertEqual(code, 0)
        self.assertEqual((written["ok"], written["run_ok"], written["measurement_ok"]), (True, True, True))
        self.assertEqual(written["cleanup"]["status"], "removed")

    def test_finalize_unlink_failure_is_not_ok_and_preserves_evidence(self):
        def unlink(name, dir_fd):
            raise PermissionError(1, "Operation not permitted", SYNTHETIC_PRIVATE_PATH)
        code, written = self.finalize(self.good_result(), unlink=unlink)
        self.assertEqual(code, 1)
        self.assertEqual((written["ok"], written["run_ok"], written["measurement_ok"]), (False, False, True))
        self.assertEqual(written["cleanup"]["reason"], "unlink_failed")
        self.assertEqual(self.remaining(), self.created)
        public = json.dumps(v.public_summary(written))
        self.assertNotIn("fixture-owner", public)
        self.assertIn('"unlink_failed"', public)

    def test_finalize_rmdir_failure_is_not_ok(self):
        def rmdir(name, dir_fd):
            raise OSError(66, "Directory not empty")
        code, written = self.finalize(self.good_result(), rmdir=rmdir)
        self.assertEqual((code, written["run_ok"], written["cleanup"]["reason"]), (1, False, "rmdir_failed"))
        self.assertTrue(self.dir.exists())

    def test_finalize_unexpected_exception_still_writes_the_record(self):
        def unlink(name, dir_fd):
            raise RuntimeError(SYNTHETIC_PRIVATE_PATH)
        code, written = self.finalize(self.good_result(), unlink=unlink)
        self.assertEqual((code, written["run_ok"], written["cleanup"]["status"]), (1, False, "failed"))
        self.assertEqual(written["errors"][-1]["where"], "cleanup")
        self.assertNotIn("fixture-owner", json.dumps(v.public_summary(written)))

    def test_finalize_preserves_when_measurement_failed_or_pending(self):
        result = self.good_result()
        result["measured"] = False
        code, written = self.finalize(result)
        self.assertEqual((code, written["cleanup"]["reason"], written["measurement_ok"]), (1, "measurement_not_ok", False))
        result = self.good_result()
        result["not_executed"] = {"fileport": {"kind": "clang_missing"}}
        self.assertEqual(self.finalize(result)[1]["cleanup"]["reason"], "measurement_not_ok")
        code, written = self.finalize(self.good_result(), pending=[{"pid": 1}])
        self.assertEqual((code, written["cleanup"]["reason"]), (1, "pending_diagnostics"))
        self.assertEqual(self.remaining(), self.created)


class MainTest(unittest.TestCase):
    def setUp(self):
        self.root = scratch()

    def tearDown(self):
        clear_flat(self.root)

    def run_main(self, *args):
        proc = subprocess.run([PY, "-I", "-B", v.SCRIPT, *args], capture_output=True, timeout=None,
                              stdin=subprocess.DEVNULL)
        return proc.returncode, proc.stdout.decode(), proc.stderr.decode()

    def test_existing_result_is_a_fatal_record_without_paths(self):
        existing = self.root / "fixture-owner-result.json"
        existing.write_text("{}")
        code, out, err = self.run_main("--scratch-root", str(self.root), "--result", str(existing))
        if platform.system() != "Darwin":
            self.skipTest("macOS only")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out), {"ok": False, "fatal": "FileExistsError"})
        self.assertEqual(err, "")
        self.assertEqual(os.listdir(self.root), [existing.name])

    def test_summarize_prints_only_the_public_summary(self):
        raw = self.root / "raw.json"
        raw.write_text(json.dumps(poisoned_raw()))
        code, out, err = self.run_main("--summarize", str(raw))
        self.assertEqual((code, err), (0, ""))
        for marker in PRIVATE_MARKERS:
            self.assertNotIn(marker, out)
        self.assertEqual(json.loads(out)["mismatches"], ["fileport:sent"])

    def test_summarize_of_a_broken_file_has_no_traceback(self):
        raw = self.root / "raw.json"
        raw.write_text("{" + SYNTHETIC_PRIVATE_PATH)
        code, out, err = self.run_main("--summarize", str(raw))
        self.assertEqual((code, err), (2, ""))
        self.assertEqual(json.loads(out), {"ok": False, "fatal": "JSONDecodeError"})

    def test_argument_combinations(self):
        for args in ((), ("--summarize", "x", "--result", "y"), ("--scratch-root", "x")):
            with self.subTest(args=args):
                self.assertEqual(self.run_main(*args)[0], 2)


class PrivateFailureTest(unittest.TestCase):
    def setUp(self):
        self.root = scratch()

    def tearDown(self):
        for name in os.listdir(self.root):
            candidate = self.root / name
            if candidate.is_dir():
                clear_flat(candidate)
        clear_flat(self.root)

    def test_actor_stderr_is_private_and_marks_collection_failure(self):
        run = v.PrivateRun(self.root)
        actor = run.start("one_shot", [PY, "-I", "-c", "import sys; sys.stderr.write('private-path-sentinel')"])
        result = run.finish(actor)
        self.assertEqual(result["exit"], 0)
        self.assertIn("one_shot:stderr", run.failures)
        self.assertEqual(run.actor_diagnostics[0]["stderr"], "private-path-sentinel")
        self.assertIsNone(actor["private_stderr"])

    def test_initialization_failure_keeps_a_private_error_record(self):
        raw = self.root / "result.json"
        args = SimpleNamespace(result=str(raw), scratch_root=str(self.root))
        with mock.patch.object(v.platform, "system", return_value="Darwin"), \
             mock.patch.object(v.tempfile, "mkdtemp", side_effect=OSError("private-path-sentinel")), \
             contextlib.redirect_stdout(io.StringIO()) as stdout:
            self.assertEqual(v.measure(args), 2)
        record = json.loads(raw.read_text())
        self.assertFalse(record["collected"])
        self.assertIn("private-path-sentinel", record["errors"][0]["detail"])
        self.assertNotIn("private-path-sentinel", stdout.getvalue())

    def test_sandbox_setup_exception_preserves_previous_stages(self):
        raw = self.root / "result.json"
        args = SimpleNamespace(result=str(raw), scratch_root=str(self.root))
        def prior(_lab, record):
            record["stages"].append({"stage": "sentinel"})
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(v.platform, "system", return_value="Darwin"))
            stack.enter_context(mock.patch.object(v, "build_actor", return_value=("unused", {})))
            stack.enter_context(mock.patch.object(v, "scenario_fileport", side_effect=prior))
            stack.enter_context(mock.patch.object(v, "scenario_hidden_sharer", return_value=None))
            stack.enter_context(mock.patch.object(v, "scenario_former_vs_opener", side_effect=prior))
            stack.enter_context(mock.patch.object(v, "sandbox_usable", side_effect=OSError("private-path-sentinel")))
            stack.enter_context(mock.patch.object(inherit, "run_diagnostic", return_value={"stderr": b""}))
            stack.enter_context(mock.patch.object(inherit, "filesystem_of", return_value="apfs"))
            stdout = stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            self.assertEqual(v.measure(args), 1)
        record = json.loads(raw.read_text())
        self.assertEqual(record["scenarios"]["fileport"]["stages"], [{"stage": "sentinel"}])
        self.assertEqual(record["not_executed"]["sandbox_observer"]["kind"], "sandbox_unusable")
        self.assertFalse(record["run_ok"])
        self.assertNotIn("private-path-sentinel", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
