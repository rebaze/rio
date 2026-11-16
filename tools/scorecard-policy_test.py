"""Run the Scorecard workflow's actual policy against synthetic SARIF reports."""

import copy
import json
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / ".github/workflows/scorecard.yaml").read_text()


def report():
    # Scorecard splits checks among runs, and lists clean checks only as rules.
    return {"version": "2.1.0", "runs": [
        {"tool": {"driver": {"name": "Scorecard", "rules": [{"id": "BranchProtectionID"}]}},
         "results": []},
        {"tool": {"driver": {"name": "Scorecard", "rules": [
            {"id": "BinaryArtifactsID"}, {"id": "VulnerabilitiesID"}]}}, "results": []},
        {"tool": {"driver": {"name": "Scorecard", "rules": [
            {"id": "CodeReviewID"}, {"id": "CIIBestPracticesID"}]}}, "results": []},
    ]}


def scan():
    return {"scorecard": {"version": "v5.6.0"}, "checks": [
        {"name": "Vulnerabilities", "score": 10, "reason": "no vulnerabilities detected"},
        {"name": "Code-Review", "score": 0, "reason": "no reviewed changes"},
        {"name": "CII-Best-Practices", "score": 0, "reason": "no badge"},
    ]}


def step(name):
    match = re.search(r"^      - name: " + re.escape(name) + r"\n(.*?)(?=^      - |\Z)",
                      WORKFLOW, re.M | re.S)
    if not match:
        raise AssertionError("missing Scorecard step: " + name)
    return match.group(1)


class ScorecardPolicyTest(unittest.TestCase):
    def gate(self, value=None, raw=None, missing=False, raw_json=None, missing_json=False):
        body = step("Enforce vulnerability policy")
        self.assertIn("        run: |\n", body)
        script = textwrap.dedent(body.split("        run: |\n", 1)[1])
        with tempfile.TemporaryDirectory() as directory:
            if not missing:
                (Path(directory) / "results.sarif").write_text(
                    raw if raw is not None else json.dumps(value))
            if not missing_json:
                (Path(directory) / "results.json").write_text(
                    raw_json if raw_json is not None else json.dumps(scan()))
            return subprocess.run(["bash", "-euo", "pipefail", "-c", script],
                                  cwd=directory, capture_output=True, text=True)

    def test_clean_split_report_passes_with_explicit_vulnerability_check_coverage(self):
        result = self.gate(report())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_governance_findings_do_not_block_vulnerability_policy(self):
        data = report()
        data["runs"][0]["results"] = [{"ruleId": "BranchProtectionID", "ruleIndex": 0,
                                         "message": {"text": "score is 3: review settings differ"}}]
        data["runs"][2]["results"] = [
            {"ruleId": "CodeReviewID", "ruleIndex": 0, "level": "error",
             "message": {"text": "score is 0: no approved changesets"}},
            {"ruleId": "CIIBestPracticesID", "ruleIndex": 1,
             "message": {"text": "score is 0: no badge"}},
        ]
        result = self.gate(data)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_every_vulnerability_result_fails_independent_of_level_or_suppression(self):
        for level in (None, "error", "warning", "note", "none"):
            with self.subTest(level=level):
                data = report()
                finding = {"ruleId": "VulnerabilitiesID", "ruleIndex": 1,
                           "message": {"text": "existing vulnerability or check error"},
                           "suppressions": [{"kind": "external", "status": "accepted"}]}
                if level is not None:
                    finding["level"] = level
                data["runs"][1]["results"] = [finding]
                self.assertNotEqual(self.gate(data).returncode, 0)

    def test_rule_index_alone_cannot_hide_a_vulnerability(self):
        data = report()
        data["runs"][1]["results"] = [{"ruleIndex": 1, "message": {"text": "finding"}}]
        self.assertNotEqual(self.gate(data).returncode, 0)

    def test_raw_vulnerability_score_must_be_successful_even_when_sarif_is_empty(self):
        # Scorecard's SARIF writer omits inconclusive/runtime-error score -1,
        # so an empty SARIF array alone cannot establish successful analysis.
        for score in (-1, 0, 9, 11, "10", True, None):
            with self.subTest(score=score):
                data = scan()
                data["checks"][0]["score"] = score
                self.assertNotEqual(self.gate(report(), raw_json=json.dumps(data)).returncode, 0)

    def test_raw_scan_must_exist_with_unambiguous_check_coverage(self):
        self.assertNotEqual(self.gate(report(), missing_json=True).returncode, 0)
        for raw in ("", "null", "[]", '{"checks":[', '{}', '{"checks":[]}',
                    json.dumps(dict(scan(), checks=scan()["checks"][1:])),
                    json.dumps(dict(scan(), checks=scan()["checks"] + [scan()["checks"][0]]))):
            with self.subTest(raw=raw):
                self.assertNotEqual(self.gate(report(), raw_json=raw).returncode, 0)

    def test_missing_or_duplicated_vulnerability_check_is_not_clean(self):
        for change in ("missing", "duplicate"):
            with self.subTest(change=change):
                data = report()
                if change == "missing":
                    data["runs"][1]["tool"]["driver"]["rules"].pop()
                else:
                    data["runs"].append(copy.deepcopy(data["runs"][1]))
                self.assertNotEqual(self.gate(data).returncode, 0)

    def test_missing_truncated_empty_or_duplicate_key_json_fails(self):
        self.assertNotEqual(self.gate(missing=True).returncode, 0)
        for raw in ("", '{"version":"2.1.0","runs":[',
                    json.dumps(report()).replace('"version": "2.1.0"', '"version":"invalid","version":"2.1.0"'),
                    json.dumps(report()).replace('"version": "2.1.0"', '"invalid":NaN,"version":"2.1.0"')):
            with self.subTest(raw=raw):
                self.assertNotEqual(self.gate(raw=raw).returncode, 0)

    def test_incomplete_or_malformed_reports_fail_closed(self):
        data = report()
        variants = [None, [], {}, {"version": "2.1.0", "runs": []},
                    dict(data, version="2.0.0")]
        for path, value in (
            (("runs",), {}), (("runs", 0), None),
            (("runs", 0, "tool"), None),
            (("runs", 0, "tool", "driver", "name"), "Other scanner"),
            (("runs", 0, "tool", "driver", "rules"), None),
            (("runs", 0, "tool", "driver", "rules", 0), {"id": ""}),
            (("runs", 1, "results"), None), (("runs", 1, "results"), {}),
            (("runs", 1, "results"), [None]),
        ):
            modified = copy.deepcopy(data)
            target = modified
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            variants.append(modified)
        missing_results = copy.deepcopy(data)
        del missing_results["runs"][1]["results"]
        variants.append(missing_results)
        for variant in variants:
            with self.subTest(report=variant):
                self.assertNotEqual(self.gate(variant).returncode, 0)

    def test_unknown_inconsistent_or_malformed_result_rules_fail(self):
        for result in (
            {"ruleId": "UnknownID"}, {"ruleIndex": -1}, {"ruleIndex": 99},
            {"ruleIndex": True}, {"ruleId": "BinaryArtifactsID", "ruleIndex": 1},
            {}, {"ruleId": "BinaryArtifactsID", "message": None},
        ):
            with self.subTest(result=result):
                data = report()
                data["runs"][1]["results"] = [dict({"message": {"text": "finding"}}, **result)]
                self.assertNotEqual(self.gate(data).returncode, 0)

    def test_execution_errors_and_error_notifications_fail(self):
        invocations = [
            [{"executionSuccessful": False}],
            [{"executionSuccessful": True, "toolExecutionNotifications": [
                {"level": "error", "message": {"text": "check failed"}}]}],
            [{"toolConfigurationNotifications": [{"level": "error"}]}],
            [{"toolExecutionNotifications": [{"exception": {"kind": "Error"}}]}],
            None, {}, [None], [{"executionSuccessful": "true"}],
        ]
        for invocation in invocations:
            with self.subTest(invocation=invocation):
                data = report()
                data["runs"][1]["invocations"] = invocation
                self.assertNotEqual(self.gate(data).returncode, 0)

    def test_report_publishing_precedes_enforcement_even_on_analysis_failure(self):
        step("Enforce vulnerability policy")
        self.assertLess(WORKFLOW.index("      - name: Upload artifact"),
                        WORKFLOW.index("      - name: Enforce vulnerability policy"))
        self.assertLess(WORKFLOW.index("      - name: Upload to code-scanning"),
                        WORKFLOW.index("      - name: Enforce vulnerability policy"))
        for name in ("Upload artifact", "Upload to code-scanning", "Enforce vulnerability policy"):
            self.assertIn("if: always()", step(name))
        self.assertIn("if-no-files-found: error", step("Upload artifact"))
        self.assertIn("results.json", step("Upload artifact"))

    def test_policy_regressions_run_without_change_filtering(self):
        ci = (ROOT / ".github/workflows/ci.yaml").read_text()
        invocation = re.search(r"^      - name: Check Scorecard vulnerability policy\n(.*?)(?=^      - )",
                               ci, re.M | re.S)
        self.assertIsNotNone(invocation)
        self.assertNotRegex(invocation.group(1), r"(?m)^\s+if:")
        self.assertIn("run: python3 tools/scorecard-policy_test.py", invocation.group(1))


if __name__ == "__main__":
    unittest.main()
