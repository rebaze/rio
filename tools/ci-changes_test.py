"""Exercise CI change detection with real workflow shell, without Git or network."""

import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / ".github/workflows/ci.yaml").read_text()
DETECTOR = textwrap.dedent(
    WORKFLOW[
        WORKFLOW.index("          go=false") : WORKFLOW.index(
            "\n      - uses: actions/setup-go"
        )
    ]
)


def detect(changed, event="pull_request"):
    script = DETECTOR.replace("${{ github.event_name }}", event)
    with tempfile.NamedTemporaryFile() as output:
        subprocess.run(
            ["bash", "-eu", "-o", "pipefail", "-c", script],
            env=dict(os.environ, CHANGED=changed, GITHUB_OUTPUT=output.name),
            check=True,
            capture_output=True,
            text=True,
        )
        return dict(
            line.split("=", 1) for line in Path(output.name).read_text().splitlines()
        )


class ChangesTest(unittest.TestCase):
    def test_every_workflow_runs_go_checks(self):
        paths = sorted(
            str(path.relative_to(ROOT))
            for path in (ROOT / ".github/workflows").glob("*.yaml")
        )
        paths.append(".github/workflows/future.yml")
        for path in paths:
            with self.subTest(path=path):
                result = detect(path)
                self.assertEqual(result["go"], "true")
                self.assertEqual(
                    result["goreleaser"], str(path.endswith("/ci.yaml")).lower()
                )
                self.assertEqual(
                    result["shell"], str(path.endswith("/ci.yaml")).lower()
                )
                self.assertEqual(
                    result["python"],
                    str(
                        path.endswith(("/ci.yaml", "/dependabot-auto-merge.yaml", "/release.yaml"))
                    ).lower(),
                )

    def test_both_module_manifests_and_checksums_run_go_checks(self):
        for path in (
            "go.mod",
            "go.sum",
            "tools/security/go.mod",
            "tools/security/go.sum",
        ):
            with self.subTest(path=path):
                self.assertEqual(detect(path)["go"], "true")

    def test_enrichment_demo_changes_run_binary_checks(self):
        for path in (
            "tools/demo-enrichment/rio.yaml",
            "tools/demo-enrichment/inputs/console.cdx.json",
            "tools/demo-enrichment/run.sh",
        ):
            with self.subTest(path=path):
                self.assertEqual(detect(path)["go"], "true")

    def test_context_demo_changes_run_binary_checks(self):
        for path in (
            "tools/demo-context/rio.yaml",
            "tools/demo-context/inputs/console.cdx.json",
            "tools/demo-context/context.json",
            "tools/demo-context/run.sh",
            "tools/demo-context/check-replacement.sh",
        ):
            with self.subTest(path=path):
                result = detect(path)
                self.assertEqual(result["go"], "true")
                if path.endswith(".sh"):
                    self.assertEqual(result["shell"], "true")

    def test_artifact_sets_demo_changes_run_binary_checks(self):
        for path in (
            "tools/demo-artifact-sets/rio.yaml",
            "tools/demo-artifact-sets/services/billing-server/pom.xml",
            "tools/demo-artifact-sets/services/billing-server/target/bom.json",
            "tools/demo-artifact-sets/run.sh",
        ):
            with self.subTest(path=path):
                result = detect(path)
                self.assertEqual(result["go"], "true")
                if path.endswith(".sh"):
                    self.assertEqual(result["shell"], "true")

    def test_first_repair_sample_runs_binary_checks(self):
        for path in (
            "tools/demo-repair/bom.json",
            "tools/demo-repair/rio.yaml",
            "tools/demo-repair/run.sh",
        ):
            with self.subTest(path=path):
                self.assertEqual(detect(path)["go"], "true")

    def test_onboarding_guide_and_examples_run_binary_checks(self):
        for path in (
            "docs/agent-integration.md",
            "tools/demo-agent-integration/examples/mixed.yaml",
            "tools/demo-agent-integration/projects/modules/seed.cdx.json",
            "tools/demo-agent-integration/ci.sh",
            "tools/demo-agent-integration/test.py",
            "tools/demo-agent-integration/EVALUATION.md",
        ):
            with self.subTest(path=path):
                self.assertEqual(detect(path)["go"], "true")

    def test_context_helper_changes_run_python_checks(self):
        self.assertEqual(detect("tools/rio-context.py")["python"], "true")
        self.assertEqual(detect("tools/rio-context_test.py")["python"], "true")
        self.assertEqual(detect("tools/rio-context.py")["go"], "true")
        self.assertEqual(detect("tools/rio-context_test.py")["go"], "true")

    def test_unrelated_documentation_keeps_checks_skipped(self):
        self.assertEqual(
            detect("README.md"),
            dict(go="false", goreleaser="false", shell="false", python="false"),
        )

    def test_scheduled_and_manual_runs_scan_without_changes(self):
        for event in ("schedule", "workflow_dispatch"):
            with self.subTest(event=event):
                self.assertEqual(detect("", event)["go"], "true")


if __name__ == "__main__":
    unittest.main()
