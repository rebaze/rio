#!/usr/bin/env python3
"""Check onboarding examples against RIO_BIN (installed binary, stdlib only)."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tarfile
import unittest

HERE = Path(__file__).resolve().parent


class OnboardingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        command = os.environ.get("RIO_BIN", "rio")
        resolved = shutil.which(command)
        if resolved is None:
            raise RuntimeError("Install Rio containing #71, or set RIO_BIN to that binary")
        cls.rio = str(Path(resolved).resolve())

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="rio onboarding [literal] ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def project(self, name):
        project = self.root / name
        shutil.copytree(HERE / "projects" / name, project)
        return project

    def command(self, cwd, *args, expected=0):
        result = subprocess.run(args, cwd=cwd, text=True, capture_output=True)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def configure(self, project, name):
        shutil.copyfile(HERE / "examples" / (name + ".yaml"), project / "rio.yaml")

    def load(self, path):
        return json.loads(path.read_text())

    def plan(self, project, expected=0):
        # A different CWD catches treating manifest paths as process-relative.
        return self.command(self.root, self.rio, "plan", "--manifest",
                            str(project / "rio.yaml"), "--json", expected=expected)

    def test_configurations_preserve_identity_and_inventory(self):
        scenarios = {
            "explicit": ["desktop"],
            "modules": ["billing-server", "orders-server"],
            "mixed": ["desktop", "legacy-server", "billing-server", "orders-server"],
        }
        for name, ids in scenarios.items():
            with self.subTest(project=name):
                project = self.project(name)
                self.command(project, "sh", "build.sh")
                original = None
                if name == "mixed":
                    original = json.loads(self.plan(project).stdout)
                self.configure(project, name)
                manifest_before = (project / "rio.yaml").read_bytes()
                plan = json.loads(self.plan(project).stdout)
                self.assertEqual([a["id"] for a in plan["artifacts"]], ids)
                if original:
                    # Existing ID, subject override (checked below), processing,
                    # and gate settings survive onboarding.
                    self.assertEqual(original["artifacts"][0], plan["artifacts"][0])
                    self.assertEqual(original["gate"], plan["gate"])
                out = project / "fresh-output"
                self.command(self.root, self.rio, "normalize", "--manifest",
                             str(project / "rio.yaml"), "--out", str(out),
                             "--gate", "fail", "--attest")
                index = self.load(out / "index.json")
                self.assertEqual([a["id"] for a in index["artifacts"]], ids)
                self.assertEqual(manifest_before, (project / "rio.yaml").read_bytes())
                for planned, row in zip(plan["artifacts"], index["artifacts"]):
                    self.assertEqual(planned["input"]["path"], row["input"]["path"])
                    self.assertEqual(planned.get("selection"), row.get("selection"))
                    source = self.load(project / row["input"]["path"])
                    output = self.load(out / row["output"]["path"])
                    self.assertEqual(source["components"], output["components"])
                    subject = output["metadata"]["component"]
                    if name == "mixed" and row["id"] == "desktop":
                        self.assertEqual(subject["name"], "shipping-desktop")
                        self.assertEqual(subject["version"], "3.2.0")
                        self.assertEqual(output["specVersion"], "1.5")
                    else:
                        self.assertEqual(source["metadata"]["component"], subject)
                    self.assertNotIn("context", row)
                    self.assertNotIn("enrichment", row)
                    self.assertNotIn("externalReferences", subject)

    def test_new_module_is_included_and_missing_output_is_not_hidden(self):
        project = self.project("modules")
        self.configure(project, "modules")
        self.command(project, "sh", "build.sh")
        before = (project / "rio.yaml").read_bytes()
        reporting = project / "services" / "reporting-server"
        shutil.copytree(project / "services" / "orders-server", reporting)
        plan = json.loads(self.plan(project).stdout)
        self.assertEqual([a["id"] for a in plan["artifacts"]],
                         ["billing-server", "orders-server", "reporting-server"])
        (reporting / "target" / "bom.json").unlink()
        result = self.plan(project, expected=2)
        self.assertIn("reporting-server", result.stderr)
        out = project / "refused"
        self.command(project, self.rio, "normalize", "--out", str(out), expected=2)
        self.assertFalse(out.exists())
        self.assertEqual(before, (project / "rio.yaml").read_bytes())

    def test_incomplete_producer_requires_a_build_step_not_a_narrower_selector(self):
        project = self.project("incomplete")
        self.configure(project, "incomplete")
        self.command(project, "sh", "build.sh")
        for command in ("plan", "normalize"):
            result = self.command(project, self.rio, command, "--out", "refused", expected=2)
            self.assertIn("reporting-server", result.stderr)
            self.assertFalse((project / "refused").exists())
        self.assertTrue((project / "services/reporting-server/pom.xml").is_file())

    def test_ambiguous_project_has_no_preselected_configuration(self):
        project = self.project("ambiguous")
        self.assertFalse((project / "rio.yaml").exists())
        self.assertFalse((HERE / "examples/ambiguous.yaml").exists())
        # Both candidates have valid SBOMs: file presence cannot answer the
        # release-policy question in this scenario.
        self.command(project, "sh", "build.sh")
        for module in ("api-server", "preview-server"):
            self.assertTrue((project / "services" / module / "target/bom.json").is_file())

    def test_ci_builds_then_bundles_only_fresh_successful_output(self):
        project = self.project("modules")
        self.configure(project, "modules")
        stale = project / "target/rio/obsolete.cdx.json"
        stale.parent.mkdir(parents=True)
        stale.write_text("stale input must not be collected")
        for _ in range(2):
            self.command(project, "sh", str(HERE / "ci.sh"), self.rio, "sh", "build.sh")
        runs = sorted(project.glob("rio-run.*"))
        self.assertEqual(len(runs), 2)
        for run in runs:
            with tarfile.open(run / "bundle.tgz") as archive:
                files = {entry.name for entry in archive.getmembers() if entry.isfile()}
            expected = {"plan.json", "normalized/index.json"}
            for artifact in ("billing-server", "orders-server"):
                expected.update({"normalized/" + artifact + ".cdx.json",
                                 "normalized/" + artifact + ".intoto.json"})
            self.assertEqual(files, expected)
            self.assertEqual(self.load(run / "plan.json")["artifacts"][0]["id"], "billing-server")
        self.assertEqual(stale.read_text(), "stale input must not be collected")

    def test_failed_archive_is_not_exposed_as_a_completed_bundle(self):
        project = self.project("modules")
        self.configure(project, "modules")
        # Simulate tar writing a partial archive before an I/O failure.
        commands = self.root / "commands"
        commands.mkdir()
        tar = commands / "tar"
        tar.write_text('#!/bin/sh\nprintf partial > "$2"\nexit 9\n')
        tar.chmod(0o755)
        result = subprocess.run(
            ["sh", str(HERE / "ci.sh"), self.rio, "sh", "build.sh"],
            cwd=project, text=True, capture_output=True,
            env=dict(os.environ, PATH=str(commands) + os.pathsep + os.environ["PATH"]),
        )
        self.assertEqual(result.returncode, 9, result.stdout + result.stderr)
        self.assertEqual(list(project.glob("rio-run.*/bundle.tgz")), [])
        self.assertNotIn("Bundle ready", result.stdout)

    def test_ci_does_not_bundle_build_plan_or_gate_failures(self):
        for failure, expected in (("build", 7), ("plan", 2), ("gate", 1)):
            with self.subTest(failure=failure):
                project = self.project("incomplete" if failure == "plan" else "modules")
                self.configure(project, "incomplete" if failure == "plan" else "modules")
                if failure == "gate":
                    seed = self.load(project / "seed.cdx.json")
                    del seed["components"][0]["purl"]
                    (project / "seed.cdx.json").write_text(json.dumps(seed))
                build = ["sh", "-c", "exit 7"] if failure == "build" else ["sh", "build.sh"]
                self.command(project, "sh", str(HERE / "ci.sh"), self.rio, *build, expected=expected)
                self.assertEqual(list(project.glob("rio-run.*/bundle.tgz")), [])
                runs = list(project.glob("rio-run.*"))
                if failure == "build":
                    self.assertEqual(runs, [])
                elif failure == "plan":
                    self.assertFalse((runs[0] / "normalized").exists())
                else:
                    index = self.load(runs[0] / "normalized/index.json")
                    self.assertTrue(all(a["gate"] == "fail" for a in index["artifacts"]))
                shutil.rmtree(project)


if __name__ == "__main__":
    unittest.main()
