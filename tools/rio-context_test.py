"""Black-box tests for the explicit one-artifact context producer."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("rio-context.py")


class ContextProducerTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.sbom = Path(self.directory.name) / "input.json"
        self.sbom.write_bytes(b'{"bomFormat":"CycloneDX"}\n')

    def run_helper(self, *args, env=None):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--artifact-id", "widget", "--sbom", str(self.sbom), *args],
            text=True,
            capture_output=True,
            env=env,
        )

    def test_raw_bytes_and_explicit_fields_are_encoded(self):
        result = self.run_helper(
            "--source-repository", "https://code.example.org/widgets/widget",
            "--source-revision", "a" * 40,
            "--source-subdirectory", "apps/widget",
            "--source-ref", "refs/heads/main",
            "--source-workspace", "clean",
            "--build-url", "https://ci.example.org/runs/42",
            "--build-id", 'run "42"',
            "--build-timestamp", "2026-01-01T12:00:00Z",
            "--build-system-name", "Gradle",
            "--build-system-version", "8.14",
            "--generator-name", "CycloneDX Gradle Plugin",
            "--generator-version", "3.0.0",
            "--lifecycle", "build",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        body = json.loads(result.stdout)
        self.assertEqual(body["contextVersion"], 1)
        self.assertEqual(len(body["artifacts"]), 1)
        entry = body["artifacts"][0]
        self.assertEqual(entry["sbom"]["sha256"], hashlib.sha256(self.sbom.read_bytes()).hexdigest())
        self.assertEqual(entry["source"]["workspace"], "clean")
        self.assertEqual(entry["build"]["id"], 'run "42"')
        self.assertEqual(entry["build"]["system"], {"name": "Gradle", "version": "8.14"})
        self.assertEqual(entry["generator"], {"name": "CycloneDX Gradle Plugin", "version": "3.0.0"})
        self.assertEqual(entry["lifecycle"], "build")

    def test_no_ambient_inference(self):
        environment = dict(os.environ, GITHUB_SHA="b" * 40, GITHUB_REPOSITORY="secret/repo", GITHUB_RUN_ID="99")
        result = self.run_helper(env=environment)
        self.assertEqual(result.returncode, 0, result.stderr)
        entry = json.loads(result.stdout)["artifacts"][0]
        self.assertEqual(set(entry), {"id", "sbom"})

    def test_invalid_input_emits_no_partial_json(self):
        for args in (
            ("--source-revision", "deadbeef"),
            ("--source-repository", "https://user:password@code.example.org/repo"),
            ("--source-repository", "https://@code.example.org/repo"),
            ("--build-system-version", "8.14"),
            ("--source-workspace", "clean", "--source-revision", "BAD"),
        ):
            with self.subTest(args=args):
                result = self.run_helper(*args)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertNotIn("password", result.stderr)

    def test_missing_sbom_emits_nothing(self):
        self.sbom.unlink()
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    @unittest.skipUnless(os.environ.get("RIO_BIN"), "set RIO_BIN to run Rio interoperability smoke")
    def test_generated_document_normalizes_with_rio(self):
        rio = os.environ["RIO_BIN"]
        self.sbom.write_bytes((SCRIPT.parent / "demo-context/inputs/console.cdx.json").read_bytes())
        result = self.run_helper(
            "--source-repository", "https://code.example.org/widgets/console",
            "--source-revision", "1" * 40,
            "--build-url", "https://ci.example.org/widgets/runs/42",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        (Path(self.directory.name) / "context.json").write_text(result.stdout)
        (Path(self.directory.name) / "rio.yaml").write_text(
            "version: 1\nartifacts:\n  - id: widget\n    sbom: input.json\n"
            "    context:\n      file: context.json\n"
            "      require: [source.repository, source.revision, build.url]\n"
        )
        normalized = subprocess.run(
            [rio, "normalize", "--manifest", "rio.yaml", "--out", "normalized"],
            cwd=self.directory.name, text=True, capture_output=True,
        )
        self.assertEqual(normalized.returncode, 0, normalized.stderr)
        index = json.loads((Path(self.directory.name) / "normalized/index.json").read_text())
        self.assertEqual(index["artifacts"][0]["context"]["effective"]["source"]["repository"],
                         "https://code.example.org/widgets/console")


if __name__ == "__main__":
    unittest.main()
