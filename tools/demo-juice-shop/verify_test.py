"""Check that offline sample verification detects stale captured evidence."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
BINARY = os.environ.get("RIO_BIN", "rio")


class VerificationTest(unittest.TestCase):
    def verify(self, example):
        return subprocess.run(
            ["python3", str(HERE / "verify.py"), BINARY, str(example)],
            capture_output=True, text=True, timeout=60,
        )

    def test_published_samples_match_rio(self):
        result = self.verify(HERE / "example")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_stale_html_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            example = Path(directory) / "example"
            shutil.copytree(HERE / "example", example)
            path = example / "backend-report.html"
            path.write_text(path.read_text().replace("Findings 0", "Findings 100"))
            result = self.verify(example)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("backend-report.html", result.stderr)

    def test_mismatched_source_identity_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            example = Path(directory) / "example"
            shutil.copytree(HERE / "example", example)
            path = example / "source.json"
            source = json.loads(path.read_text())
            source["sboms"]["backend"]["sha256"] = "0" * 64
            path.write_text(json.dumps(source))
            result = self.verify(example)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("backend input identity", result.stderr)


if __name__ == "__main__":
    unittest.main()
