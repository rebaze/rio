"""Run the authored release-note selector against controlled release directories."""
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("release-notes.py")


class NotesTests(unittest.TestCase):
    def run_case(self, tag, content, expected):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            notes, dist = root / "notes", root / "dist"
            notes.mkdir(); dist.mkdir()
            generated = b"Generated changelog\n"
            (dist / "CHANGELOG.md").write_bytes(generated)
            if content is not None:
                (notes / (tag + ".md")).write_bytes(content)
            result = subprocess.run([sys.executable, str(SCRIPT), "--tag", tag,
                                     "--notes-dir", str(notes), "--dist", str(dist)], capture_output=True)
            self.assertEqual(result.returncode, expected, result.stderr.decode())
            actual = (dist / "CHANGELOG.md").read_bytes()
            if expected or content is None:
                self.assertEqual(actual, generated)
            else:
                self.assertEqual(hashlib.sha256(actual).digest(), hashlib.sha256(content).digest())

    def test_required_notes_missing_empty_mismatched_valid(self):
        for content, code in [(None, 1), (b" \n", 1), (b"# Rio v0.5.0\n\nWrong release\n", 1),
                              (b"# Rio v0.6.0\r\n\r\nExplain your SBOM delivery.\r\n", 0)]:
            with self.subTest(content=content):
                self.run_case("v0.6.0", content, code)

    def test_historical_fallback_is_explicit(self):
        self.run_case("v0.5.0", None, 0)
        self.run_case("v0.5.0", b"", 1)
        self.run_case("v1.0.0", None, 1)
        self.run_case("v0.6.0-rc.1", None, 1)

    def test_mismatched_prefix_and_empty_body_refuse(self):
        self.run_case("v0.6.0", b"# Rio v0.6.00\n\nMismatch\n", 1)
        self.run_case("v0.6.0", b"# Rio v0.6.0\n", 1)


if __name__ == "__main__":
    unittest.main()
