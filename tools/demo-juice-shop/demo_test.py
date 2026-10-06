"""Exercise helper preflight and cleanup paths without Docker or network access."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("juice_shop_demo", HERE / "demo.py")
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)


class HelperTest(unittest.TestCase):
    def test_changed_input_is_refused_before_receiver_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "inputs").mkdir()
            source = {"revision": demo.SOURCE_REV, "sboms": {}}
            for name in demo.INPUTS:
                payload = b'{"original": true}'
                (root / "inputs" / (name + ".cdx.json")).write_bytes(payload)
                source["sboms"][name] = {"sha256": hashlib.sha256(payload).hexdigest()}
            (root / "source.json").write_text(json.dumps(source))
            (root / "inputs/backend.cdx.json").write_text('{"changed": true}')
            with self.assertRaisesRegex(demo.fixture.SetupError, "generated input changed"):
                demo.prepare(root)
            self.assertFalse((root / ".dtrack").exists())

    def test_wrong_revision_is_refused_before_receiver_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source.json").write_text(json.dumps({"revision": "unexpected"}))
            with self.assertRaisesRegex(demo.fixture.SetupError, "unexpected source revision"):
                demo.prepare(root)
            self.assertFalse((root / ".dtrack").exists())

    def test_stop_without_receiver_preserves_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source.json").write_bytes(b'preserved source metadata')
            result = subprocess.run(["python3", str(HERE / "demo.py"), "stop", str(root)],
                                    capture_output=True, text=True, check=True, timeout=30)
            self.assertIn("source files are retained", result.stdout)
            self.assertEqual((root / "source.json").read_bytes(), b'preserved source metadata')
            self.assertEqual({p.name for p in root.iterdir()}, {"source.json"})


if __name__ == "__main__":
    unittest.main()
