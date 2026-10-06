"""Offline checks for the disposable setup and teardown guards."""
import importlib.util
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("dtrack_setup", Path(__file__).with_name("setup.py"))
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


class SetupTests(unittest.TestCase):
    def test_private_unique_fixture_and_no_replacement(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "fixture"
            state = setup.create(root)
            self.assertRegex(state["project"], r"^rio-dtrack-[a-f0-9]{12}$")
            self.assertTrue(state["owner"])
            self.assertNotIn("password", json.dumps(state).lower())
            private = json.loads((root / "private.json").read_text())
            self.assertGreater(len(private["databasePassword"]), 24)
            self.assertNotEqual(private["databasePassword"], private["adminPassword"])
            if __import__('os').name != 'nt':
                self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE((root / "private.json").stat().st_mode), 0o600)
            with self.assertRaises(ValueError):
                setup.create(root)

    def test_refuses_non_loopback_and_foreign_ownership(self):
        for url in ("https://production.example", "http://192.0.2.1", "file:///tmp/data", "http://user:password@127.0.0.1"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                setup.local_url(url)
        setup.local_url("http://127.0.0.1:8080")
        with self.assertRaises(ValueError):
            setup.check_owner({"com.docker.compose.project": "production"}, {"project": "rio-dtrack-123456789abc", "owner": "ours"})
        setup.check_owner({"com.docker.compose.project": "rio-dtrack-123456789abc", "io.rebaze.rio.test-owner": "ours"}, {"project": "rio-dtrack-123456789abc", "owner": "ours"})

    def test_unobserved_login_does_not_attempt_password_change(self):
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "fixture"
            state = setup.create(root)
            state["url"] = "http://127.0.0.1:8080"
            private = json.loads((root / "private.json").read_text())
            with patch.object(setup, "request", return_value=(0, b"")) as request:
                with self.assertRaises(setup.SetupError):
                    setup.bootstrap(root, state, private)
                self.assertFalse(any(call.args[2].endswith("forceChangePassword") for call in request.call_args_list))


if __name__ == "__main__":
    unittest.main()
