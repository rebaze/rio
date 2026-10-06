"""Exercise the release publication boundary with real files and offline services."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/release-publish.py"
FIXTURE = ROOT / "tools/testdata/release/fake_service.py"


class ReleaseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        spec = importlib.util.spec_from_file_location("release_fixture", FIXTURE.with_name("fixture.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.__dict__.update(vars(module.create(self.root)))

    def command(self, operation, **extra_env):
        args = [sys.executable, str(SCRIPT), operation, "--stage", str(self.stage),
                "--inventory", str(self.inventory), "--tag", self.tag, "--repo", self.repo]
        if operation == "stage":
            args += ["--dist", str(self.dist)]
        else:
            args += ["--bundle", str(self.bundle)]
        return subprocess.run(args, text=True, capture_output=True,
                              env=dict(self.env, **extra_env))

    def prepare(self):
        result = self.command("stage")
        self.assertEqual(result.returncode, 0, result.stderr)

    def assert_blocked(self, result, reason):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(reason, result.stderr)
        self.assertFalse((self.root / "published").exists())

    def test_build_does_not_publish_before_attestation_verification(self):
        # Removing --skip=publish would expose releases before the later gate.
        workflow = (ROOT / ".github/workflows/release.yaml").read_text()
        args = re.search(r"args: (release [^\n]+)", workflow).group(1)
        subprocess.run(["goreleaser"] + shlex.split(args), env=self.env, check=True)
        self.assertFalse((self.root / "published").exists(),
                         "GoReleaser published before attestation verification")

    def test_unchanged_assets_are_verified_then_published(self):
        self.prepare()
        result = self.command("publish")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / "published").exists())
        self.assertEqual((self.root / "remote" / self.archive).read_bytes(),
                         b"packaged application A\n")
        events = (self.root / "events.jsonl").read_text().splitlines()
        self.assertTrue(any("cosign" in e for e in events))
        self.assertTrue(any("cyclonedx.org/bom" in e for e in events))
        self.assertLess(next(i for i, e in enumerate(events) if "verify" in e),
                        next(i for i, e in enumerate(events) if '"create"' in e))

    def test_replaced_archive_is_not_published(self):
        self.prepare()
        (self.stage / self.archive).write_bytes(b"packaged application B\n")
        self.assert_blocked(self.command("publish"), "changed")
        self.assertFalse((self.root / "remote").exists())

    def test_missing_or_extra_staged_asset_is_not_published(self):
        self.prepare()
        (self.stage / "unexpected.zip").write_bytes(b"extra")
        self.assert_blocked(self.command("publish"), "inventory")
        (self.stage / "unexpected.zip").unlink()
        (self.stage / self.sbom).unlink()
        self.assert_blocked(self.command("publish"), "inventory")

    def test_missing_bundle_is_not_published(self):
        self.prepare()
        self.bundle.unlink()
        self.assert_blocked(self.command("publish"), "bundle")

    def test_failed_verifiers_cannot_create_a_release(self):
        self.prepare()
        for failure in ("provenance", "sbom", "cosign"):
            with self.subTest(failure=failure):
                self.assert_blocked(self.command("publish", FAKE_FAIL=failure), "failed")
                self.assertFalse((self.root / "remote").exists())

    def test_changed_or_extra_uploaded_asset_remains_a_draft(self):
        self.prepare()
        self.assert_blocked(self.command("publish", FAKE_REMOTE_CHANGE="1"), "changed")
        self.assertTrue((self.root / "remote").exists())

    def test_existing_release_is_never_recreated(self):
        self.prepare()
        (self.root / "remote").mkdir()
        self.assert_blocked(self.command("publish"), "already exists")
        self.assertEqual(list((self.root / "remote").iterdir()), [])

    def test_unavailable_release_lookup_cannot_create_a_draft(self):
        self.prepare()
        self.assert_blocked(self.command("publish", FAKE_FAIL="lookup"), "failed")
        self.assertFalse((self.root / "remote").exists())

    def test_signed_sbom_must_match_the_published_document(self):
        self.prepare()
        self.assert_blocked(self.command("publish", FAKE_WRONG_SBOM="1"), "SBOM")
        self.assertFalse((self.root / "remote").exists())

    def test_unknown_inventory_and_wrong_tag_are_refused(self):
        self.prepare()
        data = json.loads(self.inventory.read_text())
        data["version"] = 999
        self.inventory.write_text(json.dumps(data))
        self.assert_blocked(self.command("publish"), "inventory")
        data["version"] = 1
        data["tag"] = "v9.9.9"
        self.inventory.write_text(json.dumps(data))
        self.assert_blocked(self.command("publish"), "inventory")

    def test_symlink_asset_is_refused(self):
        self.prepare()
        (self.stage / self.archive).unlink()
        (self.stage / self.archive).symlink_to(self.dist / self.archive)
        self.assert_blocked(self.command("publish"), "regular file")

    def test_stage_refuses_incomplete_or_inconsistent_build(self):
        (self.dist / self.archive).write_bytes(b"different bytes\n")
        self.assert_blocked(self.command("stage"), "checksum")
        self.assertFalse(self.inventory.exists())

    def test_stage_never_overwrites_a_previous_run(self):
        self.prepare()
        old = self.inventory.read_bytes()
        self.assert_blocked(self.command("stage"), "exists")
        self.assertEqual(self.inventory.read_bytes(), old)

    def test_prerelease_remains_prerelease(self):
        old = self.sbom
        self.tag = "v1.2.3-rc1"
        self.sbom = "rio-" + self.tag + "-source.cdx.json"
        (self.dist / old).rename(self.dist / self.sbom)
        self.prepare()
        result = self.command("publish")
        self.assertEqual(result.returncode, 0, result.stderr)
        events = (self.root / "events.jsonl").read_text()
        self.assertIn('"--prerelease"', events)


if __name__ == "__main__":
    unittest.main()
