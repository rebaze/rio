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
        args = [sys.executable, str(SCRIPT), operation,
                "--inventory", str(self.inventory), "--tag", self.tag, "--repo", self.repo]
        if operation == "stage":
            args += ["--stage", str(self.stage), "--dist", str(self.dist)]
        elif operation == "vacant":
            args = args[:3] + ["--tag", self.tag, "--repo", self.repo]
        elif operation == "draft":
            args += ["--stage", str(self.stage), "--bundle", str(self.bundle), "--record", str(self.record)]
        else:
            args += ["--record", str(self.record)]
        return subprocess.run(args, text=True, capture_output=True,
                              env=dict(self.env, **extra_env))

    def drafted(self):
        self.prepare()
        result = self.command("draft")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / "published").exists(), "draft must not publish")

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
        commands = re.findall(r"^[ \t]*(?:run: )?(goreleaser release [^\n]+)", workflow, re.MULTILINE)
        self.assertEqual(len(commands), 1, "expected exactly one GoReleaser release command")
        command = commands[0]
        subprocess.run(shlex.split(command), env=self.env, check=True)
        self.assertFalse((self.root / "published").exists(),
                         "GoReleaser published before attestation verification")

    def test_unchanged_assets_are_verified_then_published(self):
        self.drafted()
        record = json.loads(self.record.read_text())
        self.assertEqual(record["release"], 123)
        self.assertNotIn("CHANGELOG.md", record["assets"])
        self.assertIn("rio-" + self.tag + ".intoto.jsonl", record["assets"])
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
        self.assert_blocked(self.command("draft"), "changed")
        self.assertFalse((self.root / "remote").exists())

    def test_missing_or_extra_staged_asset_is_not_published(self):
        self.prepare()
        (self.stage / "unexpected.zip").write_bytes(b"extra")
        self.assert_blocked(self.command("draft"), "inventory")
        (self.stage / "unexpected.zip").unlink()
        (self.stage / self.sbom).unlink()
        self.assert_blocked(self.command("draft"), "inventory")

    def test_missing_bundle_is_not_published(self):
        self.prepare()
        self.bundle.unlink()
        self.assert_blocked(self.command("draft"), "bundle")

    def test_failed_verifiers_cannot_create_a_release(self):
        self.prepare()
        for failure in ("provenance", "sbom", "cosign"):
            with self.subTest(failure=failure):
                self.assert_blocked(self.command("draft", FAKE_FAIL=failure), "failed")
                self.assertFalse((self.root / "remote").exists())

    def test_changed_or_extra_uploaded_asset_remains_a_draft(self):
        self.prepare()
        self.assert_blocked(self.command("draft", FAKE_REMOTE_CHANGE="1"), "digest differs")
        self.assertTrue((self.root / "remote").exists())
        self.assertFalse(self.record.exists(), "a refused draft must not leave a record to publish")

    def test_existing_release_is_never_recreated(self):
        self.prepare()
        (self.root / "remote").mkdir()
        self.assert_blocked(self.command("draft"), "already exists")
        self.assertEqual(list((self.root / "remote").iterdir()), [])

    def test_unavailable_release_lookup_cannot_create_a_draft(self):
        self.prepare()
        self.assert_blocked(self.command("draft", FAKE_FAIL="lookup"), "failed")
        self.assertFalse((self.root / "remote").exists())

    def test_signed_sbom_must_match_the_published_document(self):
        self.prepare()
        self.assert_blocked(self.command("draft", FAKE_WRONG_SBOM="1"), "SBOM")
        self.assertFalse((self.root / "remote").exists())

    def test_unknown_inventory_and_wrong_tag_are_refused(self):
        self.prepare()
        data = json.loads(self.inventory.read_text())
        data["version"] = 999
        self.inventory.write_text(json.dumps(data))
        self.assert_blocked(self.command("draft"), "inventory")
        data["version"] = 1
        data["tag"] = "v9.9.9"
        self.inventory.write_text(json.dumps(data))
        self.assert_blocked(self.command("draft"), "inventory")

    def test_symlink_asset_is_refused(self):
        self.prepare()
        (self.stage / self.archive).unlink()
        (self.stage / self.archive).symlink_to(self.dist / self.archive)
        self.assert_blocked(self.command("draft"), "regular file")

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
        bundle = json.loads(self.bundle.read_text())
        bundle["subjects"][self.sbom] = bundle["subjects"].pop(old)
        self.bundle.write_text(json.dumps(bundle))
        self.drafted()
        result = self.command("publish")
        self.assertEqual(result.returncode, 0, result.stderr)
        events = (self.root / "events.jsonl").read_text()
        self.assertIn('"--prerelease"', events)

    def test_source_sbom_needs_build_provenance(self):
        self.prepare()
        self.assert_blocked(self.command("draft", FAKE_UNSIGNED=self.sbom), "failed")
        self.assertFalse((self.root / "remote").exists())

    def test_publish_flips_only_the_recorded_draft(self):
        self.drafted()
        for env in ({"FAKE_SECOND_DRAFT": "1"}, {"FAKE_DRAFT_ID": "456"}, {"FAKE_ALREADY_PUBLISHED": "1"}):
            with self.subTest(env=env):
                self.assert_blocked(self.command("publish", **env), "ambiguous or already published")

    def test_publish_refuses_a_draft_whose_digest_changed(self):
        self.drafted()
        self.assert_blocked(self.command("publish", FAKE_ASSET_DIGEST="sha256:" + "0" * 64), "digest")

    def test_publish_refuses_a_draft_whose_bytes_changed(self):
        self.drafted()
        (self.root / "remote" / self.archive).write_bytes(b"replaced while waiting\n")
        self.assert_blocked(self.command("publish"), "changed")

    def test_publish_refuses_a_missing_or_extra_draft_asset(self):
        self.drafted()
        (self.root / "remote" / "extra.zip").write_bytes(b"extra")
        self.assert_blocked(self.command("publish"), "assets")
        (self.root / "remote" / "extra.zip").unlink()
        (self.root / "remote" / "checksums.txt").unlink()
        self.assert_blocked(self.command("publish"), "assets")

    def test_publish_refuses_a_record_that_disagrees_with_the_inventory(self):
        self.drafted()
        original = self.record.read_text()
        record = json.loads(original)
        record["assets"][self.archive] = "f" * 64
        self.record.write_text(json.dumps(record))
        self.assert_blocked(self.command("publish"), "record")
        record = json.loads(original)
        record["tag"] = "v9.9.9"
        self.record.write_text(json.dumps(record))
        self.assert_blocked(self.command("publish"), "record")

    def test_vacant_refuses_a_tag_with_a_release_or_draft(self):
        self.assertEqual(self.command("vacant").returncode, 0)
        (self.root / "remote").mkdir()
        self.assert_blocked(self.command("vacant"), "already exists")
        self.assert_blocked(self.command("vacant", FAKE_FAIL="lookup"), "failed")

    def test_publish_refuses_a_changed_prerelease_flag(self):
        self.drafted()
        self.assert_blocked(self.command("publish", FAKE_PRERELEASE_FLIP="1"), "prerelease")

    def test_publish_reports_a_release_that_changed_while_it_was_published(self):
        self.drafted()
        result = self.command("publish", FAKE_SWAP_AFTER_PUBLISH="1")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("published release differs", result.stderr)

    def test_assets_are_downloaded_by_id_not_by_tag(self):
        self.drafted()
        self.assertEqual(self.command("publish").returncode, 0)
        events = (self.root / "events.jsonl").read_text()
        self.assertNotIn('"download"', events)
        self.assertIn("/releases/assets/1000", events)

    def test_publish_without_a_draft_record_does_nothing(self):
        self.prepare()
        self.assert_blocked(self.command("publish"), "record")
        self.assertFalse((self.root / "remote").exists())


if __name__ == "__main__":
    unittest.main()
