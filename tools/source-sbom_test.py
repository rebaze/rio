"""Exercise source SBOM preparation with a synthetic generator and the real Rio CLI.

Run after `make build`, or set SOURCE_SBOM_TEST_RIO to a release binary.
Only the expensive cross-platform generator is replaced; jq and Rio's strict
BSI gate, receipt, normalized artifacts and index remain real.
"""

import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/source-sbom.sh"
RIO = Path(os.environ.get("SOURCE_SBOM_TEST_RIO", str(ROOT / "rio"))).resolve()
STD_REF = "opaque:pkg:golang/std@go1.27.4?type=module"

# Go's build step installs this fixture generator, avoiding network, module
# compilation and six cross-platform inventories while retaining real inputs.
FAKE_GO = '''#!/usr/bin/env python3
import os, shutil, sys
from pathlib import Path
args = sys.argv[1:]
if len(args) != 6 or args[0] != "-C" or args[2:4] != ["build", "-o"]:
    sys.exit("unexpected go call: " + repr(args))
Path(os.environ["FIXTURE_BUILD_MARKER"]).write_text("built")
shutil.copy(os.environ["FIXTURE_GENERATOR"], args[4])
Path(args[4]).chmod(0o755)
'''
GENERATOR = '''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
fixture = Path(os.environ["FIXTURE_DIR"]) / (os.environ["GOOS"] + "-" + os.environ["GOARCH"] + ".json")
Path(args[args.index("-output") + 1]).write_text(fixture.read_text())
'''


def fixture(go_version="go1.27.4"):
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {
            "timestamp": "2026-11-14T12:00:00Z",
            "component": {
                "type": "application", "bom-ref": "rio-subject",
                "name": "github.com/rebaze/rio", "version": "v1.2.3",
                "purl": "pkg:golang/github.com/rebaze/rio@v1.2.3",
            },
        },
        "components": [
            {"type": "library", "bom-ref": STD_REF, "name": "std",
             "version": go_version, "purl": "pkg:golang/std@" + go_version},
            {"type": "library", "bom-ref": "module-ref", "name": "golang.org/x/sync",
             "version": "v0.24.0", "purl": "pkg:golang/golang.org/x/sync@v0.24.0"},
        ],
        "dependencies": [
            {"ref": "rio-subject", "dependsOn": [STD_REF, "module-ref"]},
            {"ref": "module-ref", "dependsOn": []},
            {"ref": STD_REF, "dependsOn": []},
        ],
    }


@unittest.skipUnless(RIO.is_file() and shutil.which("jq"), "requires built Rio and jq")
class SourceSBOMTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="source-sbom-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        for path, content in ((bin_dir / "go", FAKE_GO), (bin_dir / "generator", GENERATOR)):
            path.write_text(content)
            path.chmod(0o755)
        self.fixtures = self.root / "fixtures"
        self.fixtures.mkdir()
        self.env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"],
                        FIXTURE_GENERATOR=str(bin_dir / "generator"), FIXTURE_DIR=str(self.fixtures),
                        FIXTURE_BUILD_MARKER=str(self.root / "generator-built"))
        self.env.pop("SOURCE_SBOM_MODULES", None)
        self.out = self.root / "source.cdx.json"
        self.receipt = self.root / "source-receipt.json"
        self.normalized = self.root / "retained normalized"

    def generate(self, doc=None, retained=False, override=None, claims=None):
        doc = fixture() if doc is None else doc
        for target in ("linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64",
                       "windows-amd64", "windows-arm64"):
            value = override if target == "windows-arm64" and override is not None else doc
            (self.fixtures / (target + ".json")).write_text(json.dumps(value))
        args = [str(SCRIPT), "1.2.3", str(self.out), str(RIO), str(self.receipt)]
        if retained or claims is not None:
            # Relative paths containing spaces must remain valid in the manifest.
            args.append(self.normalized.name)
        if claims is not None:
            path = self.root / "build claims.json"
            path.write_text(json.dumps(claims))
            args.append(str(path))
        return subprocess.run(args, cwd=self.root, env=self.env, capture_output=True, text=True)

    def successful(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(self.out.read_text())

    def test_explicit_claims_embed_source_revision_and_build_reference_before_gate(self):
        claims = {"schemaVersion": 1, "sourceRevision": "a" * 40,
                  "buildURL": "https://github.com/rebaze/rio/actions/runs/123", "buildID": "123.2"}
        original = fixture()
        doc = self.successful(self.generate(original, claims=claims))
        properties = doc["metadata"]["properties"]
        records = [json.loads(p["value"]) for p in properties if p["name"] == "rebaze:normalize:context"]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["effective"]["source"]["revision"], "a" * 40)
        self.assertEqual(records[0]["effective"]["source"]["repository"], "https://github.com/rebaze/rio")
        self.assertEqual(records[0]["effective"]["build"], {"url": claims["buildURL"], "id": "123.2"})
        refs = doc["metadata"]["component"]["externalReferences"]
        self.assertIn({"type": "build-system", "url": claims["buildURL"]}, refs)
        self.assertEqual(json.loads((self.fixtures / "linux-amd64.json").read_text()), original)
        receipt = json.loads(self.receipt.read_text())
        member = self.normalized / "runs" / receipt["run"]["id"] / receipt["artifacts"][0]["output"]["path"]
        self.assertEqual(member.read_bytes(), self.out.read_bytes())
        index = json.loads((member.parent / "index.json").read_text())
        self.assertEqual(index["artifacts"][0]["context"]["effective"]["source"]["revision"], "a" * 40)

    def test_invalid_claims_fail_before_generator_runs(self):
        valid = {"schemaVersion": 1, "sourceRevision": "a" * 40,
                 "buildURL": "https://github.com/rebaze/rio/actions/runs/123"}
        cases = [dict(valid, sourceRevision="abc"), dict(valid, buildURL="http://example.invalid/run"),
                 dict(valid, buildURL="https://user:secret@example.invalid/run"),
                 dict(valid, buildURL="https://example.invalid/run?token=secret"),
                 {"schemaVersion": 1, "sourceRevision": "a" * 40}, dict(valid, buildID="bad\nid")]
        for claims in cases:
            with self.subTest(claims=claims):
                result = self.generate(claims=claims)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("claims", result.stderr)
                self.assertFalse((self.root / "generator-built").exists())
                self.assertFalse(self.out.exists())

    def test_legacy_interface_emits_consumer_stdlib_identity_and_preserves_references(self):
        doc = self.successful(self.generate())
        std = next(c for c in doc["components"] if c["bom-ref"] == STD_REF)
        self.assertEqual((std["name"], std["version"], std["purl"]),
                         ("stdlib", "1.27.4", "pkg:golang/stdlib@1.27.4"))
        self.assertEqual(std["manufacturer"]["url"], ["https://go.dev"])
        self.assertEqual(std["licenses"][0]["expression"], "BSD-3-Clause")
        deps = {d["ref"]: d.get("dependsOn", []) for d in doc["dependencies"]}
        self.assertIn(STD_REF, deps["rio-subject"])
        self.assertIn(STD_REF, deps["module-ref"])
        self.assertIn(STD_REF, deps)
        self.assertIn(STD_REF, doc["compositions"][0]["dependencies"])
        other = next(c for c in doc["components"] if c["bom-ref"] == "module-ref")
        self.assertEqual((other["name"], other["version"], other["purl"]),
                         ("golang.org/x/sync", "v0.24.0", "pkg:golang/golang.org/x/sync@v0.24.0"))
        self.assertTrue(self.receipt.is_file())

    def test_retained_output_contains_verified_index_and_identical_sbom(self):
        self.successful(self.generate(retained=True))
        indexes = list(self.normalized.glob("runs/*/index.json"))
        self.assertEqual(len(indexes), 1)
        receipt = json.loads(self.receipt.read_text())
        run = indexes[0].parent
        self.assertEqual(run.name, receipt["run"]["id"])
        member = run / receipt["artifacts"][0]["output"]["path"]
        self.assertEqual(member.read_bytes(), self.out.read_bytes())
        index = json.loads(indexes[0].read_text())
        self.assertIn(hashlib.sha256(self.out.read_bytes()).hexdigest(), json.dumps(index))

    def test_go_release_beta_and_rc_versions(self):
        for go_version, expected in (("go1.27.0", "1.27.0"), ("go1.27rc1", "1.27rc1"),
                                     ("go1.27beta2", "1.27beta2")):
            with self.subTest(go_version=go_version):
                self.out.unlink(missing_ok=True)
                self.receipt.unlink(missing_ok=True)
                doc = self.successful(self.generate(fixture(go_version)))
                std = next(c for c in doc["components"] if c["bom-ref"] == STD_REF)
                self.assertEqual(std["version"], expected)
                self.assertEqual(std["purl"], "pkg:golang/stdlib@" + expected)

    def test_rejects_malformed_or_conflicting_generator_stdlib(self):
        cases = [
            {"version": "1.27.4", "purl": "pkg:golang/std@1.27.4"},
            {"version": "go1.27"},
            {"version": "go1.27.4extra"},
            {"version": "devel go1.28-deadbeef"},
            {"purl": "pkg:golang/std@go1.27.3"},
            {"purl": "pkg:golang/stdlib@go1.27.4"},
            {"purl": "pkg:golang/std@go1.27.4?type=module"},
            {"purl": None},
        ]
        for changes in cases:
            with self.subTest(changes=changes):
                self.out.unlink(missing_ok=True)
                self.receipt.unlink(missing_ok=True)
                doc = fixture()
                doc["components"][0].update(changes)
                result = self.generate(doc)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("standard library", result.stderr)
                self.assertFalse(self.out.exists())
                self.assertFalse(self.receipt.exists())

    def test_rejects_conflicting_stdlib_across_targets_before_deduplication(self):
        result = self.generate(override=fixture("go1.27.3"))
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("standard library", result.stderr)
        self.assertFalse(self.out.exists())

    def test_rejects_multiple_standard_library_components(self):
        doc = fixture()
        duplicate = copy.deepcopy(doc["components"][0])
        duplicate["bom-ref"] = "other-stdlib-ref"
        doc["components"].append(duplicate)
        result = self.generate(doc)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("standard library", result.stderr)

    def test_reviewed_table_is_checked_before_renaming(self):
        doc = fixture()
        doc["components"][0]["evidence"] = {"licenses": [{"license": {"id": "MIT"}}]}
        result = self.generate(doc)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("std is detected as MIT", result.stderr)
        self.assertFalse(self.out.exists())

    def test_strict_bsi_gate_still_rejects_invalid_module(self):
        doc = fixture()
        doc["components"][1].pop("version")
        result = self.generate(doc, retained=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.receipt.exists(), result.stderr)
        self.assertEqual(len(list(self.normalized.glob("runs/*/index.json"))), 1)


if __name__ == "__main__":
    unittest.main()
