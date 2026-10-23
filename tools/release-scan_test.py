"""Exercise the published-release scan with real archives, a fake gh and a fake scanner, offline."""

import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/release-scan.py"
TAG = "v1.2.3"
COMMIT = "a" * 40

FAKE_GH = textwrap.dedent('''\
    #!/usr/bin/env python3
    import json, os, shutil, sys
    from pathlib import Path
    state = Path(os.environ["FAKE_STATE"])
    args = sys.argv[1:]
    with (state / "calls.log").open("a") as log:
        log.write(" ".join(args) + "\\n")
    if args[:2] == ["api", "repos/rebaze/rio/releases/latest"]:
        print("{TAG}")
    elif args[:2] == ["api", "repos/rebaze/rio/commits/{TAG}"]:
        print("{COMMIT}")
    elif args[:2] == ["release", "download"]:
        target = Path(args[args.index("--dir") + 1])
        for name in args[args.index("--pattern") + 1::2]:
            shutil.copy(state / "release" / name, target / name)
    elif args[:2] == ["attestation", "verify"]:
        if (state / "no-attestation").exists():
            sys.exit(1)
        print(json.dumps([{{"verificationResult": {{}}}}]))
    else:
        sys.exit("unexpected gh call: " + " ".join(args))
''').format(TAG=TAG, COMMIT=COMMIT)

# Finds a vulnerability in any binary whose bytes contain VULN; fails on BROKEN.
FAKE_SCANNER = textwrap.dedent('''\
    import sys
    if sys.argv[1] == "-version":
        print("Scanner: govulncheck@test")
        sys.exit(0)
    if not sys.argv[2].startswith("/"):
        sys.exit("relative binary path; the real scanner runs in another directory")
    data = open(sys.argv[2], "rb").read()
    if b"BROKEN" in data:
        sys.exit(1)
    if b"VULN" in data:
        print("Vulnerability #1: GO-2099-0001")
        sys.exit(3)
    print("No vulnerabilities found.")
''')


class ReleaseScanTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        (self.state / "release").mkdir(parents=True)
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        gh = bin_dir / "gh"
        gh.write_text(FAKE_GH)
        gh.chmod(0o755)
        scanner = self.root / "scanner.py"
        scanner.write_text(FAKE_SCANNER)
        self.env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"],
                        FAKE_STATE=str(self.state),
                        RIO_GOVULNCHECK=shlex.join([sys.executable, str(scanner)]))
        self.env.pop("GITHUB_STEP_SUMMARY", None)
        self.publish({})

    def publish(self, contents):
        release = self.state / "release"
        sums = []
        for system in ("darwin", "linux", "windows"):
            for arch in ("amd64", "arm64"):
                stem = "rio_" + TAG[1:] + "_" + system + "_" + arch
                data = contents.get(stem, b"binary " + stem.encode())
                if system == "windows":
                    name = stem + ".zip"
                    with zipfile.ZipFile(release / name, "w") as bundle:
                        bundle.writestr("rio.exe", data)
                        bundle.writestr("LICENSE", b"license")
                else:
                    name = stem + ".tar.gz"
                    with tarfile.open(release / name, "w:gz") as bundle:
                        for member, raw in (("rio", data), ("LICENSE", b"license")):
                            info = tarfile.TarInfo(member)
                            info.size = len(raw)
                            bundle.addfile(info, io.BytesIO(raw))
                sums.append(hashlib.sha256((release / name).read_bytes()).hexdigest() + "  " + name)
        (release / "checksums.txt").write_text("\n".join(sums) + "\n")
        (release / ("rio-" + TAG + ".intoto.jsonl")).write_text("{}\n")

    def scan(self, *extra, env=None, relative=False):
        output = self.root / "out"
        target = "out" if relative else str(output)
        result = subprocess.run([sys.executable, str(SCRIPT), "--output", target] + list(extra),
                                text=True, capture_output=True, env=env or self.env, cwd=self.root)
        report = output / "scan.json"
        return result, json.loads(report.read_text()) if report.exists() else None

    def calls(self):
        return (self.state / "calls.log").read_text()

    def test_latest_release_scans_every_binary_after_verification(self):
        result, report = self.scan()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(report["tag"], TAG)
        self.assertEqual(report["commit"], COMMIT)
        self.assertEqual(len(report["results"]), 6)
        self.assertTrue(all(r["status"] == "clean" for r in report["results"]))
        self.assertEqual(self.calls().count("attestation verify"), 6)
        self.assertIn("--source-digest " + COMMIT, self.calls())
        self.assertIn("release.yaml@refs/tags/" + TAG, self.calls())

    def test_relative_output_reaches_the_scanner_as_absolute_paths(self):
        result, report = self.scan(relative=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(all(r["status"] == "clean" for r in report["results"]))

    def test_finding_fails_and_names_the_archive(self):
        self.publish({"rio_1.2.3_windows_arm64": b"VULN"})
        result, report = self.scan()
        self.assertEqual(result.returncode, 1)
        found = [r for r in report["results"] if r["status"] != "clean"]
        self.assertEqual([(r["archive"], r["status"], r["vulnerabilities"]) for r in found],
                         [("rio_1.2.3_windows_arm64.zip", "vulnerable", ["GO-2099-0001"])])

    def test_scanner_error_is_never_clean(self):
        self.publish({"rio_1.2.3_linux_amd64": b"BROKEN"})
        result, report = self.scan()
        self.assertEqual(result.returncode, 1)
        statuses = {r["archive"]: r["status"] for r in report["results"]}
        self.assertEqual(statuses["rio_1.2.3_linux_amd64.tar.gz"], "error")

    def test_checksum_mismatch_stops_before_scanning(self):
        release = self.state / "release"
        (release / "checksums.txt").write_text((release / "checksums.txt").read_text().replace("a", "b", 1))
        result, report = self.scan()
        self.assertEqual(result.returncode, 1)
        self.assertIn("checksums differ", result.stderr)
        self.assertIsNone(report)

    def test_missing_provenance_stops_before_scanning(self):
        (self.state / "no-attestation").touch()
        result, report = self.scan()
        self.assertEqual(result.returncode, 1)
        self.assertIsNone(report)

    def test_explicit_tag_must_be_stable(self):
        result, _ = self.scan("--tag", "v1.2.3-rc1")
        self.assertEqual(result.returncode, 1)
        self.assertIn("stable", result.stderr)

    def test_existing_output_is_refused(self):
        (self.root / "out").mkdir()
        result, _ = self.scan()
        self.assertEqual(result.returncode, 1)
        self.assertIn("fresh directory", result.stderr)

    def test_summary_is_appended_for_the_workflow(self):
        summary = self.root / "summary.md"
        result, _ = self.scan(env=dict(self.env, GITHUB_STEP_SUMMARY=str(summary)))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("| `rio_1.2.3_linux_amd64.tar.gz` | clean | none |", summary.read_text())


if __name__ == "__main__":
    unittest.main()
