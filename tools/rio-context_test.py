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

    def test_control_characters_emit_no_partial_json(self):
        for codepoint in (0x01, 0x1F, 0x7F, 0x80, 0x85, 0x9F):
            with self.subTest(codepoint=codepoint):
                result = self.run_helper("--build-id", "run" + chr(codepoint) + "42")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertIn("controls", result.stderr)

    def test_unicode_text_is_preserved(self):
        result = self.run_helper("--build-id", "Büild–東京\u00a042")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["artifacts"][0]["build"]["id"],
                         "Büild–東京\u00a042")

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
            [rio, "normalize", "--manifest", "rio.yaml", "--out", "normalized", "--json"],
            cwd=self.directory.name, text=True, capture_output=True,
        )
        self.assertEqual(normalized.returncode, 0, normalized.stderr)
        run_directory = Path(self.directory.name) / json.loads(normalized.stdout)["runDirectory"]
        index = json.loads((run_directory / "index.json").read_text())
        self.assertEqual(index["artifacts"][0]["context"]["effective"]["source"]["repository"],
                         "https://code.example.org/widgets/console")

    def write_checksums(self, text):
        path = Path(self.directory.name) / "checksums.txt"
        path.write_text(text)
        return str(path)

    def test_checksums_become_ordered_distributions(self):
        a, b = "a" * 64, "b" * 64
        path = self.write_checksums("%s  widget_1.0_linux.tar.gz\n\n%s *widget_1.0_darwin.tar.gz\n" % (a, b))
        result = self.run_helper("--checksums", path,
                                 "--distribution-url", "https://dl.example.org/widget/v1.0/")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["artifacts"][0]["distributions"], [
            {"name": "widget_1.0_linux.tar.gz", "sha256": a,
             "url": "https://dl.example.org/widget/v1.0/widget_1.0_linux.tar.gz"},
            {"name": "widget_1.0_darwin.tar.gz", "sha256": b,
             "url": "https://dl.example.org/widget/v1.0/widget_1.0_darwin.tar.gz"},
        ])

    def test_distribution_url_percent_encodes_names(self):
        digest = "e" * 64
        names = {
            "app%20linux.tar.gz": "app%2520linux.tar.gz",
            "app#debug.zip": "app%23debug.zip",
            "app?x.zip": "app%3Fx.zip",
            "app linux.zip": "app%20linux.zip",
            "app:latest": "app%3Alatest",
        }
        prefix = "https://dl.example.org/widget/"
        path = self.write_checksums("".join("%s  %s\n" % (digest, name) for name in names))
        result = self.run_helper("--checksums", path, "--distribution-url", prefix)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["artifacts"][0]["distributions"],
                         [{"name": n, "sha256": digest, "url": prefix + q} for n, q in names.items()])

    def test_checksums_without_url_omit_url(self):
        path = self.write_checksums("%s  a.tgz\n" % ("c" * 64))
        result = self.run_helper("--checksums", path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["artifacts"][0]["distributions"],
                         [{"name": "a.tgz", "sha256": "c" * 64}])

    def test_invalid_checksums_emit_no_partial_json(self):
        good = "a" * 64
        cases = {
            "malformed": "nothex  a.tgz\n",
            "one space": "%s a.tgz\n" % good,
            "uppercase": "%s  a.tgz\n" % ("A" * 64),
            "short": "%s  a.tgz\n" % ("a" * 63),
            "long": "%s  a.tgz\n" % ("a" * 65),
            "duplicate": "%s  a.tgz\n%s  a.tgz\n" % (good, "b" * 64),
            "slash": "%s  dist/a.tgz\n" % good,
            "backslash": "%s  dist\\a.tgz\n" % good,
            "blank name": "%s   \n" % good,
            "padded name": "%s   a.tgz\n" % good,
            "trailing space": "%s  a.tgz \n" % good,
            "empty": "",
            "only blank lines": "\n\n",
            "too many": "".join("%s  f%d\n" % (good, i) for i in range(1001)),
        }
        for label, text in cases.items():
            with self.subTest(label):
                result = self.run_helper("--checksums", self.write_checksums(text))
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_exactly_1000_checksums_are_accepted(self):
        text = "".join("%s  f%d\n" % ("a" * 64, i) for i in range(1000))
        result = self.run_helper("--checksums", self.write_checksums(text))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(result.stdout)["artifacts"][0]["distributions"]), 1000)

    def test_missing_checksums_file_emits_nothing(self):
        result = self.run_helper("--checksums", str(Path(self.directory.name) / "absent.txt"))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_invalid_distribution_url_emits_no_partial_json(self):
        path = self.write_checksums("%s  a.tgz\n" % ("a" * 64))
        for prefix in ("https://dl.example.org/widget", "dl.example.org/", "ftp://dl.example.org/",
                       "https://user:pw@dl.example.org/", "https://dl.example.org/?x=1/",
                       "https://dl.example.org/#f/", "/relative/", ""):
            with self.subTest(prefix=prefix):
                result = self.run_helper("--checksums", path, "--distribution-url", prefix)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")
                self.assertNotIn("pw@", result.stderr)

    def test_distribution_url_requires_checksums(self):
        result = self.run_helper("--distribution-url", "https://dl.example.org/")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("--checksums", result.stderr)

    @unittest.skipUnless(os.environ.get("RIO_BIN"), "set RIO_BIN to run Rio interoperability smoke")
    def test_generated_distributions_normalize_with_rio(self):
        rio = os.environ["RIO_BIN"]
        self.sbom.write_bytes((SCRIPT.parent / "demo-context/inputs/console.cdx.json").read_bytes())
        digest = "d" * 64
        result = self.run_helper(
            "--checksums", self.write_checksums("%s  widget.tar.gz\n" % digest),
            "--distribution-url", "https://dl.example.org/widget/",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        (Path(self.directory.name) / "context.json").write_text(result.stdout)
        (Path(self.directory.name) / "rio.yaml").write_text(
            "version: 1\nartifacts:\n  - id: widget\n    sbom: input.json\n"
            "    context:\n      file: context.json\n"
        )
        normalized = subprocess.run(
            [rio, "normalize", "--manifest", "rio.yaml", "--out", "normalized", "--json"],
            cwd=self.directory.name, text=True, capture_output=True,
        )
        self.assertEqual(normalized.returncode, 0, normalized.stderr)
        run_directory = Path(self.directory.name) / json.loads(normalized.stdout)["runDirectory"]
        index = json.loads((run_directory / "index.json").read_text())
        self.assertEqual(index["artifacts"][0]["context"]["effective"]["distributions"],
                         [{"name": "widget.tar.gz", "sha256": digest,
                           "url": "https://dl.example.org/widget/widget.tar.gz"}])


    def write_pair(self, name="app-1.0-linux.tar.gz", sha512_name=None):
        d = Path(self.directory.name)
        (d / "sums256.txt").write_text("%s  %s\n" % ("a" * 64, name))
        (d / "sums512.txt").write_text("%s  %s\n" % ("b" * 128, sha512_name or name))
        return str(d / "sums256.txt"), str(d / "sums512.txt")

    def test_sha512_and_properties(self):
        s256, s512 = self.write_pair()
        result = self.run_helper("--checksums", s256, "--sha512-checksums", s512,
                                 "--file-properties", "*.tar.gz=archive,structured")
        self.assertEqual(result.returncode, 0, result.stderr)
        entry = json.loads(result.stdout)["artifacts"][0]["distributions"][0]
        self.assertEqual(entry, {"name": "app-1.0-linux.tar.gz", "sha256": "a" * 64, "sha512": "b" * 128,
                                 "executable": False, "archive": True, "structured": True})
        self.assertEqual(list(entry), ["name", "sha256", "sha512", "executable", "archive", "structured"])

    def test_first_match_wins_and_none(self):
        s256, s512 = self.write_pair()
        result = self.run_helper("--checksums", s256, "--sha512-checksums", s512,
                                 "--file-properties", "*.gz=none", "--file-properties", "*=executable")
        self.assertEqual(result.returncode, 0, result.stderr)
        entry = json.loads(result.stdout)["artifacts"][0]["distributions"][0]
        self.assertEqual((entry["executable"], entry["archive"], entry["structured"]), (False, False, False))

    def test_sha512_name_mismatch(self):
        s256, s512 = self.write_pair(sha512_name="other.tar.gz")
        result = self.run_helper("--checksums", s256, "--sha512-checksums", s512, "--file-properties", "*=none")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("sums512.txt", result.stderr)

    def test_unmatched_name(self):
        s256, s512 = self.write_pair()
        result = self.run_helper("--checksums", s256, "--sha512-checksums", s512,
                                 "--file-properties", "*.zip=archive")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("app-1.0-linux.tar.gz", result.stderr)

    def test_sha512_option_errors(self):
        s256, s512 = self.write_pair()
        cases = {
            "no checksums": (["--sha512-checksums", s512, "--file-properties", "*=none"], "--checksums"),
            "unknown flag": (["--checksums", s256, "--sha512-checksums", s512,
                              "--file-properties", "*=bogus"], "bogus"),
            "no equals": (["--checksums", s256, "--sha512-checksums", s512,
                           "--file-properties", "*"], "--file-properties"),
            "properties alone": (["--checksums", s256, "--file-properties", "*=none"], "--sha512-checksums"),
            "short digest": (["--checksums", s256, "--sha512-checksums", s256,
                              "--file-properties", "*=none"], "sums256.txt"),
        }
        for label, (args, text) in cases.items():
            with self.subTest(label):
                result = self.run_helper(*args)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertIn(text, result.stderr)

    def test_level(self):
        result = self.run_helper("--level", "assembled", "--lifecycle", "build")
        self.assertEqual(result.returncode, 0, result.stderr)
        entry = json.loads(result.stdout)["artifacts"][0]
        self.assertEqual(entry["level"], "assembled")
        self.assertEqual(list(entry), ["id", "sbom", "lifecycle", "level"])
        self.assertEqual(self.run_helper("--level", "bogus").returncode, 2)


if __name__ == "__main__":
    unittest.main()
