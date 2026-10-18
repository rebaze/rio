"""Exercise the cask revert with real published casks, a fake gh and a fake cosign, offline."""

import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/revert-cask.py"
FIXTURES = ROOT / "tools/testdata/cask"

FAKE_GH = textwrap.dedent('''\
    #!/usr/bin/env python3
    import base64, json, os, shutil, sys
    from pathlib import Path
    state = Path(os.environ["FAKE_STATE"])
    args = sys.argv[1:]
    if args[:2] == ["api", "repos/rebaze/homebrew-tap/commits?path=Casks/rio.rb&per_page=100"]:
        print((state / "commits.json").read_text())
    elif args[0] == "api" and args[1].startswith("repos/rebaze/homebrew-tap/contents/Casks/rio.rb?ref="):
        sha = args[1].split("=", 1)[1]
        print(json.dumps({"content": base64.b64encode((state / "casks" / (sha + ".rb")).read_bytes()).decode()}))
    elif args[:2] == ["release", "download"]:
        tag, target = args[2], Path(args[args.index("--dir") + 1])
        for name in args[args.index("--pattern") + 1::2]:
            shutil.copy(state / "releases" / tag / name, target / name)
    else:
        sys.exit("unexpected gh call: " + " ".join(args))
''')

FAKE_COSIGN = textwrap.dedent('''\
    #!/bin/sh
    [ -e "$FAKE_STATE/cosign-fails" ] && exit 1
    case "$*" in *"release.yaml@refs/tags/"*) exit 0;; esac
    exit 1
''')


class RevertCaskTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        (self.state / "casks").mkdir(parents=True)
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        for name, text in (("gh", FAKE_GH), ("cosign", FAKE_COSIGN)):
            (bin_dir / name).write_text(text)
            (bin_dir / name).chmod(0o755)
        self.env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ["PATH"], FAKE_STATE=str(self.state))
        for tag in ("v0.8.0", "v0.8.1"):
            release = self.state / "releases" / tag
            release.mkdir(parents=True)
            shutil.copy(FIXTURES / (tag + "-checksums.txt"), release / "checksums.txt")
            (release / "checksums.txt.sigstore.json").write_text("{}")
        # Newest first, as the GitHub API lists them.
        self.history([("c081", (FIXTURES / "v0.8.1-rio.rb").read_text()),
                      ("c080", (FIXTURES / "v0.8.0-rio.rb").read_text())])

    def history(self, commits):
        for sha, text in commits:
            (self.state / "casks" / (sha + ".rb")).write_text(text)
        (self.state / "commits.json").write_text(json.dumps([{"sha": sha} for sha, _ in commits]))

    def revert(self, tag="v0.8.0"):
        output = self.root / "rio.rb"
        result = subprocess.run([sys.executable, str(SCRIPT), "--to", tag, "--output", str(output)],
                                text=True, capture_output=True, env=self.env)
        return result, output.read_text() if output.exists() else None

    def test_restores_the_cask_published_for_that_release(self):
        result, cask = self.revert()
        self.assertEqual(result.returncode, 0, result.stderr)
        # The v0.8.0 cask still strips quarantine; re-rendering today's template would not.
        self.assertEqual(cask, (FIXTURES / "v0.8.0-rio.rb").read_text())
        self.assertIn("postflight_steps", cask)
        self.assertIn("rebaze/homebrew-tap@c080", result.stdout)

    def test_newest_cask_for_the_version_wins(self):
        fixed = (FIXTURES / "v0.8.0-rio.rb").read_text().replace("# No zap stanza required", "# fixed by hand")
        self.history([("c081", (FIXTURES / "v0.8.1-rio.rb").read_text()), ("fix", fixed),
                      ("c080", (FIXTURES / "v0.8.0-rio.rb").read_text())])
        result, cask = self.revert()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(cask, fixed)

    def test_tampered_tap_hash_is_refused(self):
        original = (FIXTURES / "v0.8.0-rio.rb").read_text()
        sha = original.split('sha256 "', 1)[1][:64]
        self.history([("c080", original.replace(sha, "0" * 64))])
        result, cask = self.revert()
        self.assertEqual(result.returncode, 1)
        self.assertIn("differs from signed checksums", result.stderr)
        self.assertIsNone(cask)

    def test_extra_hash_is_refused(self):
        original = (FIXTURES / "v0.8.0-rio.rb").read_text()
        self.history([("c080", original.replace('  binary "rio"', '  sha256 "' + "1" * 64 + '"\n  binary "rio"'))])
        result, cask = self.revert()
        self.assertEqual(result.returncode, 1)
        self.assertIn("exactly one hash per platform", result.stderr)

    def test_unverified_checksums_are_refused(self):
        (self.state / "cosign-fails").touch()
        result, cask = self.revert()
        self.assertEqual(result.returncode, 1)
        self.assertIsNone(cask)

    def test_version_missing_from_the_tap_is_refused(self):
        self.history([("c081", (FIXTURES / "v0.8.1-rio.rb").read_text())])
        result, _ = self.revert()
        self.assertEqual(result.returncode, 1)
        self.assertIn("no cask for 0.8.0", result.stderr)

    def test_prerelease_is_refused(self):
        result, _ = self.revert("v0.8.0-rc1")
        self.assertEqual(result.returncode, 1)
        self.assertIn("stable", result.stderr)


if __name__ == "__main__":
    unittest.main()
