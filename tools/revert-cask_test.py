"""Exercise the cask revert with real published casks and workflows, a fake gh and a fake cosign, offline."""

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
# Real bytes: each release's checksums.txt, release.yaml at its tag and the cask
# the workflow pushed (v0.8.0: rebaze/homebrew-tap 58ae66d, v0.8.1: 788b64f).
FIXTURES = ROOT / "tools/testdata/cask"

FAKE_GH = textwrap.dedent('''\
    #!/usr/bin/env python3
    import base64, json, os, shutil, sys
    from pathlib import Path
    state = Path(os.environ["FAKE_STATE"])
    args = sys.argv[1:]
    def encoded(path):
        print(json.dumps({"content": base64.b64encode(path.read_bytes()).decode()}))
    if args == ["api", "repos/rebaze/homebrew-tap/commits?path=Casks/rio.rb&per_page=100", "--paginate", "--slurp"]:
        print((state / "pages.json").read_text())
    elif args[0] == "api" and args[1].startswith("repos/rebaze/homebrew-tap/contents/Casks/rio.rb?ref="):
        encoded(state / "casks" / (args[1].split("=", 1)[1] + ".rb"))
    elif args[0] == "api" and args[1].startswith("repos/rebaze/rio/contents/.github/workflows/release.yaml?ref="):
        encoded(state / "workflows" / (args[1].split("=", 1)[1] + ".yaml"))
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
        for sub in ("casks", "workflows"):
            (self.state / sub).mkdir(parents=True)
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
            shutil.copy(FIXTURES / (tag + "-release.yaml"), self.state / "workflows" / (tag + ".yaml"))
        self.v080 = (FIXTURES / "v0.8.0-rio.rb").read_text()
        # Newest first, as the GitHub API lists them.
        self.history([[("c081", (FIXTURES / "v0.8.1-rio.rb").read_text()), ("c080", self.v080)]])

    def history(self, pages):
        for page in pages:
            for sha, text in page:
                (self.state / "casks" / (sha + ".rb")).write_text(text)
        (self.state / "pages.json").write_text(json.dumps([[{"sha": sha} for sha, _ in page] for page in pages]))

    def revert(self, tag="v0.8.0"):
        output = self.root / "rio.rb"
        result = subprocess.run([sys.executable, str(SCRIPT), "--to", tag, "--output", str(output)],
                                text=True, capture_output=True, env=self.env)
        return result, output.read_text() if output.exists() else None

    def test_restores_the_cask_the_workflow_generated_for_that_release(self):
        result, cask = self.revert()
        self.assertEqual(result.returncode, 0, result.stderr)
        # The v0.8.0 cask still strips quarantine; today's template would not.
        self.assertEqual(cask, self.v080)
        self.assertIn("postflight_steps", cask)
        self.assertIn("rebaze/homebrew-tap@c080", result.stdout)

    def test_changed_install_hook_with_correct_hashes_is_refused(self):
        # Hashes still match the signed checksums; the executable Ruby does not.
        for changed in (self.v080.replace('"/usr/bin/xattr"', '"/usr/bin/false"'),
                        self.v080.replace('  binary "rio"', '  system_command "/bin/sh", args: ["-c", "id"]\n  binary "rio"')):
            with self.subTest(changed=changed[-80:]):
                self.assertNotEqual(changed, self.v080)
                self.history([[("c081", (FIXTURES / "v0.8.1-rio.rb").read_text()), ("evil", changed)]])
                result, cask = self.revert()
                self.assertEqual(result.returncode, 1)
                self.assertIn("no tap commit holds", result.stderr)
                self.assertIsNone(cask)

    def test_published_cask_on_a_later_page_is_found(self):
        filler = [("f%03d" % i, (FIXTURES / "v0.8.1-rio.rb").read_text()) for i in range(100)]
        self.history([filler, [("c080", self.v080)]])
        result, cask = self.revert()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("rebaze/homebrew-tap@c080", result.stdout)

    def test_unverified_checksums_are_refused(self):
        (self.state / "cosign-fails").touch()
        result, cask = self.revert()
        self.assertEqual(result.returncode, 1)
        self.assertIsNone(cask)

    def test_unknown_template_expansion_is_refused(self):
        workflow = self.state / "workflows" / "v0.8.0.yaml"
        workflow.write_text(workflow.read_text().replace('version "${VERSION}"', 'version "${VERSION}${SUFFIX}"'))
        result, _ = self.revert()
        self.assertEqual(result.returncode, 1)
        self.assertIn("restore by hand", result.stderr)

    def test_prerelease_is_refused(self):
        result, _ = self.revert("v0.8.0-rc1")
        self.assertEqual(result.returncode, 1)
        self.assertIn("stable", result.stderr)


if __name__ == "__main__":
    unittest.main()
