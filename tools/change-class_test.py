"""Exercise pull request classification and labelling offline, with a fake gh."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/change-class.py"
_spec = importlib.util.spec_from_file_location("change_class", SCRIPT)
cc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cc)

BUMP = "@@ -5 +5 @@\n-\tgithub.com/bmatcuk/doublestar/v4 v4.10.2\n+\tgithub.com/bmatcuk/doublestar/v4 v4.10.3\n"
MAJOR = "@@ -5 +5 @@\n-\tgithub.com/bmatcuk/doublestar/v4 v4.10.3\n+\tgithub.com/bmatcuk/doublestar/v5 v5.0.0\n"
NEW = "@@ -5,0 +6 @@\n+\tgolang.org/x/net v0.50.0 // indirect\n"
MINOR = "@@ -5 +5 @@\n-\tgolang.org/x/text v0.40.0\n+\tgolang.org/x/text v0.41.0\n"
V0_TO_V1 = "@@ -5 +5 @@\n-\tgithub.com/spf13/pflag v0.9.0\n+\tgithub.com/spf13/pflag v1.0.0\n"
INCOMPATIBLE = "@@ -5 +5 @@\n-\tgithub.com/old/lib v2.3.0+incompatible\n+\tgithub.com/old/lib v3.0.0+incompatible\n"


def files(*names, patch=None):
    return [{"filename": n, "patch": patch} if patch is not None else {"filename": n} for n in names]


class ClassifyTest(unittest.TestCase):
    def test_ordinary_code_and_docs_are_standard(self):
        self.assertEqual(cc.classify(files("internal/cli/run.go", "README.md", "docs/cli.md"), ""), ("standard", {}))

    def test_each_path_rule_raises_the_class(self):
        cases = {
            "internal/receipt/write.go": "critical_function",
            "internal/gate/quality/check.go": "critical_function",
            "internal/delivery/oci/submit.go": "external_interface",
            "tools/rio-attest-sign.sh": "security_component",
            ".github/workflows/release.yaml": "pipeline_or_rules",
            ".goreleaser.yaml": "pipeline_or_rules",
            "tools/release-publish.py": "pipeline_or_rules",
            "tools/security/go.sum": "pipeline_or_rules",
            "install.sh": "pipeline_or_rules",
            ".github/pull_request_template.md": "pipeline_or_rules",
        }
        for name, criterion in cases.items():
            with self.subTest(name=name):
                cls, reasons = cc.classify(files(name), "")
                self.assertEqual(cls, "significant")
                self.assertEqual(reasons, {criterion: [name]})

    def test_single_star_stays_within_one_directory(self):
        self.assertEqual(cc.classify(files("tools/release-notes/sub/x.py"), "")[0], "standard")

    def test_moving_a_file_out_of_a_rule_still_counts(self):
        entry = [{"filename": "docs/old-release.yaml", "previous_filename": ".github/workflows/release.yaml"}]
        self.assertEqual(cc.classify(entry, "")[1], {"pipeline_or_rules": [".github/workflows/release.yaml"]})

    def test_dependency_patch_and_minor_bumps_are_standard(self):
        for patch in (BUMP, MINOR):
            with self.subTest(patch=patch):
                self.assertEqual(cc.classify(files("go.mod", patch=patch) + files("go.sum"), "")[0], "standard")

    def test_same_path_major_upgrades_are_significant(self):
        for patch, change in ((V0_TO_V1, "github.com/spf13/pflag v0.9.0 to v1.0.0"),
                              (INCOMPATIBLE, "github.com/old/lib v2.3.0+incompatible to v3.0.0+incompatible")):
            with self.subTest(change=change):
                self.assertEqual(cc.classify(files("go.mod", patch=patch), ""),
                                 ("significant", {"new_or_major_dependency": [change]}))

    def test_major_bump_and_new_module_are_significant(self):
        for patch, module in ((MAJOR, "github.com/bmatcuk/doublestar/v5"), (NEW, "golang.org/x/net")):
            with self.subTest(module=module):
                self.assertEqual(cc.classify(files("go.mod", patch=patch), ""),
                                 ("significant", {"new_or_major_dependency": [module]}))

    def test_unreadable_patch_or_file_list_raises(self):
        self.assertEqual(cc.classify(files("go.mod"), "")[0], "significant")
        self.assertEqual(cc.classify(files("README.md"), "", complete=False)[1],
                         {"incomplete_file_list": ["the API did not return every changed file"]})

    def test_ticked_box_raises_and_unticked_does_not(self):
        template = (ROOT / ".github/pull_request_template.md").read_text()
        self.assertEqual(cc.classify(files("README.md"), template)[0], "standard")
        ticked = template.replace("- [ ] Possible substantial modification", "- [x] Possible substantial modification")
        self.assertNotEqual(ticked, template)
        self.assertEqual(cc.classify(files("README.md"), ticked)[1],
                         {"cra_substantial_modification_question": ["ticked in the PR description"]})


FAKE_GH = textwrap.dedent('''\
    #!/usr/bin/env python3
    import json, os, sys
    from pathlib import Path
    state = Path(os.environ["FAKE_STATE"])
    args = sys.argv[1:]
    with (state / "calls.log").open("a") as log:
        log.write(json.dumps(args) + "\\n")
    if args[:2] == ["api", "repos/rebaze/rio/pulls/7"]:
        print((state / "pr.json").read_text())
    elif args[:3] == ["api", "--paginate", "repos/rebaze/rio/pulls/7/files?per_page=100"]:
        for entry in json.loads((state / "files.json").read_text()):
            print(json.dumps(entry))
    elif args[:3] in (["api", "-X", "POST"], ["api", "-X", "DELETE"]):
        print("{}")
    else:
        sys.exit("unexpected gh call: " + " ".join(args))
''')


class LabelTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "bin").mkdir()
        (self.root / "bin/gh").write_text(FAKE_GH)
        (self.root / "bin/gh").chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.root / "bin") + os.pathsep + os.environ["PATH"],
                        FAKE_STATE=str(self.root), GITHUB_STEP_SUMMARY=str(self.root / "summary.md"))

    def run_tool(self, names, labels=(), changed=None):
        (self.root / "files.json").write_text(json.dumps([{"filename": n} for n in names]))
        (self.root / "pr.json").write_text(json.dumps({"body": "", "labels": [{"name": n} for n in labels],
                                                       "changed_files": len(names) if changed is None else changed}))
        result = subprocess.run([sys.executable, str(SCRIPT), "--pr", "7"], text=True, capture_output=True, env=self.env)
        calls = [json.loads(line) for line in (self.root / "calls.log").read_text().splitlines()]
        return result, [c for c in calls if c[1] == "-X"]

    def test_significant_replaces_a_stale_standard_label(self):
        result, writes = self.run_tool([".github/workflows/ci.yaml"], labels=["class:standard"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(writes, [
            ["api", "-X", "POST", "repos/rebaze/rio/issues/7/labels", "-f", "labels[]=class:significant"],
            ["api", "-X", "DELETE", "repos/rebaze/rio/issues/7/labels/class:standard"]])
        self.assertIn("`pipeline_or_rules` | `.github/workflows/ci.yaml`", (self.root / "summary.md").read_text())

    def test_existing_significant_label_is_never_lowered(self):
        # For example after the author unticks the substantial-modification box.
        result, writes = self.run_tool(["README.md"], labels=["class:significant"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(writes, [])
        self.assertIn("kept_significant", (self.root / "summary.md").read_text())

    def test_existing_correct_label_is_left_alone(self):
        result, writes = self.run_tool(["README.md"], labels=["class:standard", "documentation"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(writes, [])

    def test_truncated_file_list_is_significant(self):
        result, writes = self.run_tool(["README.md"], changed=4000)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("labels[]=class:significant", writes[0])


if __name__ == "__main__":
    unittest.main()
