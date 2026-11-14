"""Keep current-tree builds on the latest patch of the supported Go line."""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class GoToolchainTest(unittest.TestCase):
    def test_policy_runs_without_change_filtering(self):
        workflow = (ROOT / '.github/workflows/ci.yaml').read_text()
        marker = '      - name: Check Go compiler policy\n'
        self.assertIn(marker, workflow, 'compiler policy must run even on module-only PRs')
        step = workflow.split(marker, 1)[1].split('      - ', 1)[0]
        self.assertNotRegex(step, r'(?m)^\s+if:')
        self.assertIn('run: python3 tools/go-toolchain_test.py', step)
        self.assertLess(workflow.index(marker), workflow.index('      - name: Detect changed file types'))

    def test_selector_tracks_the_module_release_line(self):
        selector = ROOT / '.go-version'
        self.assertTrue(selector.is_file(), 'missing shared Go patch selector')
        line = selector.read_text().strip()
        self.assertRegex(line, r'^1\.\d+$', 'select a minor line, never an exact patch or stable')
        for module in ('go.mod', 'tools/security/go.mod'):
            with self.subTest(module=module):
                version = re.search(r'^go (\d+\.\d+\.\d+)$', (ROOT / module).read_text(), re.M)
                self.assertIsNotNone(version, 'keep an explicit minimum patched compiler')
                self.assertEqual(version[1].rsplit('.', 1)[0], line)

    def test_every_current_tree_setup_checks_for_new_patches(self):
        setups = 0
        for workflow in sorted((ROOT / '.github/workflows').glob('*.y*ml')):
            for step in re.split(r'(?m)^      - ', workflow.read_text())[1:]:
                if not re.search(r'uses: actions/setup-go@', step):
                    continue
                setups += 1
                with self.subTest(workflow=workflow.name, setup=setups):
                    if workflow.name == 'test-binary.yaml':
                        # Diagnostic builds must still support historical refs
                        # that predate .go-version, using that source's compiler.
                        self.assertRegex(step, r'go-version-file: source/go\.mod\s')
                        continue
                    self.assertRegex(step, r'go-version-file: \.go-version\s')
                    self.assertRegex(step, r'check-latest: true\s')
                    self.assertNotRegex(step, r'(?m)^\s+go-version:')
                    self.assertNotIn('go-download-base-url:', step,
                                     'custom download URLs disable check-latest')
        self.assertGreater(setups, 0, 'no setup-go steps were tested')


if __name__ == '__main__':
    unittest.main()
