"""Offline contracts for the read-only pipeline version inventory and update report."""
import importlib.util
import json
import io
import os
import urllib.error
from unittest.mock import patch
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('updates', Path(__file__).with_name('pipeline-updates.py'))
updates = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updates)

class UpdatesTest(unittest.TestCase):
    def test_repository_pins_are_consistent(self):
        self.assertEqual(set(updates.inventory()), {'go','cosign','syft','goreleaser'})

    def test_new_patch_is_reported_and_prereleases_are_rejected(self):
        self.assertTrue(updates.newer('v1.27.2', 'v1.27.3'))
        self.assertFalse(updates.newer('v3.1.3', 'v3.1.3'))
        self.assertFalse(updates.newer('v3.1.3', 'v3.0.6'))
        with self.assertRaises(ValueError):
            updates.newer('v3.1.3', 'v3.2.0-rc1')

    def test_go_uses_newest_patch_in_selected_release_line(self):
        releases = [{'version': 'go1.28.1', 'stable': True},
                    {'version': 'go1.27.4', 'stable': True},
                    {'version': 'go1.27.3', 'stable': True}]
        self.assertEqual(updates.go_patch('v1.27.2', releases), 'v1.27.4')
        with self.assertRaises(ValueError):
            updates.go_patch('v1.25.0', releases)

    def test_pin_mismatch_is_a_failure_not_a_clean_report(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root/'one').write_text('pin: v3.1.3\n')
            (root/'two').write_text('pin: v3.0.6\n')
            with self.assertRaisesRegex(ValueError, 'inconsistent'):
                updates.same_pin(root, ['one', 'two'], r'pin: (v\d+\.\d+\.\d+)')

    def test_empty_or_missing_pin_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); (root/'one').write_text('pin: latest\n')
            with self.assertRaises(ValueError):
                updates.same_pin(root, ['one'], r'pin: (v\d+\.\d+\.\d+)')

    def test_issue_update_reuses_exact_tracker_title(self):
        calls = []
        def run(args):
            calls.append(args)
            if args[1:3] == ['issue', 'list']:
                return json.dumps([{'number': 20, 'title': updates.TITLE, 'author': {'login':'github-actions[bot]', 'is_bot':True}, 'labels':[{'name':'dependencies'}]},
                                   {'number': 21, 'title': updates.TITLE + ' unrelated'}])
            return ''
        report = {'updates': [{'tool': 'go', 'current': 'v1.27.2', 'latest': 'v1.27.3'}]}
        updates.publish(report, run)
        self.assertEqual(calls[-1][1:4], ['issue', 'edit', '20'])
        self.assertFalse(any(c[1:3] == ['issue','create'] for c in calls))

    def test_matching_untrusted_title_is_not_overwritten(self):
        calls=[]
        def command(args):
            calls.append(args)
            if args[1:3] == ['issue','list']:
                return json.dumps([{'number':99, 'title':updates.TITLE,
                    'author':{'login':'outside-user','is_bot':False},
                    'labels':[{'name':'dependencies'}]}])
            return ''
        updates.publish({'updates':[{'tool':'go','current':'v1.27.2','latest':'v1.27.3'}]}, command)
        self.assertEqual(calls[-1][1:3], ['issue','create'])
        self.assertFalse(any(c[1:3] == ['issue','edit'] for c in calls))

    def test_toolchain_and_executable_cosign_mismatch_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for rel in ['go.mod','tools/security/go.mod','tools/release-toolchain/manifest.json',
                        'tools/release-toolchain/cosign/go.mod','tools/release-toolchain/syft/go.mod',
                        'tools/release-toolchain/goreleaser/go.mod',
                        'tools/rio-attest-sign.sh','tools/rio-attest-verify.sh','tools/demo-attest-sign/run.py']:
                dest=root/rel;dest.parent.mkdir(parents=True,exist_ok=True)
                dest.write_bytes((updates.ROOT/rel).read_bytes())
            for rel in ['tools/rio-attest-sign.sh','tools/rio-attest-verify.sh','tools/demo-attest-sign/run.py']:
                dest=root/rel;before=dest.read_text()
                dest.write_text(before.replace('v3.1.3','v3.0.6'))
                with self.subTest(path=rel), self.assertRaisesRegex(ValueError, 'inconsistent'):
                    updates.inventory(root)
                dest.write_text(before)

    def test_token_is_never_sent_to_another_origin_and_redirects_fail(self):
        seen = []
        handlers = []
        class Opener:
            def open(self, request, timeout):
                seen.append(request)
                return io.BytesIO(b'{}')
        def opener(handler):
            handlers.append(handler)
            return Opener()
        with patch.dict(os.environ, {'GH_TOKEN': 'synthetic-canary'}), patch.object(updates.urllib.request, 'build_opener', opener):
            updates.fetch('https://api.github.com/repos/sigstore/cosign/releases/latest')
            updates.fetch('https://api.github.com.attacker.example/releases/latest')
            updates.fetch('https://go.dev/dl/?mode=json')
        self.assertEqual(seen[0].get_header('Authorization'), 'Bearer synthetic-canary')
        self.assertIsNone(seen[1].get_header('Authorization'))
        self.assertIsNone(seen[2].get_header('Authorization'))
        with self.assertRaisesRegex(ValueError, 'redirect'):
            handlers[0]().redirect_request(seen[0], None, 302, '', {}, 'https://attacker.example')

    def test_failed_api_request_propagates(self):
        class Opener:
            def open(self, request, timeout):
                raise urllib.error.URLError('unavailable')
        with patch.object(updates.urllib.request, 'build_opener', return_value=Opener()):
            with self.assertRaises(urllib.error.URLError):
                updates.fetch('https://go.dev/dl/?mode=json')

    def test_new_tracker_created_and_api_failure_does_not_create(self):
        calls = []
        def command(args):
            calls.append(args)
            if args[1:3] == ['issue', 'list']:
                return '[]'
            body = Path(args[args.index('--body-file') + 1]).read_text()
            self.assertIn('go: v1.27.2 → v1.27.3', body)
            return ''
        result = {'updates': [{'tool':'go','current':'v1.27.2','latest':'v1.27.3'}]}
        updates.publish(result, command)
        self.assertEqual(calls[-1][1:3], ['issue','create'])
        def broken(args):
            raise RuntimeError('API unavailable')
        with self.assertRaises(RuntimeError):
            updates.publish(result, broken)

    def test_no_update_does_not_create_noise(self):
        calls=[]
        updates.publish({'updates': []}, lambda args: calls.append(args))
        self.assertEqual(calls, [])

if __name__ == '__main__':
    unittest.main()
