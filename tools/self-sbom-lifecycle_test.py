"""Verify latest promotion policy without network or administrative credentials."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'tools/self-sbom-lifecycle.py'
COLLECTION = '11111111-1111-4111-8111-111111111111'
MAIN = '22222222-2222-4222-8222-222222222222'
TARGET = '33333333-3333-4333-8333-333333333333'
OLD = '44444444-4444-4444-8444-444444444444'


class Client:
    def __init__(self):
        self.projects = {
            TARGET: {'uuid': TARGET, 'name': 'rio', 'version': 'v1.2.3', 'active': True,
                     'isLatest': False, 'parent': {'uuid': COLLECTION}, 'tags': [{'name': 'owner:team-rio'}]},
            OLD: {'uuid': OLD, 'name': 'rio', 'version': 'v1.2.2', 'active': True,
                  'isLatest': True, 'parent': {'uuid': COLLECTION}},
        }
        self.writes = []
        self.break_readback = False

    def get(self, path):
        if path == '/api/v1/project/latest/rio':
            return copy.deepcopy(next((p for p in self.projects.values() if p['isLatest']), None))
        if path.startswith('/api/v1/project/'):
            return copy.deepcopy(self.projects[path.rsplit('/', 1)[1]])
        raise AssertionError(path)

    def patch(self, path, value):
        self.writes.append((path, value))
        if not self.break_readback:
            for p in self.projects.values():
                p['isLatest'] = p['uuid'] == path.rsplit('/', 1)[1]
        return self.get(path)


class PromotionTest(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), 'release latest-promotion tool is missing')
        spec = importlib.util.spec_from_file_location('lifecycle', SCRIPT)
        self.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.tool)
        self.tmp = tempfile.TemporaryDirectory(prefix='rio-promotion-test-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.config = {'schemaVersion': 1, 'url': 'https://dependencytrack.rebaze.de', 'projectName': 'rio',
                       'collection': {'name': 'Rio product', 'uuid': COLLECTION},
                       'main': {'version': 'main', 'uuid': MAIN},
                       'organization': {'name': 'rebaze', 'uuid': '55555555-5555-4555-8555-555555555555'}}
        self.pin = self.root / 'targets.json'
        self.pin.write_text(json.dumps(self.config))
        self.published = self.root / 'published.json'
        self.published.write_text('{"synthetic":"published SBOM bytes"}\n')
        self.metadata = {'schemaVersion': 1, 'release': True, 'project': {'name': 'rio', 'version': 'v1.2.3'},
                         'managedTargets': self.config, 'sha256': hashlib.sha256(self.published.read_bytes()).hexdigest()}
        (self.root / 'prepared.json').write_text(json.dumps(self.metadata))
        (self.root / 'delivery-state.json').write_text(json.dumps({'schemaVersion': 1, 'state': 'accepted'}))
        self.args = argparse.Namespace(prepared=self.root, target_config=self.pin, published_sbom=self.published,
                                       tag='v1.2.3', commit='a' * 40, repo='rebaze/rio', rio='/pinned/rio')
        self.latest = 'v1.2.3'
        self.commit = 'a' * 40
        self.client = Client()
        self.env = mock.patch.dict(os.environ, GH_TOKEN='synthetic-gh', DTRACK_LIFECYCLE_KEY='synthetic-lifecycle',
                                   DTRACK_API_KEY='original-upload-key')
        self.env.start(); self.addCleanup(self.env.stop)
        self.verify = mock.Mock(return_value={'inventory': 'verified', 'projectUUID': TARGET,
                                             'ownerTag': 'observed', 'parent': 'observed'})

    def github(self, repo, path):
        self.assertEqual(repo, 'rebaze/rio')
        if path == 'releases/latest':
            return {'tag_name': self.latest, 'draft': False, 'prerelease': False}
        if path == 'releases/tags/' + self.args.tag:
            return {'tag_name': self.args.tag, 'draft': False, 'prerelease': False,
                    'assets': [{'name': 'rio-' + self.args.tag + '-source.cdx.json',
                                'digest': 'sha256:' + self.metadata['sha256']}]}
        if path == 'commits/' + self.args.tag:
            return {'sha': self.commit}
        raise AssertionError(path)

    def promote(self):
        with mock.patch.object(self.tool, 'github', self.github), \
                mock.patch.object(self.tool, 'Client', return_value=self.client), \
                mock.patch.object(self.tool.self_sbom, 'deliver', self.verify):
            return self.tool.promote(self.args)

    def test_verified_latest_stable_is_promoted_and_previous_latest_cleared(self):
        before = copy.deepcopy(self.client.projects[TARGET])
        result = self.promote()
        self.assertEqual(result['promotion'], 'verified-latest')
        self.assertEqual(self.client.writes, [('/api/v1/project/' + TARGET, {'isLatest': True})])
        self.assertFalse(self.client.projects[OLD]['isLatest'])
        self.assertEqual(self.client.projects[TARGET]['parent'], before['parent'])
        self.assertEqual(self.client.projects[TARGET]['tags'], before['tags'])
        self.verify.assert_called_once()
        self.assertEqual(os.environ['DTRACK_API_KEY'], 'original-upload-key')

    def test_repeated_promotion_is_readback_only(self):
        self.promote()
        self.client.writes.clear()
        self.assertEqual(self.promote()['promotion'], 'verified-latest')
        self.assertEqual(self.client.writes, [])

    def test_old_release_rerun_does_not_move_latest_back(self):
        self.latest = 'v1.2.4'
        self.assertEqual(self.promote()['promotion'], 'skipped-not-latest-stable')
        self.assertEqual(self.client.writes, [])
        self.verify.assert_not_called()

    def test_prerelease_never_promotes(self):
        self.args.tag = 'v1.3.0-rc1'
        self.assertEqual(self.promote()['promotion'], 'skipped-prerelease')
        self.assertEqual(self.client.writes, [])

    def test_newer_monitored_release_cannot_be_rolled_back(self):
        self.client.projects[OLD]['version'] = 'v2.0.0'
        self.assertEqual(self.promote()['promotion'], 'skipped-newer-monitored-release')
        self.assertEqual(self.client.writes, [])

    def test_unconfirmed_upload_cannot_be_promoted(self):
        (self.root / 'delivery-state.json').write_text('{"schemaVersion":1,"state":"started"}')
        with self.assertRaisesRegex(ValueError, 'accepted'):
            self.promote()
        self.assertEqual(self.client.writes, [])
        self.verify.assert_not_called()

    def test_published_byte_mismatch_cannot_be_promoted(self):
        self.published.write_text('{}')
        with self.assertRaisesRegex(ValueError, 'published'):
            self.promote()
        self.assertEqual(self.client.writes, [])

    def test_failed_inventory_check_cannot_be_promoted(self):
        self.verify.side_effect = ValueError('inventory not verified')
        with self.assertRaisesRegex(ValueError, 'inventory'):
            self.promote()
        self.assertEqual(self.client.writes, [])
        self.assertEqual(os.environ['DTRACK_API_KEY'], 'original-upload-key')

    def test_wrong_parent_or_main_project_cannot_be_promoted(self):
        self.client.projects[TARGET]['parent'] = {'uuid': MAIN}
        with self.assertRaisesRegex(ValueError, 'parent'):
            self.promote()
        self.assertEqual(self.client.writes, [])

    def test_latest_flag_must_be_observed_after_patch(self):
        self.client.break_readback = True
        with self.assertRaisesRegex(ValueError, 'latest'):
            self.promote()

    def test_tag_commit_must_match_release_source(self):
        self.commit = 'b' * 40
        with self.assertRaisesRegex(ValueError, 'commit'):
            self.promote()
        self.assertEqual(self.client.writes, [])

    def test_remote_asset_digest_must_match(self):
        original = self.github
        def github(repo, path):
            result = original(repo, path)
            if path.startswith('releases/tags/'):
                result['assets'][0]['digest'] = 'sha256:' + '0' * 64
            return result
        self.github = github
        with self.assertRaisesRegex(ValueError, 'asset digest'):
            self.promote()
        self.assertEqual(self.client.writes, [])

    def test_new_publication_before_patch_skips_promotion(self):
        def verify(args):
            self.latest = 'v1.2.4'
            return {'inventory': 'verified', 'projectUUID': TARGET}
        self.verify.side_effect = verify
        self.assertEqual(self.promote()['promotion'], 'skipped-not-latest-stable')
        self.assertEqual(self.client.writes, [])

    def test_inactive_readback_fails_promotion(self):
        patch = self.client.patch
        def mutate(path, value):
            result = patch(path, value)
            self.client.projects[TARGET]['active'] = False
            return result
        self.client.patch = mutate
        with self.assertRaisesRegex(ValueError, 'observed'):
            self.promote()


class MainClient(Client):
    def __init__(self):
        super().__init__()
        self.projects[MAIN] = {'uuid': MAIN, 'name': 'rio', 'version': 'main', 'active': True,
                               'isLatest': False, 'parent': {'uuid': COLLECTION}}
        self.state = {'schemaVersion': 1, 'mainUUID': MAIN, 'state': 'idle', 'sequence': [0, 0]}
        self.states = []

    def get(self, path):
        if path.endswith('/property'):
            return [{'groupName': 'rio-monitoring', 'propertyName': 'main-import',
                     'propertyType': 'STRING', 'propertyValue': json.dumps(self.state)}]
        return super().get(path)

    def post(self, path, value):
        if not path.endswith('/property'):
            raise AssertionError('Main coordinator must only write its property')
        self.state = json.loads(value['propertyValue'])
        self.states.append(copy.deepcopy(self.state))


class MainPublicationTest(unittest.TestCase):
    def setUp(self):
        PromotionTest.setUp(self)
        self.client = MainClient()
        self.metadata.update(release=False, project={'name': 'rio', 'version': 'main'}, index='normalized/index.json')
        (self.root / 'prepared.json').write_text(json.dumps(self.metadata))
        (self.root / 'delivery-state.json').unlink()
        self.claims = {'schemaVersion': 1, 'sourceRevision': 'a' * 40,
                       'buildURL': 'https://github.com/rebaze/rio/actions/runs/321', 'buildID': '321.1'}
        (self.root / 'build.json').write_text(json.dumps(self.claims))
        manifest = {'delivery': {'targets': {'security': self.tool.self_sbom.target_config(
            self.metadata['project'], False, self.config['url'], False, targets=self.config)}}}
        (self.root / 'delivery.yaml').write_text(json.dumps(manifest))
        self.args.source_revision = 'a' * 40
        self.args.run_number = 83
        self.head = 'a' * 40
        self.posts = 0
        self.order = []
        self.mode = 'success'
        self.token = '66666666-6666-4666-8666-666666666666'
        self.proof = {'eventToken': self.token, 'status': 'COMPLETED', 'processing': False}
        self.env_main = mock.patch.dict(os.environ, DTRACK_MAIN_KEY='synthetic-main')
        self.env_main.start();self.addCleanup(self.env_main.stop)

    def github(self, repo, path):
        self.assertEqual(path, 'commits/main')
        return {'sha': self.head}

    def native(self, args):
        self.order.append('native')
        if not (self.root / 'delivery-state.json').exists():
            self.assertEqual(self.client.state['state'], 'dispatching')
            self.posts += 1
            if self.mode == 'ambiguous':
                (self.root / 'delivery-state.json').write_text('{"state":"started"}')
                raise ValueError('unknown response')
            receipt = self.root / 'native-receipt.json';receipt.write_text('{}')
            result = {'items': [{'result': {'observations': [{'kind': 'acknowledgment', 'value': 'accepted', 'origin': 'receiver',
                       'references': [{'kind': 'dependency-track:event-token', 'value': self.token}]}]}}]}
            self.tool.self_sbom.write_json(self.root / 'delivery-result.json', result)
            state = {'schemaVersion': 1, 'state': 'accepted', 'sha256': self.metadata['sha256'],
                     'project': self.metadata['project'],
                     'resultSHA256': self.tool.self_sbom.digest(self.root / 'delivery-result.json'),
                     'receipt': {'path': receipt.name, 'sha256': self.tool.self_sbom.digest(receipt)}}
            self.tool.self_sbom.write_json(self.root / 'delivery-state.json', state)
        if self.mode == 'timeout':
            raise ValueError('import timeout')
        return {'inventory': 'verified', 'projectUUID': MAIN, 'importCompletion': self.proof}

    def call_main(self):
        with mock.patch.object(self.tool, 'github', self.github), \
                mock.patch.object(self.tool, 'Client', return_value=self.client), \
                mock.patch.object(self.tool.subprocess, 'run', return_value=subprocess_result()), \
                mock.patch.object(self.tool.self_sbom, 'indexed_member', return_value=(self.root/'index.json', self.published, self.metadata['sha256'])), \
                mock.patch.object(self.tool.self_sbom, 'deliver', side_effect=self.native), \
                mock.patch.object(self.tool.self_sbom, 'wait_for_import', side_effect=self.wait):
            return self.tool.deliver_main(self.args)

    def wait(self, url, key, token, timeout):
        self.order.append('wait')
        return self.proof

    def next_run(self):
        for name in ('delivery-state.json', 'delivery-result.json'):
            p = self.root/name
            if p.exists():p.unlink()
        self.args.run_number += 1
        self.claims['buildID'] = '322.1'
        self.claims['buildURL'] = 'https://github.com/rebaze/rio/actions/runs/322'
        (self.root/'build.json').write_text(json.dumps(self.claims))
        self.published.write_bytes(self.published.read_bytes() + b' ')
        self.metadata['sha256'] = hashlib.sha256(self.published.read_bytes()).hexdigest()
        (self.root/'prepared.json').write_text(json.dumps(self.metadata))

    def test_main_saves_dispatch_before_post_and_completed_proof_after(self):
        self.assertEqual(self.call_main()['mainPublication'], 'verified')
        self.assertEqual(self.posts, 1)
        self.assertEqual(self.client.states[0]['state'], 'dispatching')
        self.assertEqual(self.client.state['state'], 'completed')

    def test_same_run_accepted_timeout_recovers_readonly(self):
        self.mode = 'timeout'
        with self.assertRaisesRegex(ValueError, 'timeout'):
            self.call_main()
        self.assertEqual(self.client.state['state'], 'accepted')
        self.mode = 'success'
        self.assertEqual(self.call_main()['mainPublication'], 'verified')
        self.assertEqual(self.posts, 1)

    def test_next_run_waits_for_previous_accepted_import(self):
        self.mode = 'timeout'
        with self.assertRaises(ValueError):self.call_main()
        self.next_run();self.mode = 'success';self.order.clear()
        self.call_main()
        self.assertEqual(self.order, ['wait', 'native'])
        self.assertEqual(self.posts, 2)

    def test_unknown_submission_quarantines_the_next_run(self):
        self.mode = 'ambiguous'
        with self.assertRaises(ValueError):self.call_main()
        self.assertEqual(self.client.state['state'], 'unconfirmed')
        self.next_run();self.mode = 'success'
        with self.assertRaisesRegex(ValueError, 'quarantin|unconfirmed'):
            self.call_main()
        self.assertEqual(self.posts, 1)

    def test_stale_main_head_cannot_publish(self):
        self.head = 'b' * 40
        self.assertEqual(self.call_main()['mainPublication'], 'skipped-stale')
        self.assertEqual(self.posts, 0)

    def test_delayed_old_run_with_same_head_cannot_overwrite_newer_run(self):
        self.call_main();self.next_run();self.call_main()
        self.next_run();self.args.run_number = 82
        self.assertEqual(self.call_main()['mainPublication'], 'skipped-superseded')
        self.assertEqual(self.posts, 2)

    def test_missing_persistent_state_blocks_upload(self):
        get = self.client.get
        self.client.get = lambda path: [] if path.endswith('/property') else get(path)
        with self.assertRaisesRegex(ValueError, 'state is missing'):
            self.call_main()
        self.assertEqual(self.posts, 0)

    def test_failed_prior_import_blocks_a_new_upload(self):
        self.mode = 'timeout'
        with self.assertRaises(ValueError):self.call_main()
        self.next_run();self.mode = 'success'
        self.wait = mock.Mock(side_effect=ValueError('prior import failed'))
        with self.assertRaisesRegex(ValueError, 'prior import'):
            self.call_main()
        self.assertEqual(self.posts, 1)

    def test_property_write_failure_blocks_upload(self):
        self.client.post = mock.Mock(side_effect=ValueError('property write failed'))
        with self.assertRaisesRegex(ValueError, 'property write'):
            self.call_main()
        self.assertEqual(self.posts, 0)

    def test_one_sequence_cannot_replace_bytes(self):
        self.call_main()
        number = self.args.run_number
        self.next_run();self.args.run_number = number
        with self.assertRaisesRegex(ValueError, 'different SBOM bytes'):
            self.call_main()
        self.assertEqual(self.posts, 1)


def subprocess_result():
    import subprocess
    return subprocess.CompletedProcess([], 0, '{}', '')


if __name__ == '__main__':
    unittest.main()
