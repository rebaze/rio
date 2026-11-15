"""Exercise native Rio delivery and portable self-SBOM bundles offline."""
import argparse
import copy
import contextlib
import io
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'tools/self-sbom.py'
RIO = os.environ.get('SELF_SBOM_TEST_RIO', os.environ.get('RIO_BIN', str(ROOT / 'rio')))
receiver_spec = importlib.util.spec_from_file_location('self_sbom_receiver', ROOT / 'tools/demo-use-case/run.py')
receiver = importlib.util.module_from_spec(receiver_spec)
receiver_spec.loader.exec_module(receiver)


class Receiver(receiver.Receiver):
    component_reads = 0
    hide_inventory = False
    ambiguous_ack = False
    hide_owner = False

    def reply(self, status, value=None):
        if self.ambiguous_ack and status == 200 and isinstance(value, dict) and 'token' in value:
            value = {'invalidAcknowledgment': True}
        if self.hide_owner and isinstance(value, dict) and 'tags' in value:
            value = dict(value, tags=[t for t in value['tags'] if t['name'] != 'owner:team-rio'])
        super().reply(status, value)

    def do_GET(self):
        if self.path.startswith('/api/v1/component/project/'):
            type(self).component_reads += 1
            components = []
            if self.uploads and not self.hide_inventory:
                components = json.loads(self.uploads[-1])['components']
            body = json.dumps(components).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('X-Total-Count', str(len(components)))
            self.send_header('X-Total-Count-Type', 'EXACT')
            self.end_headers()
            self.wfile.write(body)
        else:
            super().do_GET()


class BundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not Path(RIO).is_file():
            raise unittest.SkipTest('Set RIO_BIN to a built or installed Rio binary')

    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), 'self-SBOM orchestration tool is missing')
        spec = importlib.util.spec_from_file_location('self_sbom', SCRIPT)
        self.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.tool)
        self.temporary = tempfile.TemporaryDirectory(prefix='rio-self-sbom-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bundle = self.root / 'prepared'
        self.bundle.mkdir()
        Receiver.key = 'synthetic-self-sbom-key'
        Receiver.projects, Receiver.uploads = {}, []
        Receiver.component_reads, Receiver.hide_inventory = 0, False
        Receiver.ambiguous_ack = False
        Receiver.hide_owner = False
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Receiver)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.url = 'http://127.0.0.1:' + str(self.server.server_port)
        raw = self.root / 'input.json'
        raw.write_text(json.dumps({
            'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1,
            'metadata': {'component': {'type': 'application', 'name': 'rio', 'version': '1.0.0',
                                        'purl': 'pkg:golang/github.com/rebaze/rio@v1.0.0'}},
            'components': [{'type': 'library', 'name': 'stdlib', 'version': '1.27.4',
                            'purl': 'pkg:golang/stdlib@1.27.4'}]}))
        manifest = self.root / 'normalize.json'
        manifest.write_text(json.dumps({'version': 1, 'artifacts': [{'id': 'rio-source', 'sbom': str(raw)}],
                                        'gate': {'mode': 'fail', 'require': ['name', 'version', 'purl']}}))
        subprocess.run([RIO, '--manifest', str(manifest), 'normalize', '--out', str(self.bundle / 'normalized'),
                        '--receipt', str(self.bundle / 'source-receipt.json'), '--quiet'],
                       capture_output=True, check=True)
        self.index = next((self.bundle / 'normalized/runs').glob('*/index.json'))
        entry = json.loads(self.index.read_text())['artifacts'][0]
        self.member = self.index.parent / entry['output']['path']
        shutil.copyfile(self.member, self.bundle / 'source.cdx.json')

    def managed_targets(self):
        return {'schemaVersion': 1, 'url': 'https://dependencytrack.example.invalid', 'projectName': 'rio',
                'collection': {'name': 'Rio product', 'uuid': '11111111-1111-4111-8111-111111111111'},
                'main': {'version': 'main', 'uuid': '22222222-2222-4222-8222-222222222222'},
                'organization': {'name': 'rebaze', 'uuid': '33333333-3333-4333-8333-333333333333'}}

    def managed_package(self, release=False):
        targets = self.managed_targets()
        self.targets_path = self.root / 'targets.json'
        self.targets_path.write_text(json.dumps(targets))
        metadata = self.tool.package(self.bundle, self.index, 'v1.0.0' if release else 'main',
                                     release=release, url=targets['url'], targets=targets)
        return targets, metadata

    def package(self, release=False):
        return self.tool.package(self.bundle, self.index, 'v1.0.0' if release else 'dev-test',
                                 release=release, url=self.url, allow_http=True)

    def deliver(self, published=None, timeout=2):
        args = argparse.Namespace(rio=RIO, prepared=self.bundle, published_sbom=published,
                                  url=self.url, allow_http=True, timeout=timeout)
        old = os.environ.get('DTRACK_API_KEY')
        os.environ['DTRACK_API_KEY'] = Receiver.key
        try:
            return self.tool.deliver(args)
        finally:
            if old is None:
                os.environ.pop('DTRACK_API_KEY', None)
            else:
                os.environ['DTRACK_API_KEY'] = old

    def test_prepare_retains_explicit_build_claims_and_passes_them_to_source_producer(self):
        output = (self.root / 'fresh-prepare').resolve()
        args = argparse.Namespace(output=output, rio=RIO, version='1.0.0', project_version='main',
                                  release=False, url=self.url, allow_http=True, project_name='rio',
                                  source_revision='a' * 40, build_url='https://github.com/rebaze/rio/actions/runs/123',
                                  build_id='123.2')
        original = (self.bundle / 'source.cdx.json').read_bytes()
        def generate(command, **kwargs):
            self.assertEqual(command[0], str(ROOT / 'tools/source-sbom.sh'))
            self.assertEqual(command[6], str(output / 'build.json'))
            claims = json.loads(Path(command[6]).read_text())
            self.assertEqual(claims, {'schemaVersion': 1, 'sourceRevision': 'a' * 40,
                                      'buildURL': args.build_url, 'buildID': '123.2'})
            shutil.copytree(self.bundle / 'normalized', output / 'normalized')
            shutil.copyfile(self.bundle / 'source.cdx.json', output / 'source.cdx.json')
        with patch.object(self.tool.subprocess, 'run', side_effect=generate), contextlib.redirect_stdout(io.StringIO()):
            self.tool.prepare(args)
        self.assertEqual((output / 'source.cdx.json').read_bytes(), original,
                         'orchestration must not mutate producer-normalized output')

    def test_prepare_incomplete_or_malformed_build_claims_fail_before_generation(self):
        for claims in ({'source_revision': 'a' * 40}, {'build_url': 'https://example.invalid/run'},
                       {'build_id': '123'}, {'source_revision': 'abc', 'build_url': 'https://example.invalid/run'},
                       {'source_revision': 'a' * 40, 'build_url': 'http://example.invalid/run'}):
            with self.subTest(claims=claims):
                args = argparse.Namespace(output=self.root / 'must-not-exist', rio=RIO, **claims)
                with patch.object(self.tool.subprocess, 'run', side_effect=AssertionError('generator ran')):
                    with self.assertRaisesRegex(ValueError, 'build|claims|revision'):
                        self.tool.prepare(args)
                self.assertFalse(args.output.exists())

    def test_artifact_only_bundle_refuses_delivery_before_key_or_any_submission(self):
        self.tool.package(self.bundle, self.index, 'pr-123', url=self.url, allow_http=True, artifact_only=True)
        with patch.object(self.tool, 'get_json', side_effect=AssertionError('unexpected receiver access')):
            with self.assertRaisesRegex(ValueError, 'artifact.only'):
                self.deliver()
        self.assertEqual(Receiver.uploads, [])
        self.assertFalse((self.bundle / 'delivery-state.json').exists())

    def test_managed_main_uses_fixed_uuid_without_autocreation_or_latest(self):
        targets, metadata = self.managed_package()
        config = json.loads((self.bundle / 'delivery.yaml').read_text())
        target = config['delivery']['targets']['security']
        self.assertEqual(metadata['project'], {'name': 'rio', 'version': 'main'})
        self.assertEqual(metadata['managedTargets'], targets)
        self.assertFalse(metadata['artifactOnly'])
        self.assertEqual(target['project'], {'uuid': targets['main']['uuid']})
        self.assertNotIn('parent', target)
        self.assertNotIn('isLatest', target)
        planned = subprocess.run([RIO, '--manifest', str(self.bundle / 'delivery.yaml'),
                                  'delivery', 'plan', '--index', str(self.index), '--json'],
                                 capture_output=True, text=True)
        self.assertEqual(planned.returncode, 0, planned.stdout + planned.stderr)
        self.assertNotIn('autoCreate', target)
        self.assertEqual(Receiver.uploads, [], 'delivery planning must remain offline')
        with self.assertRaisesRegex(ValueError, 'main'):
            self.tool.package(self.bundle, self.index, 'dev-branch', url=targets['url'], targets=targets)

    def test_release_parent_is_set_without_early_latest_for_all_uploads(self):
        targets, metadata = self.managed_package(release=True)
        target = json.loads((self.bundle / 'delivery.yaml').read_text())['delivery']['targets']['security']
        self.assertEqual(target['project'], {'name': 'rio', 'version': 'v1.0.0'})
        self.assertEqual(target['parent'], {'uuid': targets['collection']['uuid']})
        self.assertTrue(target['autoCreate'])
        self.assertNotIn('isLatest', target)
        self.package(release=True)
        unmanaged = json.loads((self.bundle / 'delivery.yaml').read_text())['delivery']['targets']['security']
        self.assertNotIn('isLatest', unmanaged)

    def test_managed_delivery_requires_matching_external_config_and_url_before_submission(self):
        targets, _ = self.managed_package()
        args = argparse.Namespace(rio=RIO, prepared=self.bundle, published_sbom=None,
                                  url=targets['url'], allow_http=False, timeout=.1)
        with self.assertRaisesRegex(ValueError, 'target.config'):
            self.tool.deliver(args)
        wrong = copy.deepcopy(targets)
        wrong['main']['uuid'] = '44444444-4444-4444-8444-444444444444'
        self.targets_path.write_text(json.dumps(wrong))
        args.target_config = self.targets_path
        with self.assertRaisesRegex(ValueError, 'target.config'):
            self.tool.deliver(args)
        self.targets_path.write_text(json.dumps(targets))
        args.url = 'https://wrong.example.invalid'
        with self.assertRaisesRegex(ValueError, 'target.config|destination'):
            self.tool.deliver(args)
        self.assertEqual(Receiver.uploads, [])
        self.assertFalse((self.bundle / 'delivery-state.json').exists())

    def test_target_config_rejects_invalid_schema_uuid_identity_and_url(self):
        targets = self.managed_targets()
        path = self.root / 'targets.json'
        mutations = [('schemaVersion', 2), ('url', 'http://example.invalid'),
                     ('projectName', ''), ('projectName', 'rio\nother'),
                     ('url', 'https://example.invalid:bad'), ('url', 'https://example.invalid/\nother')]
        cases = []
        for key, value in mutations:
            bad = copy.deepcopy(targets)
            bad[key] = value
            cases.append(bad)
        bad = copy.deepcopy(targets)
        bad['main']['uuid'] = bad['collection']['uuid']
        cases.append(bad)
        for section in ('collection', 'main', 'organization'):
            bad = copy.deepcopy(targets)
            bad[section]['uuid'] = 'not-a-uuid'
            cases.append(bad)
        path.write_text(json.dumps(targets))
        self.assertEqual(self.tool.load_targets(path), targets)
        for bad in cases:
            with self.subTest(config=bad):
                path.write_text(json.dumps(bad))
                with self.assertRaises(ValueError):
                    self.tool.load_targets(path)

    def managed_readback(self, *, release=False, changes=None):
        targets, metadata = self.managed_package(release=release)
        project_uuid = ('44444444-4444-4444-8444-444444444444' if release else targets['main']['uuid'])
        project = dict(metadata['project'], uuid=project_uuid, active=True, isLatest=release,
                       parent={'uuid': targets['collection']['uuid']},
                       tags=[{'name': t} for t in ('owner:team-rio', 'go', 'source:release' if release else 'source:ci')])
        if changes:
            project.update(changes)
        calls = []
        def read(opener, url, key, timeout):
            calls.append(url)
            if '/project/lookup?' in url:
                # Lookup is deliberately thin; parent/latest must come from full GET.
                return 200, dict(metadata['project'], uuid=project_uuid), {}
            if '/api/v1/project/' in url:
                return 200, project, {}
            if '/component/project/' in url:
                components = json.loads((self.bundle / 'source.cdx.json').read_text())['components']
                return 200, components, {'X-Total-Count': str(len(components))}
            raise AssertionError('unexpected read-back URL')
        with patch.object(self.tool, 'get_json', side_effect=read):
            result = self.tool.verify_inventory(self.bundle, metadata, targets['url'], 'synthetic-key', .05)
        return result, calls, targets

    def test_managed_readback_checks_full_project_parent_and_main_latest(self):
        result, calls, targets = self.managed_readback()
        self.assertEqual(result['parent'], 'observed')
        self.assertIs(result['isLatest'], False)
        self.assertIn(targets['url'] + '/api/v1/project/' + targets['main']['uuid'], calls)
        for changes in ({'parent': {'uuid': '55555555-5555-4555-8555-555555555555'}},
                        {'active': False}, {'isLatest': True},
                        {'uuid': '55555555-5555-4555-8555-555555555555'}):
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, 'parent|active|latest|identity|inventory'):
                self.managed_readback(changes=changes)
        result, _, _ = self.managed_readback(release=True)
        self.assertIs(result['isLatest'], True, 'accepted release recovery may observe later promotion')
        result, _, _ = self.managed_readback(release=True, changes={'isLatest': False})
        self.assertIs(result['isLatest'], False, 'ingestion must verify before separate promotion')

    def accepted_managed_fixture(self):
        # Obtain actual native acknowledgment/receipt bytes from the offline
        # receiver, then exercise managed recovery against a controlled HTTP
        # read boundary without needing a public TLS test service.
        self.tool.package(self.bundle, self.index, 'main', url=self.url, allow_http=True)
        self.deliver()
        targets, metadata = self.managed_package()
        args = argparse.Namespace(rio=RIO, prepared=self.bundle, published_sbom=None,
                                  url=targets['url'], allow_http=False, timeout=.02,
                                  target_config=self.targets_path)
        return args, metadata, json.loads((self.bundle / 'delivery-result.json').read_text())

    def test_native_event_token_requires_one_strict_acknowledgment_reference(self):
        args, metadata, batch = self.accepted_managed_fixture()
        self.assertEqual(self.tool.event_token(batch), receiver.TOKEN)
        for value in ('not-a-token', receiver.TOKEN.upper()):
            altered = copy.deepcopy(batch)
            altered['items'][0]['result']['observations'][0]['references'][0]['value'] = value
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'token'):
                self.tool.event_token(altered)
        for refs in ([], [{'kind': 'dependency-track:event-token', 'value': receiver.TOKEN}] * 2):
            altered = copy.deepcopy(batch)
            altered['items'][0]['result']['observations'][0]['references'] = refs
            with self.assertRaisesRegex(ValueError, 'token'):
                self.tool.event_token(altered)

    def test_matching_old_inventory_cannot_verify_pending_or_unknown_import(self):
        args, metadata, batch = self.accepted_managed_fixture()
        old = os.environ.get('DTRACK_API_KEY')
        os.environ['DTRACK_API_KEY'] = Receiver.key
        try:
            for body in ({'processing': True, 'status': 'RUNNING'}, {'processing': False},
                         {'processing': False, 'status': 'UNKNOWN'}):
                with self.subTest(body=body), patch.object(self.tool, 'get_json', return_value=(200, body, {})), \
                     patch.object(self.tool, 'verify_inventory', return_value={'inventory': 'verified'}) as inventory:
                    with self.assertRaisesRegex(ValueError, 'import|completion|status'):
                        self.tool.deliver(args)
                    inventory.assert_not_called()
                self.assertFalse((self.bundle / 'verification.json').exists()
                                 and 'importCompletion' in json.loads((self.bundle / 'verification.json').read_text()))
        finally:
            if old is None:
                os.environ.pop('DTRACK_API_KEY', None)
            else:
                os.environ['DTRACK_API_KEY'] = old
        self.assertEqual(len(Receiver.uploads), 1)

    def test_fresh_managed_acceptance_persists_before_import_wait_and_cannot_verify_pending(self):
        args, metadata, batch = self.accepted_managed_fixture()
        (self.bundle / 'delivery-state.json').unlink()
        (self.bundle / 'verification.json').unlink()
        # Replay a genuine native acceptance at the subprocess boundary. All
        # referenced receipt bytes and indexed SBOM digests remain real.
        native = subprocess.CompletedProcess([], 0, stdout=json.dumps(batch), stderr='')
        with patch.dict(os.environ, {'DTRACK_API_KEY': Receiver.key}), \
             patch.object(self.tool.subprocess, 'run', return_value=native), \
             patch.object(self.tool, 'get_json', return_value=(200, {'processing': True, 'status': 'RUNNING'}, {})), \
             patch.object(self.tool, 'verify_inventory', side_effect=AssertionError('old inventory must not verify')):
            with self.assertRaisesRegex(ValueError, 'import|completion'):
                self.tool.deliver(args)
        state = json.loads((self.bundle / 'delivery-state.json').read_text())
        self.assertEqual(state['state'], 'accepted')
        self.assertEqual(self.tool.event_token(json.loads((self.bundle / 'delivery-result.json').read_text())), receiver.TOKEN)
        self.assertNotIn('importCompletion', state)
        self.assertFalse((self.bundle / 'verification.json').exists())

    def test_import_polling_requires_explicit_completed_status_and_false_processing(self):
        replies = [(200, {'processing': True, 'status': 'RUNNING'}, {}),
                   (200, {'processing': False, 'status': 'COMPLETED'}, {})]
        with patch.object(self.tool, 'get_json', side_effect=replies), patch.object(self.tool.time, 'sleep'):
            proof = self.tool.wait_for_import('https://example.invalid', 'synthetic-key', receiver.TOKEN, 1)
        self.assertEqual(proof['eventToken'], receiver.TOKEN)
        self.assertEqual(proof['status'], 'COMPLETED')
        self.assertIs(proof['processing'], False)
        with patch.object(self.tool, 'get_json', return_value=(200, {'processing': False, 'status': 'FAILED'}, {})):
            with self.assertRaisesRegex(ValueError, 'import|failed|FAILED'):
                self.tool.wait_for_import('https://example.invalid', 'synthetic-key', receiver.TOKEN, 1)

    def test_completed_import_is_saved_before_inventory_and_reused_without_event_permission(self):
        args, metadata, batch = self.accepted_managed_fixture()
        proof = {'eventToken': receiver.TOKEN, 'status': 'COMPLETED', 'processing': False}
        def inventory(*unused):
            state = json.loads((self.bundle / 'delivery-state.json').read_text())
            self.assertEqual(state['importCompletion'], proof)
            return {'inventory': 'verified'}
        with patch.dict(os.environ, {'DTRACK_API_KEY': Receiver.key}), \
             patch.object(self.tool, 'wait_for_import', return_value=proof) as wait, \
             patch.object(self.tool, 'verify_inventory', side_effect=inventory):
            result = self.tool.deliver(args)
        self.assertEqual(result['importCompletion'], proof)
        wait.assert_called_once()
        with patch.dict(os.environ, {'DTRACK_API_KEY': 'synthetic-read-only-key'}), \
             patch.object(self.tool, 'get_json', side_effect=AssertionError('event endpoint needs upload permission')), \
             patch.object(self.tool, 'verify_inventory', side_effect=inventory):
            self.assertEqual(self.tool.deliver(args)['importCompletion'], proof)
        self.assertEqual(len(Receiver.uploads), 1)

    def test_import_completion_proof_cannot_be_reused_for_another_native_token(self):
        args, metadata, batch = self.accepted_managed_fixture()
        state_path = self.bundle / 'delivery-state.json'
        state = json.loads(state_path.read_text())
        state['importCompletion'] = {'eventToken': '66666666-6666-4666-8666-666666666666',
                                     'status': 'COMPLETED', 'processing': False}
        state_path.write_text(json.dumps(state))
        with patch.dict(os.environ, {'DTRACK_API_KEY': Receiver.key}), \
             patch.object(self.tool, 'wait_for_import', side_effect=AssertionError('mismatched proof must refuse')):
            with self.assertRaisesRegex(ValueError, 'token|proof|completion'):
                self.tool.deliver(args)
        self.assertEqual(len(Receiver.uploads), 1)

    def test_development_identity_and_native_delivery_preserve_bytes(self):
        self.package()
        config = json.loads((self.bundle / 'delivery.yaml').read_text())
        target = config['delivery']['targets']['security']
        self.assertEqual(target['project'], {'name': 'rio', 'version': 'dev-test'})
        self.assertNotEqual(target.get('isLatest'), True)
        self.assertIn('owner:team-rio', target['tags'])
        result = self.deliver()
        self.assertEqual(result['inventory'], 'verified')
        self.assertEqual(Receiver.uploads, [(self.bundle / 'source.cdx.json').read_bytes()])
        self.assertGreater(Receiver.component_reads, 0)
        self.assertNotIn(Receiver.key, (self.bundle / 'verification.json').read_text())

    def test_older_unmanaged_metadata_defaults_still_deliver(self):
        self.package()
        metadata = json.loads((self.bundle / 'prepared.json').read_text())
        metadata.pop('artifactOnly')
        (self.bundle / 'prepared.json').write_text(json.dumps(metadata))
        self.assertEqual(self.deliver()['inventory'], 'verified')

    def test_prepared_bundle_can_move_between_jobs(self):
        self.package()
        relocated = self.root / 'downloaded'
        shutil.copytree(self.bundle, relocated)
        shutil.rmtree(self.bundle)
        self.bundle = relocated
        self.assertEqual(self.deliver()['inventory'], 'verified')

    def test_release_requires_published_bytes_before_upload(self):
        self.package(release=True)
        with self.assertRaisesRegex(ValueError, 'published'):
            self.deliver()
        self.assertEqual(Receiver.uploads, [])
        wrong = self.root / 'wrong.json'
        wrong.write_text('{}')
        with self.assertRaisesRegex(ValueError, 'published'):
            self.deliver(wrong)
        self.assertEqual(Receiver.uploads, [])
        self.assertEqual(self.deliver(self.bundle / 'source.cdx.json')['inventory'], 'verified')

    def test_tampered_member_is_refused_before_upload(self):
        self.package()
        self.member.write_bytes(self.member.read_bytes() + b' ')
        with self.assertRaises((ValueError, subprocess.CalledProcessError)):
            self.deliver()
        self.assertEqual(Receiver.uploads, [])

    def test_changed_destination_is_refused_before_upload(self):
        self.package()
        config = json.loads((self.bundle / 'delivery.yaml').read_text())
        config['delivery']['targets']['security']['url'] = 'https://attacker.example'
        (self.bundle / 'delivery.yaml').write_text(json.dumps(config))
        with self.assertRaisesRegex(ValueError, 'destination'):
            self.deliver()
        self.assertEqual(Receiver.uploads, [])

    def test_escaping_index_path_is_refused(self):
        self.package()
        metadata = json.loads((self.bundle / 'prepared.json').read_text())
        metadata['index'] = '../outside/index.json'
        (self.bundle / 'prepared.json').write_text(json.dumps(metadata))
        with self.assertRaisesRegex(ValueError, 'path'):
            self.deliver()
        self.assertEqual(Receiver.uploads, [])

    def test_acceptance_does_not_pass_when_inventory_is_missing(self):
        self.package()
        Receiver.hide_inventory = True
        with self.assertRaisesRegex(ValueError, 'inventory'):
            self.deliver(timeout=.1)
        self.assertEqual(len(Receiver.uploads), 1, 'verification must never retry the upload')

    def test_accepted_upload_resumes_inventory_only_after_bundle_relocation(self):
        self.package()
        Receiver.hide_inventory = True
        with self.assertRaisesRegex(ValueError, 'inventory'):
            self.deliver(timeout=.1)
        relocated = self.root / 'retry-artifact'
        shutil.copytree(self.bundle, relocated)
        shutil.rmtree(self.bundle)
        self.bundle = relocated
        Receiver.hide_inventory = False
        self.assertEqual(self.deliver()['inventory'], 'verified')
        self.assertEqual(len(Receiver.uploads), 1, 'an accepted upload must never be repeated on recovery')

    def test_ambiguous_upload_is_preserved_and_requires_reconciliation(self):
        self.package()
        Receiver.ambiguous_ack = True
        with self.assertRaises(ValueError):
            self.deliver()
        self.assertTrue((self.bundle / 'delivery-result.json').is_file())
        Receiver.ambiguous_ack = False
        with self.assertRaisesRegex(ValueError, 'prior|reconcil'):
            self.deliver()
        self.assertEqual(len(Receiver.uploads), 1)

    def test_owner_tag_must_be_observed_before_success(self):
        self.package()
        Receiver.hide_owner = True
        with self.assertRaisesRegex(ValueError, 'inventory'):
            self.deliver(timeout=.1)
        self.assertEqual(len(Receiver.uploads), 1)

    def test_failed_gate_is_refused(self):
        index = json.loads(self.index.read_text())
        index['artifacts'][0]['gate'] = 'fail'
        self.index.write_text(json.dumps(index))
        with self.assertRaisesRegex(ValueError, 'gate'):
            self.package()
        self.assertEqual(Receiver.uploads, [])

    def test_consumer_golang_purl_casing_keeps_other_identity_fields_exact(self):
        original = {'name': 'github.com/CycloneDX/cyclonedx-go', 'version': 'v0.12.0',
                    'purl': 'pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.12.0'}
        observed = dict(original, purl='pkg:golang/github.com/cyclonedx/cyclonedx-go@v0.12.0')
        self.assertEqual(self.tool.coordinates([original]), self.tool.coordinates([observed]))
        self.assertNotEqual(self.tool.coordinates([original]),
                            self.tool.coordinates([dict(observed, name=original['name'].lower())]))
        self.assertNotEqual(self.tool.coordinates([original]),
                            self.tool.coordinates([dict(observed, version='v0.12.1')]))


if __name__ == '__main__':
    unittest.main()
