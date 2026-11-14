"""Exercise native Rio delivery and portable self-SBOM bundles offline."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'tools/self-sbom.py'
RIO = os.environ.get('RIO_BIN', str(ROOT / 'rio'))
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
