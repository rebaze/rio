#!/usr/bin/env python3
"""Installed-Rio demonstration; optional real-server Go vulnerability canaries.

The default receiver and all SBOM data are synthetic. No Go toolchain is needed.
--url explicitly selects an external receiver and creates clearly named canaries.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import ThreadingHTTPServer

HERE = Path(__file__).resolve().parent
TOOLS = HERE.parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


self_sbom = module('self_sbom', TOOLS / 'self-sbom.py')
use_case = module('self_sbom_use_case', TOOLS / 'demo-use-case/run.py')


class Receiver(use_case.Receiver):
    def do_GET(self):
        if self.path.startswith('/api/v1/component/project/'):
            components = json.loads(self.uploads[-1])['components'] if self.uploads else []
            body = json.dumps(components).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('X-Total-Count', str(len(components)))
            self.end_headers()
            self.wfile.write(body)
        else:
            super().do_GET()


def canary(args, output, version, label, url, local):
    bundle = output / label
    bundle.mkdir()
    raw = bundle / 'input.cdx.json'
    raw.write_text((HERE / 'stdlib.cdx.json.in').read_text().replace('GO_VERSION', version))
    manifest = {'version': 1, 'artifacts': [{'id': 'rio-source', 'sbom': raw.name}],
                'enrichment': {'producer': {'name': 'Synthetic monitoring demonstration', 'url': ['https://example.invalid']},
                               'subject': {'manufacturer': {'name': 'Synthetic Example', 'url': ['https://example.invalid']}}},
                'gate': {'mode': 'fail', 'profile': 'bsi-tr-03183-2@2.1.0', 'require': ['name', 'version', 'purl']}}
    self_sbom.write_json(bundle / 'normalize.yaml', manifest)
    subprocess.run([args.rio, '--manifest', str(bundle / 'normalize.yaml'), 'normalize',
                    '--out', str(bundle / 'normalized'), '--receipt', str(bundle / 'source-receipt.json'), '--quiet'], check=True)
    index = next((bundle / 'normalized/runs').glob('*/index.json'))
    member = index.parent / json.loads(index.read_text())['artifacts'][0]['output']['path']
    shutil.copyfile(member, bundle / 'source.cdx.json')
    project_version = args.run_id + '-' + label
    self_sbom.package(bundle, index, project_version, project_name=args.project_name,
                      url=url, allow_http=local)
    result = self_sbom.deliver(argparse.Namespace(rio=args.rio, prepared=bundle, published_sbom=None,
                                                url=url, allow_http=local, timeout=args.timeout))
    return {'goVersion': version, 'label': label, 'inventory': result['inventory'],
            'components': result['components'], 'project': result['project'], 'projectUUID': result['projectUUID']}


def check_findings(args, cases, url):
    key = os.environ['DTRACK_VERIFY_API_KEY']
    opener = self_sbom.urllib.request.build_opener(self_sbom.NoRedirect)
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        complete = True
        for case in cases:
            status, body, _ = self_sbom.get_json(opener, url + '/api/v1/finding/project/' + case['projectUUID'], key, 15)
            if status in (401, 403):
                raise ValueError('findings reader needs VIEW_VULNERABILITY and VIEW_PORTFOLIO')
            findings = body if isinstance(body, list) else (body or {}).get('findings', [])
            ids = sorted({f.get('vulnerability', {}).get('vulnId', '') for f in findings})
            case['vulnerabilities'] = ids
            found = 'GO-2026-6859' in ids or 'CVE-2026-97054' in ids
            metrics_status, metrics, _ = self_sbom.get_json(opener, url + '/api/v1/metrics/project/' + case['projectUUID'] + '/current', key, 15)
            ready = metrics_status == 200 and (metrics or {}).get('components') == 1 and bool((metrics or {}).get('lastOccurrence'))
            expected = case['label'] == 'vulnerable'
            case['expectedAdvisoryFound'] = found
            complete = complete and status == 200 and ready and found == expected
        if complete:
            return
        time.sleep(min(2, max(0, deadline - time.monotonic())))
    raise ValueError('known vulnerable/fixed Go canaries did not reach the expected analysis results')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('rio', nargs='?', default='rio')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--url', help='explicitly upload synthetic canaries to this HTTPS receiver')
    parser.add_argument('--project-name', default='rio-sbom-monitoring-canary')
    parser.add_argument('--run-id', default='check-' + str(int(time.time())))
    parser.add_argument('--check-findings', action='store_true', help='also verify real analysis; requires DTRACK_VERIFY_API_KEY')
    parser.add_argument('--timeout', type=float, default=180)
    args = parser.parse_args()
    args.rio = shutil.which(args.rio)
    if args.rio is None:
        raise ValueError('install Rio or supply its binary path')
    if args.check_findings and (not args.url or not os.environ.get('DTRACK_VERIFY_API_KEY')):
        raise ValueError('--check-findings requires --url and a separate findings reader key')
    output = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix='rio-self-sbom-demo-'))
    if args.output:
        output.mkdir(parents=True, exist_ok=False)
    server, old_key = None, os.environ.get('DTRACK_API_KEY')
    try:
        if args.url:
            url = self_sbom.base_url(args.url, False)
            if not old_key:
                raise ValueError('DTRACK_API_KEY is required for an external receiver')
        else:
            Receiver.key = 'synthetic-' + secrets.token_hex(16)
            Receiver.projects, Receiver.uploads = {}, []
            server = ThreadingHTTPServer(('127.0.0.1', 0), Receiver)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            url = 'http://127.0.0.1:' + str(server.server_port)
            os.environ['DTRACK_API_KEY'] = Receiver.key
        cases = [canary(args, output, '1.27.3', 'vulnerable', url, server is not None),
                 canary(args, output, '1.27.4', 'fixed', url, server is not None)]
        if args.check_findings:
            check_findings(args, cases, url)
        for case in cases:
            case.pop('projectUUID', None)
        result = {'syntheticSBOMs': True, 'syntheticReceiver': server is not None,
                  'analysisChecked': args.check_findings, 'cases': cases}
        self_sbom.write_json(output / 'verification.json', result)
        print(json.dumps(result, indent=2))
        print('Evidence retained in:', output)
    finally:
        if server:
            server.shutdown()
            server.server_close()
        if old_key is None:
            os.environ.pop('DTRACK_API_KEY', None)
        else:
            os.environ['DTRACK_API_KEY'] = old_key


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print('FAILED: ' + str(error), file=sys.stderr)
        sys.exit(1)
