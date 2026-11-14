#!/usr/bin/env python3
"""Coordinate rolling-main imports and verified published-release promotion.

Native pinned Rio owns SBOM preparation and submission. This tool manages only
the receiver's bounded import-state property and latest-version metadata.
"""
import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('self_sbom', ROOT / 'tools/self-sbom.py')
self_sbom = importlib.util.module_from_spec(spec)
spec.loader.exec_module(self_sbom)
STABLE = re.compile(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\Z')


def version(tag):
    match = STABLE.fullmatch(tag or '')
    return tuple(map(int, match.groups())) if match else None


def github(repo, path):
    if repo != 'rebaze/rio' or not os.environ.get('GH_TOKEN'):
        raise ValueError('Rio repository and an explicit GH_TOKEN are required')
    result = subprocess.run(['gh', 'api', 'repos/' + repo + '/' + path], capture_output=True,
                            text=True, timeout=30, env=dict(os.environ, GH_HOST='github.com', GH_PROMPT_DISABLED='1'))
    if result.returncode:
        raise ValueError('published release metadata could not be verified')
    return json.loads(result.stdout)


class Client:
    def __init__(self, base, key):
        self.base, self.key = base, key
        self.opener = urllib.request.build_opener(self_sbom.NoRedirect)

    def request(self, method, path, value=None):
        body = json.dumps(value).encode() if value is not None else None
        request = urllib.request.Request(self.base + path, data=body, method=method,
                                         headers={'X-Api-Key': self.key, 'Accept': 'application/json',
                                                  'Content-Type': 'application/json'})
        try:
            with self.opener.open(request, timeout=30) as response:
                data = response.read(8 << 20)
                return json.loads(data) if data else None
        except urllib.error.HTTPError as error:
            if method == 'GET' and error.code == 404:
                return None
            if method == 'PATCH' and error.code == 304:
                return self.get(path)
            raise ValueError('Dependency-Track metadata operation failed with HTTP %d' % error.code) from None
        except (OSError, ValueError):
            raise ValueError('Dependency-Track metadata operation did not return a usable result') from None

    def get(self, path):
        return self.request('GET', path)

    def patch(self, path, value):
        return self.request('PATCH', path, value)

    def post(self, path, value):
        return self.request('POST', path, value)


def main_result(root, outcome, **facts):
    result = {'mainPublication': outcome,
              'checkedAt': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), **facts}
    self_sbom.write_json(root / 'main-publication.json', result)
    return result


def read_main_state(client, targets):
    properties = client.get('/api/v1/project/' + targets['main']['uuid'] + '/property')
    if not isinstance(properties, list):
        raise ValueError('main import state is unavailable; initialize or reconcile it before publishing')
    matches = [p for p in properties if p.get('groupName') == 'rio-monitoring' and p.get('propertyName') == 'main-import']
    if len(matches) != 1:
        raise ValueError('main import state is missing or ambiguous; reconcile before publishing')
    state = json.loads(matches[0]['propertyValue'])
    sequence = state.get('sequence')
    if (state.get('schemaVersion') != 1 or state.get('mainUUID') != targets['main']['uuid']
            or state.get('state') not in ('idle', 'dispatching', 'unconfirmed', 'accepted', 'import-completed', 'completed')
            or not isinstance(sequence, list) or len(sequence) != 2
            or any(type(n) is not int or n < 0 for n in sequence)):
        raise ValueError('main import state is invalid; reconcile before publishing')
    return state


def write_main_state(client, targets, state):
    value = json.dumps(state, separators=(',', ':'))
    if len(value) > 1024:
        raise ValueError('main import state exceeds receiver property bound')
    client.post('/api/v1/project/' + targets['main']['uuid'] + '/property', {
        'groupName': 'rio-monitoring', 'propertyName': 'main-import', 'propertyValue': value})
    if read_main_state(client, targets) != state:
        raise ValueError('main import-state update was not observed; no new upload is authorized')


def accepted_token(root, metadata):
    """Use only an intact native acceptance record when repairing coordination."""
    try:
        state = json.loads((root / 'delivery-state.json').read_text())
        if (state.get('schemaVersion') != 1 or state.get('state') != 'accepted'
                or state.get('sha256') != metadata['sha256'] or state.get('project') != metadata['project']
                or state.get('resultSHA256') != self_sbom.digest(root / 'delivery-result.json')):
            return None
        receipt = self_sbom.contained(root, state['receipt']['path'])
        if self_sbom.digest(receipt) != state['receipt']['sha256']:
            return None
        return self_sbom.event_token(json.loads((root / 'delivery-result.json').read_text()))
    except (OSError, KeyError, ValueError, TypeError):
        return None


def deliver_main(args):
    root = args.prepared.resolve()
    targets = self_sbom.load_targets(args.target_config)
    if type(args.run_number) is not int or args.run_number < 1 or not re.fullmatch(r'[0-9a-f]{40}', args.source_revision):
        raise ValueError('main publication requires its workflow run number and full source revision')
    metadata = json.loads((root / 'prepared.json').read_text())
    claims = json.loads((root / 'build.json').read_text())
    if (metadata.get('managedTargets') != targets or metadata.get('release') is not False
            or metadata.get('artifactOnly', False) or metadata.get('project') != {'name': targets['projectName'], 'version': 'main'}
            or claims.get('sourceRevision') != args.source_revision
            or not re.fullmatch(r'[0-9]+\.[1-9][0-9]*', claims.get('buildID', ''))):
        raise ValueError('main publication requires a traceable managed main bundle')
    sequence = [args.run_number, int(claims['buildID'].rsplit('.', 1)[1])]
    if github(args.repo, 'commits/main').get('sha') != args.source_revision:
        return main_result(root, 'skipped-stale', sourceRevision=args.source_revision)
    index, _, sha = self_sbom.indexed_member(root, metadata['index'])
    if metadata.get('sha256') != sha:
        raise ValueError('main source digest differs from verified index')
    config = json.loads((root / 'delivery.yaml').read_text())
    expected = self_sbom.target_config(metadata['project'], False, targets['url'], False, targets=targets)
    if config.get('delivery', {}).get('targets') != {'security': expected}:
        raise ValueError('main delivery destination changed')
    # Native planning is offline; do all local validation before marking a
    # possible request on the receiver. Never execute the candidate binary.
    subprocess.run([args.rio, '--manifest', str(root / 'delivery.yaml'), 'delivery', 'plan',
                    '--index', str(index), '--json'], capture_output=True, check=True)
    key = os.environ.get('DTRACK_MAIN_KEY')
    if not key:
        raise ValueError('DTRACK_MAIN_KEY is required for canonical main publication')
    client = Client(targets['url'], key)
    project = client.get('/api/v1/project/' + targets['main']['uuid'])
    if (not project or project.get('name') != targets['projectName'] or project.get('version') != 'main'
            or project.get('active') is not True or project.get('isLatest') is not False
            or (project.get('parent') or {}).get('uuid') != targets['collection']['uuid']):
        raise ValueError('fixed main destination or hierarchy differs from configuration')
    previous = read_main_state(client, targets)
    if previous['sequence'] > sequence:
        return main_result(root, 'skipped-superseded', sequence=sequence, latestSequence=previous['sequence'])
    local_token = accepted_token(root, metadata)
    same = (previous.get('sbomSHA256') == sha and previous.get('sourceRevision') == args.source_revision
            and previous.get('buildID') == claims['buildID'])
    if previous['state'] in ('dispatching', 'unconfirmed'):
        if not (same and local_token):
            raise ValueError('main publication is quarantined by an unconfirmed earlier submission; reconcile it before any new upload')
        previous = dict(previous, state='accepted', eventToken=local_token)
        write_main_state(client, targets, previous)
    if previous['state'] == 'accepted':
        proof = self_sbom.wait_for_import(targets['url'], key, previous['eventToken'], 120)
        previous = dict(previous, state='import-completed', importCompletion=proof)
        write_main_state(client, targets, previous)
    if previous['sequence'] == sequence and previous['state'] != 'idle' and not same:
        raise ValueError('one main publication sequence cannot describe different SBOM bytes')
    if github(args.repo, 'commits/main').get('sha') != args.source_revision:
        return main_result(root, 'skipped-stale', sourceRevision=args.source_revision)
    if same and previous['state'] == 'completed' and not local_token:
        proof = previous.get('importCompletion', {})
        if proof.get('status') != 'COMPLETED' or proof.get('processing') is not False:
            raise ValueError('prior completed main publication has no correlated completion proof')
        verified = self_sbom.verify_inventory(root, metadata, targets['url'], key, 120)
        return main_result(root, 'verified', recovery='read-back only from completed receiver state', **verified)
    current = {'schemaVersion': 1, 'mainUUID': targets['main']['uuid'], 'state': 'dispatching',
               'sequence': sequence, 'sourceRevision': args.source_revision, 'sbomSHA256': sha,
               'buildID': claims['buildID'], 'buildURL': claims['buildURL']}
    if local_token:
        current.update(state='accepted', eventToken=local_token)
    write_main_state(client, targets, current)
    old_key = os.environ.get('DTRACK_API_KEY')
    os.environ['DTRACK_API_KEY'] = key
    try:
        verified = self_sbom.deliver(argparse.Namespace(rio=args.rio, prepared=root,
            published_sbom=None, target_config=args.target_config, url=targets['url'], allow_http=False, timeout=120))
    except Exception:
        token = accepted_token(root, metadata)
        state = dict(current, state='accepted', eventToken=token) if token else dict(current, state='unconfirmed')
        write_main_state(client, targets, state)
        raise
    finally:
        if old_key is None:
            os.environ.pop('DTRACK_API_KEY', None)
        else:
            os.environ['DTRACK_API_KEY'] = old_key
    proof = verified.get('importCompletion', {})
    if (verified.get('inventory') != 'verified' or proof.get('status') != 'COMPLETED'
            or proof.get('processing') is not False):
        raise ValueError('main upload has no correlated import and inventory verification')
    current.update(state='completed', eventToken=proof['eventToken'], importCompletion=proof)
    write_main_state(client, targets, current)
    return main_result(root, 'verified', sourceRevision=args.source_revision, sequence=sequence, **verified)


def public_stable(release, tag):
    return (isinstance(release, dict) and release.get('tag_name') == tag and version(tag) is not None
            and release.get('draft') is False and release.get('prerelease') is False)


def decision(root, tag, outcome, **facts):
    result = {'tag': tag, 'promotion': outcome,
              'checkedAt': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'), **facts}
    self_sbom.write_json(root / 'promotion.json', result)
    return result


def promote(args):
    root = args.prepared.resolve()
    targets = self_sbom.load_targets(args.target_config)
    if version(args.tag) is None:
        if re.fullmatch(r'v\d+\.\d+\.\d+-[0-9A-Za-z.-]+', args.tag):
            return decision(root, args.tag, 'skipped-prerelease')
        raise ValueError('a stable release tag is required')
    if not re.fullmatch(r'[0-9a-f]{40}', args.commit):
        raise ValueError('full release source commit is required')
    latest = github(args.repo, 'releases/latest')
    latest_tag = latest.get('tag_name') if isinstance(latest, dict) else None
    if not public_stable(latest, latest_tag):
        raise ValueError('GitHub latest stable release could not be verified')
    if latest_tag != args.tag:
        return decision(root, args.tag, 'skipped-not-latest-stable', latestPublishedTag=latest_tag)
    release = github(args.repo, 'releases/tags/' + args.tag)
    if not public_stable(release, args.tag):
        raise ValueError('release must be public and stable before promotion')
    commit = github(args.repo, 'commits/' + args.tag)
    if not isinstance(commit, dict) or commit.get('sha') != args.commit:
        raise ValueError('published release source commit differs')
    metadata = json.loads((root / 'prepared.json').read_text())
    if (metadata.get('release') is not True or metadata.get('artifactOnly', False)
            or metadata.get('managedTargets') != targets
            or metadata.get('project') != {'name': targets['projectName'], 'version': args.tag}):
        raise ValueError('release bundle is not the expected managed release')
    if self_sbom.digest(args.published_sbom) != metadata.get('sha256'):
        raise ValueError('published source SBOM differs from the captured bytes')
    assets = [a for a in release.get('assets', [])
              if a.get('name') == 'rio-' + args.tag + '-source.cdx.json']
    if len(assets) != 1 or assets[0].get('digest') != 'sha256:' + metadata['sha256']:
        raise ValueError('published GitHub asset digest differs from the captured source SBOM')
    state = json.loads((root / 'delivery-state.json').read_text())
    if state.get('state') != 'accepted':
        raise ValueError('an accepted delivery must be recorded before latest promotion')
    key = os.environ.get('DTRACK_LIFECYCLE_KEY')
    if not key:
        raise ValueError('DTRACK_LIFECYCLE_KEY is required for release promotion')
    # This key has read/update permissions, not BOM_UPLOAD. The accepted marker
    # is mandatory before entering native read-back recovery, so no upload is
    # performed here even when a previous promotion attempt failed.
    previous_key = os.environ.get('DTRACK_API_KEY')
    os.environ['DTRACK_API_KEY'] = key
    try:
        verification = self_sbom.deliver(argparse.Namespace(
            rio=args.rio, prepared=root, published_sbom=args.published_sbom,
            target_config=args.target_config, url=targets['url'], allow_http=False, timeout=120))
    finally:
        if previous_key is None:
            os.environ.pop('DTRACK_API_KEY', None)
        else:
            os.environ['DTRACK_API_KEY'] = previous_key
    if verification.get('inventory') != 'verified':
        raise ValueError('release inventory was not verified')
    uuid = verification.get('projectUUID', '')
    if not re.fullmatch(r'[0-9a-f-]{36}', uuid) or uuid in (targets['main']['uuid'], targets['collection']['uuid']):
        raise ValueError('invalid release project identity')
    client = Client(targets['url'], key)
    path = '/api/v1/project/' + uuid
    project = client.get(path)
    if (not isinstance(project, dict) or project.get('name') != targets['projectName']
            or project.get('version') != args.tag or project.get('active') is not True):
        raise ValueError('release project identity or active state differs')
    if (project.get('parent') or {}).get('uuid') != targets['collection']['uuid']:
        raise ValueError('release parent differs from the managed collection')
    latest_path = '/api/v1/project/latest/' + urllib.parse.quote(targets['projectName'], safe='')
    before = client.get(latest_path)
    if before and version(before.get('version')) and version(before['version']) > version(args.tag):
        return decision(root, args.tag, 'skipped-newer-monitored-release', latestMonitoredTag=before['version'])
    # Recheck immediately before the only mutation. Serialized release jobs
    # prevent our promotions overlapping; this also detects newer publication.
    current = github(args.repo, 'releases/latest')
    if not public_stable(current, args.tag):
        return decision(root, args.tag, 'skipped-not-latest-stable', latestPublishedTag=current.get('tag_name'))
    if project.get('isLatest') is not True or not before or before.get('uuid') != uuid:
        client.patch(path, {'isLatest': True})
    observed, observed_latest = client.get(path), client.get(latest_path)
    if (not observed or observed.get('isLatest') is not True or observed.get('active') is not True
            or observed.get('name') != targets['projectName'] or observed.get('version') != args.tag or not observed_latest
            or observed_latest.get('uuid') != uuid or observed.get('parent') != project.get('parent')
            or sorted(t['name'] for t in observed.get('tags', [])) != sorted(t['name'] for t in project.get('tags', []))):
        raise ValueError('latest release flag or preserved parent/tags was not observed after promotion')
    if before and before.get('uuid') != uuid:
        previous = client.get('/api/v1/project/' + before['uuid'])
        if previous and previous.get('isLatest') is not False:
            raise ValueError('previous latest flag was not cleared')
    final = github(args.repo, 'releases/latest')
    outcome = 'verified-latest' if public_stable(final, args.tag) else 'superseded-after-promotion'
    return decision(root, args.tag, outcome, commit=args.commit, projectUUID=uuid,
                    sbomSHA256=metadata['sha256'], previousLatestTag=before.get('version') if before else None,
                    latestPublishedTag=final.get('tag_name'), parent='observed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    command = commands.add_parser('promote')
    command.add_argument('--prepared', type=Path, required=True)
    command.add_argument('--published-sbom', type=Path, required=True)
    command.add_argument('--target-config', type=Path, required=True)
    command.add_argument('--tag', required=True)
    command.add_argument('--commit', required=True)
    command.add_argument('--repo', default='rebaze/rio')
    command.add_argument('--rio', required=True)
    main_command = commands.add_parser('deliver-main')
    main_command.add_argument('--prepared', type=Path, required=True)
    main_command.add_argument('--target-config', type=Path, required=True)
    main_command.add_argument('--source-revision', required=True)
    main_command.add_argument('--run-number', type=int, required=True)
    main_command.add_argument('--repo', default='rebaze/rio')
    main_command.add_argument('--rio', required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(promote(args) if args.command == 'promote' else deliver_main(args)))
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        message = str(error) if isinstance(error, ValueError) and not isinstance(error, json.JSONDecodeError) else 'SBOM lifecycle operation could not be verified'
        if args.prepared.is_dir():
            if args.command == 'promote':
                decision(args.prepared, args.tag, 'failed', reason=message)
            else:
                main_result(args.prepared, 'failed', reason=message)
        print('FAILED: ' + message, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
