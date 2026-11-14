#!/usr/bin/env python3
"""Prepare Rio's source SBOM and deliver its verified bytes with native Rio.

Python 3.9+, Rio, and (for prepare) source-sbom.sh's Go/jq build dependencies.
Only the inventory read-back uses HTTP here. Rio owns normalization and upload.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_URL = 'https://dependencytrack.rebaze.de'
UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    temporary = path.with_name('.' + path.name + '.' + str(os.getpid()) + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
    temporary.replace(path)


def contained(root, relative):
    relative = PurePosixPath(relative)
    if relative.is_absolute() or '..' in relative.parts or '\\' in str(relative) or ':' in str(relative):
        raise ValueError('unsafe prepared-bundle path')
    result = (root / relative).resolve()
    try:
        result.relative_to(root.resolve())
    except ValueError:
        raise ValueError('prepared-bundle path escapes its directory') from None
    return result


def base_url(url, allow_http):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme not in ('https', 'http') or not parsed.hostname or parsed.username or parsed.password
            or parsed.query or parsed.fragment or (parsed.scheme == 'http' and not allow_http)):
        raise ValueError('destination requires HTTPS (or explicit --allow-http for a synthetic receiver)')
    return url.rstrip('/')


def validate_targets(data):
    if (not isinstance(data, dict)
            or set(data) != {'schemaVersion', 'url', 'projectName', 'collection', 'main', 'organization'}
            or type(data.get('schemaVersion')) is not int or data['schemaVersion'] != 1):
        raise ValueError('unsupported managed target-config schema')
    def text(value):
        return (isinstance(value, str) and bool(value.strip()) and value == value.strip()
                and len(value) <= 255 and not any(ord(c) < 32 for c in value))
    if (not text(data.get('projectName')) or not text(data.get('url'))
            or any(c.isspace() for c in data['url'])):
        raise ValueError('invalid target-config project name or URL')
    try:
        urllib.parse.urlsplit(data['url']).port
    except ValueError:
        raise ValueError('invalid target-config URL port') from None
    if base_url(data['url'], False) != data['url']:
        raise ValueError('target-config URL must be canonical HTTPS')
    for section, field in (('collection', 'name'), ('main', 'version'), ('organization', 'name')):
        item = data[section]
        if (not isinstance(item, dict) or set(item) != {field, 'uuid'} or not text(item.get(field))
                or not isinstance(item.get('uuid'), str) or not UUID.fullmatch(item['uuid'])):
            raise ValueError('invalid target-config ' + section + ' identity')
    if data['main']['version'] != 'main' or data['main']['uuid'] == data['collection']['uuid']:
        raise ValueError('target-config requires distinct main and collection projects')
    return data


def load_targets(path):
    return validate_targets(json.loads(Path(path).read_text(encoding='utf-8')))


def validate_build_claims(claims):
    required = {'schemaVersion', 'sourceRevision', 'buildURL'}
    if (not isinstance(claims, dict) or not required <= set(claims)
            or set(claims) - required - {'buildID'}
            or type(claims.get('schemaVersion')) is not int or claims['schemaVersion'] != 1):
        raise ValueError('build claims require source revision and build URL together')
    if (not isinstance(claims['sourceRevision'], str)
            or not re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', claims['sourceRevision'])):
        raise ValueError('build claims require a full lowercase source revision')
    url = claims['buildURL']
    if (not isinstance(url, str) or not url.startswith('https://')
            or any(c.isspace() or unicodedata.category(c) == 'Cc' for c in url)
            or '?' in url or '#' in url):
        raise ValueError('build claims require an HTTPS build URL without credentials, query or fragment')
    try:
        base_url(url, False)
        urllib.parse.urlsplit(url).port
    except ValueError:
        raise ValueError('build claims contain an invalid build URL') from None
    if 'buildID' in claims:
        value = claims['buildID']
        if (not isinstance(value, str) or not value or value != value.strip() or len(value) > 255
                or any(unicodedata.category(c) == 'Cc' for c in value)):
            raise ValueError('build claims contain an invalid build ID')
    return claims


def indexed_member(root, index):
    index = contained(root, index)
    data = json.loads(index.read_text())
    artifacts = data.get('artifacts', [])
    if len(artifacts) != 1 or artifacts[0].get('id') != 'rio-source':
        raise ValueError('expected one indexed rio-source artifact')
    artifact = artifacts[0]
    if artifact.get('gate') != 'ok' or artifact.get('schemaValidated') is not True:
        raise ValueError('source SBOM did not pass its schema and quality gate')
    output = artifact['output']
    member = contained(index.parent, output['path'])
    contained(root, member.relative_to(root.resolve()).as_posix())
    if digest(member) != output['sha256']:
        raise ValueError('indexed source SBOM bytes changed')
    if digest(contained(root, 'source.cdx.json')) != output['sha256']:
        raise ValueError('prepared source SBOM differs from indexed bytes')
    return index, member, output['sha256']


def package(root, index_path, project_version, *, release=False, url=DEFAULT_URL, allow_http=False, project_name='rio',
            targets=None, artifact_only=False):
    root = Path(root).resolve()
    if not project_version or len(project_version) > 255 or any(ord(c) < 32 for c in project_version):
        raise ValueError('invalid Dependency-Track project version')
    url = base_url(url, allow_http)
    relative = Path(index_path).resolve().relative_to(root).as_posix()
    index, member, sha = indexed_member(root, relative)
    project = {'name': project_name, 'version': project_version}
    if type(artifact_only) is not bool:
        raise ValueError('artifact-only must be boolean')
    subject = json.loads((root / 'source.cdx.json').read_text()).get('metadata', {}).get('component', {})
    if release and project_version != 'v' + subject.get('version', ''):
        raise ValueError('release project version differs from the SBOM subject')
    target = target_config(project, release, url, allow_http, targets=targets)
    # JSON is valid YAML, so preparation needs no YAML runtime dependency.
    write_json(root / 'delivery.yaml', {'version': 1, 'artifacts': [{'id': 'rio-source', 'sbom': 'source.cdx.json'}],
                                      'gate': {'mode': 'fail'}, 'delivery': {'targets': {'security': target}}})
    metadata = {'schemaVersion': 1, 'project': project, 'release': release, 'index': relative,
                'sbom': 'source.cdx.json', 'sha256': sha, 'artifactOnly': artifact_only}
    if targets is not None:
        metadata['managedTargets'] = targets
    write_json(root / 'prepared.json', metadata)
    return metadata


def target_config(project, release, url, allow_http, targets=None):
    target = {'type': 'dependency-track', 'url': url, 'apiKeyEnv': 'DTRACK_API_KEY',
              'project': project, 'autoCreate': True,
              'tags': ['owner:team-rio', 'go', 'source:release' if release else 'source:ci']}
    if targets is not None:
        validate_targets(targets)
        if url != targets['url'] or project.get('name') != targets['projectName']:
            raise ValueError('managed target-config destination differs from logical project')
        if release:
            target['parent'] = {'uuid': targets['collection']['uuid']}
        else:
            if project.get('version') != targets['main']['version']:
                raise ValueError('managed non-release delivery must target main')
            target['project'] = {'uuid': targets['main']['uuid']}
            target.pop('autoCreate')
    if allow_http:
        target['allowHTTP'] = True
    return target


def prepare(args):
    revision, build_url, build_id = (getattr(args, name, None) for name in ('source_revision', 'build_url', 'build_id'))
    claims = None
    if revision is not None or build_url is not None or build_id is not None:
        claims = {'schemaVersion': 1, 'sourceRevision': revision, 'buildURL': build_url}
        if build_id is not None:
            claims['buildID'] = build_id
        validate_build_claims(claims)
    targets_path = getattr(args, 'target_config', None)
    targets = load_targets(targets_path) if targets_path is not None else None
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    rio = shutil.which(args.rio)
    if rio is None:
        raise ValueError('cannot find the Rio executable')
    command = [str(ROOT / 'tools/source-sbom.sh'), args.version, str(output / 'source.cdx.json'),
               str(Path(rio).resolve()), str(output / 'source-receipt.json'), str(output / 'normalized')]
    if claims is not None:
        write_json(output / 'build.json', claims)
        command.append(str(output / 'build.json'))
    subprocess.run(command, check=True)
    indexes = list((output / 'normalized/runs').glob('*/index.json'))
    if len(indexes) != 1:
        raise ValueError('expected one retained normalization index')
    result = package(output, indexes[0], args.project_version, release=args.release, url=args.url,
                     allow_http=args.allow_http, project_name=args.project_name, targets=targets,
                     artifact_only=getattr(args, 'artifact_only', False))
    print(json.dumps(result))
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def get_json(opener, url, key, timeout):
    request = urllib.request.Request(url, headers={'X-Api-Key': key, 'Accept': 'application/json'})
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(8 << 20)
            return response.status, json.loads(body), response.headers
    except urllib.error.HTTPError as error:
        return error.code, None, {}
    except (OSError, ValueError):
        return 0, None, {}


def coordinates(components):
    result = []
    for component in components:
        if not isinstance(component, dict) or any(not isinstance(component.get(k), str)
                                                for k in ('name', 'version', 'purl')):
            raise ValueError('invalid component identity in inventory read-back')
        purl = component['purl']
        # Dependency-Track's PackageURL consumer lowercases the legacy golang
        # path. Compare that representation while retaining the declared Go
        # module name and version exactly; never rewrite the attested SBOM.
        if purl.startswith('pkg:golang/'):
            path, separator, version = purl.partition('@')
            purl = path.lower() + separator + version
        result.append((component['name'], component['version'], purl))
    return sorted(result)


def event_token(batch):
    try:
        items = batch['items']
        if not isinstance(items, list) or len(items) != 1:
            raise ValueError('expected one native acknowledgment event token')
        observations = items[0]['result']['observations']
        tokens = [reference.get('value') for observation in observations
                  if isinstance(observation, dict) and observation.get('kind') == 'acknowledgment'
                  and observation.get('value') == 'accepted' and observation.get('origin') == 'receiver'
                  for reference in observation.get('references', [])
                  if isinstance(reference, dict) and reference.get('kind') == 'dependency-track:event-token']
    except (KeyError, TypeError, AttributeError):
        raise ValueError('native acknowledgment event token is missing or malformed') from None
    if len(tokens) != 1 or not isinstance(tokens[0], str) or not UUID.fullmatch(tokens[0]):
        raise ValueError('native acknowledgment requires exactly one strict UUID event token')
    return tokens[0]


def wait_for_import(url, key, token, timeout):
    if not isinstance(token, str) or not UUID.fullmatch(token):
        raise ValueError('import completion requires a strict UUID event token')
    if timeout <= 0:
        raise ValueError('import completion timeout must be positive')
    url = base_url(url, False)
    opener = urllib.request.build_opener(NoRedirect)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status, body, _ = get_json(opener, url + '/api/v1/event/token/' + token, key,
                                   max(.01, min(10, deadline - time.monotonic())))
        if status in (401, 403):
            raise ValueError('import completion read-back permission denied')
        if status == 200 and isinstance(body, dict):
            processing, workflow_status = body.get('processing'), body.get('status')
            if processing is False and workflow_status == 'COMPLETED':
                return {'eventToken': token, 'status': 'COMPLETED', 'processing': False}
            if processing is False and workflow_status == 'FAILED':
                raise ValueError('correlated import workflow failed; reconcile before retry')
        time.sleep(min(1, max(0, deadline - time.monotonic())))
    raise ValueError('correlated import completion was not confirmed before timeout; do not retry the upload blindly')


def completed_import(root, state, batch, url, key, timeout):
    token = event_token(batch)
    if 'importCompletion' in state:
        proof = state['importCompletion']
        if (not isinstance(proof, dict) or proof.get('eventToken') != token
                or proof.get('status') != 'COMPLETED' or proof.get('processing') is not False):
            raise ValueError('saved import completion proof differs from native acknowledgment token')
        return proof
    proof = wait_for_import(url, key, token, timeout)
    state['importCompletion'] = proof
    write_json(root / 'delivery-state.json', state)
    return proof


def verify_inventory(root, metadata, url, key, timeout):
    expected = coordinates(json.loads((root / 'source.cdx.json').read_text()).get('components', []))
    if not expected:
        raise ValueError('source SBOM has no component inventory')
    deadline = time.monotonic() + timeout
    opener = urllib.request.build_opener(NoRedirect)
    managed = metadata.get('managedTargets')
    if managed is not None:
        validate_targets(managed)
        target_config(metadata['project'], metadata['release'], url, False, targets=managed)
    while time.monotonic() < deadline:
        remaining = max(.01, min(10, deadline - time.monotonic()))
        query = urllib.parse.urlencode(metadata['project'])
        status, project, _ = get_json(opener, url + '/api/v1/project/lookup?' + query, key, remaining)
        if managed is not None and status == 200 and isinstance(project, dict):
            lookup_uuid = project.get('uuid')
            if (not isinstance(lookup_uuid, str) or not UUID.fullmatch(lookup_uuid)
                    or project.get('name') != metadata['project']['name']
                    or project.get('version') != metadata['project']['version']
                    or (not metadata['release'] and lookup_uuid != managed['main']['uuid'])):
                raise ValueError('managed project lookup identity differs from target-config')
            status, project, _ = get_json(opener, url + '/api/v1/project/' + lookup_uuid, key,
                                          max(.01, min(10, deadline - time.monotonic())))
            if status == 200 and isinstance(project, dict):
                if (project.get('uuid') != lookup_uuid or project.get('name') != metadata['project']['name']
                        or project.get('version') != metadata['project']['version']):
                    raise ValueError('managed full project identity differs from lookup')
                if not isinstance(project.get('parent'), dict) or project['parent'].get('uuid') != managed['collection']['uuid']:
                    raise ValueError('managed project parent differs from collection')
                if project.get('active') is not True:
                    raise ValueError('managed project must be active')
                if type(project.get('isLatest')) is not bool:
                    raise ValueError('managed project latest state is missing')
                if not metadata['release'] and project['isLatest'] is not False:
                    raise ValueError('development main must never be latest')
        observed_tags = {t.get('name') for t in (project or {}).get('tags', []) if isinstance(t, dict)} if isinstance(project, dict) else set()
        required_tags = set(target_config(metadata['project'], metadata['release'], url, False)['tags'])
        if (status == 200 and isinstance(project, dict) and isinstance(project.get('uuid'), str)
                and project.get('name') == metadata['project']['name']
                and project.get('version') == metadata['project']['version'] and required_tags <= observed_tags):
            uuid = project['uuid']
            if not all(c in '0123456789abcdef-' for c in uuid.lower()) or len(uuid) != 36:
                raise ValueError('invalid project identity in inventory read-back')
            rows, page, complete = [], 1, False
            while time.monotonic() < deadline:
                query = urllib.parse.urlencode({'pageNumber': page, 'pageSize': 100})
                status, batch, headers = get_json(opener, url + '/api/v1/component/project/' + uuid + '?' + query,
                                                  key, max(.01, min(10, deadline - time.monotonic())))
                if status != 200 or not isinstance(batch, list):
                    break
                rows.extend(batch)
                if len(batch) < 100:
                    total = headers.get('X-Total-Count')
                    kind = headers.get('X-Total-Count-Type', 'EXACT')
                    complete = total is not None and kind == 'EXACT' and total.isdigit() and int(total) == len(rows)
                    break
                if len(rows) > 10000:
                    raise ValueError('inventory read-back exceeded its bound')
                page += 1
            if complete and coordinates(rows) == expected:
                verification = {'inventory': 'verified', 'project': metadata['project'], 'projectUUID': uuid,
                        'components': len(expected), 'sbomSHA256': metadata['sha256'],
                        'ownerTag': 'observed',
                        'vulnerabilityAnalysis': 'asynchronous; inventory verification is not a vulnerability gate'}
                if managed is not None:
                    verification.update({'parent': 'observed', 'isLatest': project['isLatest']})
                return verification
        elif status in (401, 403):
            raise ValueError('inventory read-back permission denied')
        time.sleep(min(1, max(0, deadline - time.monotonic())))
    raise ValueError('Dependency-Track inventory was not verified before timeout; do not retry the upload blindly')


def deliver(args):
    root = args.prepared.resolve()
    metadata = json.loads((root / 'prepared.json').read_text())
    if metadata.get('schemaVersion') != 1 or type(metadata.get('release')) is not bool:
        raise ValueError('unsupported prepared-bundle schema')
    if type(metadata.get('artifactOnly', False)) is not bool:
        raise ValueError('invalid artifact-only bundle marker')
    if metadata.get('artifactOnly', False):
        raise ValueError('artifact-only bundle cannot be delivered')
    url = base_url(args.url, args.allow_http)
    managed = metadata.get('managedTargets')
    targets_path = getattr(args, 'target_config', None)
    if managed is not None:
        validate_targets(managed)
        if targets_path is None or load_targets(targets_path) != managed or url != managed['url']:
            raise ValueError('managed delivery requires matching external target-config and destination')
    elif targets_path is not None:
        raise ValueError('external target-config does not match unmanaged prepared bundle')
    index, member, sha = indexed_member(root, metadata['index'])
    if metadata.get('sbom') != 'source.cdx.json' or metadata.get('sha256') != sha:
        raise ValueError('prepared source SBOM metadata changed')
    config = json.loads((root / 'delivery.yaml').read_text())
    targets = config.get('delivery', {}).get('targets', {})
    target = targets.get('security', {})
    if set(targets) != {'security'} or target != target_config(metadata['project'], metadata['release'], url, args.allow_http, targets=managed):
        raise ValueError('prepared delivery destination changed')
    if metadata['release'] and args.published_sbom is None:
        raise ValueError('release delivery requires the published source SBOM')
    if args.published_sbom is not None and digest(args.published_sbom) != sha:
        raise ValueError('published source SBOM differs from prepared/indexed bytes')
    key = os.environ.get('DTRACK_API_KEY')
    if not key:
        raise ValueError('DTRACK_API_KEY is required for delivery')
    state_path = root / 'delivery-state.json'
    if state_path.exists():
        state = json.loads(state_path.read_text())
        if (state.get('schemaVersion') != 1 or state.get('state') != 'accepted'
                or state.get('sha256') != sha or state.get('project') != metadata['project']):
            raise ValueError('prior delivery has no verified acceptance; inspect its journal and reconcile with Rio before explicit retry')
        if digest(root / 'delivery-result.json') != state.get('resultSHA256'):
            raise ValueError('prior delivery result changed; inspect and reconcile before retry')
        batch = json.loads((root / 'delivery-result.json').read_text())
        receipt = contained(root, state['receipt']['path'])
        if digest(receipt) != state['receipt']['sha256']:
            raise ValueError('prior delivery receipt changed; inspect and reconcile before retry')
        subprocess.run([args.rio, 'record', 'inspect', '--file', str(receipt), '--json'],
                       capture_output=True, check=True)
        completion = completed_import(root, state, batch, url, key, args.timeout) if managed is not None else None
        verification = verify_inventory(root, metadata, url, key, args.timeout)
        if completion is not None:
            verification['importCompletion'] = completion
        verification['receipt'] = dict(state['receipt'], path=str(receipt))
        verification['recovery'] = 'read-back only; prior accepted upload was not repeated'
        write_json(root / 'verification.json', verification)
        return verification
    state = {'schemaVersion': 1, 'state': 'started', 'sha256': sha, 'project': metadata['project']}
    try:
        with state_path.open('x', encoding='utf-8') as stream:
            json.dump(state, stream)
            stream.write('\n')
    except FileExistsError:
        raise ValueError('prior delivery is already recorded; wait for its result and reconcile before retry') from None
    result = subprocess.run([args.rio, '--manifest', str(root / 'delivery.yaml'), 'deliver', '--index', str(index),
                             '--out', str(root / 'delivery-runs'), '--json'], capture_output=True, text=True)
    try:
        batch = json.loads(result.stdout)
    except ValueError:
        raise ValueError('native Rio returned no usable result; prior request state is unknown, inspect and reconcile before retry') from None
    write_json(root / 'delivery-result.json', batch)
    if result.returncode:
        raise ValueError('native Rio delivery failed (exit %d); inspect its retained result/receipt and reconcile before retry' % result.returncode)
    if batch.get('outcome') != 'accepted' or len(batch.get('items', [])) != 1 or batch['items'][0].get('state') != 'accepted':
        raise ValueError('native Rio did not report one accepted delivery')
    publication = batch.get('receipt', {})
    receipt = Path(publication['path']).resolve()
    relative = receipt.relative_to(root).as_posix()
    if digest(contained(root, relative)) != publication['sha256']:
        raise ValueError('native Rio receipt does not match its publication digest')
    state.update({'state': 'accepted', 'resultSHA256': digest(root / 'delivery-result.json'),
                  'receipt': dict(publication, path=relative),
                  'record': Path(batch['items'][0]['record']).resolve().relative_to(root).as_posix()})
    write_json(state_path, state)
    completion = completed_import(root, state, batch, url, key, args.timeout) if managed is not None else None
    verification = verify_inventory(root, metadata, url, key, args.timeout)
    if completion is not None:
        verification['importCompletion'] = completion
    verification['receipt'] = batch.get('receipt')
    write_json(root / 'verification.json', verification)
    return verification


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    build = commands.add_parser('prepare', help='generate, enrich and strictly check the source SBOM')
    build.add_argument('--version', required=True)
    build.add_argument('--project-version', required=True)
    build.add_argument('--project-name', default='rio')
    build.add_argument('--release', action='store_true')
    build.add_argument('--artifact-only', action='store_true')
    build.add_argument('--source-revision')
    build.add_argument('--build-url')
    build.add_argument('--build-id')
    build.add_argument('--output', type=Path, required=True)
    upload = commands.add_parser('deliver', help='deliver verified bytes with Rio, then verify ingestion')
    upload.add_argument('--prepared', type=Path, required=True)
    upload.add_argument('--published-sbom', type=Path)
    upload.add_argument('--timeout', type=float, default=120)
    for command in (build, upload):
        command.add_argument('--target-config', type=Path)
        command.add_argument('--rio', required=True)
        command.add_argument('--url', default=DEFAULT_URL)
        command.add_argument('--allow-http', action='store_true', help='explicit local synthetic-receiver override')
    args = parser.parse_args()
    try:
        if args.command == 'prepare':
            prepare(args)
        else:
            if args.timeout <= 0:
                raise ValueError('timeout must be positive')
            print(json.dumps(deliver(args)))
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError):
        # Errors are intentionally local, never raw receiver response bodies or credentials.
        error = sys.exc_info()[1]
        if isinstance(error, ValueError):
            print('FAILED: ' + str(error), file=sys.stderr)
        else:
            print('FAILED: self-SBOM operation failed; inspect retained Rio receipts', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
