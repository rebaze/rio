#!/usr/bin/env python3
"""Report newer stable pipeline tools; optionally update one GitHub tracking issue.

Uses only stdlib. Never installs tools, modifies pins, or merges a PR. API failures
and inconsistent pins fail visibly rather than producing a clean update report.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
TITLE = 'Pipeline tool updates need review'
REPO = 'rebaze/rio'


def version(value):
    if not isinstance(value, str) or not re.fullmatch(r'v\d+\.\d+\.\d+', value):
        raise ValueError('expected a stable version: ' + repr(value))
    return tuple(int(x) for x in value[1:].split('.'))


def newer(current, latest):
    return version(latest) > version(current)


def same_pin(root, paths, pattern):
    values = []
    for path in paths:
        found = re.findall(pattern, (root/path).read_text(), re.MULTILINE)
        if not found:
            raise ValueError('missing exact version pin in ' + path)
        values.extend(found)
    if len(set(values)) != 1:
        raise ValueError('inconsistent version pins: ' + ', '.join(paths))
    value = values[0]
    if not value.startswith('v'):
        value = 'v' + value
    version(value)
    return value


def inventory(root=ROOT):
    toolchain=json.loads((root/'tools/release-toolchain/manifest.json').read_text())
    pins={name: toolchain['tools'][name]['version'] for name in ('cosign','syft','goreleaser')}
    pins['go']=same_pin(root, ['go.mod','tools/security/go.mod'] +
                       ['tools/release-toolchain/'+name+'/go.mod' for name in pins],
                       r'^go (\d+\.\d+\.\d+)$')
    if toolchain['compiler'] != 'go'+pins['go'][1:]:
        raise ValueError('inconsistent compiler/toolchain pins')
    for pin in pins.values():
        version(pin)

    shell_pin = same_pin(root, ['tools/rio-attest-sign.sh','tools/rio-attest-verify.sh'],
                         r'^\[.* = (v\d+\.\d+\.\d+) \] \|\| refuse')
    demo_pin = same_pin(root, ['tools/demo-attest-sign/run.py'],
                        r'if version\["gitVersion"\] != "(v\d+\.\d+\.\d+)":')
    if len({pins['cosign'], shell_pin, demo_pin}) != 1:
        raise ValueError('inconsistent cosign toolchain/signer/verifier/demo pins')
    return pins


def fetch(url):
    headers = {'User-Agent': 'rio-pipeline-update-check', 'Accept': 'application/json'}
    # Never forward the GitHub token to another origin, including redirects.
    if url.startswith('https://api.github.com/') and os.environ.get('GH_TOKEN'):
        headers['Authorization'] = 'Bearer ' + os.environ['GH_TOKEN']
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise ValueError('unexpected redirect from update API')
    with urllib.request.build_opener(NoRedirect).open(urllib.request.Request(url, headers=headers), timeout=30) as response:
        return json.load(response)


def go_patch(current, releases):
    line = version(current)[:2]
    candidates = ['v'+item['version'][2:] for item in releases
                  if item.get('stable') is True and re.fullmatch(r'go\d+\.\d+\.\d+', item.get('version',''))]
    candidates = [v for v in candidates if version(v)[:2] == line]
    if not candidates:
        raise ValueError('selected Go release line no longer appears in supported downloads')
    return max(candidates, key=version)


def report():
    current = inventory()
    latest = {'go': go_patch(current['go'], fetch('https://go.dev/dl/?mode=json'))}
    for tool, repo in [('cosign','sigstore/cosign'),('syft','anchore/syft'),('goreleaser','goreleaser/goreleaser')]:
        release = fetch('https://api.github.com/repos/'+repo+'/releases/latest')
        if release.get('draft') is not False or release.get('prerelease') is not False:
            raise ValueError('upstream latest response is not a stable published release')
        latest[tool] = release['tag_name']
    rows = [{'tool': tool, 'current': pin, 'latest': latest[tool]} for tool, pin in current.items()]
    return {'tools': rows, 'updates': [row for row in rows if newer(row['current'],row['latest'])],
            'scope': 'Version availability only; not an advisory scan or proof that upstream binaries are safe.'}


def run(args):
    return subprocess.check_output(args, text=True)


def publish(result, command=run):
    if not result['updates']:
        return
    rows = '\n'.join('- {tool}: {current} → {latest}'.format(**row) for row in result['updates'])
    body = ('New stable pipeline tool versions need review (refs #121).\n\n'+rows+
            '\n\nCheck upstream advisories, actual downloaded binary build metadata, signer/recipient compatibility, '
            'and full candidate CI before changing pins. This report does not authorize auto-merge or publication. '
            'Go modules/actions remain covered by Dependabot.\n')
    issues = json.loads(command(['gh','issue','list','--repo',REPO,'--state','open','--search',TITLE+' in:title','--author','github-actions[bot]','--label','dependencies','--limit','100','--json','number,title,author,labels']))
    matches = [i for i in issues if i['title'] == TITLE
               and i.get('author', {}).get('is_bot') is True
               and i.get('author', {}).get('login') in ('github-actions[bot]', 'app/github-actions')
               and any(label.get('name') == 'dependencies' for label in i.get('labels', []))]
    if len(matches) > 1:
        raise ValueError('multiple update trackers exist; reconcile them explicitly')
    with tempfile.NamedTemporaryFile(mode='w', suffix='.md') as tmp:
        tmp.write(body); tmp.flush()
        if matches:
            args = ['gh','issue','edit',str(matches[0]['number']),'--repo',REPO,'--body-file',tmp.name]
        else:
            args = ['gh','issue','create','--repo',REPO,'--title',TITLE,'--label','dependencies','--body-file',tmp.name]
        command(args)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--publish-issue', action='store_true')
    args = parser.parse_args()
    result = report()
    data = json.dumps(result, indent=2)+'\n'
    if args.output:
        args.output.write_text(data)
    print(data, end='')
    if args.publish_issue:
        publish(result)


if __name__ == '__main__':
    main()
