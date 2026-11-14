#!/usr/bin/env python3
"""Install the digest-pinned published Rio used to check and deliver Rio's SBOM.

Python 3.9+, gh, and GH_TOKEN supplied through the environment. The committed
pin records archives previously provenance-verified by release verification;
this installer never builds or selects the candidate source tree's executable.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
REPO = 'rebaze/rio'
PLATFORMS = {system + '_' + arch for system in ('linux', 'darwin', 'windows')
             for arch in ('amd64', 'arm64')}

spec = importlib.util.spec_from_file_location('verify_release', ROOT / 'tools/verify-release.py')
verify_release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify_release)


def read_pin(path):
    data = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(data, dict) or not isinstance(data.get('tag'), str):
        raise ValueError('pin requires a stable release tag')
    verify_release.expected_assets(data['tag'])
    if not isinstance(data.get('commit'), str) or not re.fullmatch('[0-9a-f]{40}', data['commit']):
        raise ValueError('pin requires a full lowercase commit digest')
    archives = data.get('archives')
    if not isinstance(archives, dict) or set(archives) != PLATFORMS:
        raise ValueError('pin requires all six explicit platform archives')
    for selector, archive in archives.items():
        suffix = '.zip' if selector.startswith('windows_') else '.tar.gz'
        expected = 'rio_' + data['tag'][1:] + '_' + selector + suffix
        if not isinstance(archive, dict) or archive.get('name') != expected:
            raise ValueError('pin archive name differs from its release and platform')
        sha = archive.get('sha256')
        if not isinstance(sha, str) or not re.fullmatch('[0-9a-f]{64}', sha):
            raise ValueError('pin archive requires a full lowercase SHA256 digest')
    return data


def native_platform():
    system = {'Linux': 'linux', 'Darwin': 'darwin', 'Windows': 'windows'}.get(platform.system())
    arch = {'x86_64': 'amd64', 'amd64': 'amd64', 'arm64': 'arm64', 'aarch64': 'arm64'}.get(platform.machine().lower())
    if not system or not arch:
        raise ValueError('host platform has no pinned release archive')
    return system + '_' + arch


def gh(args, env):
    result = subprocess.run(['gh'] + args, env=env, capture_output=True, text=True,
                            encoding='utf-8', timeout=120)
    if result.returncode:
        # Never echo response bodies, auth diagnostics or tokens into evidence.
        raise ValueError('published release metadata or archive download failed')
    return result.stdout


def install(output, pin_path):
    pin = read_pin(pin_path)
    selector = native_platform()
    archive_pin = pin['archives'][selector]
    if not os.environ.get('GH_TOKEN'):
        raise ValueError('GH_TOKEN must be supplied through the environment')
    env = dict(os.environ, GH_HOST='github.com', GH_PROMPT_DISABLED='1')
    for name in ('GITHUB_TOKEN', 'GH_ENTERPRISE_TOKEN', 'GITHUB_ENTERPRISE_TOKEN'):
        env.pop(name, None)
    output = output.resolve()
    if output.exists():
        raise ValueError('installation output exists; use a fresh directory')
    output.mkdir(mode=0o700, parents=True)
    assets = output / 'assets'
    assets.mkdir()
    repository = json.loads(gh(['api', 'repos/' + REPO], env))
    if not isinstance(repository, dict) or repository.get('private') is not False:
        raise ValueError('release repository must be public')
    release = json.loads(gh(['api', 'repos/' + REPO + '/releases/tags/' + pin['tag']], env))
    if (not isinstance(release, dict) or release.get('tag_name') != pin['tag']
            or release.get('draft') is not False or release.get('prerelease') is not False):
        raise ValueError('published stable release identity differs from pin')
    published_assets = release.get('assets', [])
    if not isinstance(published_assets, list):
        raise ValueError('published release asset metadata is invalid')
    matches = [asset for asset in published_assets
               if isinstance(asset, dict) and asset.get('name') == archive_pin['name']]
    if len(matches) != 1 or type(matches[0].get('size')) is not int or matches[0]['size'] <= 0:
        raise ValueError('published release has no unique nonempty pinned archive')
    commit = json.loads(gh(['api', 'repos/' + REPO + '/commits/' + pin['tag']], env))
    if not isinstance(commit, dict) or commit.get('sha') != pin['commit']:
        raise ValueError('published tag commit differs from pin')
    gh(['release', 'download', pin['tag'], '--repo', REPO,
        '--pattern', archive_pin['name'], '--dir', str(assets)], env)
    if {p.name for p in assets.iterdir()} != {archive_pin['name']}:
        raise ValueError('download did not produce exactly the pinned archive')
    archive = assets / archive_pin['name']
    archive_sha = verify_release.digest(archive)
    if archive_sha != archive_pin['sha256']:
        raise ValueError('downloaded archive digest differs from committed pin; nothing executed')
    binary = verify_release.extract_binary(archive, output / 'bin',
                                            'rio.exe' if selector.startswith('windows_') else 'rio')
    result = subprocess.run([str(binary), 'version'], capture_output=True, text=True,
                            encoding='utf-8', timeout=30)
    version = result.stdout.strip()
    expected = 'rio ' + pin['tag'][1:] + ' (commit: ' + pin['commit'] + ', built: '
    if (result.returncode or not version.startswith(expected) or not version.endswith(')')
            or '\n' in version or '\r' in version):
        raise ValueError('downloaded Rio version or full commit differs from pin')
    metadata = {'tag': pin['tag'], 'commit': pin['commit'], 'platform': selector,
                'archive': archive_pin['name'], 'archiveSHA256': archive_sha,
                'binarySHA256': verify_release.digest(binary), 'version': version}
    (output / 'installation.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
    print('Installed ' + str(binary) + ': ' + version)
    return metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--pin', type=Path, default=ROOT / 'tools/self-sbom-rio.json')
    args = parser.parse_args()
    try:
        install(args.output, args.pin)
    except (ValueError, OSError, subprocess.SubprocessError, tarfile.TarError, zipfile.BadZipFile) as error:
        # Only our local validation errors are printable. Subprocess failures
        # and OS errors may carry external diagnostics, so keep them generic.
        message = str(error) if isinstance(error, ValueError) and not isinstance(error, json.JSONDecodeError) else 'pinned Rio installation failed'
        print('FAILED: ' + message, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
