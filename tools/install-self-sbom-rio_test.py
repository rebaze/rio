"""Offline tests for the published, digest-pinned self-SBOM Rio installer."""
import copy
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'tools/install-self-sbom-rio.py'
TAG = 'v0.10.2'
COMMIT = '35c8da3' + 'a' * 33
SYSTEM = {'Darwin': 'darwin', 'Linux': 'linux', 'Windows': 'windows'}[platform.system()]
ARCH = {'arm64': 'arm64', 'aarch64': 'arm64', 'x86_64': 'amd64', 'amd64': 'amd64'}[platform.machine().lower()]
PLATFORM = SYSTEM + '_' + ARCH
FAKE_GH = '''#!/usr/bin/env python3
import json, os, shutil, sys
from pathlib import Path
state = Path(os.environ['INSTALL_STATE'])
args = sys.argv[1:]
if not os.environ.get('GH_TOKEN'):
    sys.exit('missing environment token')
with (state / 'calls.jsonl').open('a') as f:
    f.write(json.dumps(args) + '\\n')
if args == ['api', 'repos/rebaze/rio']:
    print((state / 'repo.json').read_text())
elif args == ['api', 'repos/rebaze/rio/releases/tags/v0.10.2']:
    print((state / 'release.json').read_text())
elif args == ['api', 'repos/rebaze/rio/commits/v0.10.2']:
    print((state / 'commit.json').read_text())
elif args[:3] == ['release', 'download', 'v0.10.2']:
    if (state / 'missing').exists():
        sys.exit('asset unavailable')
    assert args[3:5] == ['--repo', 'rebaze/rio']
    name = args[args.index('--pattern') + 1]
    destination = Path(args[args.index('--dir') + 1])
    shutil.copyfile(state / 'archive', destination / name)
else:
    sys.exit('unexpected gh operation: ' + repr(args))
'''


@unittest.skipIf(SYSTEM == 'windows', 'fixture native executable requires a POSIX shell')
class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='pinned-rio-test-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / 'tools'
        self.bin.mkdir()
        gh = self.bin / 'gh'
        gh.write_text(FAKE_GH)
        gh.chmod(0o755)
        fallback = self.bin / 'rio'
        fallback.write_text('#!/bin/sh\nprintf fallback > "$INSTALL_FALLBACK_MARKER"\n')
        fallback.chmod(0o755)
        self.marker = self.root / 'executed'
        self.fallback_marker = self.root / 'fallback-executed'
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                        INSTALL_STATE=str(self.root), GH_TOKEN='synthetic-test-token',
                        INSTALL_MARKER=str(self.marker), INSTALL_FALLBACK_MARKER=str(self.fallback_marker))
        self.pin = {'tag': TAG, 'commit': COMMIT, 'archives': {}}
        for system in ('linux', 'darwin', 'windows'):
            for arch in ('amd64', 'arm64'):
                name = 'rio_0.10.2_' + system + '_' + arch + ('.zip' if system == 'windows' else '.tar.gz')
                self.pin['archives'][system + '_' + arch] = {'name': name, 'sha256': '0' * 64}
        self.release = {'tag_name': TAG, 'draft': False, 'prerelease': False,
                        'assets': [{'name': a['name'], 'size': 100} for a in self.pin['archives'].values()]}
        self.repo = {'private': False}
        self.commit = {'sha': COMMIT}
        self.count = 0
        self.make_archive()

    def make_archive(self, version='0.10.2', commit=COMMIT):
        raw = ('#!/bin/sh\nprintf executed > "$INSTALL_MARKER"\n'
               '[ "$1" = version ] || exit 9\n'
               "printf '%s\\n' 'rio " + version + ' (commit: ' + commit + ", built: 2026-11-14T00:00:00Z)'\n").encode()
        with tarfile.open(self.root / 'archive', 'w:gz') as archive:
            entry = tarfile.TarInfo('rio')
            entry.size = len(raw)
            entry.mode = 0o755
            archive.addfile(entry, io.BytesIO(raw))
        self.pin['archives'][PLATFORM]['sha256'] = hashlib.sha256((self.root / 'archive').read_bytes()).hexdigest()

    def install(self, pin=None):
        self.count += 1
        output = self.root / ('install ' + str(self.count))
        pin_path = self.root / 'pin.json'
        pin_path.write_text(json.dumps(self.pin if pin is None else pin))
        for name, value in [('release', self.release), ('repo', self.repo), ('commit', self.commit)]:
            (self.root / (name + '.json')).write_text(json.dumps(value))
        result = subprocess.run([sys.executable, str(SCRIPT), '--pin', str(pin_path), '--output', str(output)],
                                text=True, capture_output=True, env=self.env)
        return result, output

    def test_installs_only_pinned_published_archive_and_records_verified_identity(self):
        result, output = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        binary = output / 'bin/rio'
        self.assertTrue(binary.is_file())
        self.assertTrue(self.marker.exists())
        self.assertFalse(self.fallback_marker.exists())
        metadata = json.loads((output / 'installation.json').read_text())
        self.assertEqual(metadata['tag'], TAG)
        self.assertEqual(metadata['commit'], COMMIT)
        self.assertEqual(metadata['platform'], PLATFORM)
        self.assertEqual(metadata['archive'], self.pin['archives'][PLATFORM]['name'])
        self.assertEqual(metadata['archiveSHA256'], self.pin['archives'][PLATFORM]['sha256'])
        self.assertEqual(metadata['binarySHA256'], hashlib.sha256(binary.read_bytes()).hexdigest())
        self.assertTrue(metadata['version'].startswith('rio 0.10.2 (commit: ' + COMMIT + ','))
        self.assertNotIn(self.env['GH_TOKEN'], (output / 'installation.json').read_text() + result.stdout + result.stderr)
        calls = [json.loads(line) for line in (self.root / 'calls.jsonl').read_text().splitlines()]
        download = [call for call in calls if call[:2] == ['release', 'download']]
        self.assertEqual(len(download), 1)
        self.assertEqual(download[0][download[0].index('--pattern') + 1], self.pin['archives'][PLATFORM]['name'])
        self.assertIn(str(binary), result.stdout)

    def test_digest_mismatch_never_executes_download_or_falls_back(self):
        self.pin['archives'][PLATFORM]['sha256'] = 'b' * 64
        result, output = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('digest', result.stderr)
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.fallback_marker.exists())
        self.assertFalse((output / 'bin/rio').exists())
        self.assertFalse((output / 'installation.json').exists())

    def test_rejects_unpublished_or_mismatched_release_before_execution(self):
        for field, value in [('draft', True), ('prerelease', True), ('tag_name', 'v0.10.1')]:
            with self.subTest(field=field):
                original = self.release[field]
                self.release[field] = value
                result, output = self.install()
                self.release[field] = original
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.marker.exists())
                self.assertFalse((output / 'installation.json').exists())

    def test_rejects_private_repository_or_different_tag_commit(self):
        self.repo['private'] = True
        result, _ = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.repo['private'] = False
        self.commit['sha'] = 'b' * 40
        result, _ = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.marker.exists())

    def test_missing_archive_never_executes_path_candidate(self):
        (self.root / 'missing').touch()
        result, output = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.fallback_marker.exists())
        self.assertFalse((output / 'installation.json').exists())

    def test_rejects_binary_version_or_full_commit_mismatch(self):
        for version, commit in [('0.10.1', COMMIT), ('0.10.2', COMMIT[:7]), ('0.10.2', 'b' * 40)]:
            with self.subTest(version=version, commit=commit):
                self.make_archive(version, commit)
                result, output = self.install()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((output / 'installation.json').exists())

    def test_rejects_malformed_or_nonstable_pin_before_network_or_execution(self):
        cases = []
        for field, value in [('tag', 'latest'), ('tag', 'v0.10.2-rc1'), ('tag', 'v00.10.2'),
                             ('commit', COMMIT[:7]), ('commit', 'g' * 40)]:
            altered = copy.deepcopy(self.pin)
            altered[field] = value
            cases.append(altered)
        for field, value in [('name', '../rio.tar.gz'), ('name', 'rio_0.10.1_linux_amd64.tar.gz'),
                             ('sha256', 'a' * 63), ('sha256', 'g' * 64)]:
            altered = copy.deepcopy(self.pin)
            altered['archives'][PLATFORM][field] = value
            cases.append(altered)
        altered = copy.deepcopy(self.pin)
        del altered['archives']['windows_arm64']
        cases.append(altered)
        for pin in cases:
            with self.subTest(pin=pin):
                result, _ = self.install(pin)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.marker.exists())
                self.assertFalse((self.root / 'calls.jsonl').exists())

    def test_existing_output_directory_is_rejected(self):
        result, output = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        before = (output / 'installation.json').read_bytes()
        result = subprocess.run([sys.executable, str(SCRIPT), '--pin', str(self.root / 'pin.json'),
                                 '--output', str(output)], text=True, capture_output=True, env=self.env)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((output / 'installation.json').read_bytes(), before)


class PlatformTest(unittest.TestCase):
    def test_windows_arm64_uses_its_pinned_archive(self):
        spec = importlib.util.spec_from_file_location('stable_rio_installer', SCRIPT)
        installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(installer)
        with mock.patch.object(installer.platform, 'system', return_value='Windows'), \
                mock.patch.object(installer.platform, 'machine', return_value='ARM64'):
            self.assertEqual(installer.native_platform(), 'windows_arm64')


if __name__ == '__main__':
    unittest.main()
