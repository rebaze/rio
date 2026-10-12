"""Build policy tests use synthetic inputs; live builds/scans are separate verification."""
import importlib.util
import json
from pathlib import Path
import tempfile
import os
import subprocess
import textwrap
import sys
from unittest.mock import patch
import unittest

spec=importlib.util.spec_from_file_location('builder',Path(__file__).with_name('build.py'))
builder=importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)

CONFIG = json.dumps({'config':{'scanner_name':'govulncheck','scan_mode':'binary','scan_level':'symbol','scanner_version':'v1.8.0'}}) + '\n' + json.dumps({'SBOM':{'go_version':'go1.27.2'}}) + '\n'

def assess(data, approved):
    return builder.assess(data, approved, 'v1.8.0')

class PolicyTest(unittest.TestCase):
    def scope(self, root):
        files={name:'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' for name in builder.REVIEWED_FILES}
        for name in files:
            path=root/name; path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'')
        return {'reviewedFiles':files}

    def test_changed_invocation_scope_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); scope=self.scope(root)
            (root/'tools/release-publish.py').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'reviewed scope differs'):
                builder.check_scope(root,scope)

    def test_required_reviewed_inputs_cannot_be_omitted(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);scope=self.scope(root)
            for name in ('tools/release-publish.py','tools/verify-release.py','tools/demo-attest-sign/run.py','tools/security/go.mod','tools/security/go.sum'):
                missing={'reviewedFiles':{k:v for k,v in scope['reviewedFiles'].items() if k!=name}}
                with self.subTest(name=name),self.assertRaisesRegex(ValueError,'incomplete'):
                    builder.check_scope(root,missing)

    def test_new_advisory_fails_even_at_module_precision(self):
        event={'finding':{'osv':'NEW-CVE','trace':[{'module':'example','version':'v1'}]}}
        with self.assertRaisesRegex(ValueError,'unreviewed'):
            assess(CONFIG+json.dumps(event), {})

    def test_reviewed_id_does_not_allow_different_module_or_version(self):
        approved={'GO-EXAMPLE':{'module':'example','version':'v1'}}
        for frame in [{'module':'other','version':'v1'}, {'module':'example','version':'v2'}]:
            with self.assertRaisesRegex(ValueError,'unreviewed'):
                assess(CONFIG+json.dumps({'finding':{'osv':'GO-EXAMPLE','trace':[frame]}}),approved)

    def test_package_prefix_does_not_accept_a_lookalike(self):
        approved={'GO-EXAMPLE':{'module':'example','version':'v1','packagePrefix':'example/pkg'}}
        event={'finding':{'osv':'GO-EXAMPLE','trace':[{'module':'example','version':'v1','package':'example/pkg-other','function':'Do'}]}}
        with self.assertRaisesRegex(ValueError,'unreviewed affected package'):
            assess(CONFIG+json.dumps(event),approved)

    def test_preserves_module_vs_symbol_evidence(self):
        approved={'GO-EXAMPLE':{'module':'example','version':'v1'}}
        frames=[{'module':'example','version':'v1'},
                {'module':'example','version':'v1','package':'example/pkg','function':'Do'}]
        events='\n'.join(json.dumps({'finding':{'osv':'GO-EXAMPLE','trace':[f]}}) for f in frames)
        result=assess(CONFIG+events,approved)
        self.assertEqual([f['precision'] for f in result],['module','symbol'])

    def test_stripped_fallback_is_not_accepted_as_symbol_evidence(self):
        approved={'GO-EXAMPLE':{'module':'example','version':'v1'}}
        event={'finding':{'osv':'GO-EXAMPLE','trace':[{'module':'example','version':'v1','package':'example/pkg','function':'*'}]}}
        with self.assertRaisesRegex(ValueError,'stripped'):
            assess(CONFIG+json.dumps(event),approved)

    def test_malformed_scan_fails_closed(self):
        for data in ['', '{}', '{bad', '{"config":{"scanner_name":"govulncheck"}}', '{"finding":{"osv":"GO-EXAMPLE","trace":[]}}']:
            with self.subTest(data=data), self.assertRaises(ValueError):
                assess(data,{})

    def test_clean_scan_requires_scanner_configuration(self):
        self.assertEqual(assess(CONFIG,{}),[])

    def test_download_verification_executes_reviewed_workflow_script(self):
        workflow=(builder.ROOT/'.github/workflows/verify-release.yaml').read_text()
        block=workflow.split('      - name: Verify downloaded bytes and execute native client handoff',1)[1].split('      - name: Preserve verification evidence',1)[0]
        script=textwrap.dedent(block.split('        run: |\n',1)[1])
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for name in ('source/tools','workflow/tools','bin','source/docs/releases'):
                (root/name).mkdir(parents=True)
            (root/'source/tools/verify-release.py').write_text('raise SystemExit("unreviewed historical script executed")')
            (root/'workflow/tools/verify-release.py').write_text('from pathlib import Path; Path("reviewed-executed").write_text("yes")')
            git=root/'bin/git';git.write_text('#!/usr/bin/env python3\nimport sys\nassert sys.argv[1:]==["-C","source","rev-parse","HEAD"]\nprint("expected")\n');git.chmod(0o755)
            result=subprocess.run(['bash','-c',script],cwd=root,env=dict(os.environ,
                PATH=str(root/'bin')+os.pathsep+os.environ['PATH'],RELEASE_COMMIT='expected',RELEASE_TAG='v0.7.0',RUNNER_TEMP=d),capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertTrue((root/'reviewed-executed').exists())

    def test_go_output_uses_utf8_even_with_windows_default_encoding(self):
        real_output=subprocess.check_output
        def windows_default(*args,**kwargs):
            kwargs.setdefault('encoding','cp1252')
            return real_output(*args,**kwargs)
        command=[sys.executable,'-c',"import sys; sys.stdout.buffer.write(bytes([0xe2,0x80,0x9d]))"]
        with patch.object(builder.subprocess,'check_output',side_effect=windows_default):
            self.assertEqual(builder.run(command,dict(os.environ)), '\u201d')

    def test_changed_scanner_version_is_refused(self):
        with self.assertRaisesRegex(ValueError,'scanner version'):
            assess(CONFIG.replace('v1.8.0','v1.9.0'),{})

    def test_source_identity_mismatch_refused(self):
        expected={'module':'example/tool','version':'v1.0.0','sum':'h1:expected','goModSum':'h1:mod','commit':'a'*40}
        actual={'Path':'example/tool','Version':'v1.0.0','Sum':'h1:other','GoModSum':'h1:mod','Origin':{'Hash':'a'*40}}
        with self.assertRaisesRegex(ValueError,'source identity'):
            builder.check_source(actual,expected)

if __name__=='__main__': unittest.main()
