#!/usr/bin/env python3
"""Build and audit pinned upstream release tools with reviewed dependency locks.

The sources are authenticated by Go module sums; no upstream source is patched.
The retained binaries include symbols so scans need not infer symbols from modules.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
REVIEWED_FILES = ('.goreleaser.yaml', '.github/workflows/ci.yaml',
                  '.github/workflows/release.yaml', '.github/workflows/verify-release.yaml',
                  'tools/rio-attest-sign.sh', 'tools/rio-attest-verify.sh',
                  'tools/release-publish.py', 'tools/verify-release.py',
                  'tools/demo-attest-sign/run.py', 'tools/security/go.mod', 'tools/security/go.sum')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_scope(root, manifest):
    if not set(REVIEWED_FILES).issubset(manifest['reviewedFiles']):
        raise ValueError('reviewed scope inventory is incomplete')
    for name, expected in manifest['reviewedFiles'].items():
        if digest(root/name) != expected:
            raise ValueError('reviewed scope differs: '+name+'; reassess the scoped tool findings')


def check_source(actual, expected):
    checks = {'Path':'module', 'Version':'version', 'Sum':'sum', 'GoModSum':'goModSum'}
    if any(actual.get(a) != expected[e] for a,e in checks.items()) or actual.get('Origin',{}).get('Hash') != expected['commit']:
        raise ValueError('upstream source identity differs from reviewed manifest')


def events(data):
    decoder=json.JSONDecoder()
    while data.strip():
        value, end=decoder.raw_decode(data.lstrip())
        if not isinstance(value,dict):
            raise ValueError('invalid scanner event')
        yield value
        data=data.lstrip()[end:]


def assess(data, approved, scanner_version):
    findings=[]
    configured=False
    sbom=False
    for event in events(data):
        cfg=event.get('config',{})
        if cfg:
            if cfg.get('scanner_name') != 'govulncheck' or cfg.get('scan_mode') != 'binary' or cfg.get('scan_level') != 'symbol':
                raise ValueError('unexpected scanner configuration')
            if cfg.get('scanner_version') != scanner_version:
                raise ValueError('unexpected scanner version')
            configured=True
        if isinstance(event.get('SBOM'),dict):
            sbom=True
        if 'finding' not in event:
            continue
        f=event['finding']; frames=f.get('trace',[])
        if not frames or not isinstance(frames[0],dict):
            raise ValueError('invalid scanner finding')
        frame=frames[0]; rule=approved.get(f.get('osv'),{})
        if not rule or frame.get('module') != rule.get('module') or frame.get('version') != rule.get('version'):
            raise ValueError('unreviewed advisory/module/version: '+str(f.get('osv')))
        precision='symbol' if frame.get('function') else ('package' if frame.get('package') else 'module')
        if '*' in frame.get('function',''):
            raise ValueError('stripped-binary fallback is not accepted')
        if rule.get('moduleOnly') and precision != 'module':
            raise ValueError('unreviewed package/symbol reachability: '+f['osv'])
        package=frame.get('package','')
        prefix=rule.get('packagePrefix',package)
        if package and package != prefix and not package.startswith(prefix+'/'):
            raise ValueError('unreviewed affected package: '+f['osv'])
        findings.append(dict(f,precision=precision,disposition='outside reviewed invocation scope'))
    if not configured or not sbom:
        raise ValueError('missing scanner configuration/SBOM')
    return findings


def environment(compiler):
    # Build/scanner subprocesses need no application, GitHub or cloud secrets.
    keep={'PATH','HOME','TMPDIR','TEMP','TMP','SYSTEMROOT','SystemRoot','WINDIR',
          'USERPROFILE','HOMEDRIVE','HOMEPATH','GOCACHE','GOMODCACHE','LOCALAPPDATA'}
    env={k:v for k,v in os.environ.items() if k in keep}
    env.update(GOTOOLCHAIN=compiler, GOENV='off', GOWORK='off', CGO_ENABLED='0',
               GOPROXY='https://proxy.golang.org', GOSUMDB='sum.golang.org',
               GOPRIVATE='', GONOSUMDB='', GONOPROXY='', GOFLAGS='-mod=readonly',
               GOMAXPROCS='2')
    return env


def run(args, env, cwd=None):
    return subprocess.check_output([str(a) for a in args],env=env,cwd=cwd,text=True,encoding='utf-8')


def build(output, names):
    manifest_bytes=(HERE/'manifest.json').read_bytes()
    manifest=json.loads(manifest_bytes)
    check_scope(ROOT,manifest)
    env=environment(manifest['compiler'])
    if run(['go','env','GOVERSION'],env).strip() != manifest['compiler']:
        raise ValueError('compiler identity differs')
    host=run(['go','env','GOHOSTOS','GOHOSTARCH'],env).splitlines()
    env.update(GOOS=host[0],GOARCH=host[1])
    scanner=manifest['scanner']
    run(['go','-C',ROOT/'tools/security','mod','verify'],env)
    scanner_module=json.loads(run(['go','-C',ROOT/'tools/security','list','-m','-json',scanner['module']],env))
    if scanner_module.get('Version') != scanner['version']:
        raise ValueError('scanner module version differs')
    output.mkdir(mode=0o700,parents=True,exist_ok=False)
    results=[]
    for name in names:
        cfg=manifest['tools'][name]
        for file in ('go.mod','go.sum'):
            if digest(HERE/name/file) != cfg['locks'][file]:
                raise ValueError('dependency lock differs: '+name+'/'+file)
        with tempfile.TemporaryDirectory(prefix='rio-tool-build-') as tmp:
            work=Path(tmp)
            source=json.loads(run(['go','mod','download','-json',cfg['module']+'@'+cfg['version']],env,work))
            check_source(source,cfg)
            for file in ('go.mod','go.sum'):
                shutil.copyfile(HERE/name/file,work/file)
            run(['go','mod','download'],env,work)
            run(['go','mod','verify'],env,work)
            binary=output/(name+('.exe' if host[0]=='windows' else ''))
            args=['go','build','-trimpath','-buildvcs=false','-ldflags',' '.join(cfg['ldflags']),'-o',binary]
            if cfg.get('tags'):
                args.extend(['-tags',','.join(cfg['tags'])])
            run(args+[cfg['package']],env,work)
            for file in ('go.mod','go.sum'):
                if digest(work/file) != cfg['locks'][file]:
                    raise ValueError('build changed dependency lock')
        info=run(['go','version','-m','-json',binary],env)
        identity=json.loads(info)
        if (identity.get('GoVersion') != manifest['compiler'] or
                identity.get('Main',{}).get('Path') != cfg['module'] or
                identity.get('Main',{}).get('Version') != cfg['version'] or
                identity.get('Main',{}).get('Sum') != cfg['sum']):
            raise ValueError('built tool identity differs')
        scan=run(['go','-C',ROOT/'tools/security','tool','govulncheck','-mode=binary','-format=json',binary],env)
        (output/(name+'.govulncheck.json')).write_text(scan,encoding='utf-8')
        findings=assess(scan,cfg['reviewedFindings'],scanner['version'])
        (output/(name+'.build.json')).write_text(info,encoding='utf-8')
        results.append({'tool':name,'version':cfg['version'],'upstreamCommit':cfg['commit'],
                        'sourceSum':cfg['sum'],'locks':cfg['locks'],'compiler':manifest['compiler'],
                        'platform':'/'.join(host),'binarySHA256':digest(binary),'findings':findings})
        print('BUILT AND AUDITED: '+name+'; '+str(len({f['osv'] for f in findings}))+' explicitly scoped advisory IDs',flush=True)
    check_scope(ROOT,manifest)
    if (HERE/'manifest.json').read_bytes() != manifest_bytes:
        raise ValueError('toolchain manifest changed during build')
    (output/'inventory.json').write_text(json.dumps({'manifestSHA256':hashlib.sha256(manifest_bytes).hexdigest(),
        'scanner':dict(scanner, locks={name:manifest['reviewedFiles']['tools/security/'+name] for name in ('go.mod','go.sum')}),
        'tools':results,'scope':'Only the reviewed Rio release invocations; not general-purpose tool security clearance.'},indent=2)+'\n',encoding='utf-8')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--tool',action='append',choices=['cosign','syft','goreleaser'])
    args=parser.parse_args()
    build(args.output.resolve(),list(dict.fromkeys(args.tool or ['cosign','syft','goreleaser'])))


if __name__=='__main__': main()
