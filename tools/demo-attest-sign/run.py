#!/usr/bin/env python3
"""Sign synthetic SBOM statements with installed Rio and real cosign v3.0.6."""
import argparse
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", default=os.environ.get("RIO_BIN", "rio"))
    args = parser.parse_args()
    binary = str(Path(shutil.which(args.binary) or args.binary).resolve())
    fixture = Path(__file__).resolve().parent
    helper = fixture.parent / "rio-attest-sign.sh"
    verifier = fixture.parent / "rio-attest-verify.sh"
    root = Path(tempfile.mkdtemp(prefix="rio-attest-sign-demo-"))
    root.chmod(0o700)
    print("Synthetic example directory:", root, flush=True)
    env = dict(os.environ, COSIGN_PASSWORD="")

    def run(*command, expected=0):
        result = subprocess.run(command, cwd=root, env=env, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True)
        if result.returncode != expected:
            raise RuntimeError("%s: expected exit %s, got %s\n%s\n%s" %
                               (command[0], expected, result.returncode,
                                result.stdout, result.stderr))
        return result.stdout

    version = json.loads(run("cosign", "version", "--json"))
    if version["gitVersion"] != "v3.0.6":
        raise RuntimeError("cosign v3.0.6 is required")
    for name in ("rio.yaml", "app.cdx.json", "worker.cdx.json"):
        shutil.copyfile(fixture / name, root / name)
    originals = {name: (root / name).read_bytes() for name in ("app.cdx.json", "worker.cdx.json")}
    key = root / "SYNTHETIC-ONLY.key"
    public = root / "SYNTHETIC-ONLY.pub"
    try:
        run("cosign", "generate-key-pair", "--output-key-prefix", str(root / "SYNTHETIC-ONLY"))
        result = json.loads(run(binary, "normalize", "--attest", "--json"))
        directory = Path(result["runDirectory"])
        unchanged = {path: path.read_bytes() for path in directory.iterdir() if path.is_file()}
        print(run("bash", str(helper), "--key", str(key), "--public-key", str(public),
                  str(directory)), end="")
        verify = ("bash", str(verifier), "--public-key", str(public))
        for artifact in ("app", "worker"):
            blob = directory / (artifact + ".cdx.json")
            bundle = directory / (artifact + ".sigstore.json")
            run(*verify, "--bundle", str(bundle), str(blob))
            envelope = json.loads(bundle.read_text())["dsseEnvelope"]
            assert json.loads(base64.b64decode(envelope["payload"])) == json.loads(
                (directory / (artifact + ".intoto.json")).read_text())
            assert bundle.stat().st_mode & 0o077 == 0
        assert all(path.read_bytes() == content for path, content in unchanged.items())
        assert all((root / name).read_bytes() == content for name, content in originals.items())
        snapshots = {path: path.read_bytes() for path in directory.glob("*.sigstore.json")}
        run("bash", str(helper), "--key", str(key), "--public-key", str(public),
            str(directory), expected=2)
        assert all(path.read_bytes() == content for path, content in snapshots.items())

        altered = root / "altered.cdx.json"
        altered.write_bytes((directory / "app.cdx.json").read_bytes() + b"\n")
        run(*verify, "--bundle", str(directory / "app.sigstore.json"), str(altered), expected=1)
        altered.unlink()
        changed = json.loads((directory / "app.sigstore.json").read_text())
        payload = json.loads(base64.b64decode(changed["dsseEnvelope"]["payload"]))
        payload["predicate"]["tool"]["version"] = "tampered"
        changed["dsseEnvelope"]["payload"] = base64.b64encode(json.dumps(payload).encode()).decode()
        altered_bundle = root / "altered.sigstore.json"
        altered_bundle.write_text(json.dumps(changed))
        run(*verify, "--bundle", str(altered_bundle), str(directory / "app.cdx.json"), expected=1)
        altered_bundle.unlink()
        # An embedded legacy-bundle key must never replace the recipient's key.
        wrong = root / "wrong.pub"
        run("cosign", "generate-key-pair", "--output-key-prefix", str(root / "wrong"))
        (root / "wrong.key").unlink()
        legacy = root / "legacy.sigstore.json"
        signed = json.loads((directory / "app.sigstore.json").read_text())
        legacy.write_text(json.dumps({
            "base64Signature": base64.b64encode(json.dumps(signed["dsseEnvelope"]).encode()).decode(),
            "cert": base64.b64encode(public.read_bytes()).decode(),
        }))
        wrong_verify = ("bash", str(verifier), "--public-key", str(wrong))
        run(*wrong_verify, "--bundle", str(directory / "app.sigstore.json"),
            str(directory / "app.cdx.json"), expected=1)
        run(*wrong_verify, "--bundle", str(legacy), str(directory / "app.cdx.json"), expected=2)
        legacy_data = json.loads(legacy.read_text())
        legacy_data.update(signed)
        legacy.write_text(json.dumps(legacy_data))
        run(*wrong_verify, "--bundle", str(legacy), str(directory / "app.cdx.json"), expected=2)
        legacy.unlink()
        wrong.unlink()
        print("PASS: recipient verification, unchanged inputs, overwrite refusal, altered SBOM/statement refusal.")
        print("PASS: wrong trusted key, legacy bundle and mixed-format bundle refused.")
    finally:
        if key.exists():
            key.unlink()
        if (root / "wrong.key").exists():
            (root / "wrong.key").unlink()
        print("Synthetic private key deleted. Retained public key and evidence:", root, flush=True)


if __name__ == "__main__":
    main()
