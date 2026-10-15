#!/usr/bin/env python3
"""Installed-binary demo of the opt-in security-contact check. Python 3.9+, synthetic loopback receiver only."""
import argparse
import http.server
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading

HERE = Path(__file__).resolve().parent
TOKEN = "f90934f5-cb88-47ce-81cb-db06fc67d4b4"
REQUIRE = "gate:\n  subject:\n    require: [securityContact]\n"
SCENARIOS = [
    # name, extra manifest, security-contact already in the SBOM, expected exit
    ("not-required", "", None, 0),
    ("required-missing", REQUIRE, None, 1),
    ("required-supplied", REQUIRE + "enrichment:\n  subject:\n    securityContact: mailto:security@example.com\n", None, 0),
    ("required-unsupported", REQUIRE, "security@example.com", 1),
]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    args = parser.parse_args()
    binary = str(Path(shutil.which(args.binary) or args.binary).resolve())
    retained = Path(tempfile.mkdtemp(prefix="rio-handoff-demo-"))
    uploads = []

    class Receiver(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            if self.headers.get("Transfer-Encoding") == "chunked":
                while True:
                    size = int(self.rfile.readline().strip().split(b";")[0], 16)
                    if not size:
                        self.rfile.readline()
                        break
                    self.rfile.read(size + 2)
            else:
                self.rfile.read(int(self.headers["Content-Length"]))
            uploads.append(self.path)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"token": TOKEN}).encode())

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    env = dict(os.environ, RIO_DEMO_KEY="synthetic-demo-key")
    try:
        for name, extra, contact, expected in SCENARIOS:
            work = retained / name
            work.mkdir()
            sbom = json.loads((HERE / "fixtures/cart-api.cdx.json").read_text())
            if contact:
                sbom["metadata"]["component"]["externalReferences"] = [{"type": "security-contact", "url": contact}]
            (work / "cart-api.cdx.json").write_text(json.dumps(sbom, indent=2))
            (work / "rio.yaml").write_text(
                "version: 1\nartifacts:\n  - id: cart-api\n    sbom: cart-api.cdx.json\n"
                "delivery:\n  targets:\n    security:\n      type: dependency-track\n"
                "      url: http://127.0.0.1:%d\n      allowHTTP: true\n      apiKeyEnv: RIO_DEMO_KEY\n" % server.server_port + extra)
            before = len(uploads)
            result = subprocess.run([binary, "--receipt", str(work / "record.json")], cwd=work, env=env,
                                    capture_output=True, text=True)
            assert result.returncode == expected, (name, result.returncode, result.stdout, result.stderr)
            checks = json.loads((work / "record.json").read_text())["artifacts"][0]["checks"]
            delivered = len(uploads) - before

            print("==", name, "→ exit", result.returncode, "·", "delivered" if delivered else "not delivered")
            print("   checks.subjectRequirements:", checks["subjectRequirements"])
            if "failed" in checks:
                print("   checks.failed:", checks["failed"])
            for line in result.stderr.splitlines():
                print("   " + line)

            required = "securityContact" in checks["subjectRequirements"]
            assert required == bool(extra), name
            if expected == 0:
                assert delivered == 1 and checks["gate"] == "pass" and "failed" not in checks, name
                assert "failed the gate" not in result.stderr, name
            else:
                assert delivered == 0 and checks["gate"] == "fail", name
                assert checks["failed"] == [{"requirement": "subject.securityContact", "count": 1}], name
                assert "gate mode fail, so nothing was delivered." in result.stderr, name
                assert "enrichment.subject.securityContact" in result.stderr, name
            if name == "required-supplied":
                output = json.loads(next((work / "target/rio/runs").glob("*/cart-api.cdx.json")).read_text())
                refs = output["metadata"]["component"]["externalReferences"]
                assert {"type": "security-contact", "url": "mailto:security@example.com"} in refs, refs
            if name == "required-unsupported":
                assert '"security@example.com" is not an absolute http(s) URL or a mailto address' in result.stderr
            if name == "required-missing":
                assert "Rio does not look it up." in result.stderr
        print("PASS: a contact is checked only when required; a missing or unsupported one blocks delivery with the next step;")
        print("PASS: a reviewed contact supplied through enrichment passes. A pass shows the value is present and well formed, nothing more.")
        print("Retained runs:", retained)
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
