#!/usr/bin/env python3
"""Installed-binary demo of the opt-in subject checks. Python 3.9+, synthetic loopback receiver only."""
import argparse
import hashlib
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
REQUIRE_DIGEST = "gate:\n  subject:\n    require: [digest]\n"
# Synthetic shipped files of Cart API 1.4.0. The digests are illustrative: Rio never hashes these files.
DISTRIBUTIONS = [
    {"name": "cart-api-1.4.0-linux-amd64.tar.gz", "sha256": "d1" * 32,
     "url": "https://downloads.example.com/cart-api/1.4.0/cart-api-1.4.0-linux-amd64.tar.gz"},
    {"name": "cart-api-1.4.0.jar", "sha256": "d2" * 32},
]
PROFILE = "gate:\n  profile: bsi-tr-03183-2@2.1.0\n"
PROFILE_REPAIR = (PROFILE + "enrichment:\n  producer:\n    name: Example Components GmbH\n    contact:\n      - email: sbom@example.org\n"
                  "  subject:\n    manufacturer:\n      name: Example Components GmbH\n      url: [https://example.org]\n")
SCENARIOS = [
    # name, extra manifest, security-contact already in the SBOM, distributions in a build context file, expected exit
    ("not-required", "", None, None, 0),
    ("required-missing", REQUIRE, None, None, 1),
    ("required-supplied", REQUIRE + "enrichment:\n  subject:\n    securityContact: mailto:security@example.com\n", None, None, 0),
    ("required-unsupported", REQUIRE, "security@example.com", None, 1),
    ("digest-missing", REQUIRE_DIGEST, None, None, 1),
    ("digest-supplied", REQUIRE_DIGEST, None, DISTRIBUTIONS, 0),
    # The TR-03183-2 profile: a generator's SBOM lacks the creators and the shipped files; the repair supplies them.
    ("bsi-profile-missing", PROFILE, None, None, 1),
    ("bsi-profile-repaired", PROFILE_REPAIR, None, "tr", 0),
]


def tr_distributions():
    """Two synthetic shipped files with declared digests. Rio never hashes or opens them."""
    files = []
    for name, payload, executable, archive in (
            ("cart-api-1.4.0-linux-amd64.tar.gz", b"synthetic archive of cart-api 1.4.0", False, True),
            ("cart-api-1.4.0.jar", b"synthetic jar of cart-api 1.4.0", False, True)):
        files.append({"name": name, "sha256": hashlib.sha256(payload).hexdigest(), "sha512": hashlib.sha512(payload).hexdigest(),
                      "executable": executable, "archive": archive, "structured": True})
    return files


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
        for name, extra, contact, distributions, expected in SCENARIOS:
            work = retained / name
            work.mkdir()
            profile = name.startswith("bsi-")
            sbom = json.loads((HERE / ("fixtures/cart-api-tr.cdx.json" if profile else "fixtures/cart-api.cdx.json")).read_text())
            if contact:
                sbom["metadata"]["component"]["externalReferences"] = [{"type": "security-contact", "url": contact}]
            (work / "cart-api.cdx.json").write_text(json.dumps(sbom, indent=2))
            binding = ""
            if distributions:
                tr = distributions == "tr"
                if tr:
                    distributions = tr_distributions()
                # The context entry binds the SBOM bytes as written, whatever line endings the platform used.
                digest = hashlib.sha256((work / "cart-api.cdx.json").read_bytes()).hexdigest()
                context = {"contextVersion": 1, "artifacts": [
                    {"id": "cart-api", "sbom": {"sha256": digest}, "distributions": distributions}]}
                if tr:
                    context["artifacts"][0]["level"] = "logical"
                (work / "build-context.json").write_text(json.dumps(context, indent=2))
                binding = "    context:\n      file: build-context.json\n"
            (work / "rio.yaml").write_text(
                "version: 1\nartifacts:\n  - id: cart-api\n    sbom: cart-api.cdx.json\n" + binding +
                "delivery:\n  targets:\n    security:\n      type: dependency-track\n"
                "      url: http://127.0.0.1:%d\n      allowHTTP: true\n      apiKeyEnv: RIO_DEMO_KEY\n" % server.server_port + extra)
            before = len(uploads)
            result = subprocess.run([binary, "--receipt", str(work / "record.json")], cwd=work, env=env,
                                    capture_output=True, text=True)
            assert result.returncode == expected, (name, result.returncode, result.stdout, result.stderr)
            artifact = json.loads((work / "record.json").read_text())["artifacts"][0]
            checks = artifact["checks"]
            delivered = len(uploads) - before
            if profile:
                print("==", name, "-> exit", result.returncode, "-", "delivered" if delivered else "not delivered")
                print("   checks.gate:", checks["gate"])
                if "failed" in checks:
                    print("   checks.failed:", [f["requirement"] for f in checks["failed"]])
                if "profile" in checks:
                    print("   checks.profile:", json.dumps(checks["profile"], sort_keys=True))
                    print("   checks.profileLevels:", json.dumps(checks["profileLevels"], sort_keys=True))
                for line in result.stderr.splitlines():
                    print("   " + line.replace("\u00a7", "sec."))  # ASCII only, as below
                if expected:
                    assert delivered == 0 and checks["gate"] == "fail", name
                    failed = [f["requirement"] for f in checks["failed"]]
                    for want in ("sbom.creator", "subject.creator", "subject.deployableHash"):
                        assert want in failed, (want, failed)
                        assert "  " + want + " (BSI TR-03183-2 2.1.0" in result.stderr, (want, result.stderr)
                else:
                    assert delivered == 1 and checks["gate"] == "pass" and "failed" not in checks, (name, result.stderr)
                    assert checks["profile"]["name"] == "bsi-tr-03183-2@2.1.0", checks
                    assert checks["profileLevels"] == {"assembled": 2, "full": 2, "identified": 0, "logical": 1, "referenced": 0}, checks
                    output = json.loads(next((work / "target/rio/runs").glob("*/cart-api.cdx.json")).read_text())
                    nested = output["metadata"]["component"]["components"]
                    assert [c["name"] for c in nested] == [d["name"] for d in distributions], nested
                continue

            # ASCII only: Windows consoles and redirected Python 3.9 output may use CP1252.
            print("==", name, "-> exit", result.returncode, "-", "delivered" if delivered else "not delivered")
            print("   checks.subjectRequirements:", checks["subjectRequirements"])
            if "failed" in checks:
                print("   checks.failed:", checks["failed"])
            for item in artifact.get("distributions", []):
                print("   receipt distribution: %s sha256=%s assertion=%s" % (item["name"], item["sha256"], item["assertion"]))
            for line in result.stderr.splitlines():
                print("   " + line)

            requirement = "digest" if extra == REQUIRE_DIGEST else "securityContact"
            assert checks["subjectRequirements"] == ["name", "version"] + ([requirement] if extra else []), name
            if expected == 0:
                assert delivered == 1 and checks["gate"] == "pass" and "failed" not in checks, name
                assert "failed the gate" not in result.stderr, name
            else:
                assert delivered == 0 and checks["gate"] == "fail", name
                assert checks["failed"] == [{"requirement": "subject." + requirement, "count": 1}], name
                assert "gate mode fail, so nothing was delivered." in result.stderr, name
            if expected and requirement == "securityContact":
                assert "enrichment.subject.securityContact" in result.stderr, name
            if name == "required-supplied":
                output = json.loads(next((work / "target/rio/runs").glob("*/cart-api.cdx.json")).read_text())
                refs = output["metadata"]["component"]["externalReferences"]
                assert {"type": "security-contact", "url": "mailto:security@example.com"} in refs, refs
            if name == "required-unsupported":
                assert '"security@example.com" is not an absolute http(s) URL or a mailto address' in result.stderr
            if name == "required-missing":
                assert "Rio does not look it up." in result.stderr
            if name == "digest-missing":
                assert ("subject.digest: the SBOM subject has no distribution digest. Add the shipped files under "
                        "distributions in the build context file. Rio does not hash them.") in result.stderr, result.stderr
                assert "distributions" not in artifact, name
            if name == "digest-supplied":
                output = json.loads(next((work / "target/rio/runs").glob("*/cart-api.cdx.json")).read_text())
                refs = [r for r in output["metadata"]["component"]["externalReferences"] if r["type"] == "distribution"]
                assert refs == [{"type": "distribution", "url": d.get("url", d["name"]),
                                 "hashes": [{"alg": "SHA-256", "content": d["sha256"]}]} for d in DISTRIBUTIONS], refs
                for ref in refs:
                    print("   SBOM distribution reference: %s SHA-256 %s" % (ref["url"], ref["hashes"][0]["content"]))
                assert artifact["distributions"] == [
                    {"name": d["name"], "sha256": d["sha256"], "assertion": "producer"} for d in DISTRIBUTIONS], artifact
        print("PASS: a contact is checked only when required; a missing or unsupported one blocks delivery with the next step;")
        print("PASS: a reviewed contact supplied through enrichment passes. A pass shows the value is present and well formed, nothing more.")
        print("PASS: a required digest blocks delivery until the build context file declares the shipped files;")
        print("PASS: the declared digests reach the SBOM subject and the receipt as producer assertions. Rio hashes no shipped file.")
        print("PASS: the BSI TR-03183-2 profile blocks a generator's SBOM and names the creators and shipped-file fields to supply;")
        print("PASS: enrichment, a declared logical subject and two declared shipped files pass it. The profile checks presence and form only.")
        print("Retained runs:", retained)
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
