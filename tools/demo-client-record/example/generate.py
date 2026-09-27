#!/usr/bin/env python3
"""Generate the small delivery-first documentation example with an installed Rio."""
import argparse
from email import policy
from email.parser import BytesParser
import hashlib
import http.server
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import tempfile
import threading


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("output", type=Path, help="new directory for record.json and report.html")
    args = parser.parse_args()
    binary = str(Path(shutil.which(args.binary) or args.binary).resolve())
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    tls_files = Path(__file__).resolve().parents[2] / "demo-dtrack-tls"
    secret = "synthetic-delivery-" + secrets.token_hex(16)
    received = []
    tokens = ["11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"]

    class Receiver(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            assert self.path == "/api/v1/bom"
            assert self.headers.get("X-Api-Key") == secret
            body = bytearray()
            if self.headers.get("Transfer-Encoding") == "chunked":
                while True:
                    size = int(self.rfile.readline().strip().split(b";")[0], 16)
                    if not size:
                        self.rfile.readline()
                        break
                    body.extend(self.rfile.read(size))
                    assert self.rfile.read(2) == b"\r\n"
            else:
                body.extend(self.rfile.read(int(self.headers["Content-Length"])))
            multipart = BytesParser(policy=policy.default).parsebytes(
                ("Content-Type: " + self.headers["Content-Type"] + "\r\nMIME-Version: 1.0\r\n\r\n").encode()
                + body)
            assert multipart.is_multipart()
            fields = {part.get_param("name", header="Content-Disposition"): part.get_payload(decode=True)
                      for part in multipart.iter_parts()}
            expected_project = ("api", "worker")[len(received)]
            assert fields["projectName"].decode() == expected_project
            assert fields["projectVersion"].decode() == "1.0.0"
            subject = json.loads(fields["bom"])["metadata"]["component"]
            assert subject["name"] == expected_project and subject["version"] == "1.0.0"
            token = tokens[len(received)]
            received.append(bytes(body))
            response = json.dumps({"token": token}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(str(tls_files / "SYNTHETIC-ONLY-cert.pem"), str(tls_files / "SYNTHETIC-ONLY-key.pem"))
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    env = dict(os.environ, RIO_DEMO_DELIVERY_KEY=secret)
    url = "https://127.0.0.1:" + str(server.server_port)

    def run(cwd, *command):
        result = subprocess.run([binary, *map(str, command)], cwd=cwd, env=env, capture_output=True, text=True, timeout=60)
        assert secret not in result.stdout + result.stderr
        assert result.returncode == 0, (command, result.returncode, result.stdout, result.stderr)

    def write(path, value):
        path.write_text(json.dumps(value, indent=2) + "\n")

    try:
        with tempfile.TemporaryDirectory(prefix="rio-delivery-example-") as directory:
            work = Path(directory)
            shutil.copyfile(tls_files / "SYNTHETIC-ONLY-cert.pem", work / "demo-ca.pem")
            artifacts, context = [], []
            for name in ("api", "worker"):
                path = work / (name + ".cdx.json")
                write(path, {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                            "metadata": {"component": {"type": "application", "name": name, "version": "1.0.0"}},
                            "components": [{"type": "library", "name": "commons-lang3", "version": "3.17.0",
                                            "purl": "pkg:maven/org.apache.commons/commons-lang3@3.17.0"}]})
                artifacts.append({"id": name, "sbom": path.name,
                                  "context": {"file": "pipeline.json", "require": ["build.url", "build.id"]}})
                context.append({"id": name, "sbom": {"sha256": hashlib.sha256(path.read_bytes()).hexdigest()},
                                "build": {"url": "https://ci.example.org/runs/42", "id": "42"}})
            write(work / "pipeline.json", {"contextVersion": 1, "artifacts": context})
            write(work / "rio.yaml", {"version": 1, "artifacts": artifacts, "delivery": {"targets": {
                "security": {"type": "dependency-track", "url": url, "apiKeyEnv": "RIO_DEMO_DELIVERY_KEY",
                             "caFile": "demo-ca.pem"}}}})
            run(work, "normalize", "--gate", "fail")
            run(work, "deliver", "--evidence", "record.json")
            assert len(received) == 2
            raw = (work / "record.json").read_bytes()
            record = json.loads(raw)
            assert len(record["deliveries"]) == 2
            for artifact in record["normalization"]["index"]["artifacts"]:
                payload = (work / "target/rio" / artifact["output"]["path"]).read_bytes()
                assert any(payload in body for body in received), "submitted SBOM differs from normalized bytes"
                normalized = json.loads(payload)
                assert {"type": "build-system", "url": "https://ci.example.org/runs/42"} in normalized["metadata"]["component"]["externalReferences"]
                assert artifact["context"]["effective"]["build"] == {"url": "https://ci.example.org/runs/42", "id": "42"}
                embedded = next(p["value"] for p in normalized["metadata"]["properties"] if p["name"] == "rebaze:normalize:context")
                assert json.loads(embedded)["effective"]["build"] == artifact["context"]["effective"]["build"]
                assert not artifact["transforms"], "simple example must not repair coordinates"
            for attempt in record["deliveries"]:
                observation = attempt["summary"]["lastObservation"]["observation"]
                assert observation["httpStatus"] == 200 and observation["value"] == "accepted"
                assert observation["details"]["tls"] == {"certificateVerification": "enforced", "observed": True}
                assert attempt["intent"]["destination"]["identity"]["url"] == url
                assert attempt["intent"]["destination"]["identity"]["project"] == {
                    "name": attempt["artifactId"], "version": "1.0.0"}
            (output / "record.json").write_bytes(raw)
        # The source workspace is gone and the receiver is stopped before inspection.
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    env.pop("RIO_DEMO_DELIVERY_KEY")
    run(output, "record", "inspect", "--file", "record.json")
    run(output, "record", "inspect", "--file", Path(__file__).with_name("record.json").resolve())
    run(output, "record", "report", "--file", "record.json", "--output", "report.html")
    for path in (output / "record.json", output / "report.html"):
        assert secret.encode() not in path.read_bytes()
    print("PASS: two SBOMs, pipeline URL/ID, verified HTTPS, HTTP 200 and receipts; offline JSON/HTML after teardown")
    print("Example:", output)


if __name__ == "__main__":
    main()
