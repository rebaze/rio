#!/usr/bin/env python3
"""Generate a synthetic one-invocation receipt with an installed Rio (Python 3.9+)."""
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
import socket
import ssl
import subprocess
import tempfile
import threading
import zipfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", default="rio")
    parser.add_argument("output", type=Path, help="new directory for runnable examples and generated receipt/report")
    parser.add_argument("--partial", action="store_true", help="lose the second response after receiving its bytes")
    args = parser.parse_args()
    binary = str(Path(shutil.which(args.binary) or args.binary).resolve())
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    here = Path(__file__).resolve().parent
    tls_files = here if (here / "SYNTHETIC-ONLY-cert.pem").exists() else here.parents[1] / "demo-dtrack-tls"
    secret = "synthetic-delivery-" + secrets.token_hex(16)
    received = {}
    errors = []
    tokens = ["11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"]

    class Receiver(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            try:
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
                    ("Content-Type: " + self.headers["Content-Type"] + "\r\nMIME-Version: 1.0\r\n\r\n").encode() + body)
                assert multipart.is_multipart()
                parts = {part.get_param("name", header="Content-Disposition"): part for part in multipart.iter_parts()}
                fields = {name: part.get_payload(decode=True) for name, part in parts.items()}
                name = ("api", "worker")[len(received)]
                assert fields["projectName"].decode() == name
                assert fields["projectVersion"].decode() == "1.0.0"
                assert fields["autoCreate"] == b"false"
                assert parts["bom"].get_content_type() == "application/vnd.cyclonedx+json"
                subject = json.loads(fields["bom"])["metadata"]["component"]
                assert subject["name"] == name and subject["version"] == "1.0.0"
                received[name] = fields["bom"]
                if args.partial and name == "worker":
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                response = json.dumps({"token": tokens[len(received) - 1]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)
            except Exception as exc:
                errors.append(type(exc).__name__)
                self.close_connection = True

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(str(tls_files / "SYNTHETIC-ONLY-cert.pem"), str(tls_files / "SYNTHETIC-ONLY-key.pem"))
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    env = dict(os.environ, RIO_DEMO_DELIVERY_KEY=secret)
    url = "https://127.0.0.1:" + str(server.server_port)

    def run(cwd, *command, expected=0):
        result = subprocess.run([binary, *map(str, command)], cwd=cwd, env=env, capture_output=True, text=True, timeout=90)
        assert secret not in result.stdout + result.stderr
        assert result.returncode == expected, (command, result.returncode, result.stdout, result.stderr)
        return result.stdout

    def write(path, value):
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")

    try:
        with tempfile.TemporaryDirectory(prefix="rio-one-command-") as directory:
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
                "security": {"type": "dependency-track", "url": url, "apiKeyEnv": "RIO_DEMO_DELIVERY_KEY", "caFile": "demo-ca.pem"}}}})
            # One execution owns both local stages and delivery. --json changes only stdout.
            execution = json.loads(run(work, "--json", expected=4 if args.partial else 0))
            assert not errors, errors
            assert len(received) == 2
            raw = Path(execution["receipt"]["path"]).read_bytes()
            record = json.loads(raw)
            assert record["kind"] == "rio-run-receipt" and record["schemaVersion"] == 1
            assert record["run"]["operation"] == "pipeline"
            assert record["run"]["outcome"] == ("partial" if args.partial else "success")
            assert len(raw) <= 8192, len(raw)
            assert len(record["artifacts"]) == len(record["deliveries"]) == 2
            assert record["targets"]["security"]["url"] == url
            (output / "normalized").mkdir()
            for artifact in record["artifacts"]:
                name = artifact["id"]
                source = (work / artifact["input"]["path"]).read_bytes()
                payload = (Path(execution["runDirectory"]) / artifact["output"]["path"]).read_bytes()
                assert artifact["input"]["sha256"] == hashlib.sha256(source).hexdigest()
                assert artifact["input"]["size"] == len(source)
                assert payload == received[name], "submitted SBOM differs from normalized bytes"
                assert artifact["output"]["sha256"] == hashlib.sha256(payload).hexdigest()
                assert artifact["output"]["size"] == len(payload)
                normalized = json.loads(payload)
                assert {"type": "build-system", "url": "https://ci.example.org/runs/42"} in normalized["metadata"]["component"]["externalReferences"]
                changes = {c["field"]: c for c in artifact["changes"]["metadata"]}
                assert set(changes) == {"build.url", "build.id"}
                for field, value in {"build.url": "https://ci.example.org/runs/42", "build.id": "42"}.items():
                    assert changes[field]["before"] is None and changes[field]["after"] == value
                    assert changes[field]["source"] == "context-file" and changes[field]["assertion"] == "producer"
                embedded = next(p["value"] for p in normalized["metadata"]["properties"] if p["name"] == "rebaze:normalize:context")
                assert json.loads(embedded)["effective"]["build"] == {"url": "https://ci.example.org/runs/42", "id": "42"}
                assert not artifact["changes"].get("bulk"), "introductory example must not repair coordinates"
                (output / "normalized" / (name + ".cdx.json")).write_bytes(payload)
            for i, attempt in enumerate(record["deliveries"]):
                assert attempt["project"] == {"name": attempt["artifactId"], "version": "1.0.0"}
                assert attempt["transport"] == {"scheme": "https", "tlsObserved": True, "certificateVerification": "enforced"}
                assert attempt["submitted"][0]["artifactOutput"] == attempt["artifactId"]
                response = attempt["responses"][0]
                assert response["tlsObserved"] is True
                if args.partial and i == 1:
                    assert attempt["state"] == "unknown" and attempt["requestMayHaveOccurred"]
                    assert not response.get("httpStatus") and not response.get("references")
                else:
                    assert attempt["state"] == "accepted" and response["httpStatus"] == 200
                    assert response["references"] == [{"kind": "dependency-track:event-token", "value": tokens[i]}]
            (output / "record.json").write_bytes(raw)
            for name in ("rio.yaml", "pipeline.json", "api.cdx.json", "worker.cdx.json", "demo-ca.pem"):
                shutil.copyfile(work / name, output / name)
        # The original source workspace and internal journals are now gone.
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
    env.pop("RIO_DEMO_DELIVERY_KEY")
    # Inspect in an empty directory containing only the receipt, with no receiver.
    with tempfile.TemporaryDirectory(prefix="rio-offline-recipient-") as directory:
        recipient = Path(directory)
        shutil.copyfile(output / "record.json", recipient / "record.json")
        run(recipient, "record", "inspect", "--file", "record.json")
        run(recipient, "record", "report", "--file", "record.json", "--output", "report.html")
        assert {p.name for p in recipient.iterdir()} == {"record.json", "report.html"}
        shutil.copyfile(recipient / "report.html", output / "report.html")
    shutil.copyfile(__file__, output / "run.py")
    for name in ("SYNTHETIC-ONLY-cert.pem", "SYNTHETIC-ONLY-key.pem"):
        shutil.copyfile(tls_files / name, output / name)
    (output / "README.md").write_text(
        "# Synthetic one-command Rio example\n\n"
        "`record.json` and `report.html` were generated by the supplied Rio binary. "
        "The loopback receiver and event tokens are synthetic; acceptance is not ingestion.\n\n"
        "Run with an installed Rio and Python 3.9+: `python3 run.py rio ./fresh-result`. "
        "Add `--partial` to lose the second response. No Go toolchain or external service is needed.\n\n"
        "The script starts its own local HTTPS receiver and ephemeral API key, runs the pipeline once, "
        "verifies exact bytes, then removes the workspace and stops the receiver before offline inspection. "
        "The supplied certificate/key are public synthetic fixture material.\n\n"
        "`rio.yaml`, `pipeline.json`, and the two input SBOMs are complete examples. "
        "`normalized/` contains the exact submitted SBOMs. The URL in rio.yaml is the receiver URL "
        "used for this capture; the script assigns a fresh local URL on rerun.\n", encoding="utf-8")
    for path in output.rglob("*"):
        if path.is_file():
            assert secret.encode() not in path.read_bytes(), path.name
    with zipfile.ZipFile(output / "example.zip", "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(output.rglob("*")):
            if path.is_file() and path.name != "example.zip":
                archive.write(path, "rio-example/" + path.relative_to(output).as_posix())
    print("PASS: one pipeline invocation; two SBOMs; exact build URL/ID, bytes, TLS and responses; "
          "source-free offline inspection/rendering; secret canary absent")
    print("Receipt bytes:", len(raw))
    print("Example:", output)


if __name__ == "__main__":
    main()
