#!/usr/bin/env python3
"""Installed-binary delivery demo. All receiver responses are synthetic."""
import email.parser
import email.policy
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading

TOKEN = "f90934f5-cb88-47ce-81cb-db06fc67d4b4"
HERE = Path(__file__).resolve().parent


def main():
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file():
        raise SystemExit("Provide an installed Rio binary path")
    work = Path(tempfile.mkdtemp(prefix="rio-delivery-demo-"))
    env = dict(os.environ, RIO_SYNTHETIC_KEY="synthetic-demo-key")
    received = []
    mode = ["accepted"]

    class Receiver(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            assert self.path == "/api/v1/bom"
            if self.headers.get("Transfer-Encoding") == "chunked":
                chunks = []
                while True:
                    size = int(self.rfile.readline().strip().split(b";")[0], 16)
                    if not size:
                        self.rfile.readline()
                        break
                    chunks.append(self.rfile.read(size))
                    assert self.rfile.read(2) == b"\r\n"
                body = b"".join(chunks)
            else:
                body = self.rfile.read(int(self.headers["Content-Length"]))
            message = email.parser.BytesParser(policy=email.policy.default).parsebytes(
                ("Content-Type: " + self.headers["Content-Type"] + "\r\n\r\n").encode() + body
            )
            parts = {part.get_param("name", header="content-disposition"): part.get_payload(decode=True)
                     for part in message.iter_parts()}
            assert parts["bom"] == (work / "target/rio/application.cdx.json").read_bytes()
            received.append({"sha256": hashlib.sha256(parts["bom"]).hexdigest(),
                             "fields": {k: v.decode() for k, v in parts.items() if k != "bom"},
                             "synthetic": True})
            if mode[0] == "lost":
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write((json.dumps({"token": TOKEN}) if mode[0] == "accepted" else "{}").encode())

        def do_GET(self):
            assert self.path == "/api/v1/event/token/" + TOKEN
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"processing":false}')

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    for name in ("rio.yaml", "bom.json"):
        shutil.copyfile(HERE / name, work / name)
    (work / "delivery.yaml").write_text((HERE / "delivery.yaml").read_text().replace("PORT", str(server.server_port)))

    def run(*args, code=0, json_result=True):
        command = [str(binary), *args]
        if json_result:
            command.append("--json")
        result = subprocess.run(command, cwd=work, env=env, capture_output=True, text=True)
        assert result.returncode == code, (args, result.returncode, result.stdout, result.stderr)
        assert env["RIO_SYNTHETIC_KEY"] not in result.stdout + result.stderr
        if json_result:
            value = json.loads(result.stdout)
            (work / ("result-%02d.json" % len(list(work.glob("result-*.json"))))).write_text(result.stdout)
            return value

    def deliver(name, binding="application-security", code=0, extra=()):
        return run("deliver", "--delivery", binding, "--record", name, *extra, code=code)

    try:
        run("normalize", "--attest", json_result=False)
        run("delivery", "plan", "--delivery", "application-security")
        assert deliver("accepted")["outcome"] == "accepted"
        assert run("delivery", "inspect", "--record", "accepted")["acknowledgment"] == "accepted"
        assert run("delivery", "reconcile", "--record", "accepted")["activity"] == "not-observed"
        deliver("uuid", "uuid")
        deliver("subject", "subject")
        assert received[0]["fields"] == {"projectName": "synthetic-app", "projectVersion": "1.2.3", "autoCreate": "false"}
        assert received[1]["fields"] == {"project": TOKEN}
        output = work / "target/rio/application.cdx.json"
        checked = output.read_bytes()
        output.write_bytes(checked + b" ")
        count = len(received)
        deliver("tampered", code=2)
        assert len(received) == count
        output.write_bytes(checked)
        mode[0] = "malformed"
        assert deliver("malformed", code=4)["outcome"] == "unknown"
        mode[0] = "lost"
        assert deliver("lost", code=4)["outcome"] == "unknown"
        run("delivery", "reconcile", "--record", "lost", code=2)
        mode[0] = "accepted"

        # Missing subject version is a gate failure, independent of destination identity.
        bom = json.loads((HERE / "bom.json").read_text())
        del bom["metadata"]["component"]["version"]
        (work / "bom.json").write_text(json.dumps(bom))
        run("normalize", "--attest", "--gate", "fail", code=1, json_result=False)
        shutil.copytree(work / "target/rio", work / "missing-version-evidence")
        count = len(received)
        deliver("failed-gate", code=2)
        assert len(received) == count
        result = deliver("overridden-gate", extra=("--allow-failed-gate",))
        assert result["source"]["gate"] == "fail" and result["source"]["allowFailedGate"]

        # Unmapped p2 is reported, not automatically a gate failure. Future spec skips schema validation.
        bom = json.loads((HERE / "bom.json").read_text())
        bom["specVersion"] = "1.99"
        bom["components"] = [{"type": "library", "group": "p2.eclipse.plugin", "name": "synthetic.unmapped", "version": "1",
                              "purl": "pkg:p2/synthetic.unmapped@1?classifier=osgi.bundle"}]
        (work / "bom.json").write_text(json.dumps(bom))
        (work / "rio.yaml").write_text((HERE / "rio.yaml").read_text() + "    transforms:\n      - repair-purl:\n          ecosystem: p2\n")
        run("normalize", "--attest", json_result=False)
        idx = json.loads((work / "target/rio/index.json").read_text())
        artifact = idx["artifacts"][0]
        assert artifact["schemaValidated"] is False and artifact["transforms"][0]["unmapped"] == 1
        assert deliver("unmapped-skipped-schema")["source"]["schemaValidated"] is False
        (work / "synthetic-requests.json").write_text(json.dumps(received, indent=2))
        assert len(received) == 7
        print("Synthetic demo passed: 7 uploads; exact bytes, direct selectors, refusals, unknown responses and activity only.")
        print("Evidence (including unsigned statements and skipped validation):", work)
        print("No real Dependency-Track compatibility or ingestion claim is made by this demo.")
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == "__main__":
    main()
