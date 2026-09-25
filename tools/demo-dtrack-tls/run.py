#!/usr/bin/env python3
"""Installed-binary HTTPS demonstration; all receipts and certificates are synthetic."""
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading

HERE = Path(__file__).resolve().parent
TOKEN = "f90934f5-cb88-47ce-81cb-db06fc67d4b4"
KEY = "synthetic-https-demo-api-key-DO-NOT-RETAIN"


def main():
    binary = Path(sys.argv[1]).resolve()
    assert binary.is_file(), "Provide an installed Rio binary"
    work = Path(tempfile.mkdtemp(prefix="rio-dtrack-tls-work-"))
    retained = Path(tempfile.mkdtemp(prefix="rio-dtrack-tls-evidence-"))
    env = dict(os.environ, RIO_SYNTHETIC_KEY=KEY)
    requests = []

    class Receiver(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            assert self.path == "/api/v1/bom"
            assert self.headers.get("X-Api-Key") == KEY
            if self.headers.get("Transfer-Encoding") == "chunked":
                while True:
                    size = int(self.rfile.readline().strip().split(b";")[0], 16)
                    if not size:
                        self.rfile.readline()
                        break
                    assert len(self.rfile.read(size)) == size
                    assert self.rfile.read(2) == b"\r\n"
            else:
                self.rfile.read(int(self.headers["Content-Length"]))
            requests.append("POST")
            self.reply({"token": TOKEN})

        def do_GET(self):
            assert self.path == "/api/v1/event/token/" + TOKEN
            requests.append("GET")
            self.reply({"processing": False})

        def reply(self, value):
            body = json.dumps(value).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(str(HERE / "SYNTHETIC-ONLY-cert.pem"), str(HERE / "SYNTHETIC-ONLY-key.pem"))
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    stopped = False
    config = {"version": 1, "artifacts": [{"id": "app", "sbom": "bom.json"}], "delivery": {"targets": {"security": {
        "type": "dependency-track", "url": "https://127.0.0.1:" + str(server.server_port),
        "apiKeyEnv": "RIO_SYNTHETIC_KEY"}}}}
    target = config["delivery"]["targets"]["security"]
    shutil.copyfile(HERE.parent / "demo-delivery" / "bom.json", work / "bom.json")

    def save():
        (work / "rio.yaml").write_text(json.dumps(config))

    def run(*args, code=0, as_json=True, cwd=None):
        command = [str(binary), *map(str, args)]
        if as_json:
            command.append("--json")
        result = subprocess.run(command, cwd=cwd or work, env=env, capture_output=True, text=True)
        assert result.returncode == code, (args, result.returncode, result.stdout, result.stderr)
        assert KEY not in result.stdout + result.stderr
        return json.loads(result.stdout) if as_json else result.stdout + result.stderr

    def facts(result, verification, observed):
        if "items" in result:
            result = result["items"][0]["result"]
        assert result["observations"][-1]["details"]["tls"] == {
            "certificateVerification": verification, "observed": observed}

    try:
        save()
        run("normalize", "--gate", "fail", as_json=False)
        facts(run("deliver", "--record", "default-rejected", code=4), "enforced", False)
        assert requests == [], "default trust sent an HTTP request or retried"
        target["caFile"] = str(HERE / "SYNTHETIC-ONLY-cert.pem")
        save()
        facts(run("deliver", "--record", "ca-verified"), "enforced", True)
        del target["caFile"]
        target["insecureSkipVerify"] = True
        save()
        plan = run("delivery", "plan")
        assert plan["items"][0]["destination"]["options"]["insecureSkipVerify"] is True
        assert "insecureSkipVerify=true" in run("delivery", "plan", as_json=False)
        facts(run("deliver", "--record", "explicit-bypass"), "disabled", True)
        facts(run("delivery", "reconcile", "--record", "explicit-bypass"), "disabled", True)
        human = run("delivery", "inspect", "--record", "explicit-bypass", as_json=False)
        assert "certificateVerification=disabled TLSObserved=true" in human
        assert "insecureSkipVerify=true" in human
        target.pop("insecureSkipVerify")
        save()
        run("delivery", "reconcile", "--record", "explicit-bypass", code=2)
        assert requests == ["POST", "POST", "GET"], "unexpected request or replay"
        server.shutdown()
        server.server_close()
        thread.join()
        stopped = True
        output = retained / "record.json"
        run("record", "--output", output, "--delivery-record", "default-rejected", "--delivery-record", "ca-verified", "--delivery-record", "explicit-bypass")
        for path in work.rglob("*"):
            if path.is_file():
                assert KEY.encode() not in path.read_bytes(), "API key retained"
        assert KEY.encode() not in output.read_bytes()
        shutil.rmtree(work)
        assert run("record", "inspect", "--file", output, cwd=retained)["outcome"] == "valid"
        human = run("record", "inspect", "--file", output, cwd=retained, as_json=False)
        assert "insecureSkipVerify=true" in human and "certificateVerification=disabled TLSObserved=true" in human
        print("PASS: synthetic HTTPS default refusal, CA verification, explicit bypass, saved policy and offline portable evidence")
        print("Synthetic evidence retained:", retained)
        print("record.json sha256:", hashlib.sha256(output.read_bytes()).hexdigest())
    finally:
        if not stopped:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    main()
