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

    def retain(result, name, verification, observed):
        raw = Path(result["receipt"]["path"]).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == result["receipt"]["sha256"]
        assert len(raw) == result["receipt"]["size"]
        receipt = json.loads(raw)
        assert receipt["kind"] == "rio-run-receipt" and receipt["schemaVersion"] == 1
        attempt = receipt["deliveries"][0]
        assert attempt["transport"] == {"scheme": "https", "certificateVerification": verification,
                                         "tlsObserved": observed}
        if receipt["run"]["operation"] == "reconcile":
            assert attempt["state"] == "observed" and attempt["prior"]["attemptId"]
            assert not attempt.get("submitted")
            assert attempt["responses"][0]["kind"] == "activity"
            assert attempt["responses"][0]["value"] == "not-observed"
        elif observed:
            assert attempt["state"] == "accepted"
            assert attempt["responses"][0]["references"] == [{"kind": "dependency-track:event-token", "value": TOKEN}]
        (retained / (name + ".json")).write_bytes(raw)
        return receipt

    try:
        # The introductory path performs the whole configured pipeline once.
        target["caFile"] = str(HERE / "SYNTHETIC-ONLY-cert.pem")
        save()
        execution = run()
        verified = retain(execution, "ca-verified", "enforced", True)
        assert verified["run"]["operation"] == "pipeline"
        index = Path(execution["runDirectory"]) / "index.json"
        del target["caFile"]
        save()
        retain(run("deliver", "--index", index, "--record", "default-rejected", code=4),
               "default-rejected", "enforced", False)
        assert requests == ["POST"], "default trust sent an HTTP request or retried"
        target["insecureSkipVerify"] = True
        save()
        plan = run("delivery", "plan", "--index", index)
        assert plan["items"][0]["destination"]["options"]["insecureSkipVerify"] is True
        assert "insecureSkipVerify=true" in run("delivery", "plan", "--index", index, as_json=False)
        bypass = retain(run("deliver", "--index", index, "--record", "explicit-bypass"),
               "explicit-bypass", "disabled", True)
        before = (retained / "explicit-bypass.json").read_bytes()
        reconciliation = run("delivery", "reconcile", "--record", "explicit-bypass")
        # Reconciliation is a separate observation with its own immutable receipt.
        reconciled = retain(reconciliation, "reconciled", "disabled", True)
        assert reconciled["run"]["operation"] == "reconcile"
        assert reconciled["deliveries"][0]["prior"]["attemptId"] == bypass["deliveries"][0]["attemptId"]
        assert (retained / "explicit-bypass.json").read_bytes() == before
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
        for path in work.rglob("*"):
            if path.is_file():
                assert KEY.encode() not in path.read_bytes(), "API key retained"
        shutil.rmtree(work)
        env.pop("RIO_SYNTHETIC_KEY")
        for output in sorted(retained.glob("*.json")):
            assert KEY.encode() not in output.read_bytes()
            assert run("record", "inspect", "--file", output, cwd=retained)["outcome"] == "valid"
            run("record", "report", "--file", output, "--output", output.with_suffix(".html"), cwd=retained)
            html = output.with_suffix(".html").read_text()
            assert KEY not in html
            transport = json.loads(output.read_text())["deliveries"][0]["transport"]
            assert "Certificate verification " + transport["certificateVerification"] in html
            assert ("TLS observed" if transport["tlsObserved"] else "TLS not observed") in html
        print("PASS: one-command HTTPS pipeline, default refusal, CA verification, explicit bypass, saved policy and offline receipts")
        print("Synthetic receipts retained:", retained)
        print("ca-verified.json sha256:", hashlib.sha256((retained / "ca-verified.json").read_bytes()).hexdigest())
    finally:
        if not stopped:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    main()
