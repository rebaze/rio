#!/usr/bin/env python3
"""Installed-binary evidence walkthrough. All receiver responses are synthetic."""
import base64
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

HERE = Path(__file__).resolve().parent
TOKEN = "f90934f5-cb88-47ce-81cb-db06fc67d4b4"


def main():
    binary = Path(sys.argv[1]).resolve()
    if not binary.is_file():
        raise SystemExit("Provide an installed Rio binary path")
    retained = Path(tempfile.mkdtemp(prefix="rio-record-demo-"))
    work = retained / "source-workspace"
    work.mkdir()
    env = dict(os.environ, RIO_SYNTHETIC_KEY="synthetic-record-demo-key")
    state = {"mode": "accepted", "activity": 0, "requests": 0}

    class Receiver(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            state["requests"] += 1
            assert self.path == "/api/v1/bom"
            if self.headers.get("Transfer-Encoding") == "chunked":
                while True:
                    size = int(self.rfile.readline().strip().split(b";")[0], 16)
                    if not size:
                        self.rfile.readline()
                        break
                    self.rfile.read(size)
                    assert self.rfile.read(2) == b"\r\n"
            else:
                self.rfile.read(int(self.headers["Content-Length"]))
            if state["mode"] == "lost":
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"token": TOKEN}).encode())

        def do_GET(self):
            state["requests"] += 1
            assert self.path == "/api/v1/event/token/" + TOKEN
            state["activity"] += 1
            self.send_response(503 if state["activity"] == 3 else 200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"processing": state["activity"] == 1}).encode())

    class Server(http.server.ThreadingHTTPServer):
        allow_reuse_address = True

    server = None
    thread = None

    def start(port=0):
        nonlocal server, thread
        server = Server(("127.0.0.1", port), Receiver)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server.server_port

    def stop():
        nonlocal server
        if server is not None:
            server.shutdown()
            server.server_close()
            thread.join()
            server = None

    commands = []

    def run(*args, code=0, as_json=True, cwd=None):
        cmd = [str(binary), *map(str, args)] + (["--json"] if as_json else [])
        p = subprocess.run(cmd, cwd=cwd or work, env=env, capture_output=True, text=True)
        assert p.returncode == code, (args, p.returncode, p.stdout, p.stderr)
        assert env["RIO_SYNTHETIC_KEY"] not in p.stdout + p.stderr
        commands.append({"args": list(map(str, args)), "exit": p.returncode})
        return json.loads(p.stdout) if as_json else None

    def collect(name, attempts):
        assert server is None, "record collection must run with the receiver stopped"
        before = state["requests"]
        output = retained / name
        args = ["record", "--output", output]
        for attempt in attempts:
            args.extend(["--delivery-record", attempt])
        result = run(*args)
        assert result["outcome"] == "written" and result["outputMayExist"]
        assert state["requests"] == before
        return json.loads(output.read_text())

    try:
        port = start()
        seed = (HERE / "bom.json").read_bytes()
        (work / "bom.json").write_bytes(seed)
        other = json.loads(seed)
        other["metadata"]["component"]["name"] = "synthetic-without-context"
        (work / "without-context.json").write_text(json.dumps(other))
        (work / "context.json").write_text((HERE / "context.json").read_text().replace("SBOM_SHA", hashlib.sha256(seed).hexdigest()))
        (work / "rio.yaml").write_text((HERE / "rio.yaml").read_text().replace("PORT", str(port)))
        run("normalize", "--gate", "fail", "--attest", as_json=False)
        index = json.loads((work / "target/rio/index.json").read_text())
        assert "context" in index["artifacts"][0] and "context" not in index["artifacts"][1]
        run("deliver", "--artifact", "application", "--record", "acknowledged")
        state["mode"] = "lost"
        run("deliver", "--artifact", "application", "--record", "ambiguous", code=4)
        state["mode"] = "accepted"
        run("deliver", "--artifact", "application", "--record", "retry", "--retry-of", "ambiguous")
        stop()
        before = collect("record-before.json", ["acknowledged", "ambiguous", "retry"])
        assert sorted(x["summary"]["acknowledgment"] for x in before["deliveries"]) == ["accepted", "accepted", "unknown"]
        assert all("latestActivity" not in x["summary"] for x in before["deliveries"])
        no_selected = collect("record-no-deliveries.json", [])
        assert no_selected["coverage"]["selectedDeliveryCount"] == 0
        missing = collect("record-missing-ancestry.json", ["retry"])
        assert len(missing["coverage"]["retryAttemptIdsNotIncluded"]) == 1
        start(port)
        for code in (0, 0, 4):
            run("delivery", "reconcile", "--record", "acknowledged", code=code)
        stop()
        after = collect("record-after.json", ["retry", "ambiguous", "acknowledged"])
        observed = next(x for x in after["deliveries"] if "latestActivity" in x["summary"])
        assert observed["summary"]["latestActivity"]["observation"]["value"] == "not-observed"
        assert observed["summary"]["lastObservation"]["observation"]["kind"] == "unavailable"
        assert observed["summary"]["acknowledgment"] == "accepted"
        assert len(observed["events"]) == 5
        assert (retained / "record-before.json").read_bytes() != (retained / "record-after.json").read_bytes()
        # A failed gate is recorded evidence and exports successfully without upload.
        failed = work / "failed"
        failed.mkdir()
        bad = json.loads(seed)
        del bad["metadata"]["component"]["version"]
        (failed / "bom.json").write_text(json.dumps(bad))
        (failed / "rio.yaml").write_text("version: 1\nartifacts: [{id: failed, sbom: bom.json}]\ngate:\n  require: [name, version]\n")
        run("normalize", "--gate", "warn", as_json=False, cwd=failed)
        run("record", "--output", retained / "record-failed-gate.json", cwd=failed)
        failed_record = json.loads((retained / "record-failed-gate.json").read_text())
        assert failed_record["normalization"]["index"]["artifacts"][0]["gate"] == "fail"
        # Transfer only this file, then remove every original index/journal/SBOM.
        moved = retained / "recipient"
        moved.mkdir()
        standalone = moved / "record.json"
        shutil.copyfile(retained / "record-after.json", standalone)
        shutil.rmtree(work)
        count = state["requests"]
        valid = run("record", "inspect", "--file", standalone, cwd=moved)
        assert valid["outcome"] == "valid" and state["requests"] == count
        assert valid["record"]["normalization"]["sbomBytesVerification"] == "not-performed"
        for kind in ("source", "summary"):
            corrupted = json.loads(standalone.read_text())
            if kind == "source":
                corrupted["evidence"][0]["data"] = base64.b64encode(b"{}").decode()
            else:
                corrupted["deliveries"][0]["summary"]["acknowledgment"] = "rejected"
            path = moved / ("corrupt-" + kind + ".json")
            path.write_text(json.dumps(corrupted))
            result = run("record", "inspect", "--file", path, code=2, cwd=moved)
            assert result["outcome"] == "error" and not result["outputMayExist"]
        # Inspect human output as well: this reports consistency, never ingestion.
        run("record", "inspect", "--file", standalone, as_json=False, cwd=moved)
        for path in retained.rglob("*.json"):
            assert env["RIO_SYNTHETIC_KEY"] not in path.read_text()
        (retained / "walkthrough.json").write_text(json.dumps({"syntheticReceiver": True, "commands": commands, "networkRequests": count, "collectionAndInspectionNetworkRequests": 0}, indent=2) + "\n")
        print("PASS: synthetic receipts/activity; offline snapshots and relocated inspection; corruption refused")
        print("No ingestion/authenticity/full-retention claim. Retained evidence:", retained)
    finally:
        stop()


if __name__ == "__main__":
    main()
