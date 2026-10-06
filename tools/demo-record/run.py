#!/usr/bin/env python3
"""Installed-binary evidence walkthrough. All receiver responses are synthetic."""
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

    snapshots = []
    index_path = None

    def retain(name, result):
        original = Path(result["receipt"]["path"])
        path = retained / (name + ".json")
        path.write_bytes(original.read_bytes())
        snapshots.append(path)
        return json.loads(path.read_bytes())

    try:
        port = start()
        seed = (HERE / "bom.json").read_bytes()
        (work / "bom.json").write_bytes(seed)
        other = json.loads(seed)
        other["metadata"]["component"]["name"] = "synthetic-without-context"
        (work / "without-context.json").write_text(json.dumps(other))
        (work / "context.json").write_text((HERE / "context.json").read_text().replace("SBOM_SHA", hashlib.sha256(seed).hexdigest()))
        (work / "rio.yaml").write_text((HERE / "rio.yaml").read_text().replace("PORT", str(port)))
        execution = run()
        first = retain("pipeline", execution)
        index_path = Path(execution["runDirectory"]) / "index.json"
        index = json.loads(index_path.read_bytes())
        assert "context" in index["artifacts"][0] and "context" not in index["artifacts"][1]
        assert first["run"]["operation"] == "pipeline" and len(first["deliveries"]) == 2
        assert first["artifacts"][0]["changes"]["metadata"]
        attempts = json.loads((index_path.parent / ".internal/attempts.json").read_bytes())
        acknowledged = attempts[0]["journal"]
        frozen = (retained / "pipeline.json").read_bytes()
        state["mode"] = "lost"
        lost = retain("lost-response", run("deliver", "--index", index_path, "--artifact", "application", "--record", "ambiguous", code=4))
        assert lost["deliveries"][0]["state"] == "unknown"
        assert lost["artifacts"][0]["preExisting"] and "changes" not in lost["artifacts"][0]
        state["mode"] = "accepted"
        retry = retain("retry", run("deliver", "--index", index_path, "--artifact", "application", "--record", "retry", "--retry-of", "ambiguous"))
        assert retry["deliveries"][0]["prior"]["attemptId"] == lost["deliveries"][0]["attemptId"]
        for number, code in enumerate((0, 0, 4), 1):
            current = retain("observation-" + str(number), run("delivery", "reconcile", "--record", acknowledged, code=code))
            assert current["run"]["operation"] == "reconcile"
            assert len(current["deliveries"][0]["responses"]) == 1
            assert current["deliveries"][0]["prior"]["attemptId"] == first["deliveries"][0]["attemptId"]
            assert not current["deliveries"][0].get("submitted")
        assert (retained / "pipeline.json").read_bytes() == frozen
        stop()
        failed = work / "failed"
        failed.mkdir()
        bad = json.loads(seed)
        del bad["metadata"]["component"]["version"]
        (failed / "bom.json").write_text(json.dumps(bad))
        (failed / "rio.yaml").write_text("version: 1\nartifacts: [{id: failed, sbom: bom.json}]\ngate:\n  require: [name, version]\n")
        failed_record = retain("failed-gate", run("--gate", "fail", cwd=failed, code=1))
        assert failed_record["artifacts"][0]["checks"]["gate"] == "fail"
        moved = retained / "recipient"
        moved.mkdir()
        for path in snapshots:
            shutil.copyfile(path, moved / path.name)
        shutil.rmtree(work)
        count = state["requests"]
        for path in moved.glob("*.json"):
            result = run("record", "inspect", "--file", path, cwd=moved)
            assert result["outcome"] == "valid" and state["requests"] == count
            assert result["record"]["kind"] == "rio-run-receipt"
            assert "evidence" not in result["record"] and "normalization" not in result["record"]
            run("record", "report", "--file", path, "--output", path.with_suffix(".html"), cwd=moved)
        standalone = moved / "pipeline.json"
        for kind in ("reference", "acknowledgment"):
            corrupted = json.loads(standalone.read_bytes())
            if kind == "reference":
                corrupted["deliveries"][0]["submitted"][0]["artifactOutput"] = "missing"
            else:
                corrupted["deliveries"][0]["state"] = "rejected"
            path = moved / ("corrupt-" + kind + ".json")
            path.write_text(json.dumps(corrupted))
            assert run("record", "inspect", "--file", path, code=2, cwd=moved)["outcome"] == "error"
            path.unlink()
        run("record", "inspect", "--file", standalone, as_json=False, cwd=moved)
        for path in retained.rglob("*"):
            if path.is_file() and path.suffix in (".json", ".html"):
                assert env["RIO_SYNTHETIC_KEY"] not in path.read_text()
        (retained / "walkthrough.json").write_text(json.dumps({"syntheticReceiver": True, "commands": commands, "networkRequests": count, "offlineInspectionRequests": 0}, indent=2) + "\n")
        print("PASS: one root pipeline, distinct retry/reconciliation receipts, immutable prior snapshot, source-free inspection and corruption refusal")
        print("Retained independent receipts:", moved)
    finally:
        stop()


if __name__ == "__main__":
    main()
