#!/usr/bin/env python3
"""Installed-binary failure and recovery demo. Python 3.9+, synthetic loopback receiver only."""
import argparse
import hashlib
import http.server
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading

HERE = Path(__file__).resolve().parent
TOKEN = "f90934f5-cb88-47ce-81cb-db06fc67d4b4"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    args = parser.parse_args()
    binary = str(Path(shutil.which(args.binary) or args.binary).resolve())
    retained = Path(tempfile.mkdtemp(prefix="rio-recovery-demo-"))
    work = retained / "source-workspace"
    shutil.copytree(HERE / "fixtures", work / "fixtures")
    canary = "synthetic-" + secrets.token_hex(16)
    env = dict(os.environ, RIO_DEMO_KEY=canary)
    state = {"posts": 0, "gets": 0, "pause": False}
    arrived = threading.Event()
    release = threading.Event()

    class Receiver(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            state["posts"] += 1
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
            if state["pause"]:
                arrived.set()
                release.wait(15)
                return
            if state["posts"] == 2:
                # Lose the response after the receiver has read the upload.
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"token": TOKEN}).encode())

        def do_GET(self):
            state["gets"] += 1
            assert self.path.endswith("/api/v1/event/token/" + TOKEN)
            # Three observations: still processing, done, receiver error.
            self.send_response(503 if state["gets"] == 3 else 200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"processing": state["gets"] == 1}).encode())

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    stopped = False

    def stop():
        nonlocal stopped
        if not stopped:
            server.shutdown()
            server.server_close()
            thread.join()
            stopped = True

    def run(*command, code=0, cwd=work):
        result = subprocess.run([binary, *map(str, command)], cwd=cwd, env=env,
                                capture_output=True, text=True)
        assert canary not in result.stdout + result.stderr, "secret in CLI output"
        assert result.returncode == code, (command, result.returncode, result.stdout, result.stderr)
        return json.loads(result.stdout) if "--json" in command else result

    def retain(name, result):
        path = retained / (name + ".json")
        shutil.copyfile(result["receipt"]["path"], path)
        return json.loads(path.read_bytes())

    try:
        manifest = (HERE / "rio.yaml").read_text()
        (work / "rio.yaml").write_text(manifest.replace("PORT", str(server.server_port)))

        # One root batch: the second upload loses its response, so the batch stops there.
        first = run("--json", code=4)
        index_path = Path(first["runDirectory"]) / "index.json"
        assert state["posts"] == 2 and first["outcome"] == "partial"
        partial = retain("partial", first)
        frozen = (retained / "partial.json").read_bytes()
        assert partial["run"]["operation"] == "pipeline"
        assert [p["state"] for p in partial["deliveries"]] == ["accepted", "unknown", "unattempted"]
        assert {"artifactId": "worker", "target": "archive", "reason": "target-exclude"} in partial["exclusions"]

        # Nothing is resubmitted automatically; a retry is an explicit, separate invocation.
        run("deliver", "--index", index_path, "--json", code=2)
        assert state["posts"] == 2
        attempts = json.loads((index_path.parent / ".internal/attempts.json").read_bytes())
        acknowledged, lost = attempts[0]["journal"], attempts[1]["journal"]
        retry = retain("retry", run("deliver", "--index", index_path, "--artifact", "app", "--target", "security",
                                    "--retry-of", lost, "--record", work / "retry-attempt", "--json"))
        assert retry["deliveries"][0]["prior"]["attemptId"] == partial["deliveries"][1]["attemptId"]
        retain("accepted", run("deliver", "--index", index_path, "--artifact", "worker", "--target", "security",
                               "--record", work / "worker-attempt", "--json"))
        assert state["posts"] == 4

        # Each reconciliation observes the receiver once and writes its own receipt.
        for number, code in enumerate((0, 0, 4), 1):
            current = retain("observation-" + str(number),
                             run("delivery", "reconcile", "--record", acknowledged, "--json", code=code))
            assert current["run"]["operation"] == "reconcile"
            assert len(current["deliveries"][0]["responses"]) == 1
            assert current["deliveries"][0]["prior"]["attemptId"] == partial["deliveries"][0]["attemptId"]
            assert not current["deliveries"][0].get("submitted")
        assert state["posts"] == 4

        # Kill a delivery after the receiver has the request, then recover offline.
        state["pause"] = True
        child = subprocess.Popen([binary, "deliver", "--index", str(index_path), "--out", "crash-output", "--artifact", "app",
                                  "--target", "security", "--retry-of", str(work / "retry-attempt"),
                                  "--record", str(work / "crash-attempt"), "--json"],
                                 cwd=work, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            assert arrived.wait(10), "owned delivery child did not reach receiver"
            assert (work / "crash-attempt/00000000000000000000.json").is_file()
            assert child.poll() is None
            child.kill()
            stdout, stderr = child.communicate(timeout=10)
            assert canary.encode() not in stdout + stderr and child.returncode != 0
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=10)
            release.set()
        crash_runs = list((work / "crash-output/runs").iterdir())
        assert len(crash_runs) == 1 and not (crash_runs[0] / "record.json").exists()
        stop()
        # Recovery reads committed local state without breaking crash locks,
        # reading the mutable index, constructing a client or replaying requests.
        index_path.write_text("{}")
        requests = state["posts"] + state["gets"]
        run("record", "recover", "--run", crash_runs[0], "--output", retained / "crash-incomplete.json", "--json")
        crash = json.loads((retained / "crash-incomplete.json").read_bytes())
        assert crash["run"]["outcome"] == "incomplete" and crash["run"]["stages"]["delivery"] == "incomplete"
        assert crash["deliveries"][0]["state"] == "unknown" and not crash["deliveries"][0].get("responses")
        assert (work / "crash-attempt.lock").is_dir()

        # A failed gate is recorded and blocks delivery.
        failed = work / "failed"
        failed.mkdir()
        bad = json.loads((work / "fixtures/app.json").read_bytes())
        del bad["metadata"]["component"]["version"]
        (failed / "bom.json").write_text(json.dumps(bad))
        (failed / "rio.yaml").write_text("version: 1\nartifacts: [{id: failed, sbom: bom.json}]\ngate:\n  require: [name, version]\n")
        gate = retain("failed-gate", run("--gate", "fail", "--json", cwd=failed, code=1))
        assert gate["artifacts"][0]["checks"]["gate"] == "fail" and not gate.get("deliveries")

        # Receipts stand alone: inspect and render them with the source workspace gone.
        shutil.rmtree(work)
        receipts = sorted(retained.glob("*.json"))
        for path in receipts:
            result = run("record", "inspect", "--file", path, "--json", cwd=retained)
            assert result["outcome"] == "valid" and result["record"]["kind"] == "rio-run-receipt"
            run("record", "report", "--file", path, "--output", path.with_suffix(".html"), cwd=retained)
            html = path.with_suffix(".html").read_text()
            assert canary not in html and "<script" not in html.lower()
        assert state["posts"] + state["gets"] == requests
        assert (retained / "partial.json").read_bytes() == frozen
        for kind in ("reference", "acknowledgment"):
            corrupted = json.loads(frozen)
            if kind == "reference":
                corrupted["deliveries"][0]["submitted"][0]["artifactOutput"] = "missing"
            else:
                corrupted["deliveries"][0]["state"] = "rejected"
            path = retained / ("corrupt-" + kind + ".json")
            path.write_text(json.dumps(corrupted))
            assert run("record", "inspect", "--file", path, "--json", code=2, cwd=retained)["outcome"] == "error"
            path.unlink()
        for path in retained.rglob("*"):
            if path.is_file():
                assert canary not in path.read_text(errors="replace")
        print("PASS: partial root batch with exclusion, no automatic resubmission, explicit retry and completion of the unattempted pair.")
        print("PASS: three independent reconciliations, a killed delivery recovered offline without replay or lock breaking, and a failed gate.")
        print("PASS: receipts inspected and rendered without the source workspace; earlier receipts unchanged; corruption refused.")
        print("Retained receipts:", retained)
    finally:
        stop()


if __name__ == "__main__":
    main()
