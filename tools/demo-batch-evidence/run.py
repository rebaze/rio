#!/usr/bin/env python3
"""Installed-binary compact batch/recovery demo. Python 3.9+, synthetic loopback only."""
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    args = parser.parse_args()
    binary = str(Path(shutil.which(args.binary) or args.binary).resolve())
    retained = Path(tempfile.mkdtemp(prefix="rio-batch-evidence-"))
    work = retained / "source-workspace"
    shutil.copytree(Path(__file__).resolve().parent / "fixtures", work / "fixtures")
    canary = "synthetic-" + secrets.token_hex(16)
    env = dict(os.environ, RIO_DEMO_BATCH_KEY=canary)
    state = {"requests": 0, "pause": False}
    arrived = threading.Event()
    release = threading.Event()

    class Receiver(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            state["requests"] += 1
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
            if state["requests"] == 2:
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"token":"f90934f5-cb88-47ce-81cb-db06fc67d4b4"}')

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

    try:
        manifest = (Path(__file__).resolve().parent / "rio.yaml").read_text()
        (work / "rio.yaml").write_text(manifest.replace("PORT", str(server.server_port)))
        first = run("--json", code=4)
        run_dir = Path(first["runDirectory"])
        index_path = run_dir / "index.json"
        assert state["requests"] == 2 and first["outcome"] == "partial"
        initial = Path(first["receipt"]["path"]).read_bytes()
        (retained / "partial.json").write_bytes(initial)
        before = hashlib.sha256(initial).hexdigest()
        record = json.loads(initial)
        assert [p["state"] for p in record["deliveries"]] == ["accepted", "unknown", "unattempted"]
        assert {"artifactId": "worker", "target": "archive", "reason": "target-exclude"} in record["exclusions"]
        run("deliver", "--index", index_path, "--json", code=2)
        assert state["requests"] == 2
        attempts = json.loads((run_dir / ".internal/attempts.json").read_bytes())
        old = attempts[1]["journal"]
        retry = run("deliver", "--index", index_path, "--artifact", "app", "--target", "security", "--retry-of", old,
                    "--record", work / "retry-attempt", "--json")
        shutil.copyfile(retry["receipt"]["path"], retained / "retry.json")
        accepted = run("deliver", "--index", index_path, "--artifact", "worker", "--target", "security", "--record", work / "worker-attempt", "--json")
        shutil.copyfile(accepted["receipt"]["path"], retained / "accepted.json")
        assert state["requests"] == 4
        state["pause"] = True
        child = subprocess.Popen([binary, "deliver", "--index", str(index_path), "--out", "crash-output", "--artifact", "app", "--target", "security",
                                  "--retry-of", str(work / "retry-attempt"), "--record", str(work / "crash-attempt"), "--json"],
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
        # Recovery reads committed local prefixes without breaking crash locks,
        # reading the mutable index, constructing a client or replaying requests.
        index_path.write_text("{}")
        count = state["requests"]
        final = retained / "crash-incomplete.json"
        run("record", "recover", "--run", crash_runs[0], "--output", final, "--json")
        crash = json.loads(final.read_bytes())
        assert crash["run"]["outcome"] == "incomplete" and crash["run"]["stages"]["delivery"] == "incomplete"
        assert crash["deliveries"][0]["state"] == "unknown" and not crash["deliveries"][0].get("responses")
        assert (work / "crash-attempt.lock").is_dir() and state["requests"] == count
        shutil.rmtree(work)
        for stem in ("crash-incomplete", "partial", "retry", "accepted"):
            result = run("record", "inspect", "--file", retained / (stem + ".json"), "--json", cwd=retained)
            assert result["outcome"] == "valid"
            run("record", "report", "--file", retained / (stem + ".json"), "--output", retained / (stem + ".html"), cwd=retained)
            html = (retained / (stem + ".html")).read_text()
            assert canary not in html and "<script" not in html.lower()
        assert hashlib.sha256((retained / "partial.json").read_bytes()).hexdigest() == before
        record["deliveries"][0]["state"] = "rejected"
        tampered = retained / "tampered.json"
        tampered.write_text(json.dumps(record))
        run("record", "inspect", "--file", tampered, code=2, cwd=retained)
        tampered.unlink()
        print("PASS: one root batch, partial/lost response, unattempted coverage, exclusions, explicit retry and actual child-process interruption.")
        print("PASS: unchanged prior receipts, stopped receiver, corrupt index, source removal and offline recovery/inspection without replay or lock breaking.")
        print("Retained independent receipts:", retained)
    finally:
        stop()


if __name__ == "__main__":
    main()
