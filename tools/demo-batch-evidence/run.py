#!/usr/bin/env python3
"""Installed-binary batch/v2/recovery demo. Python 3.9+, synthetic loopback only."""
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
        run("normalize", "--gate", "fail")
        first = run("deliver", "--evidence", "partial.json", "--json", code=4)
        assert state["requests"] == 2
        assert first["delivery"]["outcome"] == "partial"
        initial = (work / "partial.json").read_bytes()
        (retained / "partial.json").write_bytes(initial)
        before = hashlib.sha256(initial).hexdigest()
        record = json.loads(initial)
        pairs = record["batches"][0]["pairs"]
        assert [p["acknowledgment"] for p in pairs] == ["accepted", "unknown", "not-captured"]
        assert pairs[2]["runnerState"] == "unattempted"
        assert record["batches"][0]["exclusions"][0]["artifactIDs"] == ["worker"]
        # An unchanged rerun refuses before another request.
        run("deliver", "--evidence", "rerun.json", "--json", code=2)
        assert state["requests"] == 2
        old = first["delivery"]["items"][1]["record"]
        run("deliver", "--artifact", "app", "--target", "security", "--retry-of", old,
            "--record", work / "retry-attempt", "--evidence", "retry.json", "--json")
        # Explicit fresh slot keeps the original batch's unattempted slot absent.
        run("deliver", "--artifact", "worker", "--target", "security", "--record",
            work / "worker-attempt", "--evidence", "worker.json", "--json")
        assert state["requests"] == 4
        # Kill only the owned child after the receiver proves its durable intent
        # preceded the request. No completion or final record can be promised.
        state["pause"] = True
        child = subprocess.Popen([binary, "deliver", "--artifact", "app", "--target", "security",
                                  "--retry-of", str(work / "retry-attempt"),
                                  "--record", str(work / "crash-attempt"),
                                  "--evidence", "crash.json", "--json"],
                                 cwd=work, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            assert arrived.wait(10), "owned delivery child did not reach receiver"
            descriptor = json.loads((work / "crash.json.batch.json").read_bytes())
            assert (work / "crash-attempt/00000000000000000000.json").is_file()
            assert child.poll() is None
            child.kill()
            stdout, stderr = child.communicate(timeout=10)
            assert canary.encode() not in stdout + stderr
            assert child.returncode != 0
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate(timeout=10)
            release.set()
        assert not (work / "crash.json").exists()
        assert not (work / "crash.json.batch-result.json").exists()
        # Explicit harness cleanup after a verified terminal child. Production
        # collection never breaks these locks automatically.
        for suffix in ("", ".index.json", ".batch.json", ".batch-result.json"):
            (work / ("crash.json" + suffix + ".lock")).rmdir()
        for pair in descriptor["pairs"]:
            Path(pair["journalPathHint"] + ".lock").rmdir()
        stop()
        # The current index is deliberately unusable; --batch recovers its snapshot.
        (work / "target/rio/index.json").write_text("{}")
        final = retained / "handoff.json"
        run("record", "--schema-version", "2", "--batch", "partial.json.batch.json",
            "--batch", "retry.json.batch.json", "--batch", "worker.json.batch.json",
            "--batch", "crash.json.batch.json", "--output", final)
        handoff = json.loads(final.read_bytes())
        assert len(handoff["deliveries"]) == 5 and len(handoff["batches"]) == 4
        crash = next(b for b in handoff["batches"] if b["scope"]["completionPathHint"].endswith("crash.json.batch-result.json"))
        assert "completion" not in crash and crash["pairs"][0]["acknowledgment"] == "unknown"
        for file in work.rglob("*.json"):
            assert canary.encode() not in file.read_bytes(), "secret in retained source"
        shutil.rmtree(work)  # Only this demonstration's own synthetic workspace.
        inspected = run("record", "inspect", "--file", final, "--json", cwd=retained)
        assert inspected["outcome"] == "valid"
        assert hashlib.sha256((retained / "partial.json").read_bytes()).hexdigest() == before
        run("record", "inspect", "--file", retained / "partial.json", cwd=retained)
        handoff["deliveries"][0]["summary"]["acknowledgment"] = "forged"
        tampered = retained / "tampered.json"
        tampered.write_text(json.dumps(handoff))
        run("record", "inspect", "--file", tampered, code=2, cwd=retained)
        tampered.unlink()
        print("PASS: partial/lost response, actual process interruption, unattempted coverage, exclusions and explicit retry.")
        print("PASS: stopped receiver, replaced working index, removed sources, inspected portable snapshots.")
        print("Retained:", final)
    finally:
        stop()


if __name__ == "__main__":
    main()
