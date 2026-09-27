#!/usr/bin/env python3
"""Complete synthetic client handoff with an installed Rio and Python 3.9+."""
import argparse
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
import uuid

HERE = Path(__file__).resolve().parent
TLS = HERE.parent / "demo-dtrack-tls"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", help="installed Rio executable")
    args = parser.parse_args()
    binary = str(Path(shutil.which(args.binary) or args.binary).resolve())
    retained = Path(tempfile.mkdtemp(prefix="rio-client-record-"))
    work = retained / "source-workspace"
    work.mkdir()
    canary = "synthetic-client-" + secrets.token_hex(16)
    env = dict(os.environ, RIO_DEMO_CLIENT_KEY=canary)
    state = {"requests": 0, "failure_at": None, "queries": 0}
    commands = []

    class Receiver(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            assert self.path == "/api/v1/bom"
            assert self.headers.get("X-Api-Key") == canary
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
            if state["requests"] == state["failure_at"]:
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            self.reply({"token": str(uuid.uuid4())})

        def do_GET(self):
            assert self.path.startswith("/api/v1/event/token/")
            assert self.headers.get("X-Api-Key") == canary
            state["requests"] += 1
            state["queries"] += 1
            if state["queries"] == 3:
                self.reply({"error": "synthetic query unavailable"}, 503)
            else:
                self.reply({"processing": state["queries"] == 1})

        def reply(self, value, code=200):
            body = json.dumps(value).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(str(TLS / "SYNTHETIC-ONLY-cert.pem"), str(TLS / "SYNTHETIC-ONLY-key.pem"))
    server.socket = tls.wrap_socket(server.socket, server_side=True)
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

    def run(*command, code=0, as_json=True, cwd=work):
        argv = [binary, *map(str, command)]
        if as_json:
            argv.append("--json")
        result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True)
        assert canary not in result.stdout + result.stderr, "secret in CLI output"
        commands.append({"args": list(map(str, command)), "exit": result.returncode})
        assert result.returncode == code, (command, result.returncode, result.stdout, result.stderr)
        return json.loads(result.stdout) if as_json else result

    def save(config, directory=work):
        (directory / "rio.yaml").write_text(json.dumps(config, indent=2) + "\n")

    def configure(directory, label=None):
        shutil.copytree(HERE / "fixtures", directory / "fixtures")
        config = json.loads((HERE / "rio.yaml").read_text())
        for target in config["delivery"]["targets"].values():
            target["url"] = "https://127.0.0.1:" + str(server.server_port)
            target["caFile"] = str(TLS / "SYNTHETIC-ONLY-cert.pem")
        if label:
            config["delivery"]["targets"]["archive"]["project"]["name"] = label + "-archive"
            config["delivery"]["targets"]["security"]["overrides"] = {
                artifact: {"project": {"name": label + "-" + artifact, "version": "1"}}
                for artifact in ("alpha-server", "beta-client")}
        save(config, directory)
        return config

    try:
        config = configure(work)
        # The successful two-command flow. A failed enforced gate would stop here.
        run("normalize", "--gate", "fail", as_json=False)
        first = run("deliver", "--evidence", "client.json")
        assert first["delivery"]["outcome"] == "accepted" and state["requests"] == 3
        original = (work / "client.json").read_bytes()
        original_sha = hashlib.sha256(original).hexdigest()
        (retained / "success.json").write_bytes(original)
        record = json.loads(original)
        assert len(record["batches"][0]["pairs"]) == 3
        assert record["batches"][0]["exclusions"][0]["artifactIDs"] == ["beta-client"]
        for artifact in record["normalization"]["index"]["artifacts"]:
            assert artifact["specVersion"] == {"input": "1.4", "output": "1.6"}
            assert artifact["selection"]["kind"] == "artifactSet" and artifact["enrichment"]
            ledger = artifact["normalization"]
            repair = next(c for c in ledger["changes"] if c["target"] == "/components/0/purl")
            assert repair["after"] == "pkg:maven/com.google.code.gson/gson@2.8.9"
            assert repair["resolution"]["kind"] == "built-in-entry"
            assert len(ledger["unmapped"]) == 1 and artifact["checks"]["mode"] == "fail"
        assert all(x["summary"]["acknowledgment"] == "accepted" for x in record["deliveries"])
        assert all(x["summary"]["lastObservation"]["observation"]["details"]["tls"] == {
            "certificateVerification": "enforced", "observed": True} for x in record["deliveries"])

        # Explicit bypass is a separate destination identity, not a policy-changing retry.
        bypass = dict(config["delivery"]["targets"]["security"])
        bypass.pop("caFile")
        bypass["insecureSkipVerify"] = True
        bypass["project"] = {"name": "synthetic-bypass", "version": "1"}
        config["delivery"]["targets"]["bypass"] = bypass
        save(config)
        run("deliver", "--artifact", "alpha-server", "--target", "bypass", "--evidence", "bypass.json")
        bypass_doc = json.loads((work / "bypass.json").read_bytes())
        tls_fact = bypass_doc["deliveries"][0]["summary"]["lastObservation"]["observation"]["details"]["tls"]
        assert tls_fact == {"certificateVerification": "disabled", "observed": True}
        descriptor = bypass_doc["batches"][0]["scope"]
        assert descriptor["normalizationManifestSHA256"] != descriptor["deliveryManifestSHA256"]
        assert state["requests"] == 4
        journal = next(i["record"] for i in first["delivery"]["items"]
                       if i["artifactId"] == "alpha-server" and i["target"] == "security")
        for code in (0, 0, 4):
            run("delivery", "reconcile", "--record", journal, code=code)
        assert state["requests"] == 7

        # Keep partial/lost-response and failed-gate cases separate from the success story.
        partial = work / "partial-case"
        partial.mkdir()
        configure(partial, "partial")
        run("normalize", "--gate", "fail", as_json=False, cwd=partial)
        state["failure_at"] = state["requests"] + 2
        result = run("deliver", "--evidence", "partial.json", code=4, cwd=partial)
        assert result["delivery"]["outcome"] == "partial" and state["requests"] == 9
        shutil.copyfile(partial / "partial.json", retained / "partial.json")
        state["failure_at"] = None
        failed = work / "failed-case"
        failed.mkdir()
        bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
               "metadata": {"component": {"type": "application", "name": "failed-subject"}}}
        (failed / "bom.json").write_text(json.dumps(bom))
        target = dict(config["delivery"]["targets"]["security"])
        target["project"] = {"name": "synthetic-explicit-override", "version": "1"}
        save({"version": 1, "artifacts": [{"id": "failed", "sbom": "bom.json"}],
              "delivery": {"targets": {"security": target}}}, failed)
        run("normalize", "--gate", "fail", code=1, as_json=False, cwd=failed)
        run("record", "--schema-version", "2", "--output", retained / "failed-gate.json", cwd=failed)
        assert state["requests"] == 9, "failed gate export performed delivery"
        run("deliver", "--allow-failed-gate", "--evidence", "override.json", cwd=failed)
        shutil.copyfile(failed / "override.json", retained / "explicit-override.json")
        assert state["requests"] == 10
        stop()
        env.pop("RIO_DEMO_CLIENT_KEY")

        # Rebuild from immutable batch sources, never the now-invalid working index.
        (work / "target/rio/index.json").write_text("{}")
        run("record", "--schema-version", "2", "--batch", "client.json.batch.json",
            "--batch", "bypass.json.batch.json", "--output", retained / "record-after.json")
        after = json.loads((retained / "record-after.json").read_bytes())
        observed = next(x for x in after["deliveries"] if "latestActivity" in x["summary"])
        assert observed["summary"]["acknowledgment"] == "accepted"
        assert observed["summary"]["latestActivity"]["observation"]["value"] == "not-observed"
        assert observed["summary"]["lastObservation"]["observation"]["kind"] == "unavailable"
        recipient = retained / "recipient"
        recipient.mkdir()
        shutil.copyfile(retained / "record-after.json", recipient / "record.json")
        for path in work.rglob("*.json"):
            assert canary.encode() not in path.read_bytes(), "secret in source evidence"
        shutil.rmtree(work)
        run("record", "inspect", "--file", "record.json", cwd=recipient)
        run("record", "report", "--file", "record.json", "--output", "report.html", cwd=recipient)
        assert hashlib.sha256((retained / "success.json").read_bytes()).hexdigest() == original_sha
        for stem in ("success", "partial", "failed-gate", "explicit-override"):
            run("record", "inspect", "--file", retained / (stem + ".json"), cwd=recipient)
            run("record", "report", "--file", retained / (stem + ".json"),
                "--output", retained / (stem + ".html"), cwd=recipient)
        for kind in ("repair", "receipt", "coverage"):
            corrupt = json.loads((recipient / "record.json").read_bytes())
            if kind == "repair":
                corrupt["normalization"]["index"]["artifacts"][0]["normalization"]["changes"][0]["after"] = "forged"
            elif kind == "receipt":
                corrupt["deliveries"][0]["summary"]["acknowledgment"] = "forged"
            else:
                corrupt["batches"][0]["pairs"][0]["evidence"] = "forged"
            path = recipient / ("corrupt-" + kind + ".json")
            path.write_text(json.dumps(corrupt))
            run("record", "inspect", "--file", path, code=2, cwd=recipient)
            run("record", "report", "--file", path, "--output", recipient / (kind + ".html"), code=2, cwd=recipient)
            path.unlink()
        for path in retained.rglob("*"):
            if path.is_file() and path.suffix in (".json", ".html"):
                assert canary.encode() not in path.read_bytes(), "secret in handoff"
        (retained / "walkthrough.json").write_text(json.dumps({"syntheticReceiver": True,
            "networkRequests": state["requests"], "commands": commands,
            "originalSnapshotSHA256": original_sha, "sourceWorkspaceRemoved": True}, indent=2) + "\n")
        print("PASS: two artifact sets, uplift/repair/enrichment, exact routing and trusted HTTPS.")
        print("PASS: separate TLS bypass, lost response, failed gate/explicit override and retained reconciliation snapshots.")
        print("PASS: receiver stopped and sources removed; offline JSON/HTML handoff; three projection corruptions refused.")
        print("Recipient files:", recipient)
    finally:
        stop()


if __name__ == "__main__":
    main()
