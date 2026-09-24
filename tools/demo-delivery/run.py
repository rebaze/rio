#!/usr/bin/env python3
"""One rio.yaml, default batch delivery. Every receiver observation is synthetic."""
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
    env = dict(os.environ, RIO_SYNTHETIC_KEY="synthetic-demo-key", RIO_MISSING_KEY="")
    received, expected, modes = [], set(), {"security": "accepted", "mirror": "accepted"}

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
                ("Content-Type: " + self.headers["Content-Type"] + "\r\n\r\n").encode() + body)
            parts = {part.get_param("name", header="content-disposition"): part.get_payload(decode=True)
                     for part in message.iter_parts()}
            digest = hashlib.sha256(parts["bom"]).hexdigest()
            assert digest in expected, "upload differed from a verified normalization output"
            received.append({"sha256": digest, "receiver": self.server.label, "synthetic": True,
                             "fields": {k: v.decode() for k, v in parts.items() if k != "bom"}})
            mode = modes[self.server.label]
            if mode == "lost":
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write((json.dumps({"token": TOKEN}) if mode == "accepted" else "{}").encode())

        def do_GET(self):
            assert self.path == "/api/v1/event/token/" + TOKEN, "no project lookup is needed"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"processing":false}')

    servers, threads = [], []
    for label in ("security", "mirror"):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
        server.label = label
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append(server)
        threads.append(thread)
    manifest = (HERE / "rio.yaml").read_text().replace("PRIMARY_PORT", str(servers[0].server_port))
    manifest = manifest.replace("MIRROR_PORT", str(servers[1].server_port))
    (work / "rio.yaml").write_text(manifest)
    seed = json.loads((HERE / "bom.json").read_text())

    def source(name, bom=None):
        folder = work / "services" / name
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "pom.xml").write_text("<project/>\n")
        doc = json.loads(json.dumps(seed if bom is None else bom))
        doc["metadata"]["component"]["name"] = name
        (folder / "bom.json").write_text(json.dumps(doc))

    for name in ("application", "worker", "test-fixtures"):
        source(name)

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

    def refresh_outputs(folder="target/rio"):
        idx = json.loads((work / folder / "index.json").read_text())
        for artifact in idx["artifacts"]:
            expected.add(artifact["output"]["sha256"])
        return idx

    def single(record, *extra, code=0):
        return run("deliver", "--artifact", "application", "--target", "security",
                   "--record", record, *extra, code=code)

    try:
        # Normal path uses default filenames and no delivery selection or record flags.
        run("normalize", "--gate", "fail", "--attest", json_result=False)
        idx = refresh_outputs()
        assert len(idx["artifacts"]) == 3
        # Delivery uses index membership even when source modules change afterwards.
        shutil.rmtree(work / "services/worker")
        source("late-module")
        plan = run("delivery", "plan")
        assert [(item["artifactId"], item["target"]) for item in plan["items"]] == [
            ("application", "security"), ("application", "z-mirror"), ("worker", "security")]
        assert plan["unusedRules"] == [{"target": "z-mirror", "artifactId": "absent-module", "rule": "override"}]
        assert not (work / "target/rio/deliveries").exists()
        result = run("deliver")
        assert result["schemaVersion"] == 2 and result["outcome"] == "accepted"
        assert all(item["state"] == "accepted" for item in result["items"])
        assert [entry["fields"]["projectName"] for entry in received] == ["application", "mirror-application", "worker"]
        assert all(entry["fields"]["autoCreate"] == "false" for entry in received)
        first = result["items"][0]["record"]
        assert run("delivery", "inspect", "--record", first)["acknowledgment"] == "accepted"
        assert run("delivery", "reconcile", "--record", first)["activity"] == "not-observed"
        count = len(received)
        assert run("deliver", code=2)["error"]["code"] == "record_exists"
        assert len(received) == count

        # Collision and a later target's missing credential both refuse before any request.
        (work / "rio.yaml").write_text(manifest.replace("      exclude: [test-fixtures]", "      project: {name: collision, version: '1'}\n      exclude: [test-fixtures]"))
        assert run("deliver", code=2)["error"]["code"] == "target_collision"
        (work / "rio.yaml").write_text(manifest.replace("      exclude: [worker, test-fixtures]", "      exclude: [worker, test-fixtures]").replace(
            "apiKeyEnv: RIO_SYNTHETIC_KEY\n      exclude: [worker", "apiKeyEnv: RIO_MISSING_KEY\n      exclude: [worker"))
        assert run("deliver", code=2)["error"]["code"] == "invalid_credential"
        assert len(received) == count
        (work / "rio.yaml").write_text(manifest)

        # A fresh output location scopes a deliberate new batch. No automatic resume.
        shutil.copytree(work / "target/rio", work / "partial", ignore=shutil.ignore_patterns("deliveries"))
        modes["mirror"] = "lost"
        partial = run("deliver", "--index", "partial/index.json", code=4)
        assert partial["outcome"] == "partial"
        assert [item["state"] for item in partial["items"]] == ["accepted", "unknown", "unattempted"]
        unknown = partial["items"][1]["record"]
        assert run("delivery", "inspect", "--record", unknown)["outcome"] == "unknown"
        run("delivery", "reconcile", "--record", unknown, code=2)
        count = len(received)
        run("deliver", "--index", "partial/index.json", code=2)
        assert len(received) == count
        modes["mirror"] = "accepted"
        run("deliver", "--index", "partial/index.json", "--artifact", "worker", "--target", "security")
        run("deliver", "--index", "partial/index.json", "--artifact", "application", "--target", "z-mirror",
            "--retry-of", unknown, "--record", "deliberate-retry")

        output = work / "target/rio/application.cdx.json"
        checked = output.read_bytes()
        output.write_bytes(checked + b" ")
        count = len(received)
        single("tampered", code=2)
        assert len(received) == count
        output.write_bytes(checked)
        # Advanced UUID still works without an autoCreate multipart field.
        (work / "rio.yaml").write_text(manifest.replace("      exclude: [test-fixtures]", "      project: {uuid: " + TOKEN + "}\n      exclude: [test-fixtures]"))
        single("uuid")
        assert received[-1]["fields"] == {"project": TOKEN}
        (work / "rio.yaml").write_text(manifest)
        modes["security"] = "malformed"
        assert single("malformed", code=4)["items"][0]["state"] == "unknown"
        modes["security"] = "accepted"

        # Failed gate and skipped schema validation remain separate visible facts.
        shutil.rmtree(work / "services/late-module")
        source("worker")
        missing = json.loads(json.dumps(seed))
        del missing["metadata"]["component"]["version"]
        source("application", missing)
        run("normalize", "--out", "failed", "--gate", "fail", code=1, json_result=False)
        refresh_outputs("failed")
        count = len(received)
        single("failed-gate", "--index", "failed/index.json", code=2)
        assert len(received) == count
        explicit = manifest.replace("      exclude: [test-fixtures]", "      project: {name: application, version: '1.2.3'}\n      exclude: [test-fixtures]")
        (work / "rio.yaml").write_text(explicit)
        overridden = single("overridden-gate", "--index", "failed/index.json", "--allow-failed-gate")
        assert overridden["items"][0]["source"]["gate"] == "fail"
        assert overridden["items"][0]["source"]["allowFailedGate"]

        future = json.loads(json.dumps(seed))
        future["specVersion"] = "1.99"
        future["components"] = [{"type": "library", "group": "p2.eclipse.plugin", "name": "synthetic.unmapped", "version": "1",
                                 "purl": "pkg:p2/synthetic.unmapped@1?classifier=osgi.bundle"}]
        source("application", future)
        (work / "rio.yaml").write_text(manifest.replace("    idFrom: module-directory", "    idFrom: module-directory\n    transforms:\n      - repair-purl: {ecosystem: p2}"))
        run("normalize", "--out", "future", "--attest", json_result=False)
        future_index = refresh_outputs("future")
        artifact = future_index["artifacts"][0]
        assert artifact["schemaValidated"] is False and artifact["transforms"][0]["unmapped"] == 1
        assert single("unmapped-skipped-schema", "--index", "future/index.json")["items"][0]["source"]["schemaValidated"] is False
        (work / "synthetic-requests.json").write_text(json.dumps(received, indent=2))
        print("Synthetic demo passed:", len(received), "uploads; default paths, indexed membership, fan-out, collision/preflight refusal, partial history and deliberate retry.")
        print("Evidence (including unsigned statements and skipped validation):", work)
        print("No real Dependency-Track compatibility or ingestion claim is made by this demo.")
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join()


if __name__ == "__main__":
    main()
