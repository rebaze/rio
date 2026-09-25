#!/usr/bin/env python3
"""Installed-binary OCI walkthrough. Every receiver and subject is synthetic."""
import base64
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
import urllib.parse

HERE = Path(__file__).resolve().parent
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
INDEX = "application/vnd.oci.image.index.v1+json"
SBOM = "application/vnd.cyclonedx+json"
TOKEN = "f90934f5-cb88-47ce-81cb-db06fc67d4b4"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def compact(value):
    return json.dumps(value, separators=(",", ":")).encode()


def main():
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        raise SystemExit("Usage: python tools/demo-oci/run.py /path/to/installed/rio")
    binary = str(Path(sys.argv[1]).resolve())
    work = Path(tempfile.mkdtemp(prefix="rio-oci-demo-"))
    workspace = work / "workspace"
    workspace.mkdir()
    results = work / "results"
    results.mkdir()
    recipient = work / "recipient"
    recipient.mkdir()
    env = dict(os.environ, RIO_OCI_DEMO_USERNAME="synthetic-oci-user-value",
               RIO_OCI_DEMO_PASSWORD="synthetic-oci-password-value",
               RIO_DTRACK_DEMO_KEY="synthetic-dtrack-key-value")
    auth_value = "Basic " + base64.b64encode((env["RIO_OCI_DEMO_USERNAME"] + ":" +
                                             env["RIO_OCI_DEMO_PASSWORD"]).encode()).decode()
    canaries = [env[key] for key in ("RIO_OCI_DEMO_USERNAME", "RIO_OCI_DEMO_PASSWORD", "RIO_DTRACK_DEMO_KEY")]
    canaries.extend([auth_value, "never-copy-synthetic-receiver-error"])
    state = {"blobs": {}, "manifests": {}, "tags": {}, "requests": [], "writes": 0,
             "mode": "normal", "no_referrers": False, "tamper_blob": False, "on_ping": None,
             "stored": threading.Event(), "release": threading.Event(), "dtrack": []}
    lock = threading.Lock()
    steps, selected = [], []
    output_bytes = b""

    class Registry(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def body(self):
            if self.headers.get("Transfer-Encoding", "").lower() != "chunked":
                return self.rfile.read(int(self.headers.get("Content-Length", "0")))
            chunks = []
            while True:
                size = int(self.rfile.readline().split(b";", 1)[0].strip(), 16)
                if not size:
                    self.rfile.readline()
                    break
                chunks.append(self.rfile.read(size))
                assert self.rfile.read(2) == b"\r\n"
            return b"".join(chunks)

        def send(self, status, body=b"", media="application/json", headers=None):
            path = urllib.parse.urlsplit(self.path).path
            state["requests"].append({"method": self.command, "path": path, "status": status,
                                      "synthetic": True})
            self.send_response(status)
            self.send_header("Content-Type", media)
            self.send_header("Content-Length", str(len(body)))
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def error(self, status, code="DENIED"):
            self.send(status, compact({"errors": [{"code": code,
                                                   "message": "never-copy-synthetic-receiver-error"}]}))

        def do_GET(self):
            self.dispatch()

        def do_HEAD(self):
            self.dispatch()

        def do_POST(self):
            self.dispatch()

        def do_PUT(self):
            self.dispatch()

        def dispatch(self):
            with lock:
                url = urllib.parse.urlsplit(self.path)
                path = url.path
                if path.startswith("/api/v1/"):
                    assert self.headers.get("X-Api-Key") == env["RIO_DTRACK_DEMO_KEY"]
                    if self.command == "POST":
                        raw = self.body()
                        message = email.parser.BytesParser(policy=email.policy.default).parsebytes(
                            ("Content-Type: " + self.headers["Content-Type"] + "\r\n\r\n").encode() + raw)
                        parts = {p.get_param("name", header="content-disposition"): p.get_payload(decode=True)
                                 for p in message.iter_parts()}
                        assert parts["bom"] == output_bytes
                        state["dtrack"].append({"sbomSHA256": sha(parts["bom"]), "synthetic": True})
                        state["writes"] += 1
                        self.send(200, compact({"token": TOKEN}))
                    else:
                        assert path == "/api/v1/event/token/" + TOKEN
                        self.send(200, b'{"processing":false}')
                    return
                if self.headers.get("Authorization") != auth_value:
                    # All demo uploads pre-negotiate Basic with a read-only request.
                    self.send(401, b'{"errors":[{"code":"UNAUTHORIZED"}]}',
                              headers={"Www-Authenticate": 'Basic realm="synthetic-oci"'})
                    return
                if path == "/v2/":
                    if state["on_ping"]:
                        state["on_ping"]()
                        state["on_ping"] = None
                    self.send(200)
                    return
                prefix = "/v2/demo/application/"
                assert path.startswith(prefix), "request escaped selected synthetic repository"
                rest = path[len(prefix):]
                if rest.startswith("referrers/"):
                    if state["no_referrers"]:
                        self.error(404, "UNSUPPORTED")
                        return
                    subject = rest[len("referrers/"):]
                    refs = []
                    for digest, raw in state["manifests"].items():
                        doc = json.loads(raw)
                        if doc.get("subject", {}).get("digest") == subject:
                            refs.append({"mediaType": MANIFEST, "digest": digest, "size": len(raw),
                                         "artifactType": SBOM})
                    self.send(200, compact({"schemaVersion": 2, "mediaType": INDEX, "manifests": refs}), INDEX)
                    return
                if rest.startswith("blobs/uploads/"):
                    state["writes"] += 1
                    if self.command == "POST":
                        self.send(202, headers={"Location": prefix + "blobs/uploads/session?state=opaque%2fsession&hint=preserve+me"})
                    else:
                        assert self.command == "PUT"
                        assert url.query.startswith("state=opaque%2fsession&hint=preserve+me&digest=")
                        raw = self.body()
                        digest = "sha256:" + sha(raw)
                        assert urllib.parse.parse_qs(url.query)["digest"] == [digest]
                        state["blobs"][digest] = raw
                        self.send(201, headers={"Docker-Content-Digest": digest, "Location": prefix + "blobs/" + digest})
                    return
                if rest.startswith("blobs/"):
                    digest = rest[len("blobs/"):]
                    if digest not in state["blobs"]:
                        self.error(404, "BLOB_UNKNOWN")
                        return
                    raw = state["blobs"][digest]
                    if state["tamper_blob"] and raw == output_bytes and self.command == "GET":
                        raw = b"!" + raw[1:]  # matching digest header is deliberately false.
                    self.send(200, raw, "application/octet-stream", {"Docker-Content-Digest": digest})
                    return
                assert rest.startswith("manifests/")
                reference = rest[len("manifests/"):]
                if self.command == "PUT":
                    state["writes"] += 1
                    raw = self.body()
                    digest = "sha256:" + sha(raw)
                    assert reference == "rio-sbom-sha256-" + sha(raw)
                    doc = json.loads(raw)
                    layer = doc["layers"][0]
                    assert sha(state["blobs"][layer["digest"]]) == layer["digest"].split(":", 1)[1]
                    state["manifests"][digest] = raw
                    state["tags"][reference] = digest
                    if state["mode"] in ("lost", "crash"):
                        state["requests"].append({"method": "PUT", "path": path, "status": "response-dropped",
                                                  "storedManifestDigest": digest, "synthetic": True})
                        if state["mode"] == "crash":
                            state["stored"].set()
                            # Release the state lock before waiting for the controller process.
                            lock.release()
                            try:
                                state["release"].wait(15)
                            finally:
                                lock.acquire()
                        try:
                            self.connection.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                        self.connection.close()
                        return
                    headers = {"Location": prefix + "manifests/" + digest,
                               "Docker-Content-Digest": digest if state["mode"] != "bad-receipt" else "sha256:" + "0" * 64}
                    if "subject" in doc:
                        headers["OCI-Subject"] = doc["subject"]["digest"]
                    self.send(201, headers=headers)
                    return
                digest = reference if reference.startswith("sha256:") else state["tags"].get(reference)
                raw = state["manifests"].get(digest)
                if raw is None:
                    self.error(404, "MANIFEST_UNKNOWN")
                    return
                self.send(200, raw, json.loads(raw)["mediaType"], {"Docker-Content-Digest": digest})

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Registry)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    stopped = False
    authority = "127.0.0.1:%d" % server.server_port
    manifest_text = (HERE / "rio.yaml").read_text().replace("REGISTRY_AUTHORITY", authority)
    manifest_text = manifest_text.replace("DTRACK_URL", "http://" + authority)
    seed = (HERE / "bom.json").read_bytes()
    (workspace / "bom.json").write_bytes(seed)

    def config(subject=None):
        text = manifest_text
        if subject:
            text = text.replace("      auth:\n", "      subject: " + json.dumps(subject) + "\n      auth:\n")
        (workspace / "rio.yaml").write_text(text)

    def run(*args, code=0, json_result=True, cwd=None):
        command = [binary, *map(str, args)] + (["--json"] if json_result else [])
        result = subprocess.run(command, cwd=cwd or workspace, env=env, capture_output=True, text=True)
        assert result.returncode == code, (args, result.returncode, result.stdout, result.stderr)
        assert not any(secret in result.stdout + result.stderr for secret in canaries)
        steps.append({"command": list(map(str, args)), "exit": result.returncode, "synthetic": True})
        if json_result:
            value = json.loads(result.stdout)
            (results / ("%02d.json" % len(steps))).write_text(result.stdout)
            return value
        return result

    def one(result):
        return result["items"][0]["result"]

    def deliver(name, code=0, *extra):
        result = run("deliver", "--target", "registry", "--record", name, *extra, code=code)
        if (workspace / name).is_dir():
            selected.append(str(workspace / name))
        return one(result) if result["items"][0].get("result") else result

    def subject(label):
        raw = compact({"schemaVersion": 2, "mediaType": INDEX, "manifests": [],
                       "annotations": {"io.rebaze.rio.synthetic": label}})
        digest = "sha256:" + sha(raw)
        with lock:
            state["manifests"][digest] = raw
        return {"mediaType": INDEX, "digest": digest, "size": len(raw)}

    try:
        config()
        run("normalize", "--gate", "fail", "--attest", json_result=False)
        index_path = workspace / "target/rio/index.json"
        raw_index = index_path.read_bytes()
        index_doc = json.loads(raw_index)
        output_path = index_path.parent / index_doc["artifacts"][0]["output"]["path"]
        output_bytes = output_path.read_bytes()
        assert sha(output_bytes) == index_doc["artifacts"][0]["output"]["sha256"]
        count = len(state["requests"])
        old_password = env["RIO_OCI_DEMO_PASSWORD"]
        env["RIO_OCI_DEMO_PASSWORD"] = "\r\n"
        (workspace / "rio.yaml").write_text(manifest_text.replace("      auth:\n", "      caFile: missing-offline-ca.pem\n      auth:\n"))
        plan = run("delivery", "plan")
        assert len(plan["items"][0]["expectedReferences"]) == 3 and len(state["requests"]) == count
        env["RIO_OCI_DEMO_PASSWORD"] = old_password
        config()
        # The first read-only HTTP request happens after verification. Replacing
        # the source then must not change the uploaded immutable snapshot.
        state["on_ping"] = lambda: output_path.write_bytes(b"source replaced after verification")
        batch = run("deliver")
        output_path.write_bytes(output_bytes)
        assert batch["outcome"] == "accepted" and len(batch["items"]) == 2
        selected.extend(item["record"] for item in batch["items"])
        initial = batch["items"][0]["record"]
        initial_result = batch["items"][0]["result"]
        assert initial_result["acknowledgment"] == "accepted" and "verification" not in initial_result
        assert state["blobs"]["sha256:" + sha(output_bytes)] == output_bytes
        (work / "retrieved-sbom.cdx.json").write_bytes(state["blobs"]["sha256:" + sha(output_bytes)])
        assert run("delivery", "reconcile", "--record", initial)["verification"] == "verified"
        run("delivery", "reconcile", "--record", batch["items"][1]["record"])
        writes = state["writes"]
        repeated = deliver("explicit-retry", 0, "--retry-of", initial)
        assert repeated["verification"] == "verified" and state["writes"] == writes
        assert repeated["observations"][0]["code"] == "already_present"
        output_path.write_bytes(output_bytes + b" ")
        count = len(state["requests"])
        deliver("tampered", 2)
        assert len(state["requests"]) == count
        output_path.write_bytes(output_bytes)

        attached = subject("attached-example")
        config(attached)
        attached_result = deliver("attached")
        assert len(attached_result["expectedReferences"]) == 4
        assert run("delivery", "reconcile", "--record", "attached")["verification"] == "verified"
        writes = state["writes"]
        state["tamper_blob"] = True
        assert run("delivery", "reconcile", "--record", "attached", code=4)["verification"] == "mismatch"
        state["tamper_blob"] = False
        assert run("delivery", "reconcile", "--record", "attached")["verification"] == "verified"
        assert state["writes"] == writes

        config(subject("unsupported-api"))
        state["no_referrers"] = True
        writes = state["writes"]
        assert deliver("unsupported-referrers", 4)["acknowledgment"] == "unknown"
        assert state["writes"] == writes
        state["no_referrers"] = False
        config(subject("unusable-receipt"))
        state["mode"] = "bad-receipt"
        bad = deliver("bad-receipt", 4)
        assert bad["acknowledgment"] == "unknown" and bad["observations"][0]["httpStatus"] == 201
        assert bad["observations"][0]["value"] == "accepted"
        state["mode"] = "normal"
        assert run("delivery", "reconcile", "--record", "bad-receipt")["verification"] == "verified"

        config(subject("lost-response"))
        state["mode"] = "lost"
        lost = deliver("lost-response", 4)
        assert lost["acknowledgment"] == "unknown"
        state["mode"] = "normal"
        recovered = run("delivery", "reconcile", "--record", "lost-response")
        assert recovered["acknowledgment"] == "unknown" and recovered["verification"] == "verified"

        # A recorded failed gate is refused before HTTP; its explicit override
        # is separate evidence tied to its own exact failed normalization index.
        config()
        broken = json.loads(seed)
        del broken["metadata"]["component"]["version"]
        (workspace / "bom.json").write_bytes(compact(broken))
        run("normalize", "--out", "failed", "--gate", "fail", code=1, json_result=False)
        count = len(state["requests"])
        run("deliver", "--index", "failed/index.json", "--target", "registry", "--record", "failed-refused", code=2)
        assert len(state["requests"]) == count
        run("deliver", "--index", "failed/index.json", "--target", "registry", "--record", "failed-override", "--allow-failed-gate")
        (workspace / "bom.json").write_bytes(seed)

        config(subject("process-crash"))
        state["mode"] = "crash"
        command = [binary, "deliver", "--target", "registry", "--record", "crash", "--json"]
        process = subprocess.Popen(command, cwd=workspace, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            assert state["stored"].wait(10), "synthetic registry never stored the manifest"
            process.kill()
            process.communicate(timeout=10)
            assert process.returncode != 0
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=10)
            state["release"].set()
        state["mode"] = "normal"
        steps.append({"command": command[1:], "exit": "killed-after-registry-store-before-response", "synthetic": True})
        crash = workspace / "crash"
        assert list(crash.glob("*.json")) == [crash / "00000000000000000000.json"]
        run("delivery", "inspect", "--record", "crash", code=2)
        (workspace / "crash.lock").rmdir()  # known child has exited; explicit owned-lock recovery.
        selected.append(str(crash))
        (work / "capture-index.json").write_bytes(raw_index)
        index_path.unlink()
        output_path.unlink()
        (workspace / "bom.json").unlink()
        before = (crash / "00000000000000000000.json").read_bytes()
        recovered = run("delivery", "reconcile", "--record", "crash")
        assert recovered["acknowledgment"] == "unknown" and recovered["verification"] == "verified"
        assert (crash / "00000000000000000000.json").read_bytes() == before
        assert not (crash / "00000000000000000002.json").exists(), "recovery fabricated a submission"
        count = len(state["requests"])
        assert run("delivery", "inspect", "--record", "crash")["acknowledgment"] == "unknown"
        assert len(state["requests"]) == count

        server.shutdown()
        server.server_close()
        thread.join()
        stopped = True
        env["RIO_OCI_DEMO_PASSWORD"] = "\r\n"
        args = ["record", "--index", str(work / "capture-index.json"), "--output", str(recipient / "record.json")]
        for path in selected:
            args.extend(["--delivery-record", path])
        assert run(*args)["counts"]["deliveries"] == len(selected)
        run("record", "--index", "failed/index.json", "--delivery-record", "failed-override",
            "--output", str(work / "failed-record.json"))
        shutil.rmtree(workspace)
        (work / "capture-index.json").unlink()
        portable = run("record", "inspect", "--file", "record.json", cwd=recipient)
        assert len(portable["record"]["deliveries"]) == len(selected)
        corrupt = json.loads((recipient / "record.json").read_bytes())
        corrupt["deliveries"][0]["summary"]["acknowledgment"] = "invented"
        (recipient / "corrupt.json").write_bytes(compact(corrupt))
        run("record", "inspect", "--file", "corrupt.json", cwd=recipient, code=2)
        (work / "synthetic-observations.json").write_bytes(compact({"synthetic": True,
            "sbomSHA256": sha(output_bytes), "requests": state["requests"], "dtrack": state["dtrack"]}))
        (work / "walkthrough.json").write_bytes(compact({"synthetic": True, "steps": steps}))
        print("PASS: synthetic standalone/attached OCI, exact snapshot, mixed delivery, bad receipt, lost response and real process-crash recovery.")
        print("PASS: failed gate/tamper refusal, content mismatch, required discovery and portable mixed record inspection with source workspace removed.")
        print("Retained synthetic evidence:", work)
        print("No real registry/vendor compatibility, producer authentication, security-analysis or future-retention claim is made.")
    finally:
        state["release"].set()
        if not stopped:
            server.shutdown()
            server.server_close()
            thread.join()


if __name__ == "__main__":
    main()
