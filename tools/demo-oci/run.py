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
    steps, receipts = [], []
    originals = {}
    index_path = None
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
                        assert parts["projectName"] == b"synthetic-app" and parts["projectVersion"] == b"1.2.3"
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

    def capture(path, name):
        path = Path(path)
        if not path.is_absolute():
            path = workspace / path
        raw = path.read_bytes()
        document = json.loads(raw)
        assert document["kind"] == "rio-run-receipt" and document["schemaVersion"] == 1
        assert not any(secret.encode() in raw for secret in canaries)
        assert not any(key in document for key in ("sources", "indexes", "events", "evidence"))
        copy = recipient / (name + ".json")
        copy.write_bytes(raw)
        originals[path] = raw
        receipts.append(copy)
        return document

    def receipt(result):
        return json.loads(Path(result["receipt"]["path"]).read_bytes())

    def run(*args, code=0, json_result=True, cwd=None):
        command = [binary, *map(str, args)] + (["--json"] if json_result else [])
        result = subprocess.run(command, cwd=cwd or workspace, env=env, capture_output=True, text=True)
        assert result.returncode == code, (args, result.returncode, result.stdout, result.stderr)
        assert not any(secret in result.stdout + result.stderr for secret in canaries)
        steps.append({"command": list(map(str, args)), "exit": result.returncode, "synthetic": True})
        if json_result:
            value = json.loads(result.stdout)
            (results / ("%02d.json" % len(steps))).write_text(result.stdout)
            if isinstance(value.get("receipt"), dict) and value["receipt"].get("path"):
                doc = capture(value["receipt"]["path"], "%02d-%s" % (len(steps), value.get("operation", "pipeline")))
                if doc["run"]["operation"] in ("deliver", "reconcile"):
                    assert all(a.get("preExisting") and not a.get("changes") for a in doc.get("artifacts", []))
                if doc["run"]["operation"] == "reconcile":
                    assert all(d.get("prior") and not d.get("submitted") for d in doc["deliveries"])
            return value
        return result

    def one(result):
        return result["items"][0]["result"]

    def deliver(name, code=0, *extra):
        result = run("deliver", "--index", index_path, "--target", "registry", "--record", name, *extra, code=code)
        if result.get("receipt"):
            doc = receipt(result)
            if doc.get("deliveries"):
                assert all(d["target"] == "registry" for d in doc["deliveries"])
                assert any(e.get("target") == "security" and e["reason"] == "target-filter"
                           for e in doc.get("exclusions", []))
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
        count = len(state["requests"])
        old_password = env["RIO_OCI_DEMO_PASSWORD"]
        env["RIO_OCI_DEMO_PASSWORD"] = "\r\n"
        (workspace / "rio.yaml").write_text(manifest_text.replace("      auth:\n", "      caFile: missing-offline-ca.pem\n      auth:\n"))
        run("plan")
        assert len(state["requests"]) == count
        env["RIO_OCI_DEMO_PASSWORD"] = old_password
        config()

        # One invocation verifies both targets' snapshots before any network request.
        # Mutating its output on the first authenticated read must not alter uploads.
        def replace_after_verification():
            nonlocal output_bytes
            indexes = list((workspace / "target/rio/runs").glob("*/index.json"))
            assert len(indexes) == 1
            index = json.loads(indexes[0].read_bytes())
            output = indexes[0].parent / index["artifacts"][0]["output"]["path"]
            output_bytes = output.read_bytes()
            assert sha(output_bytes) == index["artifacts"][0]["output"]["sha256"]
            output.write_bytes(b"source replaced after verification")

        state["on_ping"] = replace_after_verification
        pipeline = run()
        assert pipeline["outcome"] == "success"
        index_path = Path(pipeline["runDirectory"]) / "index.json"
        index_doc = json.loads(index_path.read_bytes())
        output_path = index_path.parent / index_doc["artifacts"][0]["output"]["path"]
        output_path.write_bytes(output_bytes)
        primary = receipt(pipeline)
        assert primary["run"]["operation"] == "pipeline" and len(primary["deliveries"]) == 2
        assert primary["artifacts"][0]["input"]["sha256"] == sha(seed)
        assert primary["artifacts"][0]["output"]["sha256"] == sha(output_bytes)
        assert all(d["state"] == "accepted" for d in primary["deliveries"])
        assert all(d["transport"] == {"scheme": "http", "certificateVerification": "not-applicable"}
                   for d in primary["deliveries"])
        oci = next(d for d in primary["deliveries"] if d["target"] == "registry")
        assert len(oci["submitted"]) == 3
        for body in oci["submitted"]:
            identity = primary["artifacts"][0]["output"] if body.get("artifactOutput") else body
            digest = "sha256:" + identity["sha256"]
            raw = state["blobs"].get(digest, state["manifests"].get(digest))
            assert raw is not None and len(raw) == identity["size"] and sha(raw) == identity["sha256"]
        dtrack = next(d for d in primary["deliveries"] if d["target"] == "security")
        assert dtrack["submitted"][0]["artifactOutput"] == "application"
        assert any(ref["value"] == TOKEN for response in dtrack["responses"] for ref in response.get("references", []))
        assert state["blobs"]["sha256:" + sha(output_bytes)] == output_bytes
        (work / "retrieved-sbom.cdx.json").write_bytes(output_bytes)
        mappings = json.loads((Path(pipeline["runDirectory"]) / ".internal/attempts.json").read_bytes())
        journals = {d["target"]: next(m["journal"] for m in mappings if m["attemptId"] == d["attemptId"])
                    for d in primary["deliveries"]}
        initial = journals["registry"]
        count = len(state["requests"])
        env["RIO_OCI_DEMO_PASSWORD"] = "\r\n"
        plan = run("delivery", "plan", "--index", index_path)
        assert len(plan["items"][0]["expectedReferences"]) == 3 and len(state["requests"]) == count
        env["RIO_OCI_DEMO_PASSWORD"] = old_password
        assert run("delivery", "reconcile", "--record", initial)["verification"] == "verified"
        run("delivery", "reconcile", "--record", journals["security"])
        writes = state["writes"]
        repeated = deliver("explicit-retry", 0, "--retry-of", initial)
        assert repeated["verification"] == "verified" and state["writes"] == writes
        assert repeated["observations"][0]["code"] == "already_present"
        retry_receipt = json.loads(receipts[-1].read_bytes())
        assert retry_receipt["deliveries"][0]["prior"]["attemptId"] == oci["attemptId"]
        assert not retry_receipt["deliveries"][0].get("submitted")
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
        failed = run("normalize", "--out", "failed", "--gate", "fail", code=1)
        failed_index = Path(failed["runDirectory"]) / "index.json"
        assert receipt(failed)["run"]["operation"] == "normalize"
        count = len(state["requests"])
        run("deliver", "--index", failed_index, "--target", "registry", "--record", "failed-refused", code=2)
        assert len(state["requests"]) == count
        override = run("deliver", "--index", failed_index, "--target", "registry", "--record", "failed-override", "--allow-failed-gate")
        override_receipt = receipt(override)
        assert override_receipt["run"]["overrides"]["allow-failed-gate"] == "true"
        assert override_receipt["artifacts"][0]["checks"]["gate"] == "fail"
        assert override_receipt["artifacts"][0]["input"]["sha256"] == receipt(failed)["artifacts"][0]["output"]["sha256"]
        (workspace / "bom.json").write_bytes(seed)

        config(subject("process-crash"))
        state["mode"] = "crash"
        existing_runs = set((workspace / "target/rio/runs").iterdir())
        command = [binary, "deliver", "--index", str(index_path), "--target", "registry", "--record", "crash", "--json"]
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
        crash_runs = set((workspace / "target/rio/runs").iterdir()) - existing_runs
        assert len(crash_runs) == 1
        crash_run = crash_runs.pop()
        assert not (crash_run / "record.json").exists()
        count = len(state["requests"])
        recovery_path = recipient / "crash-incomplete.json"
        run("record", "recover", "--run", crash_run, "--output", recovery_path)
        assert len(state["requests"]) == count and (workspace / "crash.lock").is_dir()
        incomplete = json.loads(recovery_path.read_bytes())
        assert incomplete["run"]["outcome"] == "incomplete" and not incomplete["run"].get("finishedAt")
        assert incomplete["run"]["stages"]["delivery"] == "incomplete"
        assert incomplete["deliveries"][0]["state"] == "unknown"
        assert incomplete["deliveries"][0]["errorCode"] == "response_unavailable"
        assert incomplete["deliveries"][0]["requestMayHaveOccurred"]
        assert not incomplete["deliveries"][0].get("submitted")
        receipts.append(recovery_path)
        # Explicit specialist reconciliation after confirming our child exited.
        # Offline receipt recovery above never removes or bypasses the owned lock.
        (workspace / "crash.lock").rmdir()
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
        for path, raw in originals.items():
            assert path.read_bytes() == raw, "later invocation changed a completed receipt"
        shutil.rmtree(workspace)
        for path in receipts:
            portable = run("record", "inspect", "--file", path.name, cwd=recipient)
            assert portable["record"] == json.loads(path.read_bytes())
            run("record", "report", "--file", path.name, "--output", path.with_suffix(".html").name, cwd=recipient)
            html = path.with_suffix(".html").read_text()
            assert sha(path.read_bytes()) in html and "<script" not in html.lower()
            assert not any(secret in html for secret in canaries)
        corrupt = json.loads(receipts[0].read_bytes())
        corrupt["deliveries"][0]["state"] = "invented"
        (recipient / "corrupt.json").write_bytes(compact(corrupt))
        run("record", "inspect", "--file", "corrupt.json", cwd=recipient, code=2)
        (work / "synthetic-observations.json").write_bytes(compact({"synthetic": True,
            "sbomSHA256": sha(output_bytes), "requests": state["requests"], "dtrack": state["dtrack"]}))
        (work / "walkthrough.json").write_bytes(compact({"synthetic": True, "steps": steps}))
        print("PASS: synthetic standalone/attached OCI, exact snapshot, mixed delivery, bad receipt, lost response and real process-crash recovery.")
        print("PASS: failed gate/tamper refusal, content mismatch, required discovery and separate compact receipts inspected/rendered with source workspace removed.")
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
