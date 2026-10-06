#!/usr/bin/env python3
"""Exercise an owned real Dependency-Track fixture over HTTPS with an installed Rio."""
import argparse
from email import policy
from email.parser import BytesParser
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import urllib.error

import setup

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
TLS = REPO / "tools/demo-dtrack-tls"
CLIENT = REPO / "tools/demo-client-record"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--adapter-tests", action="store_true", help="also run the Go adapter suite through the TLS gateway")
    args = parser.parse_args()
    root, binary = args.root.resolve(), args.binary.resolve()
    state, private = setup.load(root)
    if state["phase"] != "ready":
        raise setup.SetupError("fixture is not ready")
    if "http://" + setup.compose(state, private, "port", "apiserver", "8080") != state["url"]:
        raise setup.SetupError("owned fixture endpoint changed")
    config = json.loads((root / "test-env.json").read_text())
    if config["RIO_DTRACK_TEST_URL"] != state["url"]:
        raise setup.SetupError("private test endpoint differs from owned fixture")
    authority = urllib.parse.urlsplit(setup.local_url(state["url"]))
    observed = {"requests": 0, "uploads": 0}
    submitted = []
    secret_values = [private["databasePassword"], private["adminPassword"], config["RIO_DTRACK_TEST_API_KEY"], config["RIO_DTRACK_TEST_DENIED_KEY"]]

    class Gateway(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def forward(self):
            if not self.path.startswith(("/api/v1/", "/api/version")):
                self.send_error(404)
                return
            observed["requests"] += 1
            if self.command == "POST" and self.path == "/api/v1/bom":
                observed["uploads"] += 1
            body = bytearray()
            if self.headers.get("Transfer-Encoding") == "chunked":
                while True:
                    size = int(self.rfile.readline().strip().split(b";")[0], 16)
                    if not size:
                        self.rfile.readline()
                        break
                    if len(body) + size > 65 << 20:
                        self.send_error(413)
                        return
                    body.extend(self.rfile.read(size))
                    if self.rfile.read(2) != b"\r\n":
                        self.send_error(400)
                        return
            else:
                size = int(self.headers.get("Content-Length", 0))
                if size > 65 << 20:
                    self.send_error(413)
                    return
                body.extend(self.rfile.read(size))
            if self.command == "POST" and self.path == "/api/v1/bom":
                message = BytesParser(policy=policy.default).parsebytes(
                    ("Content-Type: " + self.headers["Content-Type"] + "\r\n\r\n").encode() + body)
                fields = {part.get_param("name", header="Content-Disposition"): part.get_payload(decode=True)
                          for part in message.iter_parts()}
                submitted.append(fields)
            headers = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "connection", "transfer-encoding", "content-length")}
            connection = http.client.HTTPConnection(authority.hostname, authority.port, timeout=30)
            try:
                connection.request(self.command, self.path, bytes(body), headers)
                response = connection.getresponse()
                raw = response.read(4 << 20)
                self.send_response(response.status)
                for k, v in response.getheaders():
                    if k.lower() not in ("connection", "transfer-encoding", "content-length"):
                        self.send_header(k, v)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)
            except (OSError, http.client.HTTPException):
                self.send_error(502, "synthetic gateway unavailable")
            finally:
                connection.close()

        do_GET = forward
        do_POST = forward
        do_PUT = forward

    gateway = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Gateway)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(TLS / "SYNTHETIC-ONLY-cert.pem"), str(TLS / "SYNTHETIC-ONLY-key.pem"))
    gateway.socket = context.wrap_socket(gateway.socket, server_side=True)
    thread = threading.Thread(target=gateway.serve_forever, daemon=True)
    thread.start()
    stopped = False
    tls_url = "https://127.0.0.1:" + str(gateway.server_port)
    run_root = root / ("exercise-" + secrets.token_hex(6))
    run_root.mkdir(mode=0o700)
    work = run_root / "source-workspace"
    work.mkdir()
    env = dict(os.environ, **config)
    env["RIO_DEMO_CLIENT_KEY"] = config["RIO_DTRACK_TEST_API_KEY"]
    commands = []

    def stop_gateway():
        nonlocal stopped
        if not stopped:
            gateway.shutdown()
            gateway.server_close()
            thread.join()
            stopped = True

    def safe_bytes(raw):
        if any(value.encode() in raw for value in secret_values):
            raise setup.SetupError("credential canary found in evidence or intended log")

    def run(*args, code=0, as_json=True, cwd=work):
        command = [str(binary), *map(str, args)]
        if as_json:
            command.append("--json")
        result = subprocess.run(command, cwd=cwd, env=env, capture_output=True)
        safe_bytes(result.stdout + result.stderr)
        commands.append({"args": list(map(str, args)), "exit": result.returncode})
        if result.returncode != code:
            raise setup.SetupError("installed binary operation " + " ".join(map(str, args[:2])) + " returned " + str(result.returncode) + "; expected " + str(code))
        if not as_json:
            return result
        value = json.loads(result.stdout)
        if "receipt" in value:
            raw = Path(value["receipt"]["path"]).read_bytes()
            safe_bytes(raw)
            if hashlib.sha256(raw).hexdigest() != value["receipt"]["sha256"] or len(raw) != value["receipt"]["size"]:
                raise setup.SetupError("receipt publication digest or size differs")
        return value

    def save(value):
        (work / "rio.yaml").write_text(json.dumps(value, indent=2) + "\n")

    def read_inventory(path):
        request = urllib.request.Request(state["url"] + path, headers={"X-Api-Key": config["RIO_DTRACK_TEST_API_KEY"]})
        try:
            with urllib.request.build_opener(setup.NoRedirect()).open(request, timeout=15) as response:
                return json.loads(response.read(4 << 20))
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise setup.SetupError("inventory observation failed with status " + str(error.code))

    try:
        if args.adapter_tests:
            for label in ("http", "https"):
                test_env = dict(env, RIO_DTRACK_EVIDENCE=str(run_root / ("adapter-" + label + "-observations.json")))
                if label == "https":
                    test_env.update(RIO_DTRACK_TEST_URL=tls_url, RIO_DTRACK_TEST_ALLOW_HTTP="0",
                                    RIO_DTRACK_TEST_CA_FILE=str(TLS / "SYNTHETIC-ONLY-cert.pem"))
                result = subprocess.run(["go", "test", "-race", "./internal/delivery/dtrack", "-run",
                                         "^TestIntegrationDependencyTrack$", "-count=1", "-v"], cwd=REPO, env=test_env, capture_output=True)
                safe_bytes(result.stdout + result.stderr)
                (run_root / ("adapter-" + label + ".log")).write_bytes(result.stdout + result.stderr)
                if result.returncode:
                    raise setup.SetupError("real " + label + " adapter suite failed; sanitized log retained")
                print("PASS: real " + label + " adapter contract", flush=True)
        before_uploads = observed["uploads"]
        shutil.copytree(CLIENT / "fixtures", work / "fixtures")
        suffix = secrets.token_hex(6)
        for path in (work / "fixtures").rglob("bom.json"):
            bom = json.loads(path.read_text())
            bom["metadata"]["component"]["name"] += "-" + suffix
            path.write_text(json.dumps(bom))
        manifest = json.loads((CLIENT / "rio.yaml").read_text())
        for target in manifest["delivery"]["targets"].values():
            target.update(url=tls_url, caFile=str(TLS / "SYNTHETIC-ONLY-cert.pem"), autoCreate=True)
        manifest["delivery"]["targets"]["archive"]["project"]["name"] += "-" + suffix
        untrusted = json.loads(json.dumps(manifest))
        untrusted["delivery"]["targets"]["security"].pop("caFile")
        untrusted["delivery"]["targets"]["security"]["project"] = {"name": "rio-untrusted-" + suffix, "version": "1"}
        save(untrusted)
        refused = run("--artifact", "alpha-server", "--target", "security", code=4)
        shutil.copyfile(refused["receipt"]["path"], run_root / "record-untrusted.json")
        refusal = json.loads((run_root / "record-untrusted.json").read_text())["deliveries"][0]
        if refusal["transport"] != {"scheme": "https", "tlsObserved": False, "certificateVerification": "enforced"}:
            raise setup.SetupError("default trust receipt did not retain failed handshake facts")
        if observed["uploads"] != before_uploads:
            raise setup.SetupError("default trust unexpectedly reached application upload")
        save(manifest)
        # The happy path is one invocation for intake, enrichment, checks and delivery.
        submitted_before = len(submitted)
        result = run()
        shutil.copyfile(result["receipt"]["path"], run_root / "record-before.json")
        original_sha = hashlib.sha256((run_root / "record-before.json").read_bytes()).hexdigest()
        receipt = json.loads((run_root / "record-before.json").read_text())
        if receipt["kind"] != "rio-run-receipt" or receipt["schemaVersion"] != 1 or receipt["run"]["operation"] != "pipeline":
            raise setup.SetupError("pipeline did not produce its compact receipt")
        if result["outcome"] != "success" or any(item["state"] != "accepted" for item in receipt["deliveries"]):
            raise setup.SetupError("real receiver did not acknowledge pipeline deliveries")
        run_directory = Path(result["runDirectory"])
        recovery = json.loads((run_directory / ".internal/attempts.json").read_text())
        journals = {item["attemptId"]: item["journal"] for item in recovery}
        artifacts = {item["id"]: item for item in receipt["artifacts"]}
        uploads = submitted[submitted_before:]
        if len(uploads) != len(receipt["deliveries"]):
            raise setup.SetupError("pipeline upload count differs from receipt")
        for item, fields in zip(receipt["deliveries"], uploads):
            output = artifacts[item["artifactId"]]["output"]
            payload = (run_directory / output["path"]).read_bytes()
            if payload != fields["bom"] or hashlib.sha256(payload).hexdigest() != output["sha256"] or len(payload) != output["size"]:
                raise setup.SetupError("receipt and multipart payload bytes differ")
            if fields["projectName"].decode() != item["project"]["name"] or fields["projectVersion"].decode() != item["project"]["version"]:
                raise setup.SetupError("receipt and multipart projects differ")
            if len(item["submitted"]) != 1 or item["submitted"][0]["artifactOutput"] != item["artifactId"] or item["transport"] != {
                    "scheme": "https", "tlsObserved": True, "certificateVerification": "enforced"}:
                raise setup.SetupError("receipt omitted submission or verified TLS facts")
            response = item["responses"][0]
            if response["httpStatus"] != 200 or not any(ref["kind"] == "dependency-track:event-token" for ref in response["references"]):
                raise setup.SetupError("receipt omitted server acknowledgment")
        # These inventory reads are harness observations, not native content verification.
        inventory = []
        for i, item in enumerate(receipt["deliveries"]):
            project = item["project"]
            query = urllib.parse.urlencode({"name": project["name"], "version": project["version"]})
            expected = json.loads((run_directory / artifacts[item["artifactId"]]["output"]["path"]).read_text())
            purls = sorted(c["purl"] for c in expected["components"])
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                found = read_inventory("/api/v1/project/lookup?" + query)
                components = read_inventory("/api/v1/component/project/" + found["uuid"]) if found else None
                if components is not None and sorted(c.get("purl", "") for c in components) == purls:
                    inventory.append({"artifactId": item["artifactId"], "target": item["target"], "componentPURLsMatch": True})
                    break
                time.sleep(1)
            else:
                raise setup.SetupError("synthetic project inventory did not match normalized component PURLs")
            reconciliation = run("delivery", "reconcile", "--record", journals[item["attemptId"]])
            shutil.copyfile(reconciliation["receipt"]["path"], run_root / ("record-reconcile-%d.json" % i))
        bypass = dict(manifest["delivery"]["targets"]["security"])
        bypass.pop("caFile")
        bypass.update(insecureSkipVerify=True, project={"name": "rio-bypass-" + suffix, "version": "1"})
        manifest["delivery"]["targets"]["bypass"] = bypass
        save(manifest)
        bypass_result = run("deliver", "--index", run_directory / "index.json", "--artifact", "alpha-server", "--target", "bypass")
        shutil.copyfile(bypass_result["receipt"]["path"], run_root / "record-bypass.json")
        bypass_receipt = json.loads((run_root / "record-bypass.json").read_text())
        if bypass_receipt["deliveries"][0]["transport"] != {"scheme": "https", "tlsObserved": True, "certificateVerification": "disabled"}:
            raise setup.SetupError("explicit bypass receipt omitted transport policy")
        if observed["uploads"] != before_uploads + 4:
            raise setup.SetupError("unexpected application upload or retry count")
        stop_gateway()
        env.pop("RIO_DEMO_CLIENT_KEY")
        # Stop the real receiver too, before the source-free recipient verification.
        setup.stop(root)
        for path in work.rglob("*.json"):
            safe_bytes(path.read_bytes())
        shutil.rmtree(work)
        for path in sorted(run_root.glob("record-*.json")):
            run("record", "inspect", "--file", path, cwd=run_root)
        run("record", "report", "--file", run_root / "record-before.json", "--output", run_root / "report.html", cwd=run_root)
        if hashlib.sha256((run_root / "record-before.json").read_bytes()).hexdigest() != original_sha:
            raise setup.SetupError("original snapshot changed")
        for path in run_root.rglob("*"):
            if path.is_file():
                safe_bytes(path.read_bytes())
        summary = {"serverVersion": "5.1.1", "images": state["images"], "syntheticProjectsOnly": True,
                   "tlsTermination": "local test gateway; backend loopback HTTP", "defaultTrustReachedUpload": False,
                   "verifiedCAAcceptedPairs": 3, "explicitBypassAcceptedPairs": 1,
                   "nativeContentVerificationClaim": False, "harnessInventoryObservations": inventory,
                   "sourceWorkspaceRemoved": True, "realReceiverStoppedBeforeOfflineInspect": True,
                   "originalSnapshotSHA256": original_sha, "commands": commands}
        (run_root / "verification.json").write_text(json.dumps(summary, indent=2) + "\n")
        print("PASS: real Dependency-Track client handoff, trusted CA/bypass, activity and separate inventory observations", flush=True)
        print("PASS: receiver stopped, sources removed, JSON inspected and HTML rendered offline", flush=True)
        print("Sanitized evidence:", run_root, flush=True)
    finally:
        stop_gateway()


if __name__ == "__main__":
    try:
        main()
    except setup.SetupError as error:
        print("ERROR: " + str(error), file=sys.stderr)
        sys.exit(1)
    except Exception as error:
        print("ERROR: integration failed (" + type(error).__name__ + "); private fixture retained for diagnosis", file=sys.stderr)
        sys.exit(1)
