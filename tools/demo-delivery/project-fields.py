#!/usr/bin/env python3
"""Dependency-Track tags, parent and isLatest from rio.yaml, against a SYNTHETIC receiver.

The loopback receiver imitates the upload rules of Dependency-Track 5.2.1's
BomResource: tags, parent and isLatest are applied when the upload creates the
project; on an existing project the request's tags replace the tag set only for
a key with PORTFOLIO_MANAGEMENT(_UPDATE), and otherwise the server still answers
200; a missing parent fails with 404; reading a project needs VIEW_PORTFOLIO.
It is not Dependency-Track. Real-server evidence is in integration/.
"""
import email.parser
import email.policy
import http.server
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import urllib.parse
import uuid

HERE = Path(__file__).resolve().parent
TOKEN = "f90934f5-cb88-47ce-81cb-db06fc67d4b4"
PARENT_UUID = "6b49ae15-eded-4780-a7c0-2bc1b9001cd5"
# Synthetic keys and the permissions the receiver grants them.
KEYS = {
    "synthetic-ci-key": {"BOM_UPLOAD", "PROJECT_CREATION_UPLOAD"},
    "synthetic-ci-view-key": {"BOM_UPLOAD", "PROJECT_CREATION_UPLOAD", "VIEW_PORTFOLIO"},
    "synthetic-portfolio-key": {"BOM_UPLOAD", "PROJECT_CREATION_UPLOAD", "VIEW_PORTFOLIO", "PORTFOLIO_MANAGEMENT_UPDATE"},
}

MANIFEST = """version: 1
artifacts:
  - id: console
    sbom: console.cdx.json
  - id: agent
    sbom: agent.cdx.json
delivery:
  targets:
    security:
      type: dependency-track
      url: http://127.0.0.1:{port}
      allowHTTP: true
      apiKeyEnv: DTRACK_API_KEY
      autoCreate: true
      tags: [{tags}]
      parent: {parent}
      isLatest: true
      overrides:
        agent:
          tags: [owner:platform, rio-it]
          parent: {{uuid: {parent_uuid}}}
"""


class Receiver(http.server.BaseHTTPRequestHandler):
    projects = {}
    lock = threading.Lock()

    def log_message(self, *args):
        pass

    def permissions(self):
        return KEYS.get(self.headers.get("X-Api-Key"), set())

    def reply(self, status, value=None):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if value is not None:
            self.wfile.write(json.dumps(value).encode())

    def do_POST(self):
        if self.headers.get("Transfer-Encoding") == "chunked":
            chunks = []
            while True:
                size = int(self.rfile.readline().strip().split(b";")[0], 16)
                if not size:
                    self.rfile.readline()
                    break
                chunks.append(self.rfile.read(size))
                self.rfile.read(2)
            body = b"".join(chunks)
        else:
            body = self.rfile.read(int(self.headers["Content-Length"]))
        message = email.parser.BytesParser(policy=email.policy.default).parsebytes(
            ("Content-Type: " + self.headers["Content-Type"] + "\r\n\r\n").encode() + body)
        form = {part.get_param("name", header="content-disposition"): part.get_payload(decode=True).decode()
                for part in message.iter_parts() if part.get_param("name", header="content-disposition") != "bom"}
        granted = self.permissions()
        tags = {t.strip().lower() for t in form.get("projectTags", "").split(",") if t.strip()} or None
        with self.lock:
            key = (form["projectName"], form["projectVersion"])
            project = self.projects.get(key)
            if project is None and form.get("autoCreate") == "true":
                parent = None
                if "parentUUID" in form:
                    parent = next((p for p in self.projects.values() if p["uuid"] == form["parentUUID"]), None)
                elif "parentName" in form:
                    parent = self.projects.get((form["parentName"], form.get("parentVersion")))
                if ("parentUUID" in form or "parentName" in form) and parent is None:
                    return self.reply(404)
                latest = form.get("isLatest") == "true"
                if latest:
                    for other in self.projects.values():
                        if other["name"] == key[0]:
                            other["isLatest"] = False
                project = {"uuid": str(uuid.uuid4()), "name": key[0], "version": key[1], "tags": tags or set(),
                           "parent": parent, "isLatest": latest}
                self.projects[key] = project
            elif project is None:
                return self.reply(404)
            elif tags is not None and tags != project["tags"]:
                # maybeBindTags: without the permission it only logs a warning.
                if "PORTFOLIO_MANAGEMENT_UPDATE" in granted:
                    project["tags"] = tags
        self.reply(200, {"token": TOKEN})

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        if url.path.startswith("/api/v1/event/token/"):
            return self.reply(200, {"processing": False})
        if "VIEW_PORTFOLIO" not in self.permissions():
            return self.reply(403)
        with self.lock:
            if url.path == "/api/v1/project/lookup":
                query = urllib.parse.parse_qs(url.query)
                project, full = self.projects.get((query["name"][0], query["version"][0])), False
            else:
                wanted = url.path.rsplit("/", 1)[-1]
                project, full = next((p for p in self.projects.values() if p["uuid"] == wanted), None), True
            if project is None:
                return self.reply(404)
            value = {"uuid": project["uuid"], "name": project["name"], "version": project["version"],
                     "tags": [{"name": t} for t in sorted(project["tags"])], "isLatest": project["isLatest"], "active": True}
            # Like 5.2.1, only the project read by UUID carries its parent.
            if full and project["parent"]:
                p = project["parent"]
                value["parent"] = {"uuid": p["uuid"], "name": p["name"], "version": p["version"]}
            self.reply(200, value)


def main():
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        raise SystemExit("Usage: project-fields.py /absolute/path/to/rio")
    binary = str(Path(sys.argv[1]).resolve())
    work = Path(tempfile.mkdtemp(prefix="rio-project-fields-demo-"))
    Receiver.projects = {("Payments", "all"): {"uuid": PARENT_UUID, "name": "Payments", "version": "all",
                                               "tags": set(), "parent": None, "isLatest": False}}
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    seed = json.loads((HERE / "bom.json").read_text())

    def release(version):
        for name in ("console", "agent"):
            doc = json.loads(json.dumps(seed))
            doc["metadata"]["component"].update(name=name, version=version)
            (work / (name + ".cdx.json")).write_text(json.dumps(doc))

    def run(title, key, tags="owner:payments, rio-it", parent="{name: Payments, version: all}", code=0):
        (work / "rio.yaml").write_text(MANIFEST.format(port=server.server_port, tags=tags, parent=parent, parent_uuid=PARENT_UUID))
        env = dict(os.environ, DTRACK_API_KEY=key)
        result = subprocess.run([binary, "--json"], cwd=work, env=env, capture_output=True, text=True)
        assert result.returncode == code, (title, result.returncode, result.stdout, result.stderr)
        assert key not in result.stdout + result.stderr
        value = json.loads(result.stdout)
        receipt = json.loads(Path(value["receipt"]["path"]).read_text())
        assert key.encode() not in Path(value["receipt"]["path"]).read_bytes()
        print("\n" + title)
        print("  key: " + ", ".join(sorted(KEYS[key])))
        for d in receipt["deliveries"]:
            fields = d.get("projectFields", {})
            print("  %-8s %-11s readBack=%s" % (d["artifactId"], d["state"], fields.get("readBack")))
            for name in ("tags", "parent", "isLatest"):
                if name in fields:
                    f = fields[name]
                    line = "    %-9s requested %s -> %s" % (name, json.dumps(f["requested"]), f["state"])
                    if "observed" in f:
                        line += ", observed " + json.dumps(f["observed"])
                    print(line)
            if d.get("errorCode"):
                print("    error %s" % d["errorCode"])
        return {d["artifactId"]: d for d in receipt["deliveries"]}

    def states(delivery):
        return {k: v["state"] for k, v in delivery["projectFields"].items() if k != "readBack"}

    try:
        print("Dependency-Track project fields demo (SYNTHETIC receiver; not Dependency-Track)")
        print(subprocess.run([binary, "version"], capture_output=True, text=True).stdout.strip())

        release("1.0.0")
        first = run("1. New version 1.0.0: tags, parent by name (console) and by UUID (agent override), isLatest",
                    "synthetic-ci-view-key")
        assert states(first["console"]) == states(first["agent"]) == {"tags": "observed", "parent": "observed", "isLatest": "observed"}
        assert first["agent"]["projectFields"]["tags"]["requested"] == ["owner:platform", "rio-it"]

        changed = run("2. Same version, changed tags, key without PORTFOLIO_MANAGEMENT: 200, tags unchanged",
                      "synthetic-ci-view-key", tags="owner:security")
        assert changed["console"]["state"] == "accepted"
        assert changed["console"]["projectFields"]["tags"] == {"requested": ["owner:security"], "state": "different",
                                                               "observed": ["owner:payments", "rio-it"]}

        blind = run("3. The same without VIEW_PORTFOLIO: nothing can be observed, so nothing is claimed",
                    "synthetic-ci-key", tags="owner:security")
        assert blind["console"]["projectFields"]["readBack"] == "forbidden"
        assert set(states(blind["console"]).values()) == {"unknown"}

        replaced = run("4. With PORTFOLIO_MANAGEMENT_UPDATE: the request's tags replace the set",
                       "synthetic-portfolio-key", tags="owner:security")
        assert replaced["console"]["projectFields"]["tags"]["state"] == "observed"

        release("1.1.0")
        newer = run("5. New version 1.1.0 with isLatest: it becomes the latest version", "synthetic-ci-view-key")
        assert states(newer["console"])["isLatest"] == "observed"
        assert not Receiver.projects[("console", "1.0.0")]["isLatest"]

        release("1.2.0")
        missing = run("6. A parent that does not exist: 404, its own non-retryable failure",
                      "synthetic-ci-view-key", parent="{name: Missing, version: all}", code=5)
        assert missing["console"]["state"] == "rejected" and missing["console"]["errorCode"] == "parent_not_found"

        print("\nPASS: tags applied, tags not applied (200 without permission), parent by name and UUID,")
        print("isLatest, an artifact override and a missing parent. All receiver responses are synthetic.")
        print("Receipts and inputs retained in:", work)
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
