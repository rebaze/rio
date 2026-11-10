#!/usr/bin/env python3
"""The README's use case, run by an installed Rio against a SYNTHETIC Dependency-Track receiver.

The loopback receiver imitates the upload and read rules of Dependency-Track 5.2.1 for one API
key with BOM_UPLOAD, PROJECT_CREATION_UPLOAD and VIEW_PORTFOLIO. It is not Dependency-Track:
its acknowledgments are synthetic, and acceptance is not ingestion. Python 3.9+, no network.
"""
import email.parser
import email.policy
import http.server
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import urllib.parse
import uuid

HERE = Path(__file__).resolve().parent
TOKEN = "5d1f9a9e-2f0c-4c55-9d8e-7c3b2a1f0e64"
PARENT_UUID = "0b7e4d2a-6c1f-4e8b-9a3d-5f2c1e7b8a90"


class Receiver(http.server.BaseHTTPRequestHandler):
    key = ""
    projects = {}
    uploads = []
    lock = threading.Lock()

    def log_message(self, *args):
        pass

    def reply(self, status, value=None):
        body = json.dumps(value).encode() if value is not None else b""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_body(self):
        if self.headers.get("Transfer-Encoding") != "chunked":
            return self.rfile.read(int(self.headers["Content-Length"]))
        chunks = []
        while True:
            size = int(self.rfile.readline().strip().split(b";")[0], 16)
            if not size:
                self.rfile.readline()
                return b"".join(chunks)
            chunks.append(self.rfile.read(size))
            self.rfile.read(2)

    def do_POST(self):
        if self.path != "/api/v1/bom" or self.headers.get("X-Api-Key") != self.key:
            return self.reply(401)
        message = email.parser.BytesParser(policy=email.policy.default).parsebytes(
            ("Content-Type: " + self.headers["Content-Type"] + "\r\n\r\n").encode() + self.read_body())
        form = {part.get_param("name", header="content-disposition"): part.get_payload(decode=True)
                for part in message.iter_parts()}
        text = {k: v.decode() for k, v in form.items() if k != "bom"}
        with self.lock:
            key = (text["projectName"], text["projectVersion"])
            if key not in self.projects:
                if text.get("autoCreate") != "true":
                    return self.reply(404)
                parent = None
                if "parentName" in text:
                    parent = self.projects.get((text["parentName"], text.get("parentVersion")))
                    if parent is None:
                        return self.reply(404)
                latest = text.get("isLatest") == "true"
                for other in self.projects.values():
                    if latest and other["name"] == key[0]:
                        other["isLatest"] = False
                tags = sorted({t.strip().lower() for t in text.get("projectTags", "").split(",") if t.strip()})
                self.projects[key] = {"uuid": str(uuid.uuid4()), "name": key[0], "version": key[1],
                                      "tags": tags, "parent": parent, "isLatest": latest}
            self.uploads.append(form["bom"])
        self.reply(200, {"token": TOKEN})

    def do_GET(self):
        if self.headers.get("X-Api-Key") != self.key:
            return self.reply(401)
        url = urllib.parse.urlsplit(self.path)
        if url.path.startswith("/api/v1/event/token/"):
            return self.reply(200, {"processing": False})
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
                     "tags": [{"name": t} for t in project["tags"]], "isLatest": project["isLatest"],
                     "active": True}
            # Like 5.2.1, only the project read by UUID carries its parent.
            if full and project["parent"]:
                value["parent"] = {"uuid": project["parent"]["uuid"], "name": project["parent"]["name"]}
            self.reply(200, value)


def tree(root, prefix=""):
    entries = sorted(root.iterdir(), key=lambda p: (p.is_file(), p.name))
    lines = []
    for i, entry in enumerate(entries):
        last = i == len(entries) - 1
        lines.append(prefix + ("└── " if last else "├── ") + entry.name + ("/" if entry.is_dir() else ""))
        if entry.is_dir():
            lines.extend(tree(entry, prefix + ("    " if last else "│   ")))
    return lines


def main():
    if len(sys.argv) > 3:
        raise SystemExit("Usage: run.py [rio-command-or-path] [new-output-directory]")
    binary = shutil.which(sys.argv[1] if len(sys.argv) > 1 else "rio")
    if not binary:
        raise SystemExit("Cannot find rio. Install release v0.10.0 or newer.")
    binary = str(Path(binary).resolve())
    if len(sys.argv) == 3:
        work = Path(sys.argv[2]).resolve()
        work.mkdir(parents=True, exist_ok=False)
    else:
        work = Path(tempfile.mkdtemp(prefix="rio-use-case-"))
    # Rio prints UTF-8; so does this script, also on a Windows console.
    sys.stdout.reconfigure(encoding="utf-8")

    Receiver.key = "synthetic-" + secrets.token_hex(16)
    # A version-less grouping parent that exists before the first delivery.
    Receiver.projects = {("Payments", None): {"uuid": PARENT_UUID, "name": "Payments", "version": None,
                                              "tags": [], "parent": None, "isLatest": False}}
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        (work / "target").mkdir()
        shutil.copyfile(HERE / "inputs" / "bom.json", work / "target" / "bom.json")
        manifest = (HERE / "rio.yaml").read_text()
        local = "url: http://127.0.0.1:%d\n      allowHTTP: true              # the synthetic receiver only" % server.server_port
        assert "url: https://dtrack.example.com" in manifest
        (work / "rio.yaml").write_text(manifest.replace("url: https://dtrack.example.com", local))

        print("Rio use case (synthetic data, SYNTHETIC Dependency-Track receiver on loopback)")
        print(subprocess.run([binary, "version"], capture_output=True, encoding="utf-8").stdout.strip())
        print("\n$ rio")
        env = dict(os.environ, DTRACK_API_KEY=Receiver.key)
        result = subprocess.run([binary], cwd=work, env=env, capture_output=True, encoding="utf-8")
        print(result.stdout + result.stderr, end="")
        assert result.returncode == 0, result.returncode
        assert Receiver.key not in result.stdout + result.stderr

        runs = sorted((work / "target" / "rio" / "runs").iterdir())
        assert len(runs) == 1
        run = runs[0]
        receipt = json.loads((run / "record.json").read_text())
        assert Receiver.key.encode() not in (run / "record.json").read_bytes()
        delivery = receipt["deliveries"][0]
        assert delivery["state"] == "accepted", delivery
        fields = delivery["projectFields"]
        assert fields["readBack"] == "read"
        assert {k: v["state"] for k, v in fields.items() if k != "readBack"} == {"tags": "observed"}, fields
        delivered = (run / "payments-api.cdx.json").read_bytes()
        assert Receiver.uploads == [delivered], "the receiver got other bytes than Rio wrote"

        print("\n$ tree target")
        print("target/\n" + "\n".join(tree(work / "target")))
        subprocess.run([binary, "record", "report", "--file", str(run / "record.json"), "--output",
                        str(work / "report.html")], capture_output=True, encoding="utf-8", check=True)
        print("\n$ rio record inspect --file target/rio/runs/%s/record.json" % run.name)
        inspect = subprocess.run([binary, "record", "inspect", "--file", str(run / "record.json")],
                                 capture_output=True, encoding="utf-8", check=True)
        print(inspect.stdout, end="")
        print("\nPASS: enriched, leveled to CycloneDX 1.6, checked, delivered with a tag and read")
        print("back. The receiver and its acknowledgment are synthetic.")
        print("Everything is retained in:", work)
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
