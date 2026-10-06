#!/usr/bin/env python3
"""Prepare a local Juice Shop walkthrough; Rio itself is run by the presenter."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import sys
import subprocess
import secrets
from datetime import datetime, timezone
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("dtrack_setup", HERE.parent / "demo-delivery/integration/setup.py")
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
VERSION = "20.2.0"
SOURCE_REV = "5658473cf8814459bf89000ce373b20ed0b4eb37"
NODE_IMAGE = "node:24.18.0-bookworm@sha256:5711a0d445a1af54af9589066c646df387d1831a608226f4cd694fc59e745059"
INPUTS = {"backend": "bom.json", "frontend": "frontend/dist/bom/bom.json"}
FRONTEND_IMAGE = "ghcr.io/dependencytrack/frontend:5.1.1@sha256:985589e26a039f5879425dc5b3264c13682611dabed10304d4f45c56b1497d7b"


def write(path, text):
    with path.open("x", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        stream.write(text)


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def build(root):
    fixture.local_docker()
    if root.exists():
        raise fixture.SetupError("build directory exists; choose a fresh directory")
    root.mkdir(mode=0o700)
    owner = secrets.token_hex(16)
    cidfile = root / "builder.cid"
    started = datetime.now(timezone.utc)
    print("Building Juice Shop from source; log: " + str(root / "build.log"), flush=True)
    command = ["docker", "run", "--rm", "--init", "--cidfile", str(cidfile),
        "--label", fixture.OWNER + "=" + owner,
        "--user", str(os.getuid()) + ":" + str(os.getgid()),
        "--mount", "type=bind,src=" + str(root) + ",dst=/work",
        "--mount", "type=bind,src=" + str(HERE) + ",dst=/recipe,readonly",
        "--workdir", "/work",
        "--env", "JUICE_SOURCE_REV=" + SOURCE_REV,
        "--env", "npm_config_cache=/tmp/npm-cache",
        "--env", "npm_config_devdir=/tmp/node-gyp",
        "--env", "npm_config_package_lock=true",
        "--env", "CYPRESS_INSTALL_BINARY=0",
        "--env", "NG_CLI_ANALYTICS=false",
        NODE_IMAGE, "bash", "-o", "pipefail", "-c", "bash /recipe/build.sh 2>&1 | tee /work/build.log"]
    try:
        result = subprocess.run(command, timeout=1800)
        if result.returncode:
            raise fixture.SetupError("source build failed; inspect build.log; receiver was not started")
    finally:
        # A timeout/interrupt must not leave a builder running. Only remove the
        # ID actually created by this invocation, with its matching owner label.
        if cidfile.exists():
            cid = cidfile.read_text().strip()
            if re.fullmatch(r"[a-f0-9]{64}", cid):
                info = subprocess.run(["docker", "inspect", cid], capture_output=True, text=True)
                if info.returncode == 0:
                    saved = json.loads(info.stdout)[0]
                    if saved["Config"]["Labels"].get(fixture.OWNER) != owner:
                        raise fixture.SetupError("builder ownership differs; refusing cleanup")
                    subprocess.run(["docker", "rm", "-f", cid], check=True, stdout=subprocess.DEVNULL)
    info = json.loads((root / "build-info.json").read_text())
    if info["revision"] != SOURCE_REV:
        raise fixture.SetupError("built source revision differs")
    source = root / "source"
    (root / "inputs").mkdir()
    sboms = {}
    for name, relative in INPUTS.items():
        payload = (source / relative).read_bytes()
        doc = json.loads(payload)
        if doc.get("bomFormat") != "CycloneDX" or doc.get("metadata", {}).get("component", {}).get("version") != VERSION:
            raise fixture.SetupError("unexpected generated SBOM identity")
        (root / "inputs" / (name + ".cdx.json")).write_bytes(payload)
        sboms[name] = {"generatedPath": relative, "sha256": hashlib.sha256(payload).hexdigest()}
    info.update({"repository": "https://github.com/juice-shop/juice-shop", "ref": "refs/tags/v20.2.0",
        "builderImage": NODE_IMAGE, "buildId": "local-" + started.strftime("%Y%m%dT%H%M%SZ"),
        "startedAt": started.isoformat(), "finishedAt": datetime.now(timezone.utc).isoformat(),
        "sboms": sboms, "lockfiles": {name: digest(source / name) for name in ["package-lock.json", "frontend/package-lock.json"]}})
    write(root / "source.json", json.dumps(info, indent=2) + "\n")
    print("BUILT: backend npm SBOM and frontend bundle SBOM; source/lockfiles retained", flush=True)


def prepare(root):
    info = json.loads((root / "source.json").read_text())
    if info["revision"] != SOURCE_REV:
        raise fixture.SetupError("unexpected source revision")
    for name in INPUTS:
        if digest(root / "inputs" / (name + ".cdx.json")) != info["sboms"][name]["sha256"]:
            raise fixture.SetupError("generated input changed after build; receiver was not started")
    server = root / ".dtrack"
    fixture.create(server)
    fixture.start(server, 300)
    state, private = fixture.load(server)
    frontend = server / "frontend.compose.json"
    fixture.write_private(frontend, {"services": {"frontend": {
        "image": FRONTEND_IMAGE,
        "ports": ["127.0.0.1::8080"],
        "environment": {"API_BASE_URL": state["url"]},
        "labels": {fixture.OWNER: state["owner"]},
    }}})
    fixture.compose(state, private, "-f", str(frontend), "up", "-d", "frontend")
    bound = fixture.compose(state, private, "-f", str(frontend), "port", "frontend", "8080")
    if not re.fullmatch(r"127\.0\.0\.1:[0-9]+", bound):
        raise fixture.SetupError("frontend is not bound to loopback")
    ui = "http://" + bound
    credentials = json.loads((server / "test-env.json").read_text())
    write(root / "demo.env", "export JUICE_SHOP_DTRACK_KEY=" + shlex.quote(credentials["RIO_DTRACK_TEST_API_KEY"]) + "\n")
    write(root / "login.txt", "Browser: " + ui + "\nUsername: admin\nPassword: " + private["adminPassword"] + "\n")
    context = {"contextVersion": 1, "artifacts": []}
    for name in INPUTS:
        sha = info["sboms"][name]["sha256"]
        context["artifacts"].append({"id": name, "sbom": {"sha256": sha},
            "source": {"revision": info["revision"], "ref": info["ref"], "workspace": info["workspace"]},
            "build": {"id": info["buildId"], "url": "https://ci.example.org/juice-shop-demo/runs/" + info["buildId"],
                      "timestamp": info["startedAt"], "system": {"name": "local Docker build"}}})
    write(root / "pipeline.json", json.dumps(context, indent=2) + "\n")
    write(root / "rio.yaml", """version: 1
artifacts:
  - id: backend
    sbom: inputs/backend.cdx.json
    context: {file: pipeline.json, require: [build.id, build.url]}
  - id: frontend
    sbom: inputs/frontend.cdx.json
    context: {file: pipeline.json, require: [build.id, build.url]}
enrichment:
  subject:
    supplier: {name: rebaze demo distribution}
gate:
  mode: fail
  require: [name, version, purl]
delivery:
  targets:
    security:
      type: dependency-track
      url: """ + state["url"] + """
      allowHTTP: true
      apiKeyEnv: JUICE_SHOP_DTRACK_KEY
      autoCreate: true
""")
    print("READY: " + ui)
    print("Login details: " + str(root / "login.txt"))
    print("Configuration: " + str(root / "rio.yaml"))
    print("Only setup ran; run Rio yourself using the walkthrough.")


def status(root):
    server = root / ".dtrack"
    state, private = fixture.load(server)
    fixture.local_docker()
    if state["phase"] != "ready" or "http://" + fixture.compose(state, private, "port", "apiserver", "8080") != state["url"]:
        raise fixture.SetupError("demo receiver is not running at its recorded endpoint")
    base = fixture.local_url(state["url"])
    credentials = json.loads((server / "test-env.json").read_text())
    opener = urllib.request.build_opener(fixture.NoRedirect())

    def get(path):
        req = urllib.request.Request(base + path, headers={"X-Api-Key": credentials["RIO_DTRACK_TEST_API_KEY"]})
        try:
            with opener.open(req, timeout=15) as response:
                raw = response.read((8 << 20) + 1)
                if len(raw) > 8 << 20:
                    raise fixture.SetupError("receiver response exceeds limit")
                return json.loads(raw), response.headers
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None, {}
            raise fixture.SetupError("inventory check returned HTTP " + str(error.code)) from None

    def project(name):
        return get("/api/v1/project/lookup?" + urllib.parse.urlencode({"name": name, "version": VERSION}))[0]

    deadline = time.monotonic() + 120
    print("Waiting for the backend inventory in Dependency-Track…", flush=True)
    while time.monotonic() < deadline:
        backend = project("juice-shop")
        if backend:
            components, headers = get("/api/v1/component/project/" + backend["uuid"] + "?pageSize=1")
            if components:
                print("Backend: juice-shop / " + VERSION + "; components stored: " + headers.get("X-Total-Count", "at least 1"))
                print("Frontend project: " + ("present" if project("frontend") else "absent (no frontend delivery)"))
                print("This checks receiver inventory; the Rio receipt separately records HTTP acceptance.")
                return
        time.sleep(2)
    raise fixture.SetupError("backend inventory not observed within 120s; inspect Dependency-Track")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("build", "prepare", "status", "stop"))
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    root = args.directory.resolve()
    try:
        if args.operation == "build":
            build(root)
        elif args.operation == "prepare":
            prepare(root)
        elif args.operation == "status":
            status(root)
        else:
            if (root / ".dtrack" / "state.json").exists():
                fixture.stop(root / ".dtrack")
            else:
                print("No receiver was created; source files are retained.")
    except fixture.SetupError as error:
        print("ERROR: " + str(error), file=sys.stderr)
        return 1
    except Exception as error:
        print("ERROR: demo setup/check failed (" + type(error).__name__ + "); private details withheld", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
