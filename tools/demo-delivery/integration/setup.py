#!/usr/bin/env python3
"""Create/start/stop a private, owned Dependency-Track 5.1.1 + PostgreSQL 18 fixture."""
import argparse
import json
import http.client
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
OWNER = "io.rebaze.rio.test-owner"


class SetupError(ValueError):
    pass


def write_private(path, value):
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        os.chmod(temporary, 0o600)
        json.dump(value, stream, indent=2)
        stream.write("\n")
    os.replace(temporary, path)


def create(root):
    root = Path(root).resolve()
    if root.exists():
        raise SetupError("fixture path exists; use a new directory")
    root.mkdir(mode=0o700)
    state = {"version": 1, "project": "rio-dtrack-" + secrets.token_hex(6),
             "owner": secrets.token_hex(16), "phase": "created"}
    write_private(root / "state.json", state)
    write_private(root / "private.json", {"databasePassword": secrets.token_hex(24),
                                         "adminPassword": secrets.token_hex(24)})
    return state


def load(root):
    root = Path(root).resolve()
    state = json.loads((root / "state.json").read_text())
    if state.get("version") != 1 or not re.fullmatch(r"rio-dtrack-[a-f0-9]{12}", state.get("project", "")) or not re.fullmatch(r"[a-f0-9]{32}", state.get("owner", "")):
        raise SetupError("invalid fixture ownership record")
    return state, json.loads((root / "private.json").read_text())


def local_url(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost", "::1") or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
        raise SetupError("fixture API must be a bare loopback HTTP endpoint")
    return url


def check_owner(labels, state):
    if not labels or labels.get("com.docker.compose.project") != state["project"] or labels.get(OWNER) != state["owner"]:
        raise SetupError("refusing to alter a resource not owned by this fixture")


def command(args, env=None):
    result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise SetupError("container command failed: " + " ".join(args[:3]) + " (output withheld)")
    return result.stdout.strip()


def environment(state, private):
    return dict(os.environ, RIO_TEST_DB_PASSWORD=private["databasePassword"], RIO_DTRACK_TEST_OWNER=state["owner"])


def compose(state, private, *args):
    return command(["docker", "compose", "-p", state["project"], "-f", str(HERE / "compose.yaml"), *args], environment(state, private))


def local_docker():
    host = os.environ.get("DOCKER_HOST")
    if not host:
        host = command(["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"])
    if not host.startswith(("unix://", "npipe://")):
        raise SetupError("a local Docker socket is required for the loopback fixture")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def request(base, method, path, token=None, value=None, form=False):
    local_url(base)
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    body = None
    if value is not None:
        if form:
            body = urllib.parse.urlencode(value).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            body = json.dumps(value).encode()
            headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=15) as response:
            return response.status, response.read(4 << 20)
    except urllib.error.HTTPError as error:
        # Never retain or print raw authentication/receiver error bodies.
        return error.code, b""
    except (urllib.error.URLError, http.client.HTTPException, OSError):
        return 0, b""


def expect(base, method, path, token=None, value=None, form=False, codes=(200, 201)):
    status, body = request(base, method, path, token, value, form)
    if status not in codes:
        raise SetupError("fixture API " + method + " " + path.split('?')[0] + " returned status " + str(status))
    return body


def bootstrap(root, state, private):
    if (root / "test-env.json").exists():
        return
    base = state["url"]
    password = private["adminPassword"]
    status, body = request(base, "POST", "/api/v1/user/login", value={"username": "admin", "password": password}, form=True)
    if status not in (200, 401, 403):
        raise SetupError("fixture login outcome unavailable; password change not attempted")
    if status != 200:
        expect(base, "POST", "/api/v1/user/forceChangePassword", value={"username": "admin", "password": "admin", "newPassword": password, "confirmPassword": password}, form=True)
        body = expect(base, "POST", "/api/v1/user/login", value={"username": "admin", "password": password}, form=True)
    token = body.decode()
    if not token:
        raise SetupError("fixture login returned no session")
    bootstrap_state = private.setdefault("bootstrap", {})
    keys = {}
    for name, permissions in [("upload", ["BOM_UPLOAD", "PROJECT_CREATION_UPLOAD", "VIEW_PORTFOLIO", "PORTFOLIO_MANAGEMENT"]), ("denied", ["VIEW_PORTFOLIO"])]:
        saved = bootstrap_state.setdefault(name, {})
        if "team" not in saved:
            team = json.loads(expect(base, "PUT", "/api/v1/team", token, {"name": state["project"] + "-" + name}))
            saved["team"] = team["uuid"]
            write_private(root / "private.json", private)
        for permission in permissions:
            expect(base, "POST", "/api/v1/permission/" + permission + "/team/" + saved["team"], token, codes=(200, 304))
        if "key" not in saved:
            issued = json.loads(expect(base, "PUT", "/api/v1/team/" + saved["team"] + "/key", token))
            saved["key"] = issued["key"]
            if not saved["key"]:
                raise SetupError("fixture API key missing")
            write_private(root / "private.json", private)
        keys[name] = saved["key"]
    if "projectUUID" not in bootstrap_state:
        project = json.loads(expect(base, "PUT", "/api/v1/project", token, {"name": state["project"] + "-test", "version": "1", "active": True}))
        bootstrap_state["projectUUID"] = project["uuid"]
        write_private(root / "private.json", private)
    write_private(root / "test-env.json", {"RIO_DTRACK_INTEGRATION": "1", "RIO_DTRACK_TEST_URL": base,
        "RIO_DTRACK_TEST_ALLOW_HTTP": "1", "RIO_DTRACK_TEST_API_KEY": keys["upload"],
        "RIO_DTRACK_TEST_DENIED_KEY": keys["denied"], "RIO_DTRACK_TEST_PROJECT_UUID": bootstrap_state["projectUUID"]})
    state["phase"] = "ready"
    state["serverVersion"] = "5.1.1"
    write_private(root / "state.json", state)


def start(root, timeout):
    root = Path(root).resolve()
    state, private = load(root)
    local_docker()
    if state["phase"] == "stopped":
        raise SetupError("stopped fixtures are not restarted; create a new fixture")
    # A named project must not preexist before this fixture's first start.
    existing = command(["docker", "ps", "-aq", "--filter", "label=com.docker.compose.project=" + state["project"]]).split()
    for container in existing:
        info = json.loads(command(["docker", "inspect", container]))[0]
        check_owner(info["Config"]["Labels"], state)
    state["phase"] = "starting"
    write_private(root / "state.json", state)
    compose(state, private, "up", "-d")
    bound = compose(state, private, "port", "apiserver", "8080")
    if not re.fullmatch(r"127\.0\.0\.1:[0-9]+", bound):
        raise SetupError("API server was not bound to loopback")
    state["url"] = "http://" + bound
    state["images"] = {}
    for service in ("database", "apiserver"):
        container = compose(state, private, "ps", "-q", service)
        info = json.loads(command(["docker", "inspect", container]))[0]
        check_owner(info["Config"]["Labels"], state)
        state["images"][service] = {"reference": info["Config"]["Image"], "imageID": info["Image"]}
    write_private(root / "state.json", state)
    deadline = time.monotonic() + timeout
    last_notice = 0
    while time.monotonic() < deadline:
        status, raw = request(state["url"], "GET", "/api/version")
        if status == 200:
            value = json.loads(raw)
            if value.get("version") != "5.1.1":
                raise SetupError("unexpected server version; expected 5.1.1")
            bootstrap(root, state, private)
            state["phase"] = "ready"
            write_private(root / "state.json", state)
            print("READY: disposable Dependency-Track 5.1.1; private test-env.json written", flush=True)
            return
        if time.monotonic() - last_notice > 15:
            print("Waiting for owned API server readiness; status " + str(status), flush=True)
            last_notice = time.monotonic()
        time.sleep(2)
    raise SetupError("owned API server readiness deadline exceeded; resources retained for diagnosis")


def stop(root):
    root = Path(root).resolve()
    state, private = load(root)
    local_docker()
    for kind, listing in [("container", ["docker", "ps", "-aq"]), ("volume", ["docker", "volume", "ls", "-q"]), ("network", ["docker", "network", "ls", "-q"])]:
        ids = command(listing + ["--filter", "label=com.docker.compose.project=" + state["project"]]).split()
        for identity in ids:
            cmd = ["docker", "inspect", identity] if kind == "container" else ["docker", kind, "inspect", identity]
            info = json.loads(command(cmd))[0]
            check_owner(info["Config"]["Labels"] if kind == "container" else info["Labels"], state)
    compose(state, private, "down", "-v", "--remove-orphans")
    state["phase"] = "stopped"
    write_private(root / "state.json", state)
    print("STOPPED: only this fixture's containers, network and volumes removed", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("create", "start", "stop"))
    parser.add_argument("root", type=Path)
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()
    try:
        if args.operation == "create":
            state = create(args.root)
            print("CREATED: private fixture " + state["project"])
        elif args.operation == "start":
            start(args.root, args.timeout)
        else:
            stop(args.root)
    except SetupError as error:
        print("ERROR: " + str(error), file=sys.stderr)
        return 1
    except Exception as error:
        print("ERROR: fixture setup failed (" + type(error).__name__ + "); details withheld to protect credentials", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
