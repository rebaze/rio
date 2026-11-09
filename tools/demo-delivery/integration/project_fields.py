#!/usr/bin/env python3
"""Exercise Dependency-Track project tags, parent, isLatest and subject links
against an owned, disposable real fixture (5.2.1) with a built or installed Rio.

Each case runs the root `rio --json` pipeline with a key holding one permission
set, then compares Rio's receipt with an independent read-back by the harness's
own portfolio key. Only sanitized evidence is written: no keys, passwords,
session tokens or raw response bodies; server UUIDs become placeholders.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.parse

import setup

# Permission sets for the matrix. Each becomes one team with one key.
TEAMS = {
    "ci": ["BOM_UPLOAD", "PROJECT_CREATION_UPLOAD"],
    "ci-view": ["BOM_UPLOAD", "PROJECT_CREATION_UPLOAD", "VIEW_PORTFOLIO"],
    "upload-only": ["BOM_UPLOAD"],
    "upload-view": ["BOM_UPLOAD", "VIEW_PORTFOLIO"],
    "portfolio-update": ["BOM_UPLOAD", "VIEW_PORTFOLIO", "PORTFOLIO_MANAGEMENT_UPDATE"],
}


class Fail(setup.SetupError):
    pass


def check(condition, message):
    if not condition:
        raise Fail(message)


def session(state, private):
    status, body = setup.request(state["url"], "POST", "/api/v1/user/login",
                                 value={"username": "admin", "password": private["adminPassword"]}, form=True)
    check(status == 200 and body, "admin login failed")
    return body.decode()


def team_keys(root, state, private):
    """Create (once) the matrix teams and keys; keys stay in private.json."""
    token = session(state, private)
    saved = private.setdefault("projectFieldTeams", {})
    for name, permissions in TEAMS.items():
        entry = saved.setdefault(name, {})
        if "team" not in entry:
            team = json.loads(setup.expect(state["url"], "PUT", "/api/v1/team", token, {"name": state["project"] + "-pf-" + name}))
            entry["team"] = team["uuid"]
            setup.write_private(root / "private.json", private)
        for permission in permissions:
            setup.expect(state["url"], "POST", "/api/v1/permission/" + permission + "/team/" + entry["team"], token, codes=(200, 304))
        if "key" not in entry:
            entry["key"] = json.loads(setup.expect(state["url"], "PUT", "/api/v1/team/" + entry["team"] + "/key", token))["key"]
            check(entry["key"], "fixture API key missing")
            setup.write_private(root / "private.json", private)
    return {name: entry["key"] for name, entry in saved.items()}


class Reader:
    """The harness's own read-back, with the setup's portfolio-management key."""

    def __init__(self, base, key):
        self.base, self.key = base, key

    def get(self, path):
        import urllib.request
        import urllib.error
        request = urllib.request.Request(self.base + path, headers={"X-Api-Key": self.key, "Accept": "application/json"})
        try:
            with urllib.request.build_opener(setup.NoRedirect()).open(request, timeout=30) as response:
                return response.status, json.loads(response.read(4 << 20))
        except urllib.error.HTTPError as error:
            return error.code, None

    def project(self, name, version):
        status, found = self.get("/api/v1/project/lookup?" + urllib.parse.urlencode({"name": name, "version": version}))
        # Only a 404 shows that the project does not exist; anything else is no observation.
        if status == 404:
            return None
        check(status == 200, "harness project lookup failed with status " + str(status))
        status, project = self.get("/api/v1/project/" + found["uuid"])
        check(status == 200, "harness project read failed")
        return project

    def create(self, name):
        """Create a version-less grouping project, as parents usually are."""
        import urllib.request
        body = json.dumps({"name": name, "classifier": "APPLICATION", "active": True}).encode()
        request = urllib.request.Request(self.base + "/api/v1/project", data=body, method="PUT",
                                         headers={"X-Api-Key": self.key, "Accept": "application/json", "Content-Type": "application/json"})
        with urllib.request.build_opener(setup.NoRedirect()).open(request, timeout=30) as response:
            check(response.status == 201, "harness could not create the version-less parent")
            return json.loads(response.read())["uuid"]

    def wait(self, event_token, deadline=120):
        end = time.monotonic() + deadline
        while time.monotonic() < end:
            status, value = self.get("/api/v1/event/token/" + event_token)
            if status == 200 and value.get("processing") is False:
                return
            time.sleep(2)
        raise Fail("BOM processing did not finish in time")


def sbom(name, version, path):
    path.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
                                "metadata": {"timestamp": "2026-01-01T00:00:00Z", "component": {"type": "application", "name": name, "version": version}},
                                "components": [{"type": "library", "name": "synthetic-lib", "version": "1.0.0", "purl": "pkg:generic/synthetic-lib@1.0.0"}]}))


def manifest(url, target="", enrichment=""):
    return ("version: 1\n" + enrichment + "artifacts:\n  - id: app\n    sbom: app.cdx.json\n"
            "delivery:\n  targets:\n    dtrack:\n      type: dependency-track\n      url: " + url + "\n      allowHTTP: true\n"
            "      apiKeyEnv: DTRACK_API_KEY\n      autoCreate: true\n" + target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--evidence", type=Path, required=True, help="sanitized evidence JSON to write")
    args = parser.parse_args()
    root, binary = args.root.resolve(), args.binary.resolve()
    state, private = setup.load(root)
    check(state["phase"] == "ready", "fixture is not ready")
    check("http://" + setup.compose(state, private, "port", "apiserver", "8080") == state["url"], "owned fixture endpoint changed")
    config = json.loads((root / "test-env.json").read_text())
    check(config["RIO_DTRACK_TEST_URL"] == state["url"], "private test endpoint differs from owned fixture")
    keys = team_keys(root, state, private)
    reader = Reader(state["url"], config["RIO_DTRACK_TEST_API_KEY"])
    secrets = [private["databasePassword"], private["adminPassword"], config["RIO_DTRACK_TEST_API_KEY"], *keys.values()]
    run_id = state["project"].rsplit("-", 1)[-1]
    placeholders = {}

    def placeholder(value):
        if not value:
            return value
        return placeholders.setdefault(value, "<project-uuid-%d>" % (len(placeholders) + 1))

    work = root / "project-fields"
    work.mkdir(exist_ok=True)
    cases = []

    def run(case, team, name, version, target, enrichment="", code=0):
        folder = work / case
        folder.mkdir(exist_ok=True)
        sbom(name, version, folder / "app.cdx.json")
        (folder / "rio.yaml").write_text(manifest(state["url"], target, enrichment))
        result = subprocess.run([str(binary), "--json"], cwd=folder, env=dict(os.environ, DTRACK_API_KEY=keys[team]),
                                capture_output=True, text=True, timeout=300)
        output = result.stdout + result.stderr
        check(not any(s in output for s in secrets), "credential found in rio output")
        check(result.returncode == code, case + ": rio exit " + str(result.returncode) + ", expected " + str(code))
        value = json.loads(result.stdout)
        raw = Path(value["receipt"]["path"]).read_bytes()
        check(not any(s.encode() in raw for s in secrets), "credential found in receipt")
        delivery = json.loads(raw)["deliveries"][0]
        return delivery

    def record(case, team, name, version, delivery, expectation, observed):
        fields = json.loads(json.dumps(delivery.get("projectFields")))
        if fields and "parent" in fields:
            for side in ("requested", "observed"):
                if side in fields["parent"] and "uuid" in fields["parent"][side]:
                    fields["parent"][side]["uuid"] = placeholder(fields["parent"][side]["uuid"])
        cases.append({"case": case, "keyPermissions": TEAMS[team], "project": {"name": name, "version": version},
                      "rio": {"state": delivery["state"], "errorCode": delivery.get("errorCode"),
                              "responses": [{"kind": r["kind"], "value": r["value"], "httpStatus": r.get("httpStatus"), "code": r.get("code")} for r in delivery.get("responses", [])],
                              "projectFields": fields},
                      "expected": expectation, "harnessObservation": observed})
        print("PASS " + case, flush=True)

    def observe(name, version):
        project = reader.project(name, version)
        if project is None:
            return {"exists": False}
        parent = project.get("parent")
        return {"exists": True, "tags": sorted(t["name"] for t in project.get("tags", [])), "isLatest": project.get("isLatest"),
                "parent": {"name": parent["name"], "version": parent.get("version"), "uuid": placeholder(parent["uuid"])} if parent else None}

    parent_name, parent_version = "rio-it-parent-" + run_id, "all"
    product = "rio-it-product-" + run_id
    tags = "[owner:rio-feature-test, rio-it]"
    try:
        # The parent itself, created by a plain upload.
        d = run("parent", "ci", parent_name, parent_version, "")
        check(d["state"] == "accepted", "parent upload not accepted")
        parent_uuid = reader.project(parent_name, parent_version)["uuid"]
        placeholder(parent_uuid)

        target = "      tags: " + tags + "\n      parent: {name: " + parent_name + ", version: " + parent_version + "}\n      isLatest: true\n"
        # 1. BOM_UPLOAD + PROJECT_CREATION_UPLOAD, new version: applied on creation, unknown to Rio.
        d = run("create-without-view", "ci", product, "1.0.0", target)
        seen = observe(product, "1.0.0")
        check(d["projectFields"]["readBack"] == "forbidden" and {d["projectFields"][k]["state"] for k in ("tags", "parent", "isLatest")} == {"unknown"}, "create-without-view: Rio claimed what it could not read")
        check(seen["tags"] == ["owner:rio-feature-test", "rio-it"] and seen["isLatest"] is True and seen["parent"]["name"] == parent_name, "create-without-view: server did not apply fields on creation")
        record("create-without-view", "ci", product, "1.0.0", d, "tags, parent and isLatest set on creation; read-back forbidden, so all unknown", seen)

        # 2. Same plus VIEW_PORTFOLIO, new version: observed.
        d = run("create-with-view", "ci-view", product, "1.1.0", target)
        seen = observe(product, "1.1.0")
        check(d["projectFields"]["readBack"] == "read" and {d["projectFields"][k]["state"] for k in ("tags", "parent", "isLatest")} == {"observed"}, "create-with-view: not observed")
        check(observe(product, "1.0.0")["isLatest"] is False, "previous latest version kept isLatest")
        record("create-with-view", "ci-view", product, "1.1.0", d, "observed; 1.0.0 is no longer latest", seen)

        changed = "      tags: [owner:rio-feature-test-changed]\n"
        # 3. BOM_UPLOAD only, existing version, changed tags: 200, unchanged; unknown or different.
        d = run("existing-upload-only", "upload-only", product, "1.1.0", changed)
        seen = observe(product, "1.1.0")
        check(d["state"] == "accepted" and d["projectFields"]["tags"]["state"] == "unknown", "existing-upload-only: tags not unknown")
        check(seen["tags"] == ["owner:rio-feature-test", "rio-it"], "existing-upload-only: server changed tags without permission")
        record("existing-upload-only", "upload-only", product, "1.1.0", d, "200; tags unchanged; unknown without VIEW_PORTFOLIO", seen)
        d = run("existing-upload-view", "upload-view", product, "1.1.0", changed)
        seen = observe(product, "1.1.0")
        tags_fact = d["projectFields"]["tags"]
        check(d["state"] == "accepted" and tags_fact["state"] == "different" and tags_fact["observed"] == ["owner:rio-feature-test", "rio-it"], "existing-upload-view: not different")
        record("existing-upload-view", "upload-view", product, "1.1.0", d, "200; tags unchanged; recorded as different", seen)

        # 4. PORTFOLIO_MANAGEMENT_UPDATE, existing version: the tag set is replaced.
        d = run("existing-portfolio-update", "portfolio-update", product, "1.1.0", changed)
        seen = observe(product, "1.1.0")
        check(d["projectFields"]["tags"]["state"] == "observed" and seen["tags"] == ["owner:rio-feature-test-changed"], "existing-portfolio-update: tags not replaced")
        record("existing-portfolio-update", "portfolio-update", product, "1.1.0", d, "tag set replaced; observed", seen)

        # 5. A parent that does not exist: 404, parent_not_found, exit 5.
        missing = "rio-it-missing-parent-" + run_id
        d = run("missing-parent", "ci-view", missing, "1.0.0", "      parent: {name: rio-it-no-such-parent-" + run_id + ", version: all}\n", code=5)
        seen = observe(missing, "1.0.0")
        check(d["state"] == "rejected" and d["errorCode"] == "parent_not_found" and d["responses"][0]["httpStatus"] == 404 and not seen["exists"], "missing-parent: not a distinct 404 failure")
        record("missing-parent", "ci-view", missing, "1.0.0", d, "upload fails with 404, parent_not_found, no project created", seen)

        # 5b. A version-less parent named without a version (#213).
        group = "rio-it-group-" + run_id
        placeholder(reader.create(group))
        grouped = "rio-it-grouped-" + run_id
        d = run("parent-without-version", "ci-view", grouped, "1.0.0", "      parent: {name: " + group + "}\n")
        seen = observe(grouped, "1.0.0")
        check(d["projectFields"]["parent"]["state"] == "observed" and seen["parent"]["name"] == group and "version" not in d["projectFields"]["parent"]["requested"], "parent-without-version: not observed")
        record("parent-without-version", "ci-view", grouped, "1.0.0", d, "a version-less parent named without a version is set and observed", seen)

        # 6. #202 subject links on the project, cleared by an upload without them.
        linked = "rio-it-links-" + run_id
        enrichment = ("enrichment:\n  subject:\n    issueTracker: https://rio-it.example.com/issues\n    links:\n"
                      "      - label: Fact sheet\n        url: https://ea.example.com/factsheet/Application/rio-it\n")
        d = run("links", "ci-view", linked, "1.0.0", "", enrichment)
        reader.wait(d["responses"][0]["references"][0]["value"])
        refs = reader.project(linked, "1.0.0").get("externalReferences", [])
        shown = sorted([{k: r[k] for k in ("type", "url", "comment") if k in r} for r in refs], key=lambda r: r["type"])
        check({"type": "other", "url": "https://ea.example.com/factsheet/Application/rio-it", "comment": "Fact sheet"} in shown, "links: label not shown on the project")
        record("links", "ci-view", linked, "1.0.0", d, "project external references carry type, URL and label (comment)", {"externalReferences": shown})
        d = run("links-cleared", "ci-view", linked, "1.0.0", "")
        reader.wait(d["responses"][0]["references"][0]["value"])
        refs = reader.project(linked, "1.0.0").get("externalReferences") or []
        check(not any(r.get("comment") == "Fact sheet" for r in refs), "links-cleared: upload without the link kept it")
        record("links-cleared", "ci-view", linked, "1.0.0", d, "an upload without the link clears it", {"externalReferences": refs})
    except Fail as error:
        print("FAIL: " + str(error), file=sys.stderr)
        return 1
    finally:
        _, version = reader.get("/api/version")
        evidence = {"serverVersion": (version or {}).get("version"), "images": state.get("images"), "syntheticProjectsOnly": True,
                    "note": "Recorded by tools/demo-delivery/integration/project_fields.py against a disposable fixture. "
                            "Keys, passwords, session tokens and raw bodies are never retained; server UUIDs are placeholders.",
                    "rio": subprocess.run([str(binary), "version"], capture_output=True, text=True).stdout.strip(), "cases": cases}
        raw = json.dumps(evidence, indent=2) + "\n"
        check(not any(s in raw for s in secrets), "credential found in evidence")
        args.evidence.write_text(raw)
    print("PASS: Dependency-Track project fields matrix; evidence " + str(args.evidence))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except setup.SetupError as error:
        print("ERROR: " + str(error), file=sys.stderr)
        sys.exit(1)
