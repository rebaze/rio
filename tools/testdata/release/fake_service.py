"""OFFLINE TEST DOUBLE. No signatures are authenticated; no network is used."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

tool, *args = sys.argv[1:]
root = Path(os.environ["FAKE_RELEASE_ROOT"])
with (root / "events.jsonl").open("a") as log:
    log.write(json.dumps([tool] + args) + "\n")


def fail(message):
    print("fixture service: " + message, file=sys.stderr)
    sys.exit(1)


def value(flag):
    return args[args.index(flag) + 1]


if tool == "goreleaser":
    if not any(arg.startswith("--skip=") and "publish" in arg.split("=", 1)[1].split(",")
               for arg in args):
        (root / "published").write_text("published before verification")
elif tool == "cosign":
    if args[0] != "verify-blob" or "--certificate-identity" not in args:
        fail("unexpected cosign invocation")
    if os.environ.get("FAKE_FAIL") == "cosign":
        fail("signature verification failed (synthetic)")
elif tool == "gh" and args[:2] == ["attestation", "verify"]:
    if "--cert-identity" not in args or "--source-ref" not in args:
        fail("missing identity constraints")
    artifact = Path(args[2])
    bundle = json.loads(Path(value("--bundle")).read_text())
    if bundle.get("fixtureOnly") is not True:
        fail("requires synthetic fixture bundle")
    if bundle["subjects"].get(artifact.name) != hashlib.sha256(artifact.read_bytes()).hexdigest():
        fail("attestation digest mismatch")
    predicate = value("--predicate-type")
    failure = os.environ.get("FAKE_FAIL")
    if (failure == "provenance" and "slsa.dev" in predicate) or (
            failure == "sbom" and "cyclonedx.org" in predicate):
        fail("required attestation verification failed (synthetic)")
    if "--format" in args:
        sbom = {"wrong": "document"} if os.environ.get("FAKE_WRONG_SBOM") else bundle["predicate"]
        print(json.dumps([{"verificationResult": {"statement": {"predicate": sbom}}}]))
elif tool == "gh" and args[:2] == ["release", "create"]:
    if "--draft" not in args or "--verify-tag" not in args:
        fail("create must be a draft for an existing tag")
    remote = root / "remote"
    if remote.exists():
        fail("release already exists")
    remote.mkdir()
    (root / "tag").write_text(args[2])
    # The caller provides each asset as an absolute file argument.
    notes = value("--notes-file")
    for arg in args[3:]:
        if arg != notes and Path(arg).is_absolute() and Path(arg).is_file():
            shutil.copyfile(arg, remote / Path(arg).name)
    if os.environ.get("FAKE_REMOTE_CHANGE"):
        next(remote.glob("*.tar.gz")).write_bytes(b"replaced during upload\n")
elif tool == "gh" and args[:2] == ["release", "download"]:
    for path in (root / "remote").iterdir():
        shutil.copyfile(path, Path(value("--dir")) / path.name)
elif tool == "gh" and args[0] == "api" and "--paginate" in args:
    if os.environ.get("FAKE_FAIL") == "lookup":
        fail("release lookup failed")
    releases = []
    if (root / "remote").exists():
        releases = [{"id": 123, "tag_name": "v1.2.3", "draft": True}]
        if (root / "tag").exists():
            releases[0]["tag_name"] = (root / "tag").read_text()
    print(json.dumps([releases]))
elif tool == "gh" and args[0] == "api" and "--method" in args:
    if value("--method") != "PATCH" or "draft=false" not in args or not args[1].endswith("/123"):
        fail("only ID-bound final publication is supported")
    (root / "published").write_text("published after verification\n")
elif tool == "gh" and args[0] == "api" and args[1].endswith("/123"):
    print(json.dumps({"id": 123, "draft": True, "tag_name": (root / "tag").read_text()}))
else:
    fail("unexpected command: " + repr([tool] + args))
