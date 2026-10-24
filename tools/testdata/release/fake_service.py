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


def draft():
    return not (root / "published").exists() and not os.environ.get("FAKE_ALREADY_PUBLISHED")


def remote_files():
    # Asset IDs follow the sorted names, as stable as GitHub's within one draft.
    return {1000 + index: path for index, path in enumerate(sorted((root / "remote").iterdir()))}


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
    if (bundle["subjects"].get(artifact.name) != hashlib.sha256(artifact.read_bytes()).hexdigest()
            or os.environ.get("FAKE_UNSIGNED") == artifact.name):
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
    (root / "prerelease").write_text(json.dumps("--prerelease" in args))
    # The caller provides each asset as an absolute file argument.
    notes = value("--notes-file")
    for arg in args[3:]:
        if arg != notes and Path(arg).is_absolute() and Path(arg).is_file():
            shutil.copyfile(arg, remote / Path(arg).name)
    if os.environ.get("FAKE_REMOTE_CHANGE"):
        next(remote.glob("*.tar.gz")).write_bytes(b"replaced during upload\n")
    # GitHub computes each asset's digest from the bytes it received.
    (root / "remote-digests.json").write_text(json.dumps(
        {path.name: "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest() for path in remote.iterdir()}))
elif tool == "gh" and args[:2] == ["api", "-H"] and "/releases/assets/" in args[3]:
    if args[2] != "Accept: application/octet-stream":
        fail("asset download must request the raw bytes")
    path = remote_files().get(int(args[3].rsplit("/", 1)[1]))
    if path is None:
        fail("no such asset")
    sys.stdout.buffer.write(path.read_bytes())
elif tool == "gh" and args[0] == "api" and args[1].endswith("/123/assets"):
    # GitHub reports each asset's own SHA-256 as "digest" (cleartoship 0024).
    recorded = json.loads((root / "remote-digests.json").read_text())
    assets = [{"id": asset_id, "name": path.name, "state": "uploaded",
               "digest": os.environ.get("FAKE_ASSET_DIGEST") or recorded.get(path.name)
               or "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()}
              for asset_id, path in remote_files().items()]
    print(json.dumps([assets]))
elif tool == "gh" and args[0] == "api" and "--paginate" in args:
    if os.environ.get("FAKE_FAIL") == "lookup":
        fail("release lookup failed")
    releases = []
    if (root / "remote").exists():
        tag = (root / "tag").read_text() if (root / "tag").exists() else "v1.2.3"
        releases = [{"id": int(os.environ.get("FAKE_DRAFT_ID", "123")), "tag_name": tag,
                     "draft": draft()}]
        if os.environ.get("FAKE_SECOND_DRAFT"):
            releases.append({"id": 124, "tag_name": tag, "draft": True})
    print(json.dumps([releases]))
elif tool == "gh" and args[0] == "api" and "--method" in args:
    if value("--method") != "PATCH" or "draft=false" not in args or not args[1].endswith("/123"):
        fail("only ID-bound final publication is supported")
    (root / "published").write_text("published after verification\n")
    if os.environ.get("FAKE_SWAP_AFTER_PUBLISH"):
        recorded = json.loads((root / "remote-digests.json").read_text())
        name = next(n for n in recorded if n.endswith(".tar.gz"))
        recorded[name] = "sha256:" + "e" * 64
        (root / "remote-digests.json").write_text(json.dumps(recorded))
elif tool == "gh" and args[0] == "api" and args[1].endswith("/123"):
    prerelease = json.loads((root / "prerelease").read_text())
    if os.environ.get("FAKE_PRERELEASE_FLIP"):
        prerelease = not prerelease
    print(json.dumps({"id": 123, "draft": draft(), "tag_name": (root / "tag").read_text(),
                      "prerelease": prerelease}))
else:
    fail("unexpected command: " + repr([tool] + args))
