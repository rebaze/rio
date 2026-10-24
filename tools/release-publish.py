#!/usr/bin/env python3
"""Stage Rio release assets and verify their exact bytes before publication.

vacant refuses a tag that already has a release or draft, before anything is
built or signed. stage freezes the built files, draft verifies and uploads them
to a draft release, and publish (the gated job) checks that draft again and
only then makes it public.

Python 3.9+, gh and cosign. Network access belongs here, never in the Rio CLI.
The inventory is a local consistency boundary, not a signature or an approval.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

PROVENANCE = "https://slsa.dev/provenance/v1"
SBOM = "https://cyclonedx.org/bom"
ISSUER = "https://token.actions.githubusercontent.com"


def digest(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError(str(path) + " must be a regular file")
    if path.stat().st_size == 0:
        raise ValueError(str(path) + " is empty")
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def archive(name):
    return name.endswith((".tar.gz", ".zip"))


def source_sbom(tag):
    return "rio-" + tag + "-source.cdx.json"


def bundle_name(tag):
    return "rio-" + tag + ".intoto.jsonl"


def required(tag):
    return {"checksums.txt", "checksums.txt.sigstore.json", "CHANGELOG.md",
            source_sbom(tag)}


def validate_inventory(data, args):
    if (not isinstance(data, dict) or data.get("version") != 1
            or data.get("tag") != args.tag or data.get("repo") != args.repo):
        raise ValueError("unsupported or mismatched release inventory")
    files = data.get("files")
    if not isinstance(files, dict) or not required(args.tag).issubset(files):
        raise ValueError("release inventory is missing required assets")
    if not any(archive(name) for name in files):
        raise ValueError("release inventory has no archives")
    for name, sha in files.items():
        if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name)
                or not (archive(name) or name in required(args.tag))
                or not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{64}", sha)):
            raise ValueError("invalid release inventory entry: " + repr(name))
    return files


def check_files(directory, expected):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("release inventory directory is unavailable: " + str(directory))
    actual = {path.name for path in directory.iterdir()}
    if actual != set(expected):
        raise ValueError("release inventory differs: missing=" + repr(sorted(set(expected) - actual))
                         + ", extra=" + repr(sorted(actual - set(expected))))
    for name, sha in expected.items():
        if digest(directory / name) != sha:
            raise ValueError("asset changed since staging: " + name)


def check_checksums(directory, files):
    expected = {name: sha for name, sha in files.items() if archive(name)}
    found = {}
    for line in (directory / "checksums.txt").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *]([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        if not match or match[2] in found:
            raise ValueError("invalid or duplicate checksum entry")
        found[match[2]] = match[1]
    if found != expected:
        raise ValueError("archive checksums do not match the staged inventory")


def stage(args):
    if args.stage.exists() or args.inventory.exists():
        raise ValueError("stage or inventory already exists; use a fresh run directory")
    names = required(args.tag) | {p.name for p in args.dist.iterdir() if archive(p.name)}
    files = {name: digest(args.dist / name) for name in sorted(names)}
    data = dict(version=1, repo=args.repo, tag=args.tag, files=files)
    validate_inventory(data, args)
    check_checksums(args.dist, files)
    args.stage.mkdir(parents=True)
    for name in files:
        shutil.copyfile(args.dist / name, args.stage / name)
    check_files(args.stage, files)
    # Written last: a partial/aborted stage cannot be mistaken for a complete run.
    with args.inventory.open("x") as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print("STAGED: " + str(len(files)) + " files; SHA-256 inventory recorded", flush=True)


def run(command, capture=False):
    try:
        result = subprocess.run([str(arg) for arg in command], check=True,
                                stdout=subprocess.PIPE if capture else None, text=True)
        return result.stdout
    except subprocess.CalledProcessError as error:
        raise ValueError("command failed: " + " ".join(str(arg) for arg in command[:3])) from error


def releases_for_tag(args):
    # gh create --draft can create several drafts for the same tag. Enumerate
    # every page (including drafts); an API/authentication failure is not absence.
    pages = json.loads(run(["gh", "api", "repos/" + args.repo + "/releases",
                           "--paginate", "--slurp"], capture=True))
    if not isinstance(pages, list) or any(not isinstance(page, list) for page in pages):
        raise ValueError("invalid release lookup response")
    found = []
    for page in pages:
        for release in page:
            if not isinstance(release, dict) or "tag_name" not in release:
                raise ValueError("invalid release lookup entry")
            if release["tag_name"] == args.tag:
                found.append(release)
    return found


def vacant(args):
    if releases_for_tag(args):
        raise ValueError("release or draft already exists for " + args.tag
                         + "; delete an unpublished draft before re-running, never a release")
    print("VACANT: no release or draft for " + args.tag, flush=True)


def draft(args):
    digest(args.inventory)
    data = json.loads(args.inventory.read_text())
    files = validate_inventory(data, args)
    check_files(args.stage, files)
    check_checksums(args.stage, files)
    bundle_sha = digest(args.bundle)
    if args.record.exists():
        raise ValueError("draft record already exists; use a fresh run directory")
    if releases_for_tag(args):
        raise ValueError("release or draft already exists for " + args.tag + "; refusing to replace it")
    identity = "https://github.com/" + args.repo + "/.github/workflows/release.yaml@refs/tags/" + args.tag
    # Verify and upload a private snapshot. Never rebuild or reread dist/ at publication.
    with tempfile.TemporaryDirectory(prefix="rio-release-") as temporary:
        snapshot = Path(temporary) / "assets"
        snapshot.mkdir()
        for name in files:
            shutil.copyfile(args.stage / name, snapshot / name)
        check_files(snapshot, files)
        shutil.copyfile(args.bundle, snapshot / bundle_name(args.tag))
        expected = dict(files, **{bundle_name(args.tag): bundle_sha})
        check_files(snapshot, expected)
        print("VERIFY: exact staged bytes, release workflow identity and tag", flush=True)
        for name in sorted(files):
            # Every asset that can carry build provenance must, so its digest is
            # signed where it was built (cleartoship decision 0024).
            if archive(name) or name in ("checksums.txt", source_sbom(args.tag)):
                predicates = [PROVENANCE, SBOM] if archive(name) else [PROVENANCE]
                for predicate in predicates:
                    command = ["gh", "attestation", "verify", snapshot / name,
                               "--bundle", snapshot / bundle_name(args.tag), "--repo", args.repo,
                               "--cert-identity", identity, "--source-ref", "refs/tags/" + args.tag,
                               "--predicate-type", predicate]
                    if predicate == SBOM:
                        verified = json.loads(run(command + ["--format", "json"], capture=True))
                        source = json.loads((snapshot / source_sbom(args.tag)).read_text())
                        if not isinstance(verified, list) or not verified or any(
                                item.get("verificationResult", {}).get("statement", {}).get("predicate") != source
                                for item in verified):
                            raise ValueError("signed SBOM predicate differs from the staged source SBOM")
                    else:
                        run(command)
        run(["cosign", "verify-blob", "--bundle", snapshot / "checksums.txt.sigstore.json",
             "--certificate-identity", identity, "--certificate-oidc-issuer", ISSUER,
             snapshot / "checksums.txt"])
        check_files(snapshot, expected)
        print("VERIFIED: provenance, source-SBOM attestations and checksum signature", flush=True)
        # Check again after verification, immediately before creating a new draft.
        if releases_for_tag(args):
            raise ValueError("release or draft already exists for " + args.tag)
        assets = {name: sha for name, sha in expected.items() if name != "CHANGELOG.md"}
        command = ["gh", "release", "create", args.tag, "--repo", args.repo,
                   "--verify-tag", "--draft", "--title", args.tag,
                   "--notes-file", snapshot / "CHANGELOG.md"]
        if "-" in args.tag:
            command.append("--prerelease")
        command.extend(snapshot / name for name in sorted(assets))
        run(command)
        created = only_draft(args)
        print("DRAFT: assets uploaded; checking downloaded bytes", flush=True)
        check_draft(args, created["id"], assets, Path(temporary) / "downloaded")
        check_files(snapshot, expected)
    # Written last: the gated publish job flips only the draft this record names.
    with args.record.open("x") as stream:
        json.dump(dict(version=1, repo=args.repo, tag=args.tag, release=created["id"], assets=assets),
                  stream, indent=2, sort_keys=True)
        stream.write("\n")
    print("DRAFTED: release " + str(created["id"]) + " holds the verified bytes; publication waits for the gate",
          flush=True)


def only_draft(args, release_id=None):
    found = releases_for_tag(args)
    if (len(found) != 1 or found[0].get("draft") is not True or type(found[0].get("id")) is not int
            or (release_id is not None and found[0]["id"] != release_id)):
        raise ValueError("the tag's draft is missing, ambiguous or already published; refusing publication")
    return found[0]


def draft_assets(args, release_id):
    pages = json.loads(run(["gh", "api", "repos/" + args.repo + "/releases/" + str(release_id) + "/assets",
                            "--paginate", "--slurp"], capture=True))
    if not isinstance(pages, list) or any(not isinstance(page, list) for page in pages):
        raise ValueError("invalid release asset response")
    listed = {}
    for page in pages:
        for asset in page:
            if (not isinstance(asset, dict) or asset.get("name") in listed
                    or type(asset.get("id")) is not int):
                raise ValueError("invalid or duplicate release asset entry")
            listed[asset["name"]] = asset
    return listed


def check_listing(listed, assets):
    if set(listed) != set(assets):
        raise ValueError("draft assets differ: missing=" + repr(sorted(set(assets) - set(listed)))
                         + ", extra=" + repr(sorted(set(listed) - set(assets))))
    for name, sha in assets.items():
        if listed[name].get("state") != "uploaded" or listed[name].get("digest") != "sha256:" + sha:
            raise ValueError("draft asset digest differs from the staged inventory: " + name)


def check_draft(args, release_id, assets, downloaded):
    """Require the draft's assets, by GitHub's digest and by downloaded bytes, to equal assets."""
    listed = draft_assets(args, release_id)
    check_listing(listed, assets)
    # Download each asset by its ID from this draft, never by tag name, which
    # another draft for the same tag could also answer to.
    downloaded.mkdir()
    for name in sorted(assets):
        command = ["gh", "api", "-H", "Accept: application/octet-stream",
                   "repos/" + args.repo + "/releases/assets/" + str(listed[name]["id"])]
        with (downloaded / name).open("xb") as stream:
            try:
                subprocess.run(command, check=True, stdout=stream)
            except subprocess.CalledProcessError as error:
                raise ValueError("command failed: gh api asset download") from error
    check_files(downloaded, assets)


def publish(args):
    digest(args.inventory)
    files = validate_inventory(json.loads(args.inventory.read_text()), args)
    if not args.record.is_file():
        raise ValueError("draft record is missing; run draft first")
    record = json.loads(args.record.read_text())
    expected = {name: sha for name, sha in files.items() if name != "CHANGELOG.md"}
    if (not isinstance(record, dict) or record.get("version") != 1 or record.get("tag") != args.tag
            or record.get("repo") != args.repo or type(record.get("release")) is not int
            or not isinstance(record.get("assets"), dict)
            or {k: v for k, v in record["assets"].items() if k != bundle_name(args.tag)} != expected
            or not re.fullmatch(r"[0-9a-f]{64}", str(record["assets"].get(bundle_name(args.tag))))):
        raise ValueError("draft record does not match the staged inventory")
    release_id, assets = record["release"], record["assets"]
    release_api = "repos/" + args.repo + "/releases/" + str(release_id)
    print("VERIFY: draft " + str(release_id) + " still holds exactly the staged bytes", flush=True)
    only_draft(args, release_id)
    with tempfile.TemporaryDirectory(prefix="rio-publish-") as temporary:
        check_draft(args, release_id, assets, Path(temporary) / "downloaded")
    current = json.loads(run(["gh", "api", release_api], capture=True))
    if (current.get("draft") is not True or current.get("tag_name") != args.tag
            or current.get("id") != release_id):
        raise ValueError("draft identity or state changed before publication")
    # A cleared prerelease flag would make an rc the latest release, which install.sh installs.
    if current.get("prerelease") is not ("-" in args.tag):
        raise ValueError("draft prerelease flag changed before publication")
    only_draft(args, release_id)
    run(["gh", "api", release_api, "--method", "PATCH", "-F", "draft=false"])
    # Immutable releases freeze what is there now; catch a swap in the last seconds.
    published = json.loads(run(["gh", "api", release_api], capture=True))
    if published.get("draft") is not False:
        raise ValueError("release did not become public")
    try:
        check_listing(draft_assets(args, release_id), assets)
    except ValueError as error:
        raise ValueError("published release differs from the verified draft: " + str(error)) from error
    print("PUBLISHED: " + args.tag + " with the verified asset bytes", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    paths = {"vacant": (), "stage": ("stage", "inventory", "dist"),
             "draft": ("stage", "inventory", "bundle", "record"), "publish": ("inventory", "record")}
    for operation, names in paths.items():
        command = commands.add_parser(operation)
        for name in names:
            command.add_argument("--" + name, type=Path, required=True)
        command.add_argument("--tag", required=True)
        command.add_argument("--repo", required=True)
    args = parser.parse_args()
    try:
        if not re.fullmatch(r"v[0-9][A-Za-z0-9._+-]*", args.tag):
            raise ValueError("invalid release tag")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo):
            raise ValueError("invalid GitHub repository")
        for name in ("inventory", "record"):
            if getattr(args, "stage", None) and getattr(args, name, None) \
                    and getattr(args, name).resolve().parent == args.stage.resolve():
                raise ValueError("keep " + name + " outside the staged asset directory")
        {"vacant": vacant, "stage": stage, "draft": draft, "publish": publish}[args.operation](args)
    except (OSError, ValueError, TypeError) as error:
        print("BLOCKED: " + str(error), file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
