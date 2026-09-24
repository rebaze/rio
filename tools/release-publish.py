#!/usr/bin/env python3
"""Stage Rio release assets and verify their exact bytes before publication.

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


def required(tag):
    return {"checksums.txt", "checksums.txt.sigstore.json", "CHANGELOG.md",
            "rio-" + tag + "-source.cdx.json"}


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


def publish(args):
    digest(args.inventory)
    data = json.loads(args.inventory.read_text())
    files = validate_inventory(data, args)
    check_files(args.stage, files)
    check_checksums(args.stage, files)
    bundle_sha = digest(args.bundle)
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
        bundle_name = "rio-" + args.tag + ".intoto.jsonl"
        shutil.copyfile(args.bundle, snapshot / bundle_name)
        expected = dict(files, **{bundle_name: bundle_sha})
        check_files(snapshot, expected)
        print("VERIFY: exact staged bytes, release workflow identity and tag", flush=True)
        for name in sorted(files):
            if archive(name) or name == "checksums.txt":
                predicates = [PROVENANCE, SBOM] if archive(name) else [PROVENANCE]
                for predicate in predicates:
                    command = ["gh", "attestation", "verify", snapshot / name,
                               "--bundle", snapshot / bundle_name, "--repo", args.repo,
                               "--cert-identity", identity, "--source-ref", "refs/tags/" + args.tag,
                               "--predicate-type", predicate]
                    if predicate == SBOM:
                        verified = json.loads(run(command + ["--format", "json"], capture=True))
                        source = json.loads((snapshot / ("rio-" + args.tag + "-source.cdx.json")).read_text())
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
        created = releases_for_tag(args)
        if (len(created) != 1 or created[0].get("draft") is not True
                or type(created[0].get("id")) is not int):
            raise ValueError("new draft is missing or ambiguous; refusing publication")
        release_api = "repos/" + args.repo + "/releases/" + str(created[0]["id"])
        print("DRAFT: assets uploaded; checking downloaded bytes before publication", flush=True)
        downloaded = Path(temporary) / "downloaded"
        downloaded.mkdir()
        run(["gh", "release", "download", args.tag, "--repo", args.repo,
             "--dir", downloaded])
        check_files(downloaded, assets)
        check_files(snapshot, expected)
        current = json.loads(run(["gh", "api", release_api], capture=True))
        if (current.get("draft") is not True or current.get("tag_name") != args.tag
                or current.get("id") != created[0]["id"]):
            raise ValueError("draft identity or state changed before publication")
        run(["gh", "api", release_api, "--method", "PATCH", "-F", "draft=false"])
        print("PUBLISHED: " + args.tag + " with the verified asset bytes", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    for operation in ("stage", "publish"):
        command = commands.add_parser(operation)
        for name in ("stage", "inventory"):
            command.add_argument("--" + name, type=Path, required=True)
        command.add_argument("--tag", required=True)
        command.add_argument("--repo", required=True)
        command.add_argument("--" + ("dist" if operation == "stage" else "bundle"),
                             type=Path, required=True)
    args = parser.parse_args()
    try:
        if not re.fullmatch(r"v[0-9][A-Za-z0-9._+-]*", args.tag):
            raise ValueError("invalid release tag")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo):
            raise ValueError("invalid GitHub repository")
        if args.inventory.resolve().parent == args.stage.resolve():
            raise ValueError("keep inventory outside the staged asset directory")
        (stage if args.operation == "stage" else publish)(args)
    except (OSError, ValueError, TypeError) as error:
        print("BLOCKED: " + str(error), file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
