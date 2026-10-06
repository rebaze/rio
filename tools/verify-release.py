#!/usr/bin/env python3
"""Verify published stable assets, identities and native client demo without installing Rio."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ISSUER = "https://token.actions.githubusercontent.com"
PROVENANCE = "https://slsa.dev/provenance/v1"
SBOM = "https://cyclonedx.org/bom"


def expected_assets(tag):
    if not re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", tag):
        raise ValueError("stable v-prefixed semantic version required")
    archives = {"rio_" + tag[1:] + "_" + system + "_" + arch + (".zip" if system == "windows" else ".tar.gz")
                for system in ("darwin", "linux", "windows") for arch in ("amd64", "arm64")}
    return archives | {"checksums.txt", "checksums.txt.sigstore.json", "rio-" + tag + "-source.cdx.json", "rio-" + tag + ".intoto.jsonl"}


def client_demo_required(tag, legacy_smoke):
    expected_assets(tag)
    version = tuple(int(part) for part in tag[1:].split("."))
    if legacy_smoke and version >= (0, 6, 0):
        raise ValueError("client demo cannot be skipped for client-evidence releases")
    return not legacy_smoke


def validate_release(data, tag, notes):
    if data.get("tag_name") != tag or data.get("draft") is not False or data.get("prerelease") is not False:
        raise ValueError("release identity or stable/publication state differs")
    if data.get("body", "").encode("utf-8") != notes:
        raise ValueError("release body differs from authored notes")
    assets = data.get("assets", [])
    names = [x.get("name") for x in assets]
    if len(names) != len(set(names)) or set(names) != expected_assets(tag) or any(x.get("size", 0) <= 0 for x in assets):
        raise ValueError("published asset set is incomplete or unexpected")


def digest(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("regular downloaded asset required")
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def extract_binary(archive, directory, name):
    directory.mkdir()
    limit = 256 << 20
    if archive.name.endswith(".zip"):
        with zipfile.ZipFile(archive) as bundle:
            entries = [x for x in bundle.infolist() if x.filename == name]
            if len(entries) != 1 or entries[0].is_dir() or entries[0].file_size > limit or (entries[0].external_attr >> 16) & 0o170000 not in (0, 0o100000):
                raise ValueError("one bounded regular native binary required")
            with bundle.open(entries[0]) as stream:
                raw = stream.read(limit + 1)
    else:
        with tarfile.open(archive, "r:gz") as bundle:
            entries = [x for x in bundle.getmembers() if x.name == name]
            if len(entries) != 1 or not entries[0].isfile() or entries[0].size > limit:
                raise ValueError("one bounded regular native binary required")
            with bundle.extractfile(entries[0]) as stream:
                raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("native binary exceeds extraction limit")
    target = directory / name
    target.write_bytes(raw)
    target.chmod(0o755)
    return target


def command(args):
    result = subprocess.run([str(x) for x in args], capture_output=True, text=True, encoding="utf-8")
    if result.returncode:
        raise ValueError("verification command failed: " + " ".join(str(x) for x in args[:3]))
    return result.stdout


def verify(args):
    if not re.fullmatch(r"[0-9a-f]{40}", args.commit) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo):
        raise ValueError("expected full commit and repository required")
    names = expected_assets(args.tag)
    run_client_demo = client_demo_required(args.tag, args.legacy_smoke)
    if args.output.exists():
        raise ValueError("verification output exists; use a fresh directory")
    args.output.mkdir(mode=0o700)
    assets = args.output / "assets"
    assets.mkdir()
    metadata = json.loads(command(["gh", "api", "repos/" + args.repo + "/releases/tags/" + args.tag]))
    repository = json.loads(command(["gh", "api", "repos/" + args.repo]))
    if repository.get("private") is not False:
        raise ValueError("release repository is not public")
    notes = args.notes.read_bytes()
    validate_release(metadata, args.tag, notes)
    command(["gh", "release", "download", args.tag, "--repo", args.repo, "--dir", assets])
    if {p.name for p in assets.iterdir()} != names:
        raise ValueError("downloaded asset set differs")
    hashes = {name: digest(assets / name) for name in sorted(names)}
    sums = {}
    for line in (assets / "checksums.txt").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *]([A-Za-z0-9._-]+)", line)
        if not match or match[2] in sums:
            raise ValueError("invalid checksum inventory")
        sums[match[2]] = match[1]
    archives = {n: h for n, h in hashes.items() if n.endswith((".zip", ".tar.gz"))}
    if sums != archives:
        raise ValueError("downloaded archive checksums differ")
    identity = "https://github.com/" + args.repo + "/.github/workflows/release.yaml@refs/tags/" + args.tag
    command(["cosign", "verify-blob", "--bundle", assets / "checksums.txt.sigstore.json",
             "--certificate-identity", identity, "--certificate-oidc-issuer", ISSUER, assets / "checksums.txt"])
    source_sbom = json.loads((assets / ("rio-" + args.tag + "-source.cdx.json")).read_bytes())
    attestations = []
    for name in sorted(set(archives) | {"checksums.txt"}):
        for predicate in ([PROVENANCE, SBOM] if name in archives else [PROVENANCE]):
            verified = json.loads(command(["gh", "attestation", "verify", assets / name,
                "--bundle", assets / ("rio-" + args.tag + ".intoto.jsonl"), "--repo", args.repo,
                "--cert-identity", identity, "--cert-oidc-issuer", ISSUER,
                "--source-ref", "refs/tags/" + args.tag, "--source-digest", args.commit,
                "--predicate-type", predicate, "--format", "json"]))
            if not isinstance(verified, list) or not verified:
                raise ValueError("no verified attestation returned")
            if predicate == SBOM and any(x.get("verificationResult", {}).get("statement", {}).get("predicate") != source_sbom for x in verified):
                raise ValueError("source SBOM differs from signed predicate")
            attestations.append({"asset": name, "predicate": predicate, "verified": verified})
    (args.output / "attestations.json").write_text(json.dumps(attestations, indent=2) + "\n")
    system = {"Darwin": "darwin", "Linux": "linux", "Windows": "windows"}.get(platform.system())
    arch = {"x86_64": "amd64", "AMD64": "amd64", "arm64": "arm64", "aarch64": "arm64"}.get(platform.machine())
    if not system or not arch:
        raise ValueError("host platform has no release archive")
    archive = assets / ("rio_" + args.tag[1:] + "_" + system + "_" + arch + (".zip" if system == "windows" else ".tar.gz"))
    binary = extract_binary(archive, args.output / "native", "rio.exe" if system == "windows" else "rio")
    version = command([binary, "version"])
    if not version.startswith("rio " + args.tag[1:] + " (commit: " + args.commit + ", built: "):
        raise ValueError("published native binary version/commit differs")
    if run_client_demo:
        demo = command([sys.executable, ROOT / "tools/demo-client-record/run.py", binary])
        (args.output / "native-demo.log").write_text(demo)
    summary = {"tag": args.tag, "commit": args.commit, "repo": args.repo, "releaseURL": metadata["html_url"],
               "assetSHA256": hashes, "notesSHA256": hashlib.sha256(notes).hexdigest(),
               "cosignVerified": True, "attestedSourceCommitVerified": True,
               "nativeExecution": {"os": system, "arch": arch, "binarySHA256": digest(binary), "version": version.strip()},
               "clientDemoPassed": run_client_demo, "legacyVersionOnly": not run_client_demo, "otherArchitectures": "verified archives; not executed by this host"}
    (args.output / "verification.json").write_text(json.dumps(summary, indent=2) + "\n")
    print("VERIFIED:", args.tag, "complete signed asset set and native", system, arch, "client demo" if run_client_demo else "legacy version smoke")
    print("Native binary:", binary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy-smoke", action="store_true", help="version-only native smoke for releases before v0.6.0; never permitted for newer releases")
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--repo", default="rebaze/rio")
    parser.add_argument("--notes", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        verify(args)
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as error:
        print("FAILED: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
