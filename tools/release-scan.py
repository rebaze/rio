#!/usr/bin/env python3
"""Scan the binaries of a published Rio release for known Go vulnerabilities.

Python 3.9+ and gh. CI's daily scan covers main; this covers what users already
downloaded. It verifies archive checksums and build provenance first, then runs
the pinned govulncheck in binary mode on every released binary. A finding or a
scanner error fails the run; neither is reported as clean.
"""

import argparse
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("verify_release", ROOT / "tools/verify-release.py")
verify_release = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verify_release)
command, digest, extract_binary = verify_release.command, verify_release.digest, verify_release.extract_binary

# govulncheck exits 3 when it reports a vulnerability and nonzero otherwise on errors.
FOUND = 3


def scanner():
    override = os.environ.get("RIO_GOVULNCHECK")
    if override:
        return shlex.split(override)
    return ["go", "-C", str(ROOT / "tools/security"), "tool", "govulncheck"]


def resolve_tag(repo, tag):
    if not tag:
        tag = command(["gh", "api", "repos/" + repo + "/releases/latest", "--jq", ".tag_name"]).strip()
    names = verify_release.expected_assets(tag)
    return tag, sorted(n for n in names if n.endswith((".tar.gz", ".zip")))


def verify_archives(args, assets, archives, commit):
    sums = {}
    for line in (assets / "checksums.txt").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *]([A-Za-z0-9._-]+)", line)
        if not match or match[2] in sums:
            raise ValueError("invalid checksum inventory")
        sums[match[2]] = match[1]
    hashes = {name: digest(assets / name) for name in archives}
    if sums != hashes:
        raise ValueError("downloaded archive checksums differ")
    identity = "https://github.com/" + args.repo + "/.github/workflows/release.yaml@refs/tags/" + args.tag
    for name in archives:
        verified = json.loads(command(["gh", "attestation", "verify", assets / name,
            "--bundle", assets / ("rio-" + args.tag + ".intoto.jsonl"), "--repo", args.repo,
            "--cert-identity", identity, "--cert-oidc-issuer", verify_release.ISSUER,
            "--source-ref", "refs/tags/" + args.tag, "--source-digest", commit,
            "--predicate-type", verify_release.PROVENANCE, "--format", "json"]))
        if not isinstance(verified, list) or not verified:
            raise ValueError("no verified provenance for " + name)
    return hashes


def scan(args):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repo):
        raise ValueError("owner/name repository required")
    if args.output.exists():
        raise ValueError("scan output exists; use a fresh directory")
    args.tag, archives = resolve_tag(args.repo, args.tag)
    commit = command(["gh", "api", "repos/" + args.repo + "/commits/" + args.tag, "--jq", ".sha"]).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("release tag does not resolve to a commit")
    args.output.mkdir(mode=0o700, parents=True)
    assets = args.output / "assets"
    assets.mkdir()
    patterns = []
    for name in archives + ["checksums.txt", "rio-" + args.tag + ".intoto.jsonl"]:
        patterns += ["--pattern", name]
    command(["gh", "release", "download", args.tag, "--repo", args.repo, "--dir", assets] + patterns)
    hashes = verify_archives(args, assets, archives, commit)

    version = subprocess.run(scanner() + ["-version"], capture_output=True, text=True, encoding="utf-8")
    if version.returncode:
        raise ValueError("scanner is not available")
    results = []
    for name in archives:
        stem = name[: -len(".tar.gz")] if name.endswith(".tar.gz") else name[: -len(".zip")]
        binary = extract_binary(assets / name, args.output / stem, "rio.exe" if name.endswith(".zip") else "rio")
        run = subprocess.run(scanner() + ["-mode=binary", str(binary)], capture_output=True, text=True, encoding="utf-8")
        (args.output / (stem + ".txt")).write_text(run.stdout + run.stderr)
        status = {0: "clean", FOUND: "vulnerable"}.get(run.returncode, "error")
        ids = sorted(set(re.findall(r"^Vulnerability #\d+: (\S+)", run.stdout, re.M)))
        results.append({"archive": name, "archiveSHA256": hashes[name], "status": status, "vulnerabilities": ids})

    report = {"tag": args.tag, "commit": commit, "repo": args.repo,
              "scannedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
              "scanner": version.stdout.strip().splitlines(), "results": results}
    (args.output / "scan.json").write_text(json.dumps(report, indent=2) + "\n")
    summary(report)
    return all(r["status"] == "clean" for r in results)


def summary(report):
    lines = ["## Published release scan: " + report["tag"], "",
             "Commit `" + report["commit"] + "`, scanned " + report["scannedAt"] + ". "
             + "; ".join(report["scanner"]), "",
             "| Archive | Result | Vulnerabilities |", "|---|---|---|"]
    for r in report["results"]:
        lines.append("| `" + r["archive"] + "` | " + r["status"] + " | " + (", ".join(r["vulnerabilities"]) or "none") + " |")
    text = "\n".join(lines) + "\n"
    print(text)
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as stream:
            stream.write(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", default="", help="published stable tag; default: the latest release")
    parser.add_argument("--repo", default="rebaze/rio")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        clean = scan(args)
    except (OSError, ValueError, tarfile.TarError, zipfile.BadZipFile) as error:
        print("FAILED: " + str(error), file=sys.stderr)
        return 1
    if not clean:
        print("FAILED: published binaries have known vulnerabilities or could not be scanned", file=sys.stderr)
        return 1
    print("CLEAN:", args.tag, "all published binaries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
