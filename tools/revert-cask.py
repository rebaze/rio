#!/usr/bin/env python3
"""Recover the Homebrew cask of an earlier Rio release, checked against its signed checksums.

Python 3.9+, gh and cosign. Used when a release is withdrawn (docs/recovery.md).
The cask template has changed between releases (v0.8.0 still stripped macOS
quarantine; v0.8.1 is notarized and does not), so a revert restores the cask
that was published for that release instead of re-rendering it. The newest
rebaze/homebrew-tap commit whose cask has that version is taken, and every
sha256 in it must equal the release's cosign-verified checksums.txt. It writes
the file; committing and pushing it to the tap stays a human step.
"""

import argparse
import base64
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ISSUER = "https://token.actions.githubusercontent.com"
PLATFORMS = ("darwin_amd64", "darwin_arm64", "linux_amd64", "linux_arm64")


def command(args):
    result = subprocess.run([str(x) for x in args], capture_output=True, text=True, encoding="utf-8")
    if result.returncode:
        raise ValueError("command failed: " + " ".join(str(x) for x in args[:3]))
    return result.stdout


def checksums(text):
    sums = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *]([A-Za-z0-9._-]+)", line)
        if not match or match[2] in sums:
            raise ValueError("invalid checksum inventory")
        sums[match[2]] = match[1]
    return sums


def check_cask(cask, version, sums):
    found = re.findall(r'version "([^"]+)"', cask)
    if found != [version]:
        raise ValueError("cask does not declare exactly version " + version)
    pairs = re.findall(r'sha256 "([0-9a-f]{64})"\s*\n\s*url "https://github\.com/rebaze/rio/releases/download/'
                       r'v#\{version\}/rio_#\{version\}_([a-z]+_[a-z0-9]+)\.tar\.gz"', cask)
    if sorted(platform for _, platform in pairs) != sorted(PLATFORMS) or cask.count("sha256 ") != len(PLATFORMS):
        raise ValueError("cask does not hold exactly one hash per platform")
    for sha, platform in pairs:
        name = "rio_" + version + "_" + platform + ".tar.gz"
        if sums.get(name) != sha:
            raise ValueError("cask hash differs from signed checksums for " + name)


def find_cask(tap, version):
    commits = json.loads(command(["gh", "api", "repos/" + tap + "/commits?path=Casks/rio.rb&per_page=100"]))
    for commit in commits:
        data = json.loads(command(["gh", "api", "repos/" + tap + "/contents/Casks/rio.rb?ref=" + commit["sha"]]))
        cask = base64.b64decode(data["content"]).decode("utf-8")
        if re.search(r'^  version "' + re.escape(version) + r'"$', cask, re.M):
            return commit["sha"], cask
    raise ValueError("no cask for " + version + " in " + tap)


def revert(args):
    if not re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", args.to):
        raise ValueError("stable v-prefixed semantic version required")
    version = args.to[1:]
    with tempfile.TemporaryDirectory() as tmp:
        assets = Path(tmp)
        command(["gh", "release", "download", args.to, "--repo", args.repo, "--dir", assets,
                 "--pattern", "checksums.txt", "--pattern", "checksums.txt.sigstore.json"])
        identity = "https://github.com/" + args.repo + "/.github/workflows/release.yaml@refs/tags/" + args.to
        command(["cosign", "verify-blob", "--bundle", assets / "checksums.txt.sigstore.json",
                 "--certificate-identity", identity, "--certificate-oidc-issuer", ISSUER, assets / "checksums.txt"])
        sums = checksums((assets / "checksums.txt").read_text())
    sha, cask = find_cask(args.tap, version)
    check_cask(cask, version, sums)
    args.output.write_text(cask)
    print("VERIFIED: cask for " + args.to + " from " + args.tap + "@" + sha + " matches the signed checksums")
    print("Wrote " + str(args.output) + ". Commit it to " + args.tap + " as Casks/rio.rb with the message:")
    print("  rio " + version + " (withdraw <broken version>, see <issue>)")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--to", required=True, help="earlier published stable tag to restore, e.g. v0.8.0")
    parser.add_argument("--repo", default="rebaze/rio")
    parser.add_argument("--tap", default="rebaze/homebrew-tap")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        revert(args)
    except (OSError, ValueError, KeyError) as error:
        print("FAILED: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
