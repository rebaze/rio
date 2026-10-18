#!/usr/bin/env python3
"""Recover the Homebrew cask of an earlier Rio release, authenticated end to end.

Python 3.9+, gh and cosign. Used when a release is withdrawn (docs/recovery.md).
A cask is Ruby that Homebrew executes, so matching archive hashes is not enough.
The tool renders the cask the release workflow generated for that release: the
template in .github/workflows/release.yaml at the protected tag, filled with the
release's cosign-verified checksums. It then requires a byte-identical cask in
rebaze/homebrew-tap's history, which shows that exact file was published. Any
other content (a later hand edit, a changed install hook) is refused for review
by hand. It writes the file; committing and pushing it to the tap stays a human step.
"""

import argparse
import base64
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap

ISSUER = "https://token.actions.githubusercontent.com"
PLATFORMS = {"DARWIN_AMD": "darwin_amd64", "DARWIN_ARM": "darwin_arm64",
             "LINUX_AMD": "linux_amd64", "LINUX_ARM": "linux_arm64"}


def command(args):
    result = subprocess.run([str(x) for x in args], capture_output=True, text=True, encoding="utf-8")
    if result.returncode:
        raise ValueError("command failed: " + " ".join(str(x) for x in args[:3]))
    return result.stdout


def content(repo, path, ref):
    data = json.loads(command(["gh", "api", "repos/" + repo + "/contents/" + path + "?ref=" + ref]))
    return base64.b64decode(data["content"]).decode("utf-8")


def checksums(text):
    sums = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *]([A-Za-z0-9._-]+)", line)
        if not match or match[2] in sums:
            raise ValueError("invalid checksum inventory")
        sums[match[2]] = match[1]
    return sums


def render(workflow, version, sums):
    """Expand the workflow's cask heredoc as bash does for the variables it uses."""
    start = workflow.find("cat > rio.rb <<EOF\n")
    end = re.search(r"^\s*EOF$", workflow[start:], re.M) if start >= 0 else None
    if not end:
        raise ValueError("release workflow at this tag has no cask template")
    cask = textwrap.dedent(workflow[start + len("cat > rio.rb <<EOF\n"): start + end.start()])
    values = {"VERSION": version}
    for key, platform in PLATFORMS.items():
        name = "rio_" + version + "_" + platform + ".tar.gz"
        if name not in sums:
            raise ValueError("signed checksums lack " + name)
        values["SHA_" + key] = sums[name]
    for key, value in values.items():
        cask = cask.replace("${" + key + "}", value)
    if "$" in cask or "\\" in cask or "`" in cask:
        raise ValueError("cask template uses shell expansions this tool does not reproduce; restore by hand")
    return cask


def published(tap, cask):
    pages = json.loads(command(["gh", "api", "repos/" + tap + "/commits?path=Casks/rio.rb&per_page=100",
                                "--paginate", "--slurp"]))
    if not isinstance(pages, list) or any(not isinstance(page, list) for page in pages):
        raise ValueError("invalid tap history response")
    for page in pages:
        for commit in page:
            if content(tap, "Casks/rio.rb", commit["sha"]) == cask:
                return commit["sha"]
    raise ValueError("no tap commit holds the cask the release workflow generated; review the tap history by hand")


def revert(args):
    if not re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", args.to):
        raise ValueError("stable v-prefixed semantic version required")
    with tempfile.TemporaryDirectory() as tmp:
        assets = Path(tmp)
        command(["gh", "release", "download", args.to, "--repo", args.repo, "--dir", assets,
                 "--pattern", "checksums.txt", "--pattern", "checksums.txt.sigstore.json"])
        identity = "https://github.com/" + args.repo + "/.github/workflows/release.yaml@refs/tags/" + args.to
        command(["cosign", "verify-blob", "--bundle", assets / "checksums.txt.sigstore.json",
                 "--certificate-identity", identity, "--certificate-oidc-issuer", ISSUER, assets / "checksums.txt"])
        sums = checksums((assets / "checksums.txt").read_text())
    workflow = content(args.repo, ".github/workflows/release.yaml", args.to)
    cask = render(workflow, args.to[1:], sums)
    sha = published(args.tap, cask)
    args.output.write_text(cask)
    print("VERIFIED: cask for " + args.to + " equals the release workflow's output at that tag with the signed "
          "checksums, as published in " + args.tap + "@" + sha)
    print("Wrote " + str(args.output) + ". Commit it to " + args.tap + " as Casks/rio.rb with the message:")
    print("  rio " + args.to[1:] + " (withdraw <broken version>, see <issue>)")


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
