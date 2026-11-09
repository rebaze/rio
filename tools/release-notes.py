#!/usr/bin/env python3
"""Select the release notes before the publisher freezes its inventory.

docs/releases/<tag>.md, when it exists, becomes the release body byte for byte;
a file that exists but has no exact '# Rio <tag>' heading or no body stops the
release. Without one, for example when a tag is pushed by hand, GoReleaser's
generated notes stay, so a missing file never blocks a release.
"""
import argparse
import os
from pathlib import Path
import re
import sys
import tempfile

TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?")


def select(tag, notes_dir, dist):
    match = TAG.fullmatch(tag)
    if not match or any(part.isdigit() and len(part) > 1 and part.startswith("0") for part in (match[4] or "").split(".")):
        raise ValueError("tag must be a v-prefixed semantic version")
    if dist.is_symlink() or not dist.is_dir():
        raise ValueError("existing regular dist directory required")
    source = notes_dir / (tag + ".md")
    output = dist / "CHANGELOG.md"
    if output.is_symlink():
        raise ValueError("generated notes path must not be a symlink")
    if not source.exists() and not source.is_symlink():
        if not output.is_file() or not output.read_bytes().strip():
            raise ValueError("no authored notes for " + tag + ", and GoReleaser's generated notes are missing or empty")
        print("NOTES: no " + str(source) + "; using GoReleaser's generated notes for " + tag)
        return
    if source.is_symlink() or not source.is_file():
        raise ValueError("authored notes must be a regular file")
    raw = source.read_bytes()
    text = raw.decode("utf-8")
    lines = text.splitlines()
    if not lines or not re.fullmatch(r"# Rio " + re.escape(tag) + r"(?:\s+.+)?", lines[0]) or not "\n".join(lines[1:]).strip():
        raise ValueError("authored notes need an exact '# Rio " + tag + "' heading and nonempty body")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=dist, prefix=".rio-notes-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    if output.read_bytes() != raw:
        raise ValueError("authored notes failed read-back verification")
    print("NOTES: exact authored bytes selected for " + tag)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--notes-dir", type=Path, default=Path("docs/releases"))
    parser.add_argument("--dist", type=Path, default=Path("dist"))
    args = parser.parse_args()
    try:
        select(args.tag, args.notes_dir, args.dist)
    except (ValueError, OSError) as error:
        print("ERROR: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
