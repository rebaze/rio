#!/usr/bin/env python3
"""Emit one explicit v1 Rio build-context entry for original local SBOM bytes."""

import argparse
import hashlib
import json
import re
import sys
import unicodedata
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit


FIELDS = (
    "source-repository", "source-revision", "source-subdirectory", "source-ref",
    "source-workspace", "build-url", "build-id", "build-timestamp",
    "build-system-name", "build-system-version", "generator-name",
    "generator-version", "lifecycle",
)
MAX_DISTRIBUTIONS = 1000
CHECKSUM_LINE = re.compile(r"([0-9a-f]{64}) [ *](.*)", re.DOTALL)
PHASES = ("design", "pre-build", "build", "post-build", "operations", "discovery", "decommission")


def check_url(label, value):
    try:
        parsed = urlsplit(value)
        valid = (parsed.scheme in ("http", "https") and parsed.hostname and
                 parsed.username is None and parsed.password is None and not parsed.query and
                 not parsed.fragment and "?" not in value and "#" not in value)
    except ValueError:
        valid = False
    if not valid:
        raise ValueError("%s must be an absolute HTTP(S) URL without credentials, query or fragment" % label)


def parse_checksums(path, prefix):
    """Read sha256sum/GoReleaser lines; the digests are the producer's assertion."""
    distributions, seen = [], set()
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line:
            continue
        match = CHECKSUM_LINE.fullmatch(line)
        if not match:
            raise ValueError("checksums line %d must be 64 lowercase hex characters, a space, a space or *, and a name" % number)
        digest, name = match.groups()
        validate("checksums line %d name" % number, name)
        if "/" in name or "\\" in name:
            raise ValueError("checksums line %d name must not contain a path separator" % number)
        if name in seen:
            raise ValueError("checksums line %d repeats name %s" % (number, name))
        seen.add(name)
        item = {"name": name, "sha256": digest}
        if prefix is not None:
            item["url"] = prefix + name
            check_url("checksums line %d url" % number, item["url"])
        distributions.append(item)
        if len(distributions) > MAX_DISTRIBUTIONS:
            raise ValueError("checksums must list at most %d files" % MAX_DISTRIBUTIONS)
    if not distributions:
        raise ValueError("checksums file lists no files")
    return distributions


def validate(label, value):
    if not value or value != value.strip() or any(unicodedata.category(ch) == "Cc" for ch in value):
        raise ValueError("%s must be a nonblank string without surrounding whitespace or controls" % label)
    if label in ("source-repository", "build-url", "distribution-url"):
        check_url(label, value)
    elif label == "source-revision" and not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value):
        raise ValueError("source-revision must be 40 or 64 lowercase hex characters")
    elif label == "source-subdirectory" and (value in (".", "..") or value.startswith("/") or
                                               "\\" in value or any(part in ("", ".", "..") for part in value.split("/"))):
        raise ValueError("source-subdirectory must be a canonical relative POSIX directory")
    elif label == "source-workspace" and value not in ("clean", "dirty", "unknown"):
        raise ValueError("source-workspace must be clean, dirty or unknown")
    elif label == "lifecycle" and value not in PHASES:
        raise ValueError("lifecycle must be a CycloneDX lifecycle phase")
    elif label == "build-timestamp":
        try:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
            valid = bool(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)", value))
        except ValueError:
            valid = False
        if not valid:
            raise ValueError("build-timestamp must be RFC3339")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-id", required=True)
    parser.add_argument("--sbom", required=True, help="original SBOM file to hash byte for byte")
    for field in FIELDS:
        parser.add_argument("--" + field)
    parser.add_argument("--checksums", help="sha256sum/GoReleaser checksums file listing the shipped files")
    parser.add_argument("--distribution-url", help="absolute http(s) URL prefix ending in /; url = prefix + name")
    args = parser.parse_args()
    try:
        validate("artifact-id", args.artifact_id)
        for field in FIELDS:
            value = getattr(args, field.replace("-", "_"))
            if value is not None:
                validate(field, value)
        for parent in ("build-system", "generator"):
            if getattr(args, parent.replace("-", "_") + "_version") is not None and getattr(args, parent.replace("-", "_") + "_name") is None:
                raise ValueError("%s-version requires %s-name" % (parent, parent))
        distributions = None
        if args.distribution_url is not None:
            if args.checksums is None:
                raise ValueError("--distribution-url requires --checksums")
            validate("distribution-url", args.distribution_url)
            if not args.distribution_url.endswith("/"):
                raise ValueError("distribution-url must end with /")
        if args.checksums is not None:
            distributions = parse_checksums(args.checksums, args.distribution_url)
        digest = hashlib.sha256(Path(args.sbom).read_bytes()).hexdigest()
    except (ValueError, OSError, UnicodeError) as error:
        parser.error(str(error))

    entry = {"id": args.artifact_id, "sbom": {"sha256": digest}}
    source = {key: getattr(args, "source_" + key) for key in
              ("repository", "revision", "subdirectory", "ref", "workspace")
              if getattr(args, "source_" + key) is not None}
    if source:
        entry["source"] = source
    build = {key: getattr(args, "build_" + key) for key in ("url", "id", "timestamp")
             if getattr(args, "build_" + key) is not None}
    if args.build_system_name is not None:
        build["system"] = {"name": args.build_system_name}
        if args.build_system_version is not None:
            build["system"]["version"] = args.build_system_version
    if build:
        entry["build"] = build
    if args.generator_name is not None:
        entry["generator"] = {"name": args.generator_name}
        if args.generator_version is not None:
            entry["generator"]["version"] = args.generator_version
    if args.lifecycle is not None:
        entry["lifecycle"] = args.lifecycle
    if distributions is not None:
        entry["distributions"] = distributions
    print(json.dumps({"contextVersion": 1, "artifacts": [entry]}, indent=2))


if __name__ == "__main__":
    main()
