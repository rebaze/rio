"""Synthetic release assets shared by the offline demo and tests. No credentials."""

import hashlib
import json
import os
from pathlib import Path
import shlex
import sys
from types import SimpleNamespace

SERVICE = Path(__file__).with_name("fake_service.py")


def create(root):
    self = SimpleNamespace(root=Path(root))
    self.dist = self.root / "dist"
    self.dist.mkdir()
    self.stage = self.root / "stage"
    self.inventory = self.root / "inventory.json"
    self.bundle = self.root / "bundle.jsonl"
    self.tag = "v1.2.3"
    self.repo = "rebaze/rio"
    self.archive = "rio_1.2.3_linux_amd64.tar.gz"
    (self.dist / self.archive).write_bytes(b"packaged application A\n")
    digest = hashlib.sha256((self.dist / self.archive).read_bytes()).hexdigest()
    (self.dist / "checksums.txt").write_text(digest + "  " + self.archive + "\n")
    (self.dist / "checksums.txt.sigstore.json").write_text("fixture signature\n")
    (self.dist / "CHANGELOG.md").write_text("Release fixture\n")
    self.sbom = "rio-" + self.tag + "-source.cdx.json"
    (self.dist / self.sbom).write_text('{"bomFormat":"CycloneDX","specVersion":"1.6"}\n')
    subjects = {
        name: hashlib.sha256((self.dist / name).read_bytes()).hexdigest()
        for name in (self.archive, "checksums.txt")
    }
    self.bundle.write_text(json.dumps({"fixtureOnly": True, "subjects": subjects,
                                      "predicate": json.loads((self.dist / self.sbom).read_text())}))
    self.bin = self.root / "bin"
    self.bin.mkdir()
    for name in ("gh", "cosign", "goreleaser"):
        path = self.bin / name
        path.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " "
                        + shlex.quote(str(SERVICE)) + " " + name + ' "$@"\n')
        path.chmod(0o755)
    self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                    FAKE_RELEASE_ROOT=str(self.root), GITHUB_REPOSITORY=self.repo)
    return self
