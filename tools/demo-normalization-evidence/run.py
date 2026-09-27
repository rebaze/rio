#!/usr/bin/env python3
"""Python 3.9+, installed Rio; entirely offline synthetic evidence example."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", help="installed Rio executable")
    args = parser.parse_args()
    binary = str(Path(shutil.which(args.binary) or args.binary).resolve())
    root = Path(tempfile.mkdtemp(prefix="rio-normalization-evidence-"))
    work = root / "source-workspace"
    work.mkdir()
    fixture = Path(__file__).resolve().parent
    for name in ("rio.yaml", "bom.json", "table.json"):
        shutil.copyfile(fixture / name, work / name)
    bom = json.loads((work / "bom.json").read_text())
    bom["components"].append(dict(type="library", name="unmapped.synthetic", version="1.2.3.today",
                                  group="p2.eclipse.plugin", purl="pkg:p2/unmapped.synthetic@1.2.3.today?classifier=osgi.bundle"))
    original = (json.dumps(bom, indent=2) + "\n").encode()
    (work / "bom.json").write_bytes(original)

    def run(*command):
        return subprocess.run([binary, *command], cwd=work, check=True, capture_output=True, text=True).stdout

    run("normalize", "--gate", "fail")
    index_path = work / "target/rio/index.json"
    first = index_path.read_bytes()
    artifact = json.loads(first)["artifacts"][0]
    ledger = artifact["normalization"]
    assert ledger["version"] == 1
    repair = next(c for c in ledger["changes"] if c["target"] == "/components/0/purl")
    assert repair["resolution"]["kind"] == "external-table-entry"
    assert repair["resolution"]["sha256"] == hashlib.sha256((work / "table.json").read_bytes()).hexdigest()
    assert repair["resolution"]["metadata"]["confidence"] == "manifest-proven"
    assert len(ledger["unmapped"]) == 1
    assert artifact["transforms"][0]["applied"] == 2  # one rewrite per component
    assert (work / "bom.json").read_bytes() == original
    run("normalize", "--gate", "fail")
    assert index_path.read_bytes() == first
    record_path = root / "record.json"
    run("record", "--index", str(index_path), "--output", str(record_path))
    shutil.rmtree(work)  # Only this demo's synthetic workspace.
    result = subprocess.run([binary, "record", "inspect", "--file", str(record_path)],
                            cwd=root, check=True, capture_output=True, text=True)
    print(result.stdout + result.stderr)
    print("PASS: exact source digest, categorical provenance, stable changes, deterministic output.")
    print("Source workspace removed; offline record retained:", record_path)


if __name__ == "__main__":
    main()
