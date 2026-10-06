#!/usr/bin/env python3
"""Python 3.9+, installed Rio; entirely offline synthetic evidence example."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", default=os.environ.get("RIO_BIN", "rio"),
                        help="installed Rio executable (default: RIO_BIN or rio)")
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

    first_result = json.loads(run("normalize", "--gate", "fail", "--json"))
    index_path = Path(first_result["runDirectory"]) / "index.json"
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
    second_result = json.loads(run("normalize", "--gate", "fail", "--json"))
    second_dir = Path(second_result["runDirectory"])
    assert first_result["runId"] != second_result["runId"]
    assert (second_dir / "index.json").read_bytes() == first
    assert (second_dir / artifact["output"]["path"]).read_bytes() == (index_path.parent / artifact["output"]["path"]).read_bytes()
    # Retain each actual invocation's receipt independently, with no assembly step.
    for number, result in enumerate((first_result, second_result), 1):
        record_path = root / ("record-%d.json" % number)
        shutil.copyfile(result["receipt"]["path"], record_path)
        record = json.loads(record_path.read_text())
        assert record["kind"] == "rio-run-receipt" and record["schemaVersion"] == 1
        assert record["run"]["operation"] == "normalize"
        summary = record["artifacts"][0]
        assert summary["input"]["sha256"] == hashlib.sha256(original).hexdigest()
        assert summary["changes"]["specVersion"] == {"from": "1.5", "to": "1.6"}
        repair = summary["changes"]["bulk"][0]
        assert repair["evaluated"] == 2 and repair["applied"] == 2 and repair["unmapped"] == 1
        assert repair["scope"] == "top-level components"
        assert "normalization" not in summary

    shutil.rmtree(work)  # Only this demo's synthetic workspace.
    for record_path in sorted(root.glob("record-*.json")):
        result = subprocess.run([binary, "record", "inspect", "--file", str(record_path)],
                                cwd=root, check=True, capture_output=True, text=True)
        print(result.stdout + result.stderr)
    print("PASS: exact source digest, categorical provenance, stable changes, deterministic output.")
    print("Source workspace removed; offline receipts retained:", root)


if __name__ == "__main__":
    main()
