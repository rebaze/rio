#!/usr/bin/env python3
"""Verify captured Juice Shop receipts and reports offline with an installed Rio."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise ValueError(message)


def verify(binary, example):
    source = json.loads((example / "source.json").read_text())
    context = json.loads((example / "pipeline.json").read_text())
    for name in ("backend", "frontend"):
        filename = name + "-record.json"
        record = json.loads((example / filename).read_text())
        require(len(record["artifacts"]) == 1, name + " artifact scope")
        artifact = record["artifacts"][0]
        ctx = next(a for a in context["artifacts"] if a["id"] == name)
        require(artifact["id"] == name, name + " artifact identity")
        require(artifact["input"]["sha256"] == source["sboms"][name]["sha256"] == ctx["sbom"]["sha256"], name + " input identity")
        changes = {c["field"]: c["after"] for c in artifact["changes"]["metadata"]}
        for field, value in (("source.revision", source["revision"]),
                             ("source.ref", source["ref"]),
                             ("source.workspace", source["workspace"]),
                             ("build.id", source["buildId"]),
                             ("build.timestamp", source["startedAt"])):
            require(changes.get(field) == value, name + " " + field)
            section, key = field.split(".", 1)
            require(ctx[section][key] == value, name + " context " + field)
        require(changes["build.url"] == ctx["build"]["url"], name + " build URL")
        require(source["workspace"] == "dirty", "build override workspace")
        checks = artifact["checks"]
        require(checks["mode"] == "fail" and checks["schema"] == "pass", name + " check policy")
        if name == "backend":
            require(record["run"]["outcome"] == "success" and checks["gate"] == "pass" and checks["findings"] == 0, "backend outcome")
            require(len(record["deliveries"]) == 1, "backend delivery scope")
            delivery = record["deliveries"][0]
            require(delivery["state"] == "accepted", "backend acknowledgment")
            require(delivery["responses"][0]["httpStatus"] == 200, "backend HTTP acknowledgment")
        else:
            require(record["run"]["outcome"] == "failed" and checks["gate"] == "fail" and checks["findings"] > 0, "frontend outcome")
            require(record["run"]["stages"]["delivery"] == "not-attempted", "frontend blocked delivery")
            require(all(d["state"] == "unattempted" and not d.get("requestMayHaveOccurred") and not d.get("submitted") for d in record["deliveries"]), "frontend request state")
        # Only the receipt is copied: no source checkout, receiver or credentials.
        with tempfile.TemporaryDirectory(prefix="rio-juice-shop-verify-") as directory:
            recipient = Path(directory)
            shutil.copyfile(example / filename, recipient / filename)
            result = subprocess.run([binary, "record", "inspect", "--file", filename],
                                    cwd=recipient, capture_output=True, check=True, timeout=60)
            require(result.stdout == (example / (name + "-inspect.txt")).read_bytes(), name + "-inspect.txt differs from Rio output")
            output = name + "-report.html"
            subprocess.run([binary, "record", "report", "--file", filename, "--output", output],
                           cwd=recipient, capture_output=True, check=True, timeout=60)
            require((recipient / output).read_bytes() == (example / output).read_bytes(), output + " differs from Rio output")
        print("PASS: " + name + " provenance, receipt inspection and exact offline HTML")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", nargs="?", default="rio")
    parser.add_argument("example", nargs="?", type=Path, default=HERE / "example")
    args = parser.parse_args()
    binary = str(Path(shutil.which(args.binary) or args.binary).resolve())
    try:
        verify(binary, args.example.resolve())
    except (ValueError, KeyError, StopIteration, OSError, subprocess.SubprocessError) as error:
        print("ERROR: " + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
