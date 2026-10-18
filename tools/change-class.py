#!/usr/bin/env python3
"""Label a pull request class:standard or class:significant and say why.

Python 3.9+ and gh. Reads only API metadata (the PR body and its changed files);
it never checks out or runs PR code. A change is significant when any rule below
matches, when the author ticks the substantial-modification box in the PR
template, or when the file list cannot be read completely. Automation may raise a
class, never lower it: an unreadable patch counts as significant.
"""

import argparse
import json
import os
import re
import subprocess
import sys

LABELS = {"standard": "class:standard", "significant": "class:significant"}

# (criterion, glob patterns). "**" spans directories, "*" stays within one.
PATH_RULES = [
    ("critical_function", ["internal/receipt/**", "internal/gate/**"]),
    ("external_interface", ["internal/delivery/**"]),
    ("security_component", ["tools/rio-attest-sign.sh", "tools/rio-attest-verify.sh"]),
    ("pipeline_or_rules", [".github/workflows/**", ".github/dependabot.yml", ".github/pull_request_template.md",
                           ".goreleaser.yaml", "tools/release-*.py", "tools/verify-release.py",
                           "tools/revert-cask.py", "tools/change-class.py", "tools/security/**",
                           "install.sh", "SECURITY.md"]),
]
MODULE_FILES = {"go.mod", "tools/security/go.mod"}
SUBSTANTIAL = re.compile(r"^\s*[-*] \[[xX]\] Possible substantial modification", re.M)


def glob(pattern):
    out = ""
    for part in re.split(r"(\*\*|\*|\?)", pattern):
        out += {"**": ".*", "*": "[^/]*", "?": "[^/]"}.get(part, re.escape(part))
    return re.compile(out + r"\Z")


COMPILED = [(criterion, [glob(p) for p in patterns]) for criterion, patterns in PATH_RULES]


def modules(patch, sign):
    """Module paths on added (+) or removed (-) require lines of a go.mod patch."""
    found = set()
    for line in patch.splitlines():
        if line.startswith(sign) and not line.startswith(sign * 3):
            match = re.match(r"^[+-]\s*(?:require\s+)?([a-z0-9.-]+\.[a-z]{2,}/[^\s]+)\s+v\S+", line)
            if match:
                found.add(match[1])
    return found


def classify(files, body, complete=True):
    """Return (class, {criterion: [reasons]}) for a PR's file entries and body."""
    reasons = {}
    for entry in files:
        for name in {entry.get("filename"), entry.get("previous_filename")} - {None}:
            for criterion, patterns in COMPILED:
                if any(p.match(name) for p in patterns):
                    reasons.setdefault(criterion, []).append(name)
        if entry.get("filename") in MODULE_FILES:
            patch = entry.get("patch")
            if patch is None:
                reasons.setdefault("new_or_major_dependency", []).append(entry["filename"] + " (patch unavailable)")
            else:
                for module in sorted(modules(patch, "+") - modules(patch, "-")):
                    reasons.setdefault("new_or_major_dependency", []).append(module)
    if SUBSTANTIAL.search(body or ""):
        reasons.setdefault("cra_substantial_modification_question", []).append("ticked in the PR description")
    if not complete:
        reasons.setdefault("incomplete_file_list", []).append("the API did not return every changed file")
    return ("significant" if reasons else "standard"), {k: sorted(set(v)) for k, v in reasons.items()}


def gh(args):
    result = subprocess.run(["gh"] + args, capture_output=True, text=True, encoding="utf-8")
    if result.returncode:
        raise ValueError("gh failed: " + " ".join(args[:2]) + ": " + result.stderr.strip())
    return result.stdout


def label(repo, number):
    pr = json.loads(gh(["api", "repos/" + repo + "/pulls/" + str(number)]))
    lines = gh(["api", "--paginate", "repos/" + repo + "/pulls/" + str(number) + "/files?per_page=100",
                "--jq", ".[] | {filename, previous_filename, patch}"]).splitlines()
    files = [json.loads(line) for line in lines if line.strip()]
    cls, reasons = classify(files, pr.get("body") or "", complete=len(files) == pr.get("changed_files"))
    current = {x["name"] for x in pr.get("labels", [])}
    wanted, other = LABELS[cls], LABELS["standard" if cls == "significant" else "significant"]
    if wanted not in current:
        gh(["api", "-X", "POST", "repos/" + repo + "/issues/" + str(number) + "/labels", "-f", "labels[]=" + wanted])
    if other in current:
        gh(["api", "-X", "DELETE", "repos/" + repo + "/issues/" + str(number) + "/labels/" + other])
    return cls, reasons


def summary(number, cls, reasons):
    lines = ["## Change class for #" + str(number) + ": " + cls, ""]
    if reasons:
        lines += ["| Criterion | Triggered by |", "|---|---|"]
        lines += ["| `" + k + "` | " + ", ".join("`" + v + "`" for v in vs) + " |" for k, vs in sorted(reasons.items())]
    else:
        lines.append("No significance criterion matched.")
    text = "\n".join(lines) + "\n"
    print(text)
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as stream:
            stream.write(text)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default="rebaze/rio")
    parser.add_argument("--pr", type=int, required=True)
    args = parser.parse_args()
    try:
        cls, reasons = label(args.repo, args.pr)
    except (OSError, ValueError, KeyError) as error:
        print("FAILED: " + str(error), file=sys.stderr)
        return 1
    summary(args.pr, cls, reasons)
    return 0


if __name__ == "__main__":
    sys.exit(main())
