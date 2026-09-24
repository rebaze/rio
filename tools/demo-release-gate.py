#!/usr/bin/env python3
"""Capture a guided demo: exact shell commands, their output, and interpretation."""

import argparse
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE = "rio_1.2.3_linux_amd64.tar.gz"


def package(path, identity):
    content = ("Application: demo\nVersion: 1.2.3\nBuild: " + identity + "\n").encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as output:
        info = tarfile.TarInfo("app.txt")
        info.size = len(content)
        info.mtime = 0
        output.addfile(info, io.BytesIO(content))
    path.write_bytes(gzip.compress(buffer.getvalue(), mtime=0))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="new directory for demo evidence")
    args = parser.parse_args()
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location("release_fixture", ROOT / "tools/testdata/release/fixture.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    document = dict(version=2, title="What is allowed to ship?", cases=[])
    summary, plain = [], []
    stage = "python3 release-publish.py stage \\\n  --dist dist --stage stage \\\n  --inventory inventory.json \\\n  --tag v1.2.3 --repo rebaze/rio"
    publish = "python3 release-publish.py publish \\\n  --stage stage --inventory inventory.json \\\n  --bundle bundle.jsonl \\\n  --tag v1.2.3 --repo rebaze/rio"
    scenarios = [
        ("unchanged", "The unchanged candidate", "All required files are present. The archive stays unchanged.",
         "PUBLISH", "The verified bytes are the bytes uploaded.",
         "First, the success case. We have a small application archive and its supporting evidence. Nothing changes between staging and publication."),
        ("replaced", "The archive is replaced", "Start fresh with A. Replace it with B after staging.",
         "BLOCK", "Same version does not mean same bytes.",
         "Case two starts from fresh inputs. We stage build A, then replace its archive with build B. Both say version one point two point three."),
        ("missing", "The evidence is missing", "Start fresh with A. Remove the attestation bundle.",
         "BLOCK", "Required evidence cannot be silently skipped.",
         "Case three starts fresh again. The application is unchanged, but we remove the attestation bundle before trying to publish."),
        ("failed", "A required check fails", "Files are present. The offline SBOM verifier rejects its check.",
         "BLOCK", "Present evidence is not necessarily accepted evidence.",
         "In the last case all files are present. We ask the offline verifier to reject the required software bill of materials check."),
    ]
    for number, (name, title, setup, verdict, takeaway, voice) in enumerate(scenarios, 1):
        directory = args.out / name
        directory.mkdir()
        fixture = module.create(directory)
        # The demonstration uses real, inspectable archives. Test service claims
        # remain explicitly synthetic; the publication guard itself is unchanged.
        package(fixture.dist / ARCHIVE, "A")
        sha = hashlib.sha256((fixture.dist / ARCHIVE).read_bytes()).hexdigest()
        (fixture.dist / "checksums.txt").write_text(sha + "  " + ARCHIVE + "\n")
        bundle = json.loads(fixture.bundle.read_text())
        bundle["subjects"] = {p: hashlib.sha256((fixture.dist / p).read_bytes()).hexdigest()
                              for p in (ARCHIVE, "checksums.txt")}
        fixture.bundle.write_text(json.dumps(bundle, indent=2) + "\n")
        shutil.copyfile(ROOT / "tools/release-publish.py", directory / "release-publish.py")
        if name == "replaced":
            (directory / "rebuilt").mkdir()
            package(directory / "rebuilt/B.tar.gz", "B")
        case = dict(number=number, name=name, title=title, setup=setup, verdict=verdict,
                    takeaway=takeaway, voice=voice, steps=[])
        document["cases"].append(case)

        def execute(title, command, explanation, narration, expected=0):
            print(f"\nCASE {number}: {title}\n$ {command}", flush=True)
            started = time.monotonic()
            result = subprocess.run(["bash", "-c", command], cwd=directory, env=fixture.env,
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            print(result.stdout, end="", flush=True)
            print("exit " + str(result.returncode), flush=True)
            if result.returncode != expected:
                raise RuntimeError(f"{name}: {title}: expected exit {expected}, got {result.returncode}")
            step = dict(title=title, command=command, output=result.stdout.rstrip(),
                        exitCode=result.returncode, explanation=explanation, voice=narration,
                        elapsed=round(time.monotonic() - started, 3))
            case["steps"].append(step)
            index = len(case["steps"])
            (directory / f"{index:02d}-command.sh").write_text(command + "\n")
            (directory / f"{index:02d}-output.txt").write_text(result.stdout)
            plain.append(f"CASE {number} / {title}\n$ {command}\n{result.stdout}\nexit {result.returncode}\nMEANING: {explanation}\n")
            return result

        if name == "unchanged":
            execute("What files do we have?", "ls -1 dist/",
                    "dist/ holds the release archive, checksums, signature, source SBOM and release notes. Each has a different role.",
                    "Here are the files at hand. The archive is what ships. The other files describe it or support verification.")
            execute("What is inside the archive?", "tar -xOzf dist/" + ARCHIVE + " app.txt",
                    "This is build A, labeled version 1.2.3. We will follow this exact archive through the gate.",
                    "Opening the archive shows build A. Remember that identity as we follow it through publication.")
        execute("Freeze the candidate", stage,
                "stage copies the candidate files and records their SHA-256 hashes in inventory.json. It does not publish anything.",
                "The stage command freezes a copy and records the file hashes. No release has been published yet.")
        if name == "unchanged":
            execute("Look at the recorded fingerprint", "grep 'tar.gz' inventory.json",
                    "This full SHA-256 value identifies the staged archive bytes. The guard checks them again before publication.",
                    "The inventory contains the archive's fingerprint. A change to the archive will change that fingerprint.")
        elif name == "replaced":
            execute("Inspect the replacement", "tar -xOzf rebuilt/B.tar.gz app.txt",
                    "B has the same version label as A. Its contents differ, so its archive has different bytes.",
                    "The replacement still says version one point two point three, but this is build B.")
            execute("Replace A with B", "cp rebuilt/B.tar.gz stage/" + ARCHIVE,
                    "The copy succeeds silently. The staged archive is now B, while inventory.json still describes A.",
                    "This command replaces the staged archive. The absence of output is normal for a successful copy.")
            execute("Compare recorded and current fingerprints", "grep 'tar.gz' inventory.json | cut -d '\"' -f 4\nshasum -a 256 stage/*.tar.gz | cut -d ' ' -f 1",
                    "First line: the recorded hash for A. Second: the current hash for B. Different hashes expose the replacement.",
                    "Compare the two fingerprints. The recorded value belongs to A. The current file has a different value.")
        elif name == "missing":
            execute("Remove a required input", "ls bundle.jsonl\nrm bundle.jsonl\ntest ! -e bundle.jsonl && echo 'bundle.jsonl is now absent.'",
                    "The listing finds the bundle. After removal, a file-existence check confirms it is absent. The candidate itself is unchanged.",
                    "The bundle exists at first. We remove it, and the final check confirms that it is gone.")
        if name == "failed":
            command = "FAKE_FAIL=sbom " + publish
            explanation = "FAKE_FAIL controls only the offline test service. It makes the required SBOM verification fail; the production guard must honor that failure."
            narration = "Watch the variable at the beginning. It tells our offline service to reject the check. The real guard must stop when verification fails."
        else:
            command = publish
            explanation = {"unchanged": "All checks succeed. The guard uploads a draft, checks downloaded bytes, then publishes through the offline service.",
                           "replaced": "The guard detects changed bytes before upload. Exit 1 means this candidate is blocked.",
                           "missing": "The bundle cannot be read. The guard stops before creating a draft. Missing evidence does not count as a pass."}[name]
            narration = {"unchanged": "Now publish. The guard verifies the staged bytes and evidence, checks the uploaded draft, and only then permits publication.",
                         "replaced": "We run the same publish command. The guard detects the changed archive and blocks it before upload.",
                         "missing": "The same publish command now stops because the required bundle is missing. There is no successful verification to rely on."}[name]
        execute("Run the publication gate", command, explanation, narration, expected=0 if name == "unchanged" else 1)
        if name == "unchanged":
            execute("Confirm what reached the publisher", "cat published\ncmp stage/" + ARCHIVE + " remote/" + ARCHIVE + " && echo 'Uploaded archive matches staged bytes.'",
                    "The local publisher marker exists, and a byte-for-byte comparison succeeds. This is an offline publication, not a GitHub release.",
                    "Here is the publisher's receipt. The byte comparison confirms that the uploaded archive is the one we staged.")
        else:
            execute("Confirm that nothing was uploaded", "test ! -d remote && echo 'No draft created. No upload occurred.'",
                    "The offline release directory was never created. This checks the side effect, beyond just reading the error message.",
                    "Finally, we check the side effect. No draft directory exists, so nothing reached the publisher.")
        published = (directory / "published").exists()
        if published != (name == "unchanged"):
            raise RuntimeError("unexpected publication for " + name)
        summary.append(dict(scenario=name, exitCode=0 if published else 1, published=published))
    document["summary"] = summary
    (args.out / "transcript.json").write_text(json.dumps(document, indent=2) + "\n")
    (args.out / "transcript.txt").write_text("\n".join(plain))
    (args.out / "results.json").write_text(json.dumps(summary, indent=2) + "\n")
    print("\nPASS: all four cases behaved as expected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
