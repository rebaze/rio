"""Exercise self-SBOM workflow shell and the release/CI security boundaries offline."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]

FAKE_GH = '''#!{python}
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
root = Path(os.environ["GH_FIXTURES"])
with (root / "calls").open("a") as calls:
    calls.write(json.dumps(args) + "\\n")
if args[0] == "api":
    pages = json.loads((root / "pages.json").read_text())
    if args[1] not in pages:
        sys.exit("unexpected or unavailable metadata endpoint: " + args[1])
    print(json.dumps(pages[args[1]]))
elif args[:2] == ["run", "download"]:
    name = args[args.index("--name") + 1]
    target = Path(args[args.index("--dir") + 1])
    target.mkdir(parents=True)
    (target / "restored-artifact").write_text(name)
    if name.startswith(("release-self-sbom-delivery-", "main-self-sbom-delivery-")):
        (target / "delivery-state.json").write_text('{{"status":"accepted"}}')
elif args[:2] == ["release", "download"]:
    target = Path(args[args.index("--dir") + 1])
    target.mkdir(parents=True)
    (target / args[args.index("--pattern") + 1]).write_bytes(b"immutable published source\\n")
else:
    sys.exit("unexpected gh command: " + repr(args))
'''.format(python=sys.executable)


def workflow(name):
    return (ROOT / ".github/workflows" / (name + ".yaml")).read_text()


def job(source, name):
    match = re.search(r"^  " + re.escape(name) + r":\n(.*?)(?=^  [\w-]+:|\Z)",
                      source, re.M | re.S)
    if not match:
        raise AssertionError("missing workflow job: " + name)
    return match.group(1)


def step(source, name):
    match = re.search(r"^      - name: " + re.escape(name) + r"\n(.*?)(?=^      - |\Z)",
                      source, re.M | re.S)
    if not match:
        raise AssertionError("missing workflow step: " + name)
    return match.group(1)


def script(source):
    match = re.search(r"^        run: \|\n((?:          .*\n|\n)*)", source, re.M)
    if not match:
        raise AssertionError("missing multiline workflow script")
    return textwrap.dedent(match.group(1))


class SelfSBOMWorkflowTest(unittest.TestCase):
    def test_self_sbom_consumers_install_and_use_pinned_stable_rio(self):
        for file, job_name in (("ci", "build"), ("ci", "self-sbom"), ("ci", "publish-main-sbom"),
                               ("release", "build"), ("release", "deliver-sbom"), ("release", "promote-sbom")):
            with self.subTest(workflow=file, job=job_name):
                source = job(workflow(file), job_name)
                install = step(source, "Install pinned stable Rio for self-SBOMs")
                self.assertIn('python3 tools/install-self-sbom-rio.py --output "$RUNNER_TEMP/rio-stable"', install)
                self.assertIn("GH_TOKEN: ${{ github.token }}", install)
                self.assertNotIn("latest", install.lower())
                self.assertNotIn("||", install.split("run:", 1)[1])
                if file == "ci" and job_name == "build":
                    self.assertIn("steps.changes.outputs.go == 'true' || steps.changes.outputs.python == 'true'", install)
                    exercise = step(source, "Exercise source-SBOM generation")
                    self.assertIn('"$RUNNER_TEMP/rio-stable/bin/rio"', exercise)
                    self.assertNotIn('"$PWD/rio"', exercise)
                    tests = step(source, "Test the Python tools")
                    self.assertIn("RIO_BIN: ${{ github.workspace }}/rio", tests)
                    self.assertIn("SELF_SBOM_TEST_RIO: ${{ runner.temp }}/rio-stable/bin/rio", tests)
                    self.assertIn("SOURCE_SBOM_TEST_RIO: ${{ runner.temp }}/rio-stable/bin/rio", tests)
                elif file == "release" and job_name == "build":
                    prepare = step(source, "Prepare release source SBOM")
                    self.assertIn('--rio "$RUNNER_TEMP/rio-stable/bin/rio"', prepare)
                    self.assertNotIn("find dist", prepare)
                else:
                    self.assertNotIn("go build", source)
                    if job_name in ("deliver-sbom", "publish-main-sbom", "promote-sbom"):
                        self.assertNotIn("actions/setup-go@", source)
                        delivery = step(source, {"deliver-sbom": "Deliver the exact published source SBOM",
                                                 "publish-main-sbom": "Deliver main source SBOM",
                                                 "promote-sbom": "Promote the verified latest stable release"}[job_name])
                        self.assertIn('--rio "$RUNNER_TEMP/rio-stable/bin/rio"', delivery)
                    else:
                        demo = step(source, "Exercise installed-binary self-SBOM demonstration offline")
                        self.assertIn('"$RUNNER_TEMP/rio-stable/bin/rio"', demo)
                consumers = [part for part in re.split(r"(?m)^      - ", source)
                             if "tools/self-sbom.py" in part]
                for consumer in consumers:
                    self.assertIn('--rio "$RUNNER_TEMP/rio-stable/bin/rio"', consumer)
                    if "tools/self-sbom.py prepare" in consumer:
                        self.assertIn('cp "$RUNNER_TEMP/rio-stable/installation.json" "$RUNNER_TEMP/rio-self-sbom/rio-tool.json"', consumer)

    def test_self_sbom_tests_prefer_explicit_stable_rio_over_candidate(self):
        result = subprocess.run(
            [sys.executable, "-c", "import runpy; print(runpy.run_path('tools/self-sbom_test.py')['RIO'])"],
            cwd=ROOT, env=dict(os.environ, SELF_SBOM_TEST_RIO="/stable/bin/rio", RIO_BIN="/candidate/rio"),
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "/stable/bin/rio")

    def test_scoped_bundles_keep_interruption_checkpoints(self):
        for file, job_name, step_name in (
            ('ci', 'self-sbom', 'Retain self-SBOM and delivery receipts'),
            ('release', 'build', 'Retain prepared release self-SBOM'),
            ('release', 'deliver-sbom', 'Retain release self-SBOM delivery receipts'),
            ('ci', 'publish-main-sbom', 'Retain main delivery evidence'),
            ('release', 'promote-sbom', 'Retain release lifecycle evidence'),
        ):
            with self.subTest(workflow=file, step=step_name):
                retention = step(job(workflow(file), job_name), step_name)
                self.assertIn('include-hidden-files: true', retention)
                self.assertIn('path: ${{ runner.temp }}/rio-self-sbom/', retention)

    def restore(self, attempt, jobs, artifacts=None, extra_pages=None, main=False, promotion=False):
        source = script(step(job(workflow("ci" if main else "release"),
                                 "publish-main-sbom" if main else "promote-sbom" if promotion else "deliver-sbom"),
                             "Restore accepted delivery evidence and published source SBOM" if promotion else
                             "Restore prior main delivery state" if main else
                             "Restore prior delivery state and download published source SBOM"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "gh"
            binary.write_text(FAKE_GH)
            binary.chmod(0o755)
            pages = {}
            for number, entries in jobs.items():
                pages["repos/rebaze/rio/actions/runs/321/attempts/" + str(number) +
                      "/jobs?per_page=100&page=1"] = {"jobs": entries}
            if artifacts is not None:
                pages["repos/rebaze/rio/actions/runs/321/artifacts?per_page=100&page=1"] = {
                    "artifacts": artifacts}
            pages.update(extra_pages or {})
            (root / "pages.json").write_text(json.dumps(pages))
            result = subprocess.run(["bash", "-euo", "pipefail", "-c", source],
                                    capture_output=True, text=True,
                                    env=dict(os.environ, RUNNER_TEMP=directory,
                                             PATH=directory + os.pathsep + os.environ["PATH"],
                                             GH_FIXTURES=directory, GITHUB_RUN_ID="321",
                                             GITHUB_RUN_ATTEMPT=str(attempt), TAG="v1.2.3",
                                             GITHUB_REPOSITORY="rebaze/rio",
                                             DELIVERY_JOB="publish-main-sbom" if main else "deliver-sbom",
                                             DELIVERY_ARTIFACT_PREFIX="main-self-sbom-delivery" if main else "release-self-sbom-delivery-v1.2.3",
                                             DELIVERY_ARTIFACT="release-self-sbom-delivery-v1.2.3-321-1",
                                             PREPARED_ARTIFACT="rio-self-sbom-v1.2.3-321-1"))
            calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()] if (root / "calls").exists() else []
            restored = root / "rio-self-sbom/restored-artifact"
            published = root / "rio-published-sbom/rio-v1.2.3-source.cdx.json"
            state = root / "rio-self-sbom/delivery-state.json"
            return result, calls, restored.read_text() if restored.exists() else None, \
                published.read_bytes() if published.exists() else None, state.exists()

    def run_shell(self, source, extra_prefix="", **env):
        # Only the external self-SBOM tool is replaced: the workflow's version
        # selection, quoting, key guard and exit behavior run as written.
        with tempfile.TemporaryDirectory() as directory:
            calls = Path(directory) / "calls"
            output = Path(directory) / "output"
            (Path(directory) / "rio-stable").mkdir()
            (Path(directory) / "rio-stable/installation.json").write_text('{"tag":"v0.10.2"}')
            (Path(directory) / "rio-self-sbom").mkdir()
            prefix = 'python3() { printf "%s\\0" "$@" > "$CALLS"; }\n'
            shell_env = dict(os.environ, RUNNER_TEMP=directory,
                             GITHUB_RUN_ID="321", GITHUB_RUN_ATTEMPT="2",
                             GITHUB_RUN_NUMBER="83",
                             GITHUB_SHA="0123456789abcdef0123456789abcdef01234567",
                             GITHUB_REPOSITORY="rebaze/rio",
                             WORKFLOW_NAME="Release preflight", REPOSITORY="rebaze/rio",
                             REF="refs/heads/main",
                             SOURCE_SHA="0123456789abcdef0123456789abcdef01234567",
                             BUILD_URL="https://github.com/rebaze/rio/actions/runs/321", BUILD_ID="321.2",
                             GITHUB_OUTPUT=str(output), GITHUB_STEP_SUMMARY=str(Path(directory) / "summary"), CALLS=str(calls))
            shell_env.update(env)
            result = subprocess.run(["bash", "-euo", "pipefail", "-c", prefix + extra_prefix + source],
                                    env=shell_env,
                                    capture_output=True, text=True)
            args = calls.read_bytes().decode().rstrip("\0").split("\0") if calls.exists() else []
            self.last_outputs = dict(line.split("=", 1) for line in output.read_text().splitlines()) if output.exists() else {}
            return result, args

    def test_ci_streams_and_subject_versions(self):
        prepare = script(step(job(workflow("ci"), "self-sbom"), "Prepare source SBOM"))
        for event, kind, ref, number, expected in (
            ("push", "branch", "main", "", "dev-main"),
            ("schedule", "branch", "main", "", "dev-main"),
            ("workflow_dispatch", "branch", "feature/test", "", "dev-feature/test"),
            ("pull_request", "branch", "230/merge", "230", "pr-230"),
            ("push", "tag", "v1.2.3", "", "ci-tag-v1.2.3"),
            ("push", "branch", 'feature/$(touch injected);"', "", 'dev-feature/$(touch injected);"'),
        ):
            with self.subTest(event=event, ref=ref):
                self.assertNotIn("${{", prepare, "event data must enter shell through env")
                result, args = self.run_shell(prepare, EVENT_NAME=event, REF_TYPE=kind,
                                              REF_NAME=ref, PR_NUMBER=number)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(args[:2], ["tools/self-sbom.py", "prepare"])
                self.assertTrue(args[args.index("--rio") + 1].endswith("/rio-stable/bin/rio"))
                self.assertEqual(args[args.index("--version") + 1], "0.0.0-ci.321.2")
                self.assertIn("--source-revision", args)
                self.assertEqual(args[args.index("--source-revision") + 1], "0123456789abcdef0123456789abcdef01234567")
                self.assertEqual(args[args.index("--build-url") + 1], "https://github.com/rebaze/rio/actions/runs/321")
                self.assertEqual(args[args.index("--build-id") + 1], "321.2")
                self.assertEqual(args[args.index("--project-version") + 1],
                                 expected + "-0123456789ab.321.2")
                self.assertNotIn("--release", args)
                self.assertIn("--artifact-only", args)
                self.assertEqual(self.last_outputs.get("publish-main"), "false")

    def test_only_canonical_main_ci_manages_the_rolling_project(self):
        prepare = script(step(job(workflow("ci"), "self-sbom"), "Prepare source SBOM"))
        for event, workflow_name, repo, ref, eligible in (
            ("push", "CI", "rebaze/rio", "refs/heads/main", True),
            ("schedule", "CI", "rebaze/rio", "refs/heads/main", True),
            ("workflow_dispatch", "CI", "rebaze/rio", "refs/heads/main", True),
            ("pull_request", "CI", "rebaze/rio", "refs/heads/main", False),
            ("push", "Release", "rebaze/rio", "refs/heads/main", False),
            ("workflow_dispatch", "Release preflight", "rebaze/rio", "refs/heads/main", False),
            ("push", "CI", "someone/rio", "refs/heads/main", False),
            ("workflow_dispatch", "CI", "rebaze/rio", "refs/heads/feature", False),
        ):
            with self.subTest(event=event, workflow=workflow_name, repo=repo, ref=ref):
                result, args = self.run_shell(prepare, EVENT_NAME=event, REF_TYPE="branch", REF_NAME="main",
                                              PR_NUMBER="230", WORKFLOW_NAME=workflow_name, REPOSITORY=repo, REF=ref)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.last_outputs.get("publish-main"), str(eligible).lower())
                self.assertEqual("--artifact-only" in args, not eligible)
                if eligible:
                    self.assertEqual(args[args.index("--project-version") + 1], "main")
                    self.assertEqual(args[args.index("--target-config") + 1], "tools/self-sbom-targets.json")

    def test_ci_same_stream_separates_revisions_runs_and_attempts(self):
        prepare = script(step(job(workflow("ci"), "self-sbom"), "Prepare source SBOM"))
        versions = []
        for sha, run, attempt, expected in (
            ("a" * 40, "321", "1", "dev-main-aaaaaaaaaaaa.321.1"),
            ("a" * 40, "322", "1", "dev-main-aaaaaaaaaaaa.322.1"),
            ("b" * 40, "321", "1", "dev-main-bbbbbbbbbbbb.321.1"),
            ("a" * 40, "321", "2", "dev-main-aaaaaaaaaaaa.321.2"),
        ):
            result, args = self.run_shell(prepare, EVENT_NAME="push", REF_TYPE="branch",
                                          REF_NAME="main", PR_NUMBER="", SOURCE_SHA=sha,
                                          GITHUB_RUN_ID=run, GITHUB_RUN_ATTEMPT=attempt)
            self.assertEqual(result.returncode, 0, result.stderr)
            version = args[args.index("--project-version") + 1]
            self.assertEqual(version, expected)
            versions.append(version)
        self.assertEqual(len(set(versions)), 4)

    def test_ci_rejects_invalid_source_revision_before_preparing(self):
        source = step(job(workflow("ci"), "self-sbom"), "Prepare source SBOM")
        self.assertRegex(source, r"SOURCE_SHA: \$\{\{ github.sha \}\}")
        for sha in ("", "a" * 12, "g" * 40, "$(touch injected)"):
            result, args = self.run_shell(script(source), EVENT_NAME="push", REF_TYPE="branch",
                                          REF_NAME="main", PR_NUMBER="", SOURCE_SHA=sha)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(args, [])

    def test_current_main_requires_key_before_delivery(self):
        delivery = step(job(workflow("ci"), "publish-main-sbom"), "Deliver main source SBOM")
        self.assertIn("steps.current.outputs.current == 'true'", delivery)
        self.assertIn("DTRACK_MAIN_KEY: ${{ secrets.RIO_DTRACK_MAIN_KEY }}", delivery)
        self.assertIn("GH_TOKEN: ${{ github.token }}", delivery)
        self.assertNotIn("RIO_DTRACK_API_KEY", delivery)
        result, args = self.run_shell(script(delivery), DTRACK_MAIN_KEY="")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(args, [])
        result, args = self.run_shell(script(delivery), DTRACK_MAIN_KEY="test-only")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(args[:2], ["tools/self-sbom-lifecycle.py", "deliver-main"])
        self.assertTrue(args[args.index("--rio") + 1].endswith("/rio-stable/bin/rio"))
        self.assertEqual(args[args.index("--target-config") + 1], "tools/self-sbom-targets.json")
        self.assertEqual(args[args.index("--source-revision") + 1], "0123456789abcdef0123456789abcdef01234567")
        self.assertEqual(args[args.index("--repo") + 1], "rebaze/rio")
        self.assertIn("--run-number", args)
        self.assertEqual(args[args.index("--run-number") + 1], "83")

    def test_forks_prepare_without_receiving_the_delivery_secret(self):
        source = job(workflow("ci"), "self-sbom")
        self.assertNotRegex(source.split("steps:", 1)[0], r"(?i)if:|DTRACK_API_KEY")
        self.assertNotIn("DTRACK_API_KEY", step(source, "Prepare source SBOM"))
        secret_lines = [line.strip() for line in source.splitlines() if "secrets." in line]
        self.assertEqual(secret_lines, [])
        self.assertIn("actions/upload-artifact@", source)

    def test_reusable_ci_callers_forward_no_delivery_keys(self):
        ci = workflow("ci")
        declaration = ci.split("  workflow_call:", 1)[1].split("\npermissions:", 1)[0]
        self.assertNotIn("secrets:", declaration)
        for name in ("release", "release-preflight"):
            validate = job(workflow(name), "validate")
            self.assertNotIn("secrets:", validate)
            self.assertRegex(validate, r"permissions:\s+contents: read\s+actions: read")
            self.assertNotIn("inherit", validate)
            self.assertNotIn("MACOS_", validate)

    def test_release_delivery_uses_retained_build_bundle_after_publication(self):
        source = workflow("release")
        build = job(source, "build")
        prepare = step(build, "Prepare release source SBOM")
        self.assertIn('--version "${TAG#v}"', prepare)
        self.assertIn('--project-version "$TAG"', prepare)
        self.assertIn("--release", prepare)
        self.assertIn("--target-config tools/self-sbom-targets.json", prepare)
        self.assertIn("source.cdx.json", prepare)
        self.assertRegex(build, r"self-sbom-artifact: \$\{\{ steps\.[\w-]+\.outputs\.artifact-name \}\}")
        self.assertIn("actions/upload-artifact@", build)
        deliver = job(source, "deliver-sbom")
        self.assertRegex(deliver, r"needs: \[build, publish\]")
        self.assertIn("needs.build.outputs.self-sbom-artifact", deliver)
        self.assertIn('gh run download "$GITHUB_RUN_ID"', deliver)
        self.assertIn('--name "$PREPARED_ARTIFACT"', deliver)
        self.assertIn('gh release download "$TAG"', deliver)
        self.assertIn("--published-sbom", deliver)
        self.assertNotIn("source-sbom.sh", deliver)
        self.assertNotIn("goreleaser", deliver)
        self.assertNotIn("environment:", deliver)
        self.assertRegex(deliver, r"permissions:\s+contents: read\s+actions: read")
        for line in deliver.splitlines():
            if "secrets." in line:
                self.assertEqual(line.strip(), "DTRACK_API_KEY: ${{ secrets.RIO_DTRACK_API_KEY }}")

    def test_release_preparation_stages_the_prepared_bytes_and_records_artifact_identity(self):
        prepare = script(step(job(workflow("release"), "build"), "Prepare release source SBOM"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "dist").mkdir()
            (root / "rio-stable").mkdir()
            (root / "rio-stable/installation.json").write_bytes(b'{"tag":"v0.10.2"}\n')
            calls = root / "calls"
            output = root / "output"
            # Source generation itself is covered by the helper's integration
            # tests. This boundary fixture supplies bytes for the workflow copy.
            fake = '''python3() {
              printf '%s\\0' "$@" > "$CALLS"
              mkdir -p "$RUNNER_TEMP/rio-self-sbom"
              printf 'prepared source bytes\\n' > "$RUNNER_TEMP/rio-self-sbom/source.cdx.json"
            }
            '''
            result = subprocess.run(["bash", "-euo", "pipefail", "-c", fake + prepare],
                                    cwd=root, capture_output=True, text=True,
                                    env=dict(os.environ, RUNNER_TEMP=directory,
                                             GITHUB_OUTPUT=str(output), CALLS=str(calls),
                                             TAG="v1.2.3", GITHUB_RUN_ID="321",
                                             SOURCE_SHA="0123456789abcdef0123456789abcdef01234567",
                                             BUILD_URL="https://github.com/rebaze/rio/actions/runs/321", BUILD_ID="321.2",
                                             GITHUB_RUN_ATTEMPT="2"))
            self.assertEqual(result.returncode, 0, result.stderr)
            args = calls.read_bytes().decode().rstrip("\0").split("\0")
            self.assertEqual(args[args.index("--version") + 1], "1.2.3")
            self.assertEqual(args[args.index("--rio") + 1], directory + "/rio-stable/bin/rio")
            self.assertEqual(args[args.index("--project-version") + 1], "v1.2.3")
            self.assertIn("--source-revision", args)
            self.assertEqual(args[args.index("--source-revision") + 1], "0123456789abcdef0123456789abcdef01234567")
            self.assertEqual(args[args.index("--build-url") + 1], "https://github.com/rebaze/rio/actions/runs/321")
            self.assertEqual(args[args.index("--build-id") + 1], "321.2")
            self.assertIn("--release", args)
            self.assertEqual((root / "dist/rio-v1.2.3-source.cdx.json").read_bytes(),
                             b"prepared source bytes\n")
            self.assertEqual((root / "rio-self-sbom/rio-tool.json").read_bytes(),
                             b'{"tag":"v0.10.2"}\n')
            self.assertEqual(output.read_text().strip(),
                             "artifact-name=rio-self-sbom-v1.2.3-321-2")

    def test_release_failed_preparation_retains_its_original_artifact_identity(self):
        build = job(workflow("release"), "build")
        prepare = script(step(build, "Prepare release source SBOM"))
        upload = step(build, "Retain prepared release self-SBOM")
        self.assertRegex(upload, r"if: always\(\)")
        self.assertIn("if-no-files-found: warn", upload)
        self.assertRegex(upload, r"name: \$\{\{ steps.self-sbom.outputs.artifact-name \|\| format\(")
        self.assertIn("github.ref_name, github.run_id, github.run_attempt", upload)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "dist").mkdir()
            output = root / "output"
            fake = '''python3() {
              mkdir -p "$RUNNER_TEMP/rio-self-sbom"
              printf '{"gate":"fail"}\\n' > "$RUNNER_TEMP/rio-self-sbom/source-receipt.json"
              return 1
            }
            '''
            result = subprocess.run(["bash", "-euo", "pipefail", "-c", fake + prepare],
                                    cwd=root, capture_output=True, text=True,
                                    env=dict(os.environ, RUNNER_TEMP=directory,
                                             GITHUB_OUTPUT=str(output), TAG="v1.2.3",
                                             SOURCE_SHA="0123456789abcdef0123456789abcdef01234567",
                                             BUILD_URL="https://github.com/rebaze/rio/actions/runs/321", BUILD_ID="321.2",
                                             GITHUB_RUN_ID="321", GITHUB_RUN_ATTEMPT="2"))
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output.read_text().strip(),
                             "artifact-name=rio-self-sbom-v1.2.3-321-2")
            self.assertTrue((root / "rio-self-sbom/source-receipt.json").is_file())
            self.assertFalse((root / "dist/rio-v1.2.3-source.cdx.json").exists())

    def test_release_first_delivery_after_build_retries_uses_original_build_bundle(self):
        for attempt, history in (
            (1, {}),
            (3, {1: [{"name": "deliver-sbom", "conclusion": "skipped"}],
                 2: [{"name": "build", "conclusion": "failure"}]}),
        ):
            with self.subTest(attempt=attempt):
                result, calls, restored, published, state = self.restore(attempt, history)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(restored, "rio-self-sbom-v1.2.3-321-1")
                self.assertEqual(published, b"immutable published source\n")
                self.assertFalse(state)

    def test_release_retry_restores_newest_actual_delivery_evidence(self):
        for latest, history in (
            (2, {2: [{"name": "deliver-sbom", "conclusion": "failure"}]}),
            (1, {1: [{"name": "deliver-sbom", "conclusion": "success"}],
                 2: [{"name": "deliver-sbom", "conclusion": "skipped"}]}),
        ):
            with self.subTest(latest=latest):
                name = "release-self-sbom-delivery-v1.2.3-321-" + str(latest)
                artifacts = [{"name": name, "expired": False, "workflow_run": {"id": 321}}]
                result, calls, restored, published, state = self.restore(3, history, artifacts)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(restored, name)
                self.assertTrue(state)
                self.assertEqual(published, b"immutable published source\n")
                downloads = [args for args in calls if args[:2] == ["run", "download"]]
                self.assertEqual(len(downloads), 1)
                self.assertEqual(downloads[0][2], "321")

    def test_release_retry_refuses_missing_expired_wrong_or_stale_delivery_evidence(self):
        history = {2: [{"name": "deliver-sbom", "conclusion": "failure"}]}
        for artifacts in (
            [],
            [{"name": "release-self-sbom-delivery-v1.2.3-321-2", "expired": True,
              "workflow_run": {"id": 321}}],
            [{"name": "release-self-sbom-delivery-v1.2.3-321-1", "expired": False,
              "workflow_run": {"id": 321}}],
            [{"name": "release-self-sbom-delivery-v1.2.4-321-2", "expired": False,
              "workflow_run": {"id": 321}}],
            [{"name": "release-self-sbom-delivery-v1.2.3-321-2", "expired": False,
              "workflow_run": {"id": 999}}],
        ):
            with self.subTest(artifacts=artifacts):
                result, calls, restored, published, state = self.restore(3, history, artifacts)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("delivery evidence", result.stderr)
                self.assertIsNone(restored)
                self.assertIsNone(published)
                self.assertFalse(any(args[:2] == ["run", "download"] for args in calls))

    def test_release_retry_refuses_unavailable_job_history(self):
        result, calls, restored, published, state = self.restore(3, {})
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(restored)
        self.assertFalse(any(args[:2] == ["run", "download"] for args in calls))

    def test_release_retry_reads_all_job_and_artifact_metadata_pages(self):
        name = "release-self-sbom-delivery-v1.2.3-321-2"
        result, calls, restored, published, state = self.restore(
            3, {2: [{"name": "other-" + str(number), "conclusion": "success"}
                    for number in range(100)]},
            [{"name": "unrelated-" + str(number), "expired": False,
              "workflow_run": {"id": 321}} for number in range(100)],
            extra_pages={
                "repos/rebaze/rio/actions/runs/321/attempts/2/jobs?per_page=100&page=2": {
                    "jobs": [{"name": "deliver-sbom", "conclusion": "failure"}]},
                "repos/rebaze/rio/actions/runs/321/artifacts?per_page=100&page=2": {
                    "artifacts": [{"name": name, "expired": False,
                                   "workflow_run": {"id": 321}}]},
            })
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(restored, name)
        self.assertTrue(state)
        self.assertEqual(published, b"immutable published source\n")

    def test_ci_runs_the_source_and_workflow_regressions(self):
        source = step(job(workflow("ci"), "build"), "Test the Python tools")
        for name in ("source-sbom_test.py", "self-sbom_test.py", "self-sbom-workflows_test.py",
                     "install-self-sbom-rio_test.py", "self-sbom-lifecycle_test.py"):
            self.assertIn("python3 tools/" + name, source)

    def test_main_publication_serializes_only_eligible_uploads_and_checks_head_without_key(self):
        source = job(workflow("ci"), "publish-main-sbom")
        self.assertIn("needs: self-sbom", source)
        header = source.split("steps:", 1)[0]
        self.assertIn("if: needs.self-sbom.result == 'success' && needs.self-sbom.outputs.publish-main == 'true'", header)
        self.assertIn("environment: rio-main", header)
        self.assertIn("group: rio-main-sbom", header)
        self.assertNotIn("rio-artifact-only", header)
        self.assertNotIn("RIO_DTRACK_API_KEY", source)
        self.assertEqual(workflow("ci").count("RIO_DTRACK_MAIN_KEY }}"), 1)
        self.assertNotIn("RIO_DTRACK_MAIN_KEY", workflow("release"))
        self.assertNotIn("RIO_DTRACK_MAIN_KEY", workflow("release-preflight"))
        self.assertIn("needs.self-sbom.result == 'success'", source)
        self.assertIn("cancel-in-progress: false", source)
        self.assertIn("needs.self-sbom.outputs.publish-main == 'true'", source)
        check = step(source, "Skip superseded main source revisions")
        self.assertNotIn("secrets.", check)
        for head, expected in (("0123456789abcdef0123456789abcdef01234567", "true"), ("b" * 40, "false")):
            boundary = 'gh() { [[ "$1" == api && "$2" == repos/rebaze/rio/git/ref/heads/main ]] || return 1; printf "%s\\n" "$MAIN_HEAD"; }\n'
            result, args = self.run_shell(script(check), extra_prefix=boundary, MAIN_HEAD=head)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(self.last_outputs["current"], expected)
            self.assertEqual(args, [])

    def test_main_retry_retains_accepted_upload_state_and_refuses_lost_state(self):
        history = {2: [{"name": "publish-main-sbom", "conclusion": "failure", "steps": [
            {"name": "Deliver main source SBOM", "conclusion": "success"}]}]}
        artifact = {"name": "main-self-sbom-delivery-321-2", "expired": False, "workflow_run": {"id": 321}}
        result, calls, restored, published, state = self.restore(3, history, [artifact], main=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(restored, "main-self-sbom-delivery-321-2")
        self.assertTrue(state)
        result, calls, restored, published, state = self.restore(3, history, [], main=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIsNone(restored)

    def test_main_first_upload_ignores_prior_ineligible_and_stale_job_attempts(self):
        history = {2: [{"name": "publish-main-sbom", "conclusion": "success", "steps": [
            {"name": "Deliver main source SBOM", "conclusion": "skipped"}]}],
                   1: [{"name": "publish-main-sbom", "conclusion": "success", "steps": [
            {"name": "Explain artifact-only observation", "conclusion": "success"}]}]}
        result, calls, restored, published, state = self.restore(3, history, main=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(restored, "rio-self-sbom-v1.2.3-321-1")
        self.assertFalse(state)

    def test_promotion_only_uses_release_environment_management_key_and_exact_delivery_artifact(self):
        source = workflow("release")
        promote = job(source, "promote-sbom")
        self.assertIn("needs: [publish, deliver-sbom]", promote)
        self.assertIn("environment: release", promote)
        self.assertIn("if: github.event_name == 'push' && github.repository == 'rebaze/rio' && startsWith(github.ref, 'refs/tags/v')", promote)
        self.assertRegex(promote, r"permissions:\s+contents: read\s+actions: read")
        self.assertNotIn("contents: write", promote)
        self.assertNotIn("id-token:", promote)
        self.assertIn("cancel-in-progress: false", promote)
        self.assertIn("needs.deliver-sbom.outputs.artifact-name", promote)
        self.assertIn('gh run download "$GITHUB_RUN_ID"', promote)
        command = step(promote, "Promote the verified latest stable release")
        self.assertIn("GH_TOKEN: ${{ github.token }}", command)
        result, args = self.run_shell(script(command), TAG="v1.2.3", COMMIT="a" * 40,
                                      DTRACK_LIFECYCLE_KEY="synthetic")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(args[:2], ["tools/self-sbom-lifecycle.py", "promote"])
        for flag, value in (("--tag", "v1.2.3"), ("--commit", "a" * 40),
                            ("--target-config", "tools/self-sbom-targets.json"), ("--repo", "rebaze/rio")):
            self.assertEqual(args[args.index(flag) + 1], value)
        self.assertIn("--published-sbom", args)
        key_line = "DTRACK_LIFECYCLE_KEY: ${{ secrets.RIO_DTRACK_LIFECYCLE_KEY }}"
        self.assertEqual(source.count(key_line), 1)
        self.assertIn(key_line, promote)
        self.assertNotIn("RIO_DTRACK_LIFECYCLE_KEY", workflow("ci"))
        self.assertNotIn("RIO_DTRACK_LIFECYCLE_KEY", workflow("release-preflight"))

    def test_promotion_retry_downloads_exact_original_delivery_output(self):
        result, calls, restored, published, state = self.restore(5, {}, promotion=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(restored, "release-self-sbom-delivery-v1.2.3-321-1")
        self.assertEqual(published, b"immutable published source\n")
        self.assertTrue(state)
        self.assertFalse(any(args[0] == "api" for args in calls))


if __name__ == "__main__":
    unittest.main()
