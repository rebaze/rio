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
    if name.startswith("release-self-sbom-delivery-"):
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
    def test_scoped_bundles_keep_interruption_checkpoints(self):
        for file, job_name, step_name in (
            ('ci', 'self-sbom', 'Retain self-SBOM and delivery receipts'),
            ('release', 'build', 'Retain prepared release self-SBOM'),
            ('release', 'deliver-sbom', 'Retain release self-SBOM delivery receipts'),
        ):
            with self.subTest(workflow=file, step=step_name):
                retention = step(job(workflow(file), job_name), step_name)
                self.assertIn('include-hidden-files: true', retention)
                self.assertIn('path: ${{ runner.temp }}/rio-self-sbom/', retention)

    def restore(self, attempt, jobs, artifacts=None, extra_pages=None):
        source = script(step(job(workflow("release"), "deliver-sbom"),
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
                                             PREPARED_ARTIFACT="rio-self-sbom-v1.2.3-321-1"))
            calls = [json.loads(line) for line in (root / "calls").read_text().splitlines()] if (root / "calls").exists() else []
            restored = root / "rio-self-sbom/restored-artifact"
            published = root / "rio-published-sbom/rio-v1.2.3-source.cdx.json"
            state = root / "rio-self-sbom/delivery-state.json"
            return result, calls, restored.read_text() if restored.exists() else None, \
                published.read_bytes() if published.exists() else None, state.exists()

    def run_shell(self, source, **env):
        # Only the external self-SBOM tool is replaced: the workflow's version
        # selection, quoting, key guard and exit behavior run as written.
        with tempfile.TemporaryDirectory() as directory:
            calls = Path(directory) / "calls"
            output = Path(directory) / "output"
            prefix = 'python3() { printf "%s\\0" "$@" > "$CALLS"; }\n'
            shell_env = dict(os.environ, RUNNER_TEMP=directory,
                             GITHUB_RUN_ID="321", GITHUB_RUN_ATTEMPT="2",
                             SOURCE_SHA="0123456789abcdef0123456789abcdef01234567",
                             GITHUB_OUTPUT=str(output), CALLS=str(calls))
            shell_env.update(env)
            result = subprocess.run(["bash", "-euo", "pipefail", "-c", prefix + source],
                                    env=shell_env,
                                    capture_output=True, text=True)
            args = calls.read_bytes().decode().rstrip("\0").split("\0") if calls.exists() else []
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
                self.assertEqual(args[args.index("--version") + 1], "0.0.0-ci.321.2")
                self.assertEqual(args[args.index("--project-version") + 1],
                                 expected + "-0123456789ab.321.2")
                self.assertNotIn("--release", args)

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

    def test_trusted_ci_requires_key_before_delivery(self):
        delivery = step(job(workflow("ci"), "self-sbom"), "Deliver source SBOM")
        self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", delivery)
        self.assertIn("github.event_name != 'pull_request'", delivery)
        result, args = self.run_shell(script(delivery), DTRACK_API_KEY="")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(args, [])
        result, args = self.run_shell(script(delivery), DTRACK_API_KEY="test-only")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(args[:2], ["tools/self-sbom.py", "deliver"])

    def test_forks_prepare_without_receiving_the_delivery_secret(self):
        source = job(workflow("ci"), "self-sbom")
        self.assertNotRegex(source.split("steps:", 1)[0], r"(?i)if:|DTRACK_API_KEY")
        self.assertNotIn("DTRACK_API_KEY", step(source, "Prepare source SBOM"))
        skipped = step(source, "Explain skipped fork delivery")
        self.assertIn("github.event.pull_request.head.repo.full_name != github.repository", skipped)
        self.assertIn("GITHUB_STEP_SUMMARY", skipped)
        secret_lines = [line.strip() for line in source.splitlines() if "secrets." in line]
        self.assertEqual(secret_lines, ["DTRACK_API_KEY: ${{ secrets.RIO_DTRACK_API_KEY }}"])
        self.assertIn("actions/upload-artifact@", source)

    def test_reusable_ci_only_receives_its_declared_delivery_key(self):
        ci = workflow("ci")
        declaration = ci.split("  workflow_call:", 1)[1].split("\npermissions:", 1)[0]
        self.assertRegex(declaration, r"secrets:\s+RIO_DTRACK_API_KEY:\s+required: false")
        for name in ("release", "release-preflight"):
            validate = job(workflow(name), "validate")
            self.assertRegex(validate, r"secrets:\s+RIO_DTRACK_API_KEY: \$\{\{ secrets.RIO_DTRACK_API_KEY \}\}")
            self.assertNotIn("inherit", validate)
            self.assertNotIn("MACOS_", validate)

    def test_release_delivery_uses_retained_build_bundle_after_publication(self):
        source = workflow("release")
        build = job(source, "build")
        prepare = step(build, "Prepare release source SBOM")
        self.assertIn('--version "${TAG#v}"', prepare)
        self.assertIn('--project-version "$TAG"', prepare)
        self.assertIn("--release", prepare)
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
            (root / "dist/rio_linux_amd64").mkdir(parents=True)
            (root / "dist/rio_linux_amd64/rio").touch()
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
                                             GITHUB_RUN_ATTEMPT="2"))
            self.assertEqual(result.returncode, 0, result.stderr)
            args = calls.read_bytes().decode().rstrip("\0").split("\0")
            self.assertEqual(args[args.index("--version") + 1], "1.2.3")
            self.assertEqual(args[args.index("--project-version") + 1], "v1.2.3")
            self.assertIn("--release", args)
            self.assertEqual((root / "dist/rio-v1.2.3-source.cdx.json").read_bytes(),
                             b"prepared source bytes\n")
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
            (root / "dist/rio_linux_amd64").mkdir(parents=True)
            (root / "dist/rio_linux_amd64/rio").touch()
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
        for name in ("source-sbom_test.py", "self-sbom_test.py", "self-sbom-workflows_test.py"):
            self.assertIn("python3 tools/" + name, source)


if __name__ == "__main__":
    unittest.main()
