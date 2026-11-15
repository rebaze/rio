"""Run the actual aggregate CI gate against success and failure job results."""
import json
import os
from pathlib import Path
import subprocess
import textwrap
import unittest

WORKFLOW = (Path(__file__).resolve().parents[1] / '.github/workflows/ci.yaml').read_text()

class CompleteTest(unittest.TestCase):
    def gate(self, jobs):
        marker = '      - name: Require every validation job\n'
        self.assertTrue(marker in WORKFLOW, "aggregate CI gate is missing")
        script = textwrap.dedent(WORKFLOW.split(marker, 1)[1].split('        run: |\n', 1)[1])
        return subprocess.run(['bash', '-eu', '-o', 'pipefail', '-c', script],
                              env=dict(os.environ, NEEDS_JSON=json.dumps(jobs)),
                              capture_output=True).returncode

    def jobs(self):
        jobs = {name: {'result': 'success'} for name in
                ('build', 'delivery-platforms', 'oci-distribution', 'dependency-track', 'self-sbom', 'publish-main-sbom')}
        jobs['self-sbom']['outputs'] = {'publish-main': 'true'}
        return jobs

    def test_all_jobs_must_succeed(self):
        self.assertEqual(self.gate(self.jobs()), 0)

    def test_artifact_only_context_allows_only_the_main_publication_skip(self):
        jobs = self.jobs()
        jobs['self-sbom']['outputs']['publish-main'] = 'false'
        jobs['publish-main-sbom']['result'] = 'skipped'
        self.assertEqual(self.gate(jobs), 0)
        for name in jobs:
            if name == 'publish-main-sbom':
                continue
            with self.subTest(job=name):
                failed = self.jobs()
                failed['self-sbom']['outputs']['publish-main'] = 'false'
                failed['publish-main-sbom']['result'] = 'skipped'
                failed[name]['result'] = 'skipped'
                self.assertNotEqual(self.gate(failed), 0)

    def test_missing_or_invalid_eligibility_never_permits_a_skip(self):
        for value in (None, '', 'invalid'):
            jobs = self.jobs()
            jobs['self-sbom']['outputs']['publish-main'] = value
            jobs['publish-main-sbom']['result'] = 'skipped'
            self.assertNotEqual(self.gate(jobs), 0)

    def test_failed_cancelled_pending_skipped_or_missing_refused(self):
        for name in self.jobs():
            for result in ('failure', 'cancelled', 'skipped', 'pending', None):
                with self.subTest(name=name, result=result):
                    jobs = self.jobs(); jobs[name]['result'] = result
                    self.assertNotEqual(self.gate(jobs), 0)
            jobs = self.jobs(); del jobs[name]
            self.assertNotEqual(self.gate(jobs), 0)
        self.assertNotEqual(self.gate({}), 0)

if __name__ == '__main__':
    unittest.main()
