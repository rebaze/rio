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
        return {name: {'result': 'success'} for name in
                ('build', 'delivery-platforms', 'oci-distribution', 'dependency-track')}

    def test_all_jobs_must_succeed(self):
        self.assertEqual(self.gate(self.jobs()), 0)

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
