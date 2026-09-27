# Batch evidence and portable record v2

Run with Python 3.9+ and an installed Rio containing the client evidence workflow (v0.6.0 planned):

```sh
python3 tools/demo-batch-evidence/run.py /absolute/path/to/rio
```

Only synthetic inputs and a loopback receiver are used. No Go toolchain or container is required.
Two artifacts route to two targets, with one configured exclusion. The receiver accepts the first
upload and loses the second response; Rio retains the unknown acknowledgment and records the
unattempted suffix. An unchanged rerun refuses. Separate explicitly selected attempts retry the
unknown pair and deliver the unattempted artifact using fresh journal paths.

The demo also kills its own delivery child after the receiver observes a request backed by a durable
intent. After verifying that child has exited, the harness explicitly removes only its owned empty
locks; Rio itself never breaks locks. The absent completion remains unknown in the recovered record.

The demo then stops the receiver, corrupts the working index, and collects all four batches from
their retained index snapshots. It deletes its own source workspace and inspects only portable
JSON files, keeping the original partial snapshot. A forged receipt summary refuses inspection.
Runtime secret canaries must be absent from CLI output, journals, recovery sources and records.

The explicit HTTP policy is for this local synthetic receiver. These receipts demonstrate
acknowledgment and uncertainty, not Dependency-Track processing or content verification.
The optional HTML client report is covered by the complete client-record demo.

The client-evidence version of this demo requires an installed release containing `record report`
(v0.6.0 planned). It renders self-contained HTML after removing the source workspace. No JavaScript,
external fonts or network resources are needed to read it; retain the JSON for machine inspection.
