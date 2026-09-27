# Installed-binary OCI walkthrough

One `rio --json` invocation consumes the synthetic SBOM, checks it, delivers its exact output to
an OCI registry and Dependency-Track, and writes one compact `rio-run-receipt`. The receipt identifies
the input/output hashes, OCI config/SBOM/manifest bodies actually written, destination repository,
explicit HTTP transport, immutable references and synthetic receiver acknowledgments.

Run with an installed Rio v0.7.0 or newer binary and Python 3.9+:

```sh
python3 tools/demo-oci/run.py /absolute/path/to/rio
```

Windows uses the same script with the native `rio.exe`. The script never runs Go, ORAS or Docker.
It creates a loopback synthetic OCI/Dependency-Track receiver, a temporary source workspace, and
clearly labeled synthetic image-index subjects. No production endpoint is used.

The first delivery runs the complete pipeline once. It proves both targets receive the verified
snapshot even when the source output is replaced after verification. The receipt's three OCI
submitted bodies are checked against bytes stored by the receiver; the Dependency-Track output
reference and event token are checked independently. Read-only planning is exercised with an invalid
credential and, for the root plan, a nonexistent CA file.

Specialist stage invocations exercise standalone and exact-subject attachment, complete read-back
and Referrers, explicit already-present retry without new submitted bodies, failed-gate/tamper
refusals, wrong content with matching digest headers, unsupported discovery, unusable positive
receipts and lost responses. Each normalization, delivery and reconciliation invocation retains
its own automatic receipt. Earlier normalization remains explicitly pre-existing in delivery and
reconciliation receipts; retries and reconciliation link prior attempts without rewriting them.

An actual child Rio process is killed after the stub stores its manifest and before any response.
`rio record recover --run DIR --output NEW` produces an incomplete receipt offline, leaves the
owned journal lock in place and makes no requests. Only after confirming the child has exited does
the script explicitly remove its owned stale lock for a separate native reconciliation. The original
index/SBOM files are deleted first. Reconciliation records content verification in its own receipt;
the original upload acknowledgment remains unknown and no submission is fabricated.

The script copies each completed receipt separately and checks that later invocations never change
it. It stops the receiver and removes the source workspace before inspecting and rendering every
recipient JSON file to self-contained HTML. Deliberate receipt corruption is refused. Results,
a retrieved SBOM copy, sanitized request/status summaries, separate recipient JSON/HTML files and
`walkthrough.json` remain in the printed output directory. Secret canaries are checked in CLI
results, receipts and HTML. There is no collection step or combined history bundle.

These observations are synthetic. They establish neither real registry compatibility nor producer
authentication, security-analysis ingestion or future availability. This demo deliberately uses
explicit loopback HTTP; it makes no TLS-handshake claim. Real Docker/vendor checks use
[the separate integration harness](integration/README.md).
