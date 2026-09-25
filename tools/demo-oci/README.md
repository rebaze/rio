# Installed-binary OCI walkthrough

Run with an installed Rio binary containing OCI delivery and Python 3.9+:

```sh
python3 tools/demo-oci/run.py /absolute/path/to/rio
```

Windows uses the same script with the native `rio.exe`. The script never runs Go, ORAS or Docker.
It creates a loopback synthetic OCI/Dependency-Track receiver, a temporary source workspace, and
clearly labeled synthetic image-index subjects. No production endpoint is used.

It exercises default mixed-target delivery, exact verified snapshot bytes despite source replacement,
standalone and exact-subject attachment, complete read-back and Referrers, explicit already-present
retry, gate/tamper refusals, wrong content with matching digest headers, unsupported discovery,
unusable positive receipts and lost responses. An actual child Rio process is killed after the stub
stores its manifest and before any response; only after the child has exited does the script remove
its owned stale lock and reconcile the intent-only journal without the original index/SBOM files.

The final shared record includes the mixed journals and independent unknown/accepted/verified facts.
The receiver is stopped before collection. The source workspace is removed and only the recipient's
`record.json` is used for portable inspection; deliberate corruption is refused. A separate record
retains the failed-gate override's different normalization history. Results, a retrieved SBOM copy,
request/status summaries, the recipient record and `walkthrough.json` remain in the printed output
directory. Auth values and session URLs are excluded.

These observations are synthetic. They establish neither real registry compatibility nor producer
authentication, security-analysis ingestion or future availability. Real Docker/vendor checks use
[the separate integration harness](integration/README.md).
