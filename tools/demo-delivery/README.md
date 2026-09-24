# Installed-binary verified delivery demo

Run `python3 tools/demo-delivery/run.py /absolute/path/to/rio` with Python 3.9+.
On Windows use `python tools/demo-delivery/run.py C:\path\rio.exe`.
Only an installed Rio binary and the Python standard library are needed. The demo never builds Rio.

The normal path runs `rio normalize`, `rio delivery plan`, and `rio deliver` with default filenames,
using one rio.yaml. Three synthetic artifact-set modules feed two loopback receivers. The demo
retains its temporary directory and demonstrates:

- Index membership remains authoritative after source modules change.
- Default subject projects, target fan-out, overrides/exclusions, unused rules and exact upload bytes.
- Duplicate project and later missing-credential refusal before any upload.
- Automatic journal paths and unchanged-rerun refusal.
- Partial acceptance followed by a lost response, unattempted work, filtered completion and deliberate retry.
- Journal inspection and read-only receipt activity reconciliation.
- Explicit UUID, digest tampering, failed-gate refusal/override, malformed receipt and skipped schema validation.

All receiver receipts/statuses are explicitly **synthetic**. They prove the demo behavior and do
not establish Dependency-Track compatibility, ingestion or content retention. The separately
retained [real 5.1.1 integration evidence](integration/README.md) covers the unchanged adapter's
transport contract; this demo does not relabel or refresh that historical evidence.

See [configuration, limits and recovery semantics](../README.md#native-verified-delivery).
